//! IKEv2 encrypted payload (SK) — AES-CBC + HMAC-SHA-256-128 (RFC 7296 §3.14).
//!
//! Once the IKE SA exists, every payload travels inside a single `SK` payload:
//!
//! ```text
//! header (next = first inner payload) | IV | ciphertext | ICV
//! plaintext = [payload chain] [padding] [pad length]
//! ```
//!
//! * Encryption: AES-CBC with the PKCS#7-style padding IKEv2 defines, where the
//!   last plaintext octet is the number of padding octets.
//! * Integrity: HMAC-SHA-256 truncated to 128 bits, computed over the **whole
//!   message** (header + payload header + IV + ciphertext), not over the
//!   plaintext.
//!
//! Only AES-CBC-128 + HMAC-SHA-256-128 is implemented; anything else is
//! reported as unsupported rather than guessed at.

#![forbid(unsafe_code)]

use crate::ikev2::{
    decode_payloads, encode_payloads, Header, IkeError, Message, Payload, PayloadType, HEADER_LEN,
};
use aka::eap_aka_prime::hmac_sha256;
use aka::{decrypt_block, encrypt_block};

/// AES block size / CBC IV length.
pub const BLOCK_LEN: usize = 16;
/// Truncated HMAC-SHA-256 length (`hmac-sha-256-128`).
pub const ICV_LEN: usize = 16;

/// Errors from the SK layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkError {
    /// The key lengths do not match AES-CBC-128 + SHA-256-128.
    BadKeyLength { encryption: usize, integrity: usize },
    /// The message failed to parse.
    Ike(IkeError),
    /// The ciphertext was not a whole number of blocks.
    BadCipherLength(usize),
    /// The ICV did not verify.
    BadIcv,
    /// The padding length was larger than the plaintext.
    BadPadding(u8),
    /// The outer payload was not `ENCRYPTED`.
    NotEncrypted(PayloadType),
}

impl core::fmt::Display for SkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SkError::BadKeyLength {
                encryption,
                integrity,
            } => write!(
                f,
                "SK key lengths {encryption}/{integrity} do not fit AES-CBC-128 + SHA-256-128"
            ),
            SkError::Ike(e) => write!(f, "IKE error: {e}"),
            SkError::BadCipherLength(n) => {
                write!(f, "ciphertext length {n} is not a block multiple")
            }
            SkError::BadIcv => f.write_str("SK integrity check failed"),
            SkError::BadPadding(n) => write!(f, "SK padding length {n} overruns the plaintext"),
            SkError::NotEncrypted(t) => write!(f, "payload type {t:?} is not ENCRYPTED"),
        }
    }
}

impl std::error::Error for SkError {}

impl From<IkeError> for SkError {
    fn from(e: IkeError) -> Self {
        SkError::Ike(e)
    }
}

/// One direction's SK keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sk {
    encryption: Vec<u8>,
    integrity: Vec<u8>,
}

impl Sk {
    /// Build from `SK_e` (16 octets) and `SK_a` (32 octets).
    pub fn aes_cbc_128_sha256_128(sk_e: &[u8], sk_a: &[u8]) -> Result<Self, SkError> {
        if sk_e.len() != 16 || sk_a.len() != 32 {
            return Err(SkError::BadKeyLength {
                encryption: sk_e.len(),
                integrity: sk_a.len(),
            });
        }
        Ok(Self {
            encryption: sk_e.to_vec(),
            integrity: sk_a.to_vec(),
        })
    }

    /// Encrypt a payload chain into one message: `header | IV | ciphertext | ICV`.
    ///
    /// `iv` is caller-supplied so the result is deterministic in tests; a real
    /// implementation uses a fresh random IV per message.
    pub fn seal(&self, header: Header, payloads: &[Payload], iv: &[u8; BLOCK_LEN]) -> Vec<u8> {
        let inner = encode_payloads(payloads);
        // RFC 7296 §3.14: plaintext = payloads || padding, and the last byte of
        // the padding field holds the padding length. There is no trailing
        // next-payload byte; the chain ends inside the payloads.
        let pad_len = (BLOCK_LEN - ((inner.len() + 1) % BLOCK_LEN)) % BLOCK_LEN;
        let mut plaintext = inner;
        plaintext.resize(plaintext.len() + pad_len, 0);
        plaintext.push(pad_len as u8);

        let ciphertext = self.cbc_encrypt(&plaintext, iv);

        // The outer SK payload header, then IV + ciphertext.
        let first_next = payloads
            .first()
            .map(|p| p.kind)
            .unwrap_or(PayloadType::None);
        let body_len = BLOCK_LEN + ciphertext.len();
        let mut out = Vec::with_capacity(HEADER_LEN + 4 + body_len + ICV_LEN);
        let mut sealed = header;
        sealed.next_payload = PayloadType::Encrypted;
        out.extend_from_slice(&sealed.encode(HEADER_LEN + 4 + body_len + ICV_LEN));
        // Outer payload: next = first inner payload, critical 0, length.
        out.push(first_next as u8);
        out.push(0);
        out.extend_from_slice(&((4 + body_len) as u16).to_be_bytes());
        out.extend_from_slice(iv);
        out.extend_from_slice(&ciphertext);
        let icv = self.icv(&out);
        out.extend_from_slice(&icv);
        out
    }

    /// Verify and decrypt a sealed message.
    pub fn open(&self, bytes: &[u8]) -> Result<Message, SkError> {
        let (header, total) = Header::decode(bytes)?;
        if total < HEADER_LEN + 4 + BLOCK_LEN + ICV_LEN {
            return Err(SkError::Ike(IkeError::Malformed(
                "sealed message too short",
            )));
        }
        let icv_at = total - ICV_LEN;
        let expected = self.icv(&bytes[..icv_at]);
        if !constant_time_eq(&bytes[icv_at..total], &expected) {
            return Err(SkError::BadIcv);
        }
        if header.next_payload != PayloadType::Encrypted {
            return Err(SkError::NotEncrypted(header.next_payload));
        }
        let payload = &bytes[HEADER_LEN..icv_at];
        // Outer payload header: next, critical/reserved, length.
        if payload.len() < 4 {
            return Err(SkError::Ike(IkeError::Malformed(
                "SK payload header truncated",
            )));
        }
        let first_next =
            PayloadType::from_u8(payload[0]).ok_or(IkeError::UnknownPayload(payload[0]))?;
        let plen = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        if plen != payload.len() {
            return Err(SkError::Ike(IkeError::Malformed(
                "SK payload length mismatch",
            )));
        }
        let body = &payload[4..];
        if body.len() < BLOCK_LEN {
            return Err(SkError::BadCipherLength(body.len()));
        }
        let mut iv = [0u8; BLOCK_LEN];
        iv.copy_from_slice(&body[..BLOCK_LEN]);
        let ciphertext = &body[BLOCK_LEN..];
        if ciphertext.is_empty() || ciphertext.len() % BLOCK_LEN != 0 {
            return Err(SkError::BadCipherLength(ciphertext.len()));
        }
        let mut plaintext = self.cbc_decrypt(ciphertext, &iv);
        let pad_len = *plaintext
            .last()
            .ok_or(SkError::Ike(IkeError::Malformed("empty plaintext")))?
            as usize;
        if pad_len + 1 > plaintext.len() {
            return Err(SkError::BadPadding(pad_len as u8));
        }
        plaintext.truncate(plaintext.len() - 1 - pad_len);
        let payloads = decode_payloads(&plaintext, first_next)?;
        Ok(Message {
            header: Header {
                next_payload: PayloadType::Encrypted,
                ..header
            },
            payloads,
        })
    }

    fn icv(&self, data: &[u8]) -> [u8; ICV_LEN] {
        let full = hmac_sha256(&self.integrity, data);
        let mut out = [0u8; ICV_LEN];
        out.copy_from_slice(&full[..ICV_LEN]);
        out
    }

    fn cbc_encrypt(&self, plaintext: &[u8], iv: &[u8; BLOCK_LEN]) -> Vec<u8> {
        let mut key = [0u8; 16];
        key.copy_from_slice(&self.encryption);
        let mut previous = *iv;
        let mut out = Vec::with_capacity(plaintext.len());
        for chunk in plaintext.chunks_exact(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            for i in 0..BLOCK_LEN {
                block[i] = chunk[i] ^ previous[i];
            }
            previous = encrypt_block(&key, &block);
            out.extend_from_slice(&previous);
        }
        out
    }

    fn cbc_decrypt(&self, ciphertext: &[u8], iv: &[u8; BLOCK_LEN]) -> Vec<u8> {
        let mut key = [0u8; 16];
        key.copy_from_slice(&self.encryption);
        let mut previous = *iv;
        let mut out = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks_exact(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(chunk);
            let plain = decrypt_block(&key, &block);
            for i in 0..BLOCK_LEN {
                out.push(plain[i] ^ previous[i]);
            }
            previous = block;
        }
        out
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::{ExchangeType, FLAG_INITIATOR};

    fn sk() -> Sk {
        Sk::aes_cbc_128_sha256_128(&[0x11; 16], &[0x22; 32]).unwrap()
    }

    fn header() -> Header {
        Header {
            initiator_spi: [0x01; 8],
            responder_spi: [0x02; 8],
            next_payload: PayloadType::None,
            exchange: ExchangeType::IkeAuth,
            flags: FLAG_INITIATOR,
            message_id: 1,
        }
    }

    #[test]
    fn seal_and_open_round_trip() {
        let payloads = vec![
            Payload {
                kind: PayloadType::Idi,
                critical: false,
                body: vec![2, 0, 0, 0, b'u', b's', b'e', b'r'],
            },
            Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: vec![2, 1, 0, 9, 50, 1, 0xAA, 0xBB, 0xCC],
            },
        ];
        let bytes = sk().seal(header(), &payloads, &[0x33; 16]);
        // Outer header: next payload = ENCRYPTED, length covers ICV.
        assert_eq!(bytes[16], PayloadType::Encrypted as u8);
        let total = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
        assert_eq!(total, bytes.len());
        // The plaintext never appears on the wire.
        assert!(!bytes.windows(4).any(|w| w == b"user"));

        let opened = sk().open(&bytes).unwrap();
        assert_eq!(opened.payloads, payloads);
        assert_eq!(opened.header.message_id, 1);
    }

    #[test]
    fn tampering_breaks_the_icv() {
        let payloads = vec![Payload {
            kind: PayloadType::Nonce,
            critical: false,
            body: vec![0xAA; 16],
        }];
        let mut bytes = sk().seal(header(), &payloads, &[0x33; 16]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert_eq!(sk().open(&bytes), Err(SkError::BadIcv));
    }

    #[test]
    fn a_different_key_cannot_open() {
        let payloads = vec![Payload {
            kind: PayloadType::Nonce,
            critical: false,
            body: vec![0xAA; 16],
        }];
        let bytes = sk().seal(header(), &payloads, &[0x33; 16]);
        let other = Sk::aes_cbc_128_sha256_128(&[0x11; 16], &[0x99; 32]).unwrap();
        assert_eq!(other.open(&bytes), Err(SkError::BadIcv));
    }

    #[test]
    fn padding_brings_the_plaintext_to_a_block_multiple() {
        // 1 payload byte of header plus a body of length 1 => pad to 16.
        let payloads = vec![Payload {
            kind: PayloadType::Nonce,
            critical: false,
            body: vec![0x01],
        }];
        let bytes = sk().seal(header(), &payloads, &[0x33; 16]);
        let total = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
        let cipher_len = total - HEADER_LEN - 4 - BLOCK_LEN - ICV_LEN;
        assert_eq!(cipher_len % BLOCK_LEN, 0);
        assert_eq!(sk().open(&bytes).unwrap().payloads, payloads);
    }

    #[test]
    fn bad_key_lengths_are_rejected() {
        assert!(matches!(
            Sk::aes_cbc_128_sha256_128(&[0; 8], &[0; 32]),
            Err(SkError::BadKeyLength { .. })
        ));
    }
}
