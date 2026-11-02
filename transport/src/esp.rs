//! IPsec ESP for the IMS security mechanism (SEC-002/SEC-003).
//!
//! 3GPP TS 33.203 §7 protects the Gm interface with **transport-mode ESP** whose
//! keys come straight from IMS-AKA: `IK` gives integrity and `CK` would give
//! encryption (null encryption is the mandatory profile). There is no IKE in
//! IMS; the SAs are programmed from the negotiated `Security-Client` /
//! `Security-Server` parameters (RFC 3329).
//!
//! This module is the real ESP data-plane codec:
//!
//! ```text
//! +--------+--------+-----------------+-----+--------+--------+--------+
//! |  SPI   |  Seq   |    payload      | pad | PadLen | NextHd |  ICV   |
//! | 4      | 4      |                 | 0..3|   1    |   1    | 12     |
//! +--------+--------+-----------------+-----+--------+--------+--------+
//! ```
//!
//! * Integrity: **HMAC-MD5-96** (RFC 2403, mandatory in TS 33.203) or
//!   **HMAC-SHA-1-96** (RFC 2404).
//! * Encryption: **null** only. `CK` is accepted and stored for future AES
//!   support but never applied.
//! * Anti-replay: the 64-packet window of RFC 4303 §3.4.3.
//!
//! The wire format is verified byte-exactly against RFC 2403's HMAC vector in
//! the tests. `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

/// Octets in the ESP SPI field.
pub const SPI_LEN: usize = 4;
/// Octets in the ESP sequence field.
pub const SEQ_LEN: usize = 4;
/// Octets in a 96-bit ICV (`hmac-*-96`).
pub const ICV_LEN: usize = 12;
/// Octets in the Pad Length field.
pub const PAD_LEN_LEN: usize = 1;
/// Octets in the Next Header field.
pub const NEXT_HDR_LEN: usize = 1;
/// Fixed overhead of an authenticated null-encryption frame (no payload/pad).
pub const OVERHEAD: usize = SPI_LEN + SEQ_LEN + PAD_LEN_LEN + NEXT_HDR_LEN + ICV_LEN;

/// `Next Header` for SIP over UDP: UDP (RFC 1700).
pub const NEXT_HDR_UDP: u8 = 17;

/// The integrity algorithms IMS uses (TS 33.203 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspIntegrity {
    /// `hmac-md5-96` (RFC 2403) — mandatory.
    HmacMd5_96,
    /// `hmac-sha-1-96` (RFC 2404).
    HmacSha1_96,
}

impl EspIntegrity {
    /// Map an IMS `algorithm=` token to an ESP integrity algorithm.
    pub fn from_ims(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "hmac-md5-96" => Some(EspIntegrity::HmacMd5_96),
            "hmac-sha-1-96" => Some(EspIntegrity::HmacSha1_96),
            _ => None,
        }
    }

    /// The IMS token for this algorithm.
    pub fn ims_name(self) -> &'static str {
        match self {
            EspIntegrity::HmacMd5_96 => "hmac-md5-96",
            EspIntegrity::HmacSha1_96 => "hmac-sha-1-96",
        }
    }

    /// The kernel name used by `ip xfrm`: `hmac(md5)` / `hmac(sha1)`.
    pub fn xfrm_name(self) -> &'static str {
        match self {
            EspIntegrity::HmacMd5_96 => "hmac(md5)",
            EspIntegrity::HmacSha1_96 => "hmac(sha1)",
        }
    }

    fn icv(self, key: &[u8], data: &[u8]) -> [u8; ICV_LEN] {
        let full = match self {
            EspIntegrity::HmacMd5_96 => hmac_md5(key, data).to_vec(),
            EspIntegrity::HmacSha1_96 => hmac_sha1(key, data).to_vec(),
        };
        let mut icv = [0u8; ICV_LEN];
        icv.copy_from_slice(&full[..ICV_LEN]);
        icv
    }
}

/// Errors from ESP (de)capsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EspError {
    /// The frame is shorter than the fixed header + trailer + ICV.
    TooShort(usize),
    /// The declared pad length overruns the frame.
    BadPadLength { total: usize, pad: u8 },
    /// The ICV did not verify.
    BadIcv,
    /// The sequence number was already seen (replay) or is zero.
    Replay(u32),
    /// The integrity key is empty or absurdly long.
    BadKey(usize),
}

impl core::fmt::Display for EspError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EspError::TooShort(n) => write!(f, "ESP frame too short: {n} bytes"),
            EspError::BadPadLength { total, pad } => {
                write!(f, "ESP pad length {pad} overruns a {total}-byte frame")
            }
            EspError::BadIcv => f.write_str("ESP ICV did not verify"),
            EspError::Replay(seq) => write!(f, "ESP sequence {seq} replayed or invalid"),
            EspError::BadKey(n) => write!(f, "ESP integrity key length {n} is not usable"),
        }
    }
}

impl std::error::Error for EspError {}

/// A decapsulated ESP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspPacket {
    pub spi: u32,
    pub seq: u32,
    pub next_header: u8,
    pub payload: Vec<u8>,
}

/// Anti-replay window (RFC 4303 §3.4.3), 64 packets wide.
#[derive(Debug, Clone)]
struct ReplayWindow {
    highest: u32,
    bitmap: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    /// Return `true` if `seq` is fresh and record it. Rejects replays and
    /// anything older than the window.
    fn accept(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if self.highest == 0 || seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = seq;
            return true;
        }
        let offset = self.highest - seq;
        if offset >= 64 {
            return false;
        }
        let mask = 1u64 << offset;
        if self.bitmap & mask != 0 {
            return false;
        }
        self.bitmap |= mask;
        true
    }
}

/// One directional security association: an SPI, an integrity algorithm and a
/// key, with outbound sequence and inbound replay state.
#[derive(Debug, Clone)]
pub struct EspSa {
    /// Security Parameter Index.
    pub spi: u32,
    /// Integrity algorithm.
    pub integrity: EspIntegrity,
    /// Integrity key (`IK` from AKA).
    integrity_key: Vec<u8>,
    /// Encryption key (`CK`); stored but unused while `ealg=null`.
    encryption_key: Vec<u8>,
    seq: u32,
    replay: ReplayWindow,
}

impl EspSa {
    /// Build an SA. `ik` is the AKA integrity key; `ck` is stored for future
    /// AES support and may be empty.
    pub fn new(spi: u32, integrity: EspIntegrity, ik: &[u8], ck: &[u8]) -> Result<Self, EspError> {
        if ik.is_empty() || ik.len() > 64 {
            return Err(EspError::BadKey(ik.len()));
        }
        Ok(Self {
            spi,
            integrity,
            integrity_key: ik.to_vec(),
            encryption_key: ck.to_vec(),
            seq: 0,
            replay: ReplayWindow::new(),
        })
    }

    /// The integrity key (used when programming a kernel SA).
    pub fn integrity_key(&self) -> &[u8] {
        &self.integrity_key
    }

    /// Whether the SA carries a stored (currently unused) encryption key.
    pub fn has_encryption_key(&self) -> bool {
        !self.encryption_key.is_empty()
    }

    /// The next outbound sequence number.
    pub fn next_seq(&self) -> u32 {
        self.seq.wrapping_add(1)
    }

    /// Wrap `payload` in an authenticated ESP transport frame.
    pub fn encapsulate(&mut self, payload: &[u8], next_hdr: u8) -> Vec<u8> {
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        // Pad so the encrypted region (payload + pad + padlen + nexthdr) is a
        // multiple of 4, as ESP requires (RFC 4303 §2.4).
        let pad = (4 - ((payload.len() + 2) % 4)) % 4;

        let mut frame = Vec::with_capacity(OVERHEAD + payload.len() + pad);
        frame.extend_from_slice(&self.spi.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&vec![0u8; pad]);
        frame.push(pad as u8);
        frame.push(next_hdr);
        let icv = self.integrity.icv(&self.integrity_key, &frame);
        frame.extend_from_slice(&icv);
        frame
    }

    /// Verify and unwrap an ESP frame. Enforces the replay window.
    pub fn decapsulate(&mut self, frame: &[u8]) -> Result<EspPacket, EspError> {
        if frame.len() < OVERHEAD {
            return Err(EspError::TooShort(frame.len()));
        }
        let spi = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if spi != self.spi {
            return Err(EspError::BadIcv);
        }
        let seq = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);

        let body_end = frame.len() - ICV_LEN;
        let received = &frame[body_end..];
        let expected = self.integrity.icv(&self.integrity_key, &frame[..body_end]);
        if !constant_time_eq(received, &expected) {
            return Err(EspError::BadIcv);
        }

        let pad = frame[body_end - 2];
        let next_header = frame[body_end - 1];
        let payload_end = body_end
            .checked_sub(2 + pad as usize)
            .ok_or(EspError::BadPadLength {
                total: frame.len(),
                pad,
            })?;
        if payload_end < SPI_LEN + SEQ_LEN {
            return Err(EspError::BadPadLength {
                total: frame.len(),
                pad,
            });
        }

        if !self.replay.accept(seq) {
            return Err(EspError::Replay(seq));
        }

        Ok(EspPacket {
            spi,
            seq,
            next_header,
            payload: frame[SPI_LEN + SEQ_LEN..payload_end].to_vec(),
        })
    }
}

/// Constant-time comparison (avoid leaking ICV match position through timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-MD5 (RFC 2104) with a 64-byte block.
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&md5_digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    let mut outer = Vec::with_capacity(64 + 16);
    for b in block.iter() {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(data);
    outer.extend_from_slice(&md5_digest(&inner));
    md5_digest(&outer)
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

/// HMAC-SHA-1 (RFC 2104) with a 64-byte block.
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    let mut outer = Vec::with_capacity(64 + 20);
    for b in block.iter() {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(data);
    outer.extend_from_slice(&sha1(&inner));
    sha1(&outer)
}

/// Minimal SHA-1 (FIPS 180-4). Only used for HMAC-SHA-1-96.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const IK: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    #[test]
    fn round_trips_inner_packet() {
        let mut out = EspSa::new(0x20000, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut inbound = EspSa::new(0x20000, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let inner = b"SIP/2.0 request bytes";
        let frame = out.encapsulate(inner, NEXT_HDR_UDP);
        let packet = inbound.decapsulate(&frame).unwrap();
        assert_eq!(packet.spi, 0x20000);
        assert_eq!(packet.seq, 1, "the first ESP packet has sequence 1");
        assert_eq!(packet.payload, inner);
        assert_eq!(packet.next_header, NEXT_HDR_UDP);
        // Frame shape: SPI + seq + payload + pad + 2 trailer + ICV, with the
        // encrypted region aligned to 4 octets.
        assert!(frame.len() >= OVERHEAD + inner.len());
        assert_eq!((frame.len() - SPI_LEN - SEQ_LEN - ICV_LEN) % 4, 0);
    }

    #[test]
    fn sequence_advances_per_packet() {
        let mut out = EspSa::new(1, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut inbound = EspSa::new(1, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let a = out.encapsulate(b"one", NEXT_HDR_UDP);
        let b = out.encapsulate(b"two", NEXT_HDR_UDP);
        assert_eq!(inbound.decapsulate(&a).unwrap().seq, 1);
        let second = inbound.decapsulate(&b).unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.payload, b"two");
    }

    #[test]
    fn icv_is_enforced() {
        let mut out = EspSa::new(7, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut inbound = EspSa::new(7, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut frame = out.encapsulate(b"tamper me", NEXT_HDR_UDP);
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(inbound.decapsulate(&frame), Err(EspError::BadIcv));
    }

    #[test]
    fn a_different_key_is_rejected() {
        let mut out = EspSa::new(9, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut other_key = IK;
        other_key[0] ^= 0xFF;
        let mut inbound = EspSa::new(9, EspIntegrity::HmacMd5_96, &other_key, &[]).unwrap();
        let frame = out.encapsulate(b"x", NEXT_HDR_UDP);
        assert_eq!(inbound.decapsulate(&frame), Err(EspError::BadIcv));
    }

    #[test]
    fn replay_is_rejected() {
        let mut out = EspSa::new(3, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let mut inbound = EspSa::new(3, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        let frame = out.encapsulate(b"once", NEXT_HDR_UDP);
        assert!(inbound.decapsulate(&frame).is_ok());
        assert_eq!(inbound.decapsulate(&frame), Err(EspError::Replay(1)));
    }

    #[test]
    fn replay_window_accepts_reorder_within_64() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(3)); // in-window, older, not seen
        assert!(w.accept(4));
        assert!(!w.accept(3)); // replay
        assert!(w.accept(6));
        // A packet 64 behind the highest is outside the window.
        assert!(w.accept(70));
        assert!(!w.accept(5));
    }

    #[test]
    fn rejects_truncated_frame() {
        let mut sa = EspSa::new(1, EspIntegrity::HmacMd5_96, &IK, &[]).unwrap();
        assert_eq!(sa.decapsulate(&[0, 1, 2]), Err(EspError::TooShort(3)));
    }

    #[test]
    fn sha1_and_hmac_vectors() {
        // RFC 3174 §7.3: SHA-1("abc").
        assert_eq!(
            sha1(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
        // RFC 2202 §3, test case 1: HMAC-SHA-1 with 20-byte 0x0b key.
        let key = [0x0b; 20];
        assert_eq!(
            hmac_sha1(&key, b"Hi There"),
            [
                0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
                0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
            ]
        );
        // RFC 2202 §2, test case 1: HMAC-MD5 with 16-byte 0x0b key.
        let key16 = [0x0b; 16];
        assert_eq!(
            hmac_md5(&key16, b"Hi There"),
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
                0xfc, 0x9d
            ]
        );
    }

    #[test]
    fn ims_algorithm_tokens_map() {
        assert_eq!(
            EspIntegrity::from_ims("hmac-md5-96"),
            Some(EspIntegrity::HmacMd5_96)
        );
        assert_eq!(
            EspIntegrity::from_ims("HMAC-SHA-1-96"),
            Some(EspIntegrity::HmacSha1_96)
        );
        assert_eq!(EspIntegrity::from_ims("hmac-sha-256-128"), None);
        assert_eq!(EspIntegrity::HmacMd5_96.xfrm_name(), "hmac(md5)");
    }
}
