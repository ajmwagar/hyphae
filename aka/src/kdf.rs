//! The generic 3GPP key derivation function (TS 33.220 Annex B.2).
//!
//! ```text
//! S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
//! derived key = HMAC-SHA-256(K, S)
//! ```
//!
//! `Li` is the length of `Pi` in octets as two big-endian octets, and `FC`
//! selects which 3GPP procedure owns the derivation (Annex B.2.2 allocates the
//! ranges). Several specifications reuse this function with different `FC`
//! values and parameter lists: TS 24.302 for EAP-AKA' CK'/IK' (`FC = 0x20`),
//! TS 33.220 for the GBA NAF keys (`FC = 0x01`), among others.
//!
//! The primitive is HMAC-SHA-256, which this crate already pins to RFC 4231
//! §4.2–4.8. What is implemented here is only the input encoding, which is the
//! part that goes wrong: dropping a length, using a 1-octet length, or putting
//! the parameters back to front.

use crate::eap_aka_prime::hmac_sha256;

/// Length of a KDF output (HMAC-SHA-256).
pub const OUTPUT_LEN: usize = 32;

/// Errors from building a KDF input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdfError {
    /// A parameter exceeded the 65535-octet limit of the two-octet length.
    ParameterTooLong(usize),
    /// `FC` must be one or two octets (Annex B.2.0).
    BadFc(usize),
}

impl core::fmt::Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KdfError::ParameterTooLong(n) => {
                write!(f, "KDF parameter of {n} octets exceeds 65535")
            }
            KdfError::BadFc(n) => write!(f, "KDF FC must be 1 or 2 octets, got {n}"),
        }
    }
}

impl std::error::Error for KdfError {}

/// Build the string `S` from an `FC` and its parameters (Annex B.2.0).
pub fn input(fc: &[u8], params: &[&[u8]]) -> Result<Vec<u8>, KdfError> {
    if fc.len() != 1 && fc.len() != 2 {
        return Err(KdfError::BadFc(fc.len()));
    }
    let mut s = Vec::with_capacity(8 + params.iter().map(|p| p.len() + 2).sum::<usize>());
    s.extend_from_slice(fc);
    for p in params {
        if p.len() > 0xffff {
            return Err(KdfError::ParameterTooLong(p.len()));
        }
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    Ok(s)
}

/// `KDF(K, S) = HMAC-SHA-256(K, S)` (Annex B.2.0 step 3).
pub fn kdf(fc: &[u8], params: &[&[u8]], key: &[u8]) -> Result<[u8; OUTPUT_LEN], KdfError> {
    let s = input(fc, params)?;
    Ok(hmac_sha256(key, &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_is_fc_then_each_parameter_with_its_length() {
        let s = input(&[0x01], &[b"gba-me", b"rnd", b"impi"]).unwrap();
        assert_eq!(
            s,
            vec![
                0x01, // FC
                b'g', b'b', b'a', b'-', b'm', b'e', 0x00, 0x06, // P0, L0
                b'r', b'n', b'd', 0x00, 0x03, // P1, L1
                b'i', b'm', b'p', b'i', 0x00, 0x04, // P2, L2
            ]
        );
    }

    #[test]
    fn empty_parameter_is_allowed_and_encodes_a_zero_length() {
        let s = input(&[0x20], &[b""]).unwrap();
        assert_eq!(s, vec![0x20, 0x00, 0x00]);
    }

    #[test]
    fn two_octet_fc_is_allowed_one_octet_is_required_otherwise() {
        assert!(input(&[0xff, 0x01], &[]).is_ok());
        assert_eq!(input(&[], &[]), Err(KdfError::BadFc(0)));
        assert_eq!(input(&[1, 2, 3], &[]), Err(KdfError::BadFc(3)));
    }
}
