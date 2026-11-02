//! AES-128 single-block encryption, as Milenage and IKEv2's SK layer need.
//!
//! The implementation is the RustCrypto `aes` crate. This module exists only to
//! fix the signature the protocol code wants — one block in, one block out —
//! rather than to reimplement AES.
//!
//! Why it is delegated: a hand-written AES agreed with itself perfectly, so
//! every self-consistent test passed while an independent peer disagreed. A
//! primitive has no business being validated only against itself.

#![forbid(unsafe_code)]

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

/// Encrypt one 16-octet block with a 128-bit key (FIPS 197).
pub fn encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut out = (*block).into();
    cipher.encrypt_block(&mut out);
    out.into()
}

/// Decrypt one 16-octet block with a 128-bit key (FIPS 197).
pub fn decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut out = (*block).into();
    cipher.decrypt_block(&mut out);
    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// FIPS 197 Appendix C.1: the AES-128 example vector.
    #[test]
    fn fips_197_appendix_c1() {
        let key = h("000102030405060708090a0b0c0d0e0f");
        let pt = h("00112233445566778899aabbccddeeff");
        let ct = encrypt_block(&key, &pt);
        assert_eq!(ct, h("69c4e0d86a7b0430d8cdb78070b4c55a"));
        assert_eq!(decrypt_block(&key, &ct), pt);
    }

    /// FIPS 197 Appendix B: the all-zero key and plaintext.
    #[test]
    fn fips_197_appendix_b() {
        let ct = encrypt_block(&[0u8; 16], &[0u8; 16]);
        assert_eq!(ct, h("66e94bd4ef8a2c3b884cfa59ca342b2e"));
    }

    /// Every key produces a bijection: decrypt undoes encrypt.
    #[test]
    fn decrypt_inverts_encrypt_for_many_inputs() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        for seed in 0u8..64 {
            let pt = [seed; 16];
            let ct = encrypt_block(&key, &pt);
            assert_eq!(decrypt_block(&key, &ct), pt, "seed {seed}");
        }
    }
}
