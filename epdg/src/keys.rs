//! IKEv2 key schedule (RFC 7296 §2.13–2.14).
//!
//! After SA_INIT both sides have the DH shared secret and the two nonces. The
//! key schedule is:
//!
//! ```text
//! SKEYSEED = prf(Ni | Nr, g^ir)
//! {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
//!          = prf+(SKEYSEED, Ni | Nr)
//! ```
//!
//! `prf+` is the same construction as the RFC 5448 PRF', so this module reuses
//! the HMAC-SHA-256 primitive from `aka::eap_aka_prime` rather than growing a
//! second one.

#![forbid(unsafe_code)]

use aka::eap_aka_prime::hmac_sha256;

/// How much key material each class needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeKeySizes {
    /// `SK_d` — derivation key for rekeying child SAs.
    pub sk_d: usize,
    /// `SK_ei` / `SK_er` — encryption keys (one per direction).
    pub sk_e: usize,
    /// `SK_ai` / `SK_ar` — integrity keys (one per direction).
    pub sk_a: usize,
    /// `SK_pi` / `SK_pr` — AUTH payload keys (one per direction).
    pub sk_p: usize,
}

impl IkeKeySizes {
    /// AES-CBC-128 + HMAC-SHA-256-128, the profile ePDGs commonly negotiate.
    pub fn aes_cbc_128_sha256_128() -> Self {
        Self {
            sk_d: 32,
            sk_e: 16,
            sk_a: 32,
            sk_p: 32,
        }
    }

    /// AES-CBC-256 + HMAC-SHA-256-128.
    pub fn aes_cbc_256_sha256_128() -> Self {
        Self {
            sk_d: 32,
            sk_e: 32,
            sk_a: 32,
            sk_p: 32,
        }
    }

    fn total(&self) -> usize {
        self.sk_d + 2 * self.sk_a + 2 * self.sk_e + 2 * self.sk_p
    }
}

/// The derived IKE SA keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IkeKeys {
    pub sk_d: Vec<u8>,
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

/// `SKEYSEED = prf(Ni | Nr, g^ir)` (RFC 7296 §2.14).
pub fn skeyseed(nonce_i: &[u8], nonce_r: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    let mut key = Vec::with_capacity(nonce_i.len() + nonce_r.len());
    key.extend_from_slice(nonce_i);
    key.extend_from_slice(nonce_r);
    hmac_sha256(&key, shared_secret)
}

/// `prf+`, the IKEv2 key-expansion function (RFC 7296 §2.13).
pub fn prf_plus(key: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len + 32);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(previous.len() + seed.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(seed);
        input.push(counter);
        let block = hmac_sha256(key, &input);
        out.extend_from_slice(&block);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
        if counter == 0 {
            break;
        }
    }
    out.truncate(out_len);
    out
}

/// Expand `SKEYSEED` into the seven IKE SA keys (RFC 7296 §2.14).
pub fn derive_keys(
    skeyseed: &[u8; 32],
    nonce_i: &[u8],
    nonce_r: &[u8],
    sizes: IkeKeySizes,
) -> IkeKeys {
    let mut seed = Vec::with_capacity(nonce_i.len() + nonce_r.len());
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    let material = prf_plus(skeyseed, &seed, sizes.total());
    let mut at = 0;
    let mut take = |len: usize| {
        let slice = material[at..at + len].to_vec();
        at += len;
        slice
    };
    // RFC 7296 §2.14 order: SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr.
    IkeKeys {
        sk_d: take(sizes.sk_d),
        sk_ai: take(sizes.sk_a),
        sk_ar: take(sizes.sk_a),
        sk_ei: take(sizes.sk_e),
        sk_er: take(sizes.sk_e),
        sk_pi: take(sizes.sk_p),
        sk_pr: take(sizes.sk_p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_plus_is_prefix_stable() {
        let key = [0x11u8; 32];
        let short = prf_plus(&key, b"seed", 32);
        let long = prf_plus(&key, b"seed", 200);
        assert_eq!(&long[..32], &short[..]);
        assert_eq!(long.len(), 200);
        // The first block is HMAC(key, seed || 0x01).
        let mut first = b"seed".to_vec();
        first.push(1);
        assert_eq!(&long[..32], &hmac_sha256(&key, &first)[..]);
    }

    #[test]
    fn skeyseed_binds_both_nonces_and_the_secret() {
        let shared = [0xAAu8; 256];
        let a = skeyseed(&[1, 2, 3], &[4, 5, 6], &shared);
        assert_eq!(a, skeyseed(&[1, 2, 3], &[4, 5, 6], &shared));
        assert_ne!(a, skeyseed(&[1, 2, 4], &[4, 5, 6], &shared));
        assert_ne!(a, skeyseed(&[1, 2, 3], &[4, 5, 6], &[0xAB; 256]));
    }

    #[test]
    fn derived_keys_have_the_requested_lengths_and_order() {
        let seed = [0x33u8; 32];
        let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
        let keys = derive_keys(&seed, &[0x01; 32], &[0x02; 32], sizes);
        assert_eq!(keys.sk_d.len(), 32);
        assert_eq!(keys.sk_ai.len(), 32);
        assert_eq!(keys.sk_ar.len(), 32);
        assert_eq!(keys.sk_ei.len(), 16);
        assert_eq!(keys.sk_er.len(), 16);
        assert_eq!(keys.sk_pi.len(), 32);
        assert_eq!(keys.sk_pr.len(), 32);

        // The stream is sliced in the RFC order.
        let seed_input = [&[0x01; 32][..], &[0x02; 32][..]].concat();
        let material = prf_plus(&seed, &seed_input, sizes.total());
        assert_eq!(keys.sk_d, material[..32]);
        assert_eq!(keys.sk_ai, material[32..64]);
        assert_eq!(keys.sk_ar, material[64..96]);
        assert_eq!(keys.sk_ei, material[96..112]);
        assert_eq!(keys.sk_er, material[112..128]);
        assert_eq!(keys.sk_pi, material[128..160]);
        assert_eq!(keys.sk_pr, material[160..192]);
    }

    #[test]
    fn aes_256_changes_only_the_encryption_key_length() {
        let sizes = IkeKeySizes::aes_cbc_256_sha256_128();
        let keys = derive_keys(&[0x33u8; 32], &[1], &[2], sizes);
        assert_eq!(keys.sk_ei.len(), 32);
        assert_eq!(keys.sk_er.len(), 32);
        assert_eq!(keys.sk_d.len(), 32);
    }
}
