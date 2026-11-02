//! IKEv2 AUTH payloads and child-SA key material (RFC 7296 §2.15–2.17).
//!
//! In a normal IKEv2 exchange `AUTH` proves possession of the shared secret
//! behind the peer's identity. With EAP (RFC 5998), the secret is the **MSK**
//! produced by EAP-AKA', not `SK_pi`/`SK_pr`:
//!
//! ```text
//! AUTH = prf(prf(SharedSecret, "Key Pad for IKEv2"), SignedOctets)
//! SignedOctets(I) = RealMessage1 | NonceR | prf(SK_pi, IDi')
//! SignedOctets(R) = RealMessage2 | NonceI | prf(SK_pr, IDr')
//! ```
//!
//! `IDi'`/`IDr'` are the Identification payload bodies *without* the generic
//! payload header, and `RealMessageN` are the SA_INIT messages as sent.

#![forbid(unsafe_code)]

use crate::keys::prf_plus;
use aka::eap_aka_prime::hmac_sha256;

/// The ASCII key-pad constant from RFC 7296 §2.15.
pub const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// `prf(SharedSecret, "Key Pad for IKEv2")`.
pub fn key_pad(shared_secret: &[u8]) -> [u8; 32] {
    hmac_sha256(shared_secret, KEY_PAD)
}

/// Compute an AUTH payload value (32 octets with SHA-256).
pub fn auth_payload(shared_secret: &[u8], signed_octets: &[u8]) -> Vec<u8> {
    hmac_sha256(&key_pad(shared_secret), signed_octets).to_vec()
}

/// `RealMessage1 | NonceR | prf(SK_pi, IDi')` (RFC 7296 §2.15).
pub fn signed_octets_initiator(
    real_message1: &[u8],
    nonce_r: &[u8],
    sk_pi: &[u8],
    id_i_body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(real_message1.len() + nonce_r.len() + 32);
    out.extend_from_slice(real_message1);
    out.extend_from_slice(nonce_r);
    out.extend_from_slice(&hmac_sha256(sk_pi, id_i_body));
    out
}

/// `RealMessage2 | NonceI | prf(SK_pr, IDr')` (RFC 7296 §2.15).
pub fn signed_octets_responder(
    real_message2: &[u8],
    nonce_i: &[u8],
    sk_pr: &[u8],
    id_r_body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(real_message2.len() + nonce_i.len() + 32);
    out.extend_from_slice(real_message2);
    out.extend_from_slice(nonce_i);
    out.extend_from_slice(&hmac_sha256(sk_pr, id_r_body));
    out
}

/// Child-SA key material: `KEYMAT = prf+(SK_d, Ni | Nr)` (RFC 7296 §2.17).
pub fn child_keymat(sk_d: &[u8], nonce_i: &[u8], nonce_r: &[u8], len: usize) -> Vec<u8> {
    let mut seed = Vec::with_capacity(nonce_i.len() + nonce_r.len());
    seed.extend_from_slice(nonce_i);
    seed.extend_from_slice(nonce_r);
    prf_plus(sk_d, &seed, len)
}

/// Constant-time equality for MAC comparisons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_payload_is_prf_of_the_key_pad() {
        let secret = [0x11u8; 32];
        let signed = b"signed octets";
        let auth = auth_payload(&secret, signed);
        // AUTH = prf(prf(secret, "Key Pad for IKEv2"), signed octets).
        let expected = hmac_sha256(&hmac_sha256(&secret, KEY_PAD), signed);
        assert_eq!(auth, expected.to_vec());
        assert_eq!(auth.len(), 32);
    }

    #[test]
    fn signed_octets_include_the_id_hash() {
        let msg = b"real message 1";
        let nonce_r = [0x22u8; 32];
        let sk_pi = [0x33u8; 32];
        let id = b"\x02\x00\x00\x00user";
        let signed = signed_octets_initiator(msg, &nonce_r, &sk_pi, id);
        assert_eq!(&signed[..msg.len()], msg);
        assert_eq!(&signed[msg.len()..msg.len() + 32], &nonce_r);
        assert_eq!(&signed[msg.len() + 32..], &hmac_sha256(&sk_pi, id)[..]);
        // The responder construction uses its own message and key; with
        // identical inputs it is the same shape but a different call site.
        let r = signed_octets_responder(b"real message 2", &nonce_r, &sk_pi, id);
        assert_ne!(signed, r);
    }

    #[test]
    fn child_keymat_is_prefix_stable() {
        let sk_d = [0x44u8; 32];
        let a = child_keymat(&sk_d, &[1], &[2], 32);
        let b = child_keymat(&sk_d, &[1], &[2], 96);
        assert_eq!(&b[..32], &a[..]);
        assert_ne!(a, child_keymat(&sk_d, &[1], &[3], 32));
    }
}
