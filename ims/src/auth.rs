//! SIP `Authorization` header construction from an IMS AKA challenge.
//!
//! The Digest computation itself is not SIP-specific and lives in
//! [`aka::digest`]; this module only maps a [`sip::Method`] onto it and renders
//! the header.

use crate::profile::ImsProfile;
use sip::{AuthChallenge, Method};

pub use aka::digest::{aka_password, hex_lower, DigestInput};

/// Compute the RFC 2617 Digest `response` value for an IMS AKA challenge.
///
/// * `HA1 = MD5(IMPI ":" realm ":" HEX(RES))` (RFC 3310 §3.2)
/// * `HA2 = MD5(method ":" digest-uri)`
/// * `response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)` when qop
///   is present, else `MD5(HA1 ":" nonce ":" HA2)`.
pub fn digest_response(input: &DigestInput<'_>) -> String {
    aka::digest::digest_response(input)
}

/// Build the `Authorization`/`Proxy-Authorization` header value for a challenge.
pub fn authorization_value(
    challenge: &AuthChallenge,
    profile: &ImsProfile,
    res: &[u8],
    method: &Method,
    digest_uri: &str,
    cnonce: &str,
) -> String {
    let realm = challenge
        .param("realm")
        .unwrap_or(profile.home_domain.as_str());
    let nonce = challenge.param("nonce").unwrap_or("");
    let algorithm = challenge.param("algorithm").unwrap_or("AKAv1-MD5");
    let qop = challenge.param("qop");
    let nc = "00000001";
    let method = method.to_string();
    let response = digest_response(&DigestInput {
        impi: &profile.private_identity,
        realm,
        res,
        method: &method,
        digest_uri,
        nonce,
        nc,
        cnonce,
        qop,
        entity_body: None,
    });

    let mut out = format!(
        "Digest username=\"{}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{digest_uri}\", response=\"{response}\", algorithm={algorithm}",
        profile.private_identity
    );
    if let Some(qop) = qop {
        out.push_str(&format!(", qop={qop}, nc={nc}, cnonce=\"{cnonce}\""));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ImsProfile;

    #[test]
    fn aka_digest_uses_hex_res() {
        let res = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];
        let r = digest_response(&DigestInput {
            impi: "234150123456789@ims.mnc015.mcc234.3gppnetwork.org",
            realm: "ims.mnc015.mcc234.3gppnetwork.org",
            res: &res,
            method: &Method::Register.to_string(),
            digest_uri: "sip:ims.mnc015.mcc234.3gppnetwork.org",
            nonce: "bm9uY2U=",
            nc: "00000001",
            cnonce: "0a4f113b",
            qop: Some("auth"),
            entity_body: None,
        });
        assert_eq!(r.len(), 32);
        assert!(r
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn authorization_header_shape() {
        let p = ImsProfile::lab_default();
        let ch = sip::parse_challenge(
            "Digest realm=\"ims.mnc015.mcc234.3gppnetwork.org\", nonce=\"bm9uY2U=\", algorithm=AKAv1-MD5, qop=\"auth\"",
        )
        .unwrap();
        let v = authorization_value(
            &ch,
            &p,
            &[0u8; 8],
            &Method::Register,
            "sip:ims.mnc015.mcc234.3gppnetwork.org",
            "0a4f113b",
        );
        assert!(v.starts_with("Digest username=\""));
        assert!(v.contains("algorithm=AKAv1-MD5"));
        assert!(v.contains("qop=auth"));
    }
}
