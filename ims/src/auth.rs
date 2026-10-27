//! RFC 3310 IMS-AKA digest response and RFC 2617 Digest header construction.

use crate::profile::ImsProfile;
use aka::ims_aka_response;
use sip::{AuthChallenge, Method};

/// Lowercase hex, as required for Digest `response` values (RFC 2617 §3.2.2.1).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn md5_hex(input: &str) -> String {
    hex_lower(md5::compute(input.as_bytes()).as_slice())
}

/// RFC 3310 §3.2: for IMS-AKA the digest password is the hex RES.
pub fn aka_password(res: &[u8]) -> String {
    ims_aka_response(res)
}

/// Compute the RFC 2617 Digest `response` value for an IMS AKA challenge.
///
/// * `HA1 = MD5(IMPI ":" realm ":" HEX(RES))` (RFC 3310 §3.2)
/// * `HA2 = MD5(method ":" digest-uri)`
/// * `response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)` when qop
///   is present, else `MD5(HA1 ":" nonce ":" HA2)`.
pub fn digest_response(
    impi: &str,
    realm: &str,
    res: &[u8],
    method: &Method,
    digest_uri: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: Option<&str>,
) -> String {
    let ha1 = md5_hex(&format!("{impi}:{realm}:{}", aka_password(res)));
    let ha2 = md5_hex(&format!("{method}:{digest_uri}"));
    match qop {
        Some(qop) => md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")),
        None => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
    }
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
    let response = digest_response(
        &profile.private_identity,
        realm,
        res,
        method,
        digest_uri,
        nonce,
        nc,
        cnonce,
        qop,
    );

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
    fn rfc2617_md5_vector() {
        // RFC 2617 §3.5 example: Mufasa / Circle Of Life.
        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let response = md5_hex(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}"
        ));
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn aka_digest_uses_hex_res() {
        let res = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];
        let r = digest_response(
            "234150123456789@ims.mnc015.mcc234.3gppnetwork.org",
            "ims.mnc015.mcc234.3gppnetwork.org",
            &res,
            &Method::Register,
            "sip:ims.mnc015.mcc234.3gppnetwork.org",
            "bm9uY2U=",
            "00000001",
            "0a4f113b",
            Some("auth"),
        );
        assert_eq!(r.len(), 32);
        assert!(r
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn authorization_header_shape() {
        let p = ImsProfile::lab_default();
        let ch = sip::parse_challenge(
            "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"abc\", algorithm=AKAv1-MD5, qop=\"auth\"",
        )
        .unwrap();
        let v = authorization_value(
            &ch,
            &p,
            &[0u8; 8],
            &Method::Register,
            "sip:ims.mnc001.mcc001.3gppnetwork.org",
            "cnonce-1",
        );
        assert!(v.starts_with("Digest username=\""));
        assert!(v.contains("algorithm=AKAv1-MD5"));
        assert!(v.contains("qop=auth"));
        assert!(v.contains("nc=00000001"));
    }
}
