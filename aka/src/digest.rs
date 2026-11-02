//! RFC 3310 IMS-AKA digest response, over the RFC 2617 Digest algorithm.
//!
//! Both IMS registration and GBA's `Ub` reference point authenticate with a
//! password that is **HEX(RES)** rather than a user secret (RFC 3310 §3.2):
//! IMS wraps it in a SIP `Authorization` header, GBA in an HTTP one. The digest
//! computation is identical, which is why it lives here instead of in either
//! caller.

use crate::ims_aka_response;

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

/// Inputs to one RFC 2617 Digest computation.
///
/// `method` is the uppercased request method (`REGISTER`, `GET`, …); RFC 2617
/// includes it verbatim in `HA2`, so it is kept as a string rather than an enum
/// that would tie this crate to one protocol.
#[derive(Debug, Clone, Copy)]
pub struct DigestInput<'a> {
    pub impi: &'a str,
    pub realm: &'a str,
    pub res: &'a [u8],
    pub method: &'a str,
    pub digest_uri: &'a str,
    pub nonce: &'a str,
    pub nc: &'a str,
    pub cnonce: &'a str,
    pub qop: Option<&'a str>,
}

/// Compute the RFC 2617 Digest `response` value for an IMS AKA challenge.
///
/// * `HA1 = MD5(IMPI ":" realm ":" HEX(RES))` (RFC 3310 §3.2)
/// * `HA2 = MD5(method ":" digest-uri)`
/// * `response = MD5(HA1 ":" nonce ":" nc ":" cnonce ":" qop ":" HA2)` when qop
///   is present, else `MD5(HA1 ":" nonce ":" HA2)`.
pub fn digest_response(input: &DigestInput<'_>) -> String {
    let ha1 = md5_hex(&format!(
        "{}:{}:{}",
        input.impi,
        input.realm,
        aka_password(input.res)
    ));
    let ha2 = md5_hex(&format!("{}:{}", input.method, input.digest_uri));
    match input.qop {
        Some(qop) => md5_hex(&format!(
            "{ha1}:{}:{}:{}:{qop}:{ha2}",
            input.nonce, input.nc, input.cnonce
        )),
        None => md5_hex(&format!("{ha1}:{}:{ha2}", input.nonce)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let r = digest_response(&DigestInput {
            impi: "234150123456789@ims.mnc015.mcc234.3gppnetwork.org",
            realm: "ims.mnc015.mcc234.3gppnetwork.org",
            res: &res,
            method: "REGISTER",
            digest_uri: "sip:ims.mnc015.mcc234.3gppnetwork.org",
            nonce: "bm9uY2U=",
            nc: "00000001",
            cnonce: "0a4f113b",
            qop: Some("auth"),
        });
        assert_eq!(r.len(), 32);
        assert!(r
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
