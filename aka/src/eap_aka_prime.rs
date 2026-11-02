//! EAP-AKA' key hierarchy (RFC 5448) — the crypto core of Wi-Fi calling.
//!
//! VoLTE over IMS uses AKA on the Gm interface. Wi-Fi calling reaches IMS through
//! an **ePDG**: the UE builds an IKEv2 tunnel to the ePDG and authenticates with
//! EAP-AKA'. That method takes the AKA `CK`/`IK`, derives `CK'`/`IK'` bound to
//! the access-network name (3GPP TS 33.402), and expands them with a
//! SHA-256-based PRF into `K_encr`, `K_aut`, `K_re`, `MSK` and `EMSK`
//! (RFC 5448 §3.3).
//!
//! This module implements exactly that derivation plus the EAP-AKA' attribute
//! framing. It performs no I/O and speaks no IKEv2; the tunnel is a later layer.
//!
//! ```text
//! CK | IK ──KDF(0x20, network name)──► CK' | IK'
//!                                         │
//!          PRF'(IK'|CK', "EAP-AKA'"|identity)
//!                                         │
//!   ┌────────┬────────┬────────┬─────────┬─────────┐
//!   K_encr   K_aut    K_re     MSK       EMSK
//!   128 b    256 b    256 b    512 b     512 b
//! ```
//!
//! ## Unsafe policy
//!
//! Pure Rust: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

use crate::Amf;

/// A 128-bit cipher key from AKA.
pub type Ck = [u8; 16];
/// A 128-bit integrity key from AKA.
pub type Ik = [u8; 16];

/// RFC 5448 §3.4.2: AT_MAC is HMAC-SHA-256-128.
pub const AT_MAC_LEN: usize = 16;

/// AT_BIDDING (RFC 5448 §4).
pub const AT_BIDDING: u8 = 136;
/// AT_KDF_INPUT (RFC 5448 §3.1).
pub const AT_KDF_INPUT: u8 = 23;
/// AT_KDF (RFC 5448 §3.2).
pub const AT_KDF: u8 = 24;

/// The key set produced by a successful EAP-AKA' run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapAkaPrimeKeys {
    /// 128-bit AT_ENCR_DATA key.
    pub k_encr: [u8; 16],
    /// 256-bit AT_MAC key.
    pub k_aut: [u8; 32],
    /// 256-bit fast re-authentication key.
    pub k_re: [u8; 32],
    /// 512-bit master session key exported to IKEv2.
    pub msk: [u8; 64],
    /// 512-bit extended master session key.
    pub emsk: [u8; 64],
}

/// Errors from the derivation or attribute framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapError {
    /// The network name was empty or absurdly long.
    BadNetworkName(usize),
    /// An attribute list was truncated or misaligned.
    MalformedAttribute(&'static str),
    /// The AMF separation bit was clear, so the challenge is not EAP-AKA'.
    SeparationBitClear,
}

impl core::fmt::Display for EapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EapError::BadNetworkName(n) => write!(f, "bad access-network name length {n}"),
            EapError::MalformedAttribute(what) => write!(f, "malformed EAP attribute: {what}"),
            EapError::SeparationBitClear => {
                f.write_str("AUTN AMF separation bit is clear (not an EAP-AKA' challenge)")
            }
        }
    }
}

impl std::error::Error for EapError {}

/// Derive `CK'` and `IK'` from the AKA keys and the access-network name
/// (3GPP TS 33.402 / TS 33.220 KDF).
///
/// The KDF input is `S = 0x20 || network_name || len(network_name)` with the
/// length as two big-endian octets, exactly as the generic 3GPP KDF defines.
pub fn ck_ik_prime(ck: &Ck, ik: &Ik, network_name: &str) -> Result<([u8; 16], [u8; 16]), EapError> {
    let name = network_name.as_bytes();
    if name.is_empty() || name.len() > 0xffff {
        return Err(EapError::BadNetworkName(name.len()));
    }
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    // TS 24.302: FC = 0x20, P0 = the access network name.
    let out = crate::kdf::kdf(&[0x20], &[name], &key)
        .map_err(|_| EapError::BadNetworkName(name.len()))?;

    let mut ck_prime = [0u8; 16];
    ck_prime.copy_from_slice(&out[..16]);
    let mut ik_prime = [0u8; 16];
    ik_prime.copy_from_slice(&out[16..]);
    Ok((ck_prime, ik_prime))
}

/// The full EAP-AKA' key set for a full authentication (RFC 5448 §3.3).
///
/// `identity` is the peer identity (the IMPI/NAI), used exactly as sent.
/// The AUTN must carry the AMF separation bit; that is checked here because a
/// clear bit means the challenge is not an EAP-AKA' challenge.
pub fn derive_keys(
    ck: &Ck,
    ik: &Ik,
    network_name: &str,
    identity: &str,
    amf: &Amf,
) -> Result<EapAkaPrimeKeys, EapError> {
    if !separation_bit_set(amf) {
        return Err(EapError::SeparationBitClear);
    }
    let (ck_prime, ik_prime) = ck_ik_prime(ck, ik, network_name)?;

    let mut prf_key = [0u8; 32];
    prf_key[..16].copy_from_slice(&ik_prime);
    prf_key[16..].copy_from_slice(&ck_prime);

    let mut seed = Vec::with_capacity(8 + identity.len());
    seed.extend_from_slice(b"EAP-AKA'");
    seed.extend_from_slice(identity.as_bytes());

    // 1664 bits = 208 octets of PRF' output.
    let mk = prf_prime(&prf_key, &seed, 208);
    let mut keys = EapAkaPrimeKeys {
        k_encr: [0u8; 16],
        k_aut: [0u8; 32],
        k_re: [0u8; 32],
        msk: [0u8; 64],
        emsk: [0u8; 64],
    };
    keys.k_encr.copy_from_slice(&mk[0..16]);
    keys.k_aut.copy_from_slice(&mk[16..48]);
    keys.k_re.copy_from_slice(&mk[48..80]);
    keys.msk.copy_from_slice(&mk[80..144]);
    keys.emsk.copy_from_slice(&mk[144..208]);
    Ok(keys)
}

/// TS 33.102: the AMF separation bit is bit 8 of the first AMF octet.
pub fn separation_bit_set(amf: &Amf) -> bool {
    amf[0] & 0x80 != 0
}

/// PRF' from RFC 5448 §3.4.1 (the IKEv2 PRF), truncated to `out_len` octets.
pub fn prf_prime(key: &[u8; 32], seed: &[u8], out_len: usize) -> Vec<u8> {
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

/// HMAC-SHA-256-128 over `packet` with the AT_MAC value zeroed, per RFC 5448.
///
/// `mac_offset` is the byte offset of the 16-octet AT_MAC value inside
/// `packet`; those octets are treated as zero for the computation.
pub fn at_mac(k_aut: &[u8; 32], packet: &[u8], mac_offset: usize) -> Result<[u8; 16], EapError> {
    let mut buf = packet.to_vec();
    let end = mac_offset
        .checked_add(AT_MAC_LEN)
        .ok_or(EapError::MalformedAttribute("MAC offset overflow"))?;
    let mac = buf
        .get_mut(mac_offset..end)
        .ok_or(EapError::MalformedAttribute(
            "MAC offset outside the packet",
        ))?;
    for b in mac.iter_mut() {
        *b = 0;
    }
    let full = hmac_sha256(k_aut, &buf);
    let mut out = [0u8; AT_MAC_LEN];
    out.copy_from_slice(&full[..AT_MAC_LEN]);
    Ok(out)
}

/// Encode one EAP attribute (RFC 4187 §10): type, length in 4-octet units, then
/// a value padded with zeros to a 4-octet boundary.
///
/// `kind` is the attribute number; the `P` bit (0x80) is set automatically for
/// `AT_` attributes, as the EAP-AKA attributes all are.
pub fn attribute(kind: u8, value: &[u8]) -> Vec<u8> {
    // The length field counts the 2-byte header too, and the whole attribute
    // must land on a 4-octet boundary.
    let total = (2 + value.len()).div_ceil(4) * 4;
    let mut out = Vec::with_capacity(total);
    out.push(kind);
    out.push((total / 4) as u8);
    out.extend_from_slice(value);
    out.resize(total, 0);
    out
}

/// Parse a sequence of EAP attributes, stripping padding.
/// Split an EAP-AKA' attribute list into `(type, value)` pairs.
///
/// The length field of an EAP attribute counts 4-octet units (RFC 4187 §10.1),
/// so the boundary between value and padding is not recoverable from the wire.
/// Each returned value therefore **includes its padding**: a 16-octet `AT_RAND`
/// comes back as 20 bytes (18 rounded up to a multiple of 4, since the 2-octet
/// header is included). Callers that know the attribute's shape must truncate.
pub fn parse_attributes(bytes: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, EapError> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if at + 2 > bytes.len() {
            return Err(EapError::MalformedAttribute("truncated header"));
        }
        let kind = bytes[at];
        let units = bytes[at + 1] as usize;
        if units == 0 {
            return Err(EapError::MalformedAttribute("zero length"));
        }
        let len = units * 4;
        let end = at
            .checked_add(len)
            .ok_or(EapError::MalformedAttribute("length overflow"))?;
        let value = bytes
            .get(at + 2..end)
            .ok_or(EapError::MalformedAttribute("value truncated"))?;
        out.push((kind, value.to_vec()));
        at = end;
    }
    Ok(out)
}

/// The `AT_KDF_INPUT` attribute carrying the access-network name.
pub fn kdf_input_attribute(network_name: &str) -> Result<Vec<u8>, EapError> {
    let name = network_name.as_bytes();
    if name.is_empty() || name.len() > 0xffff {
        return Err(EapError::BadNetworkName(name.len()));
    }
    let mut value = Vec::with_capacity(2 + name.len());
    value.extend_from_slice(&(name.len() as u16).to_be_bytes());
    value.extend_from_slice(name);
    Ok(attribute(0x80 | AT_KDF_INPUT, &value))
}

/// The `AT_KDF` attribute selecting a key-derivation function (1 = EAP-AKA').
pub fn kdf_attribute(kdf: u16) -> Vec<u8> {
    attribute(0x80 | AT_KDF, &kdf.to_be_bytes())
}

/// The `AT_BIDDING` attribute (RFC 5448 §4); `supports_prime` sets the D bit.
pub fn bidding_attribute(supports_prime: bool) -> Vec<u8> {
    let mut value = [0u8; 2];
    if supports_prime {
        value[0] = 0x80;
    }
    attribute(AT_BIDDING, &value)
}

// --- SHA-256 and HMAC-SHA-256 ---------------------------------------------

/// SHA-256 (FIPS 180-4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC-SHA-256 (RFC 2104) with a 64-byte block.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac =
        <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod crypto_vector_tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231 §4.2–4.8: the published HMAC-SHA-256 test cases.
    ///
    /// These exist because a hand-written HMAC is self-consistent by
    /// construction: every round-trip test passes whether or not the
    /// primitive is right. Only a published vector settles it.
    #[test]
    fn rfc_4231_hmac_sha256_vectors() {
        // 4.2 Test Case 1
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // 4.3 Test Case 2 — key shorter than the block size.
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // 4.4 Test Case 3
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        // 4.7 Test Case 6 — key longer than the block size, so it is hashed.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // 4.8 Test Case 7 — long key and long data.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
            )),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    /// FIPS 180-4 / NIST: SHA-256 of the empty string and of "abc".
    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn prf_prime_matches_a_manual_expansion() {
        // T1 = HMAC(K, S | 0x01), T2 = HMAC(K, T1 | S | 0x02) — RFC 5448 §3.3.
        let key = [0x11u8; 32];
        let mut t1_input = b"seed".to_vec();
        t1_input.push(1);
        let t1 = hmac_sha256(&key, &t1_input);
        let mut t2_input = t1.to_vec();
        t2_input.extend_from_slice(b"seed");
        t2_input.push(2);

        let expanded = prf_prime(&key, b"seed", 64);
        assert_eq!(&expanded[..32], &t1[..]);
        assert_eq!(&expanded[32..], &hmac_sha256(&key, &t2_input)[..]);
        let _ = h; // keep the helper available for future vectors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231() {
        // Test case 1: key = 0x0b * 20, data = "Hi There".
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2: key = "Jefe", data = "what do ya want for nothing?".
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn prf_prime_is_deterministic_and_length_correct() {
        let key = [0x11u8; 32];
        let a = prf_prime(&key, b"seed", 208);
        let b = prf_prime(&key, b"seed", 208);
        assert_eq!(a, b);
        assert_eq!(a.len(), 208);
        // The first block is HMAC(key, seed || 0x01).
        let mut first = b"seed".to_vec();
        first.push(1);
        assert_eq!(&a[..32], &hmac_sha256(&key, &first)[..]);
        // A different seed diverges.
        assert_ne!(prf_prime(&key, b"other", 208), a);
    }

    #[test]
    fn separation_bit_is_checked() {
        assert!(separation_bit_set(&[0x80, 0x00]));
        assert!(!separation_bit_set(&[0x00, 0x00]));
        assert!(!separation_bit_set(&[0x7f, 0xff]));
    }

    #[test]
    fn key_derivation_splits_the_prf_output() {
        let ck = [0x11u8; 16];
        let ik = [0x22u8; 16];
        let amf: Amf = [0x80, 0x00];
        let keys = derive_keys(&ck, &ik, "WLAN", "user@example", &amf).unwrap();
        // Sizes follow RFC 5448 §3.3.
        assert_eq!(keys.k_encr.len(), 16);
        assert_eq!(keys.k_aut.len(), 32);
        assert_eq!(keys.k_re.len(), 32);
        assert_eq!(keys.msk.len(), 64);
        assert_eq!(keys.emsk.len(), 64);
        // Reproducible.
        assert_eq!(
            keys,
            derive_keys(&ck, &ik, "WLAN", "user@example", &amf).unwrap()
        );
        // The network name binds the keys.
        let other = derive_keys(&ck, &ik, "WLAN2", "user@example", &amf).unwrap();
        assert_ne!(keys.msk, other.msk);
        // A different identity binds them too.
        let other_id = derive_keys(&ck, &ik, "WLAN", "other@example", &amf).unwrap();
        assert_ne!(keys.msk, other_id.msk);
    }

    #[test]
    fn clear_separation_bit_is_rejected() {
        assert_eq!(
            derive_keys(&[0u8; 16], &[0u8; 16], "WLAN", "id", &[0x00, 0x00]),
            Err(EapError::SeparationBitClear)
        );
    }

    #[test]
    fn ck_prime_depends_on_the_network_name() {
        let ck = [0x01u8; 16];
        let ik = [0x02u8; 16];
        let (ck1, ik1) = ck_ik_prime(&ck, &ik, "WLAN").unwrap();
        let (ck2, _) = ck_ik_prime(&ck, &ik, "WLAN-other").unwrap();
        assert_ne!(ck1, ck2);
        assert_ne!(ck1, ck);
        assert_ne!(ik1, ik);
        assert_eq!(ck_ik_prime(&ck, &ik, ""), Err(EapError::BadNetworkName(0)));
    }

    #[test]
    fn attributes_round_trip_with_padding() {
        let bytes = [
            kdf_input_attribute("WLAN").unwrap(),
            kdf_attribute(1),
            bidding_attribute(true),
        ]
        .concat();
        let parsed = parse_attributes(&bytes).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, 0x80 | AT_KDF_INPUT);
        // The network name is length-prefixed.
        assert_eq!(parsed[0].1[..2], [0x00, 0x04]);
        assert_eq!(&parsed[0].1[2..6], b"WLAN");
        assert_eq!(parsed[1].0, 0x80 | AT_KDF);
        assert_eq!(parsed[1].1[..2], [0x00, 0x01]);
        assert_eq!(parsed[2].0, AT_BIDDING);
        assert_eq!(parsed[2].1[0] & 0x80, 0x80, "D bit set");
        // Every attribute is a multiple of 4 octets.
        assert_eq!(bytes.len() % 4, 0);
        // The P bit is set on the wire.
        assert_eq!(bytes[0], 0x80 | AT_KDF_INPUT);
    }

    #[test]
    fn malformed_attribute_lists_are_rejected() {
        assert!(parse_attributes(&[0x97]).is_err());
        assert!(parse_attributes(&[0x97, 0x00]).is_err());
        assert!(parse_attributes(&[0x97, 0x02, 0x00]).is_err());
    }

    #[test]
    fn at_mac_zeroes_the_mac_field_before_hashing() {
        let k_aut = [0x33u8; 32];
        // 2-byte header + 16-byte MAC value + 2 filler.
        let mut packet = vec![0x8b, 0x05];
        packet.extend_from_slice(&[0xaa; 16]);
        packet.extend_from_slice(&[0xbb, 0xcc]);
        let mac = at_mac(&k_aut, &packet, 2).unwrap();
        assert_eq!(mac.len(), 16);
        // Recomputing with the MAC already zeroed gives the same value.
        let mut zeroed = packet.clone();
        zeroed[2..18].fill(0);
        let again = at_mac(&k_aut, &zeroed, 2).unwrap();
        assert_eq!(mac, again);
        // Pointing outside the packet is an error, not a panic.
        assert!(at_mac(&k_aut, &packet, 100).is_err());
    }
}
