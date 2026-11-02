//! GBA bootstrapping (3GPP TS 33.220): the half a UE can own without a network.
//!
//! Generic Bootstrapping Architecture lets an application authenticate to an
//! operator service (a NAF) using the SIM, without ever handling `K`. The UE
//! speaks **Ub** to a BSF, gets a `Ks` derived from the AKA keys, and derives a
//! per-service key `Ks_NAF` for the NAF's **Ua** reference point.
//!
//! Interfaces **Zh** (BSF↔HSS) and **Zn** (NAF→BSF, TS 29.109) belong to the
//! network; a UE never speaks them, so they are not here.
//!
//! What is here is pure and network-free, deliberately:
//!
//! - [`bsf_fqdn`] / [`bsf_fqdn_for_impi`] — which BSF to talk to (TS 23.003 §16)
//! - [`ks_naf`] and friends — `Ks_NAF = KDF(Ks, "gba-me", RAND, IMPI, NAF_Id)`
//!   (TS 33.220 §4.5.3 and Annex B.3)
//!
//! The Ub and Ua exchanges themselves are **not implemented**: they are HTTP
//! over TLS, and no HTTP client lives in a protocol crate. See
//! `docs/adr/0002-gba-deferred.md`.

#![forbid(unsafe_code)]

pub use carrier::PlmnId;

use aka::kdf;

/// The delegated domain every operator 3GPP name ends with (TS 23.003 Annex D).
pub const GBA_SUFFIX: &str = "pub.3gppnetwork.org";

/// The KDF `FC` value this specification owns (TS 33.220 Annex B.2.2: `0x00`–
/// `0x0F` are allocated to TS 33.220; Annex B.3 fixes GBA at `0x01`).
pub const FC_GBA: u8 = 0x01;

/// The `P0` label for `Ks_NAF` and `Ks_ext_NAF` (TS 33.220 Annex B.3).
pub const LABEL_GBA_ME: &[u8] = b"gba-me";

/// The `P0` label for `Ks_int_NAF` (TS 33.220 Annex B.3).
pub const LABEL_GBA_U: &[u8] = b"gba-u";

/// Errors from building GBA parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GbaError {
    /// The IMPI has no `@`, so there is no domain to derive from.
    ImpiWithoutDomain(String),
    /// The IMPI domain is empty.
    EmptyDomain,
    /// A KDF input must be ASCII: TS 33.220 Annex B.2.1.2 requires UTF-8 with
    /// NFKC, which is the identity on ASCII and is not implemented for anything
    /// else. IMPIs are NAIs and therefore ASCII (TS 23.003 §13.2).
    NonAscii(&'static str),
    /// A KDF parameter was too long, or `FC` was malformed.
    Kdf(kdf::KdfError),
}

impl core::fmt::Display for GbaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GbaError::ImpiWithoutDomain(v) => write!(f, "IMPI {v:?} has no '@domain'"),
            GbaError::EmptyDomain => write!(f, "IMPI domain is empty"),
            GbaError::NonAscii(what) => write!(f, "{what} must be ASCII"),
            GbaError::Kdf(e) => write!(f, "KDF input: {e}"),
        }
    }
}

impl std::error::Error for GbaError {}

impl From<kdf::KdfError> for GbaError {
    fn from(e: kdf::KdfError) -> Self {
        GbaError::Kdf(e)
    }
}

/// The BSF address for a USIM, derived from the IMSI's MCC and MNC
/// (TS 23.003 §16.2, USIM case).
///
/// ```text
/// bsf.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
/// ```
pub fn bsf_fqdn(plmn: &PlmnId) -> String {
    format!("bsf.{}.{}", plmn.plmn_labels(), GBA_SUFFIX)
}

/// The BSF address for an ISIM, derived from the IMPI's domain
/// (TS 23.003 §16.2, ISIM case).
///
/// If the last two labels are `3gppnetwork.org`, the `pub` label is inserted
/// before them; otherwise `bsf.` is simply prefixed:
///
/// ```text
/// 234150999999999@ims.mnc015.mcc234.3gppnetwork.org
///   -> bsf.ims.mnc015.mcc234.pub.3gppnetwork.org
/// user@operator.com
///   -> bsf.operator.com
/// ```
pub fn bsf_fqdn_for_impi(impi: &str) -> Result<String, GbaError> {
    let (_, domain) = impi
        .split_once('@')
        .ok_or_else(|| GbaError::ImpiWithoutDomain(impi.to_string()))?;
    if domain.is_empty() {
        return Err(GbaError::EmptyDomain);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let is_3gpp = labels.len() > 2 && labels[labels.len() - 2..] == ["3gppnetwork", "org"];
    if is_3gpp {
        let head = labels[..labels.len() - 2].join(".");
        Ok(format!("bsf.{head}.{GBA_SUFFIX}"))
    } else {
        Ok(format!("bsf.{domain}"))
    }
}

fn ascii<'a>(what: &'static str, s: &'a str) -> Result<&'a [u8], GbaError> {
    if s.is_ascii() {
        Ok(s.as_bytes())
    } else {
        Err(GbaError::NonAscii(what))
    }
}

/// Build the KDF input `S` for a NAF key (TS 33.220 Annex B.3).
///
/// ```text
/// S = FC || P0 || L0 || RAND || L1 || IMPI || L2 || NAF_Id || L3
/// ```
///
/// with `FC = 0x01`, `P0` the service label (`"gba-me"` or `"gba-u"`), and
/// `L1 = 16` for the `RAND`.
///
/// `naf_id` is the **whole** `NAF_Id`: the NAF's FQDN encoded as UTF-8 with the
/// 4-octet Ua security protocol identifier appended (TS 33.220 §4.5.3 and
/// Annex H). It is taken as bytes so that this crate never has to invent which
/// protocol identifier a caller's service uses.
pub fn naf_kdf_input(
    rand: &[u8; 16],
    impi: &str,
    naf_id: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, GbaError> {
    if !naf_id.is_ascii() {
        return Err(GbaError::NonAscii("NAF_Id"));
    }
    let impi = ascii("IMPI", impi)?;
    Ok(kdf::input(&[FC_GBA], &[label, rand, impi, naf_id])?)
}

/// Derive a NAF-specific key: `Ks_NAF = KDF(Ks, "gba-me", RAND, IMPI, NAF_Id)`
/// (TS 33.220 §4.5.3, Annex B.3).
///
/// `ks` is `CK || IK` as agreed with the BSF in the Ub exchange.
pub fn naf_key(
    ks: &[u8; 32],
    rand: &[u8; 16],
    impi: &str,
    naf_id: &[u8],
    label: &[u8],
) -> Result<[u8; kdf::OUTPUT_LEN], GbaError> {
    let s = naf_kdf_input(rand, impi, naf_id, label)?;
    Ok(aka::eap_aka_prime::hmac_sha256(ks, &s))
}

/// `Ks_NAF` in GBA_ME, and `Ks_ext_NAF` in GBA_U (both use `"gba-me"`).
pub fn ks_naf(
    ks: &[u8; 32],
    rand: &[u8; 16],
    impi: &str,
    naf_id: &[u8],
) -> Result<[u8; kdf::OUTPUT_LEN], GbaError> {
    naf_key(ks, rand, impi, naf_id, LABEL_GBA_ME)
}

/// `Ks_ext_NAF` in GBA_U — same derivation as [`ks_naf`], kept as its own
/// function because the two keys have different lifetimes on the card.
pub fn ks_ext_naf(
    ks: &[u8; 32],
    rand: &[u8; 16],
    impi: &str,
    naf_id: &[u8],
) -> Result<[u8; kdf::OUTPUT_LEN], GbaError> {
    naf_key(ks, rand, impi, naf_id, LABEL_GBA_ME)
}

/// `Ks_int_NAF` in GBA_U: `KDF(Ks, "gba-u", RAND, IMPI, NAF_Id)`.
pub fn ks_int_naf(
    ks: &[u8; 32],
    rand: &[u8; 16],
    impi: &str,
    naf_id: &[u8],
) -> Result<[u8; kdf::OUTPUT_LEN], GbaError> {
    naf_key(ks, rand, impi, naf_id, LABEL_GBA_U)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn bsf_from_plmn_matches_the_ts_23_003_example() {
        // TS 23.003 §16.2 Example 1: IMSI 234150999999999.
        let plmn = PlmnId::new("234", "15").unwrap();
        assert_eq!(bsf_fqdn(&plmn), "bsf.mnc015.mcc234.pub.3gppnetwork.org");
    }

    #[test]
    fn bsf_from_impi_inserts_pub_before_the_delegated_domain() {
        // TS 23.003 §16.2 Example 2.
        assert_eq!(
            bsf_fqdn_for_impi("234150999999999@ims.mnc015.mcc234.3gppnetwork.org").unwrap(),
            "bsf.ims.mnc015.mcc234.pub.3gppnetwork.org"
        );
    }

    #[test]
    fn bsf_from_non_3gpp_impi_just_prepends_the_label() {
        // TS 23.003 §16.2 Example 3.
        assert_eq!(
            bsf_fqdn_for_impi("user@operator.com").unwrap(),
            "bsf.operator.com"
        );
    }

    #[test]
    fn bsf_from_impi_rejects_a_missing_domain() {
        assert_eq!(
            bsf_fqdn_for_impi("234150999999999").unwrap_err(),
            GbaError::ImpiWithoutDomain("234150999999999".into())
        );
        assert_eq!(
            bsf_fqdn_for_impi("user@").unwrap_err(),
            GbaError::EmptyDomain
        );
    }

    #[test]
    fn kdf_input_layout_is_pinned_to_annex_b3() {
        // Small values chosen so the encoding is readable; the point is the
        // order (label first, then RAND, IMPI, NAF_Id) and the two-octet lengths.
        let rand = [0x11; 16];
        let s = naf_kdf_input(&rand, "i@d", b"naf", LABEL_GBA_ME).unwrap();
        let mut want = vec![FC_GBA];
        want.extend_from_slice(b"gba-me");
        want.extend_from_slice(&[0x00, 0x06]);
        want.extend_from_slice(&rand);
        want.extend_from_slice(&[0x00, 0x10]);
        want.extend_from_slice(b"i@d");
        want.extend_from_slice(&[0x00, 0x03]);
        want.extend_from_slice(b"naf");
        want.extend_from_slice(&[0x00, 0x03]);
        assert_eq!(hex(&s), hex(&want));
    }

    #[test]
    fn ks_naf_is_hmac_sha256_of_the_annex_b3_input() {
        // Ks = 00..1f, RAND = 20..2f, IMPI/NAF from Annex B.3's shape.
        let ks: [u8; 32] = core::array::from_fn(|i| i as u8);
        let rand: [u8; 16] = core::array::from_fn(|i| 0x20 + i as u8);
        let impi = "234150999999999@ims.mnc015.mcc234.3gppnetwork.org";
        // FQDN || Ua security protocol identifier (4 octets).
        let naf_id = b"ims.mnc015.mcc234.3gppnetwork.org\x01\x00\x00\x00";

        let got = ks_naf(&ks, &rand, impi, naf_id).unwrap();
        // Recomputed independently with OpenSSL:
        //   printf '%s' "$S" | openssl dgst -sha256 -mac HMAC -macopt hexkey:<Ks>
        assert_eq!(
            hex(got.as_slice()),
            "d2ba484fda4e9bb89b60d2227e8b0565ec22b4f23ae8faff001ad57120ef7714"
        );
    }

    #[test]
    fn gba_u_and_gba_me_labels_differ() {
        let ks = [0u8; 32];
        let rand = [0u8; 16];
        let me = ks_naf(&ks, &rand, "i@d", b"n").unwrap();
        let int = ks_int_naf(&ks, &rand, "i@d", b"n").unwrap();
        let ext = ks_ext_naf(&ks, &rand, "i@d", b"n").unwrap();
        assert_ne!(me, int);
        assert_eq!(me, ext);
    }

    #[test]
    fn non_ascii_identifiers_are_refused_rather_than_silently_encoded() {
        let rand = [0u8; 16];
        assert_eq!(
            naf_kdf_input(&rand, "ü@d", b"n", LABEL_GBA_ME).unwrap_err(),
            GbaError::NonAscii("IMPI")
        );
    }
}
