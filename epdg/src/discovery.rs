//! ePDG discovery: the FQDNs a UE resolves to find a Wi-Fi calling gateway.
//!
//! Before any IKEv2 byte is sent, a UE has to answer "which ePDG?" — and the
//! answer is a DNS name built from the PLMN. 3GPP TS 23.003 §19.4.2.9 defines
//! five of them; all are pure string construction, which is why they live here
//! and not behind a resolver.
//!
//! ```text
//! Operator Identifier  epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
//! Tracking Area        tac-lb<lo>.tac-hb<hi>.tac.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
//! Location Area        lac<LAC>.epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org
//! 5GS Tracking Area    tac-lb<lo>.tac-mb<mid>.tac-hb<hi>.5gstac.epdg.epc...
//! Visited Country      epdg.epc.mcc<MCC>.visited-country.pub.3gppnetwork.org
//! ```
//!
//! Two rules are easy to get wrong and are enforced here rather than left to
//! the caller: **MCC and MNC are always three digits** in DNS, with a one-digit
//! MNC zero-padded on the left, and the TAC/LAC fields are **hexadecimal**,
//! not decimal.

#![forbid(unsafe_code)]

/// The DNS suffix every ePDG name ends with (TS 23.003 §19.4.2.9.2).
pub const EPDG_SUFFIX: &str = "pub.3gppnetwork.org";

/// The PLMN type and its validation error live in `carrier`, because every 3GPP
/// discovery name is built from them, not just the ePDG ones.
pub use carrier::{PlmnError as DiscoveryError, PlmnId};

/// The Operator Identifier based ePDG FQDN (TS 23.003 §19.4.2.9.2).
///
/// This is the name to try first: it identifies the PLMN where the ePDG is
/// located, using the VPLMN or HPLMN as the selection policy dictates.
pub fn epdg_fqdn(plmn: &PlmnId) -> String {
    format!("epdg.epc.{}.{}", plmn.plmn_labels(), EPDG_SUFFIX)
}

/// The Tracking Area Identity based ePDG FQDN, 2-octet TAC
/// (TS 23.003 §19.4.2.9.3).
///
/// `tac` is a 16-bit integer; the two bytes appear **low byte first**, each as
/// two hex digits, e.g. TAC `0x0B21` becomes `tac-lb21.tac-hb0b`.
pub fn epdg_fqdn_tai(plmn: &PlmnId, tac: u16) -> String {
    let lo = (tac & 0x00ff) as u8;
    let hi = (tac >> 8) as u8;
    format!(
        "tac-lb{lo:02x}.tac-hb{hi:02x}.tac.epdg.epc.{}.{}",
        plmn.plmn_labels(),
        EPDG_SUFFIX
    )
}

/// The 5GS Tracking Area Identity based ePDG FQDN, 3-octet TAC
/// (TS 23.003 §19.4.2.9.3).
///
/// `tac` is a 24-bit integer; the bytes appear low, middle, high, e.g.
/// `0x0B1A21` becomes `tac-lb21.tac-mb1a.tac-hb0b`.
pub fn epdg_fqdn_5gs_tai(plmn: &PlmnId, tac: u32) -> String {
    let lo = (tac & 0x0000_00ff) as u8;
    let mid = ((tac >> 8) & 0x0000_00ff) as u8;
    let hi = ((tac >> 16) & 0x0000_00ff) as u8;
    format!(
        "tac-lb{lo:02x}.tac-mb{mid:02x}.tac-hb{hi:02x}.5gstac.epdg.epc.{}.{}",
        plmn.plmn_labels(),
        EPDG_SUFFIX
    )
}

/// The Location Area Identity based ePDG FQDN (TS 23.003 §19.4.2.9.3).
///
/// `lac` is rendered as four **hexadecimal** digits, e.g. `0x0B21` becomes
/// `lac0b21`.
pub fn epdg_fqdn_lac(plmn: &PlmnId, lac: u16) -> String {
    format!(
        "lac{lac:04x}.epdg.epc.{}.{}",
        plmn.plmn_labels(),
        EPDG_SUFFIX
    )
}

/// The Visited Country FQDN (TS 23.003 §19.4.2.9.4).
///
/// A roaming UE resolves this to learn whether the visited country requires an
/// ePDG in that country; its NAPTR records point at the permitted ePDG names.
pub fn visited_country_fqdn(mcc: &str) -> Result<String, DiscoveryError> {
    if mcc.len() != 3 || !mcc.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DiscoveryError::BadMcc(mcc.to_string()));
    }
    Ok(format!("epdg.epc.mcc{mcc}.visited-country.{EPDG_SUFFIX}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every expected string below is one of the examples printed in
    // TS 23.003 §19.4.2.9.2–19.4.2.9.4 (MCC 345, MNC 12).

    fn plmn() -> PlmnId {
        PlmnId::new("345", "12").unwrap()
    }

    #[test]
    fn operator_identifier_fqdn_zero_pads_the_mnc() {
        assert_eq!(
            epdg_fqdn(&plmn()),
            "epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
        );
    }

    #[test]
    fn a_three_digit_mnc_is_left_alone() {
        let plmn = PlmnId::new("310", "260").unwrap();
        assert_eq!(
            epdg_fqdn(&plmn),
            "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
        );
        assert_eq!(plmn.mnc_dns(), "260");
    }

    #[test]
    fn tracking_area_fqdn_is_hex_and_low_byte_first() {
        // TS 23.003: TAC H'0B21, MCC 345, MNC 12.
        assert_eq!(
            epdg_fqdn_tai(&plmn(), 0x0B21),
            "tac-lb21.tac-hb0b.tac.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
        );
    }

    #[test]
    fn location_area_fqdn_is_four_hex_digits() {
        // TS 23.003: LAC H'0B21, MCC 345, MNC 12.
        assert_eq!(
            epdg_fqdn_lac(&plmn(), 0x0B21),
            "lac0b21.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
        );
        // Small values are zero-padded to four digits.
        assert!(epdg_fqdn_lac(&plmn(), 1).starts_with("lac0001."));
    }

    #[test]
    fn five_gs_tracking_area_fqdn_is_low_middle_high() {
        // TS 23.003: 5GS TAC H'0B1A21, MCC 345, MNC 12.
        assert_eq!(
            epdg_fqdn_5gs_tai(&plmn(), 0x0B1A21),
            "tac-lb21.tac-mb1a.tac-hb0b.5gstac.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
        );
    }

    #[test]
    fn visited_country_fqdn_uses_only_the_mcc() {
        assert_eq!(
            visited_country_fqdn("345").unwrap(),
            "epdg.epc.mcc345.visited-country.pub.3gppnetwork.org"
        );
        assert_eq!(
            visited_country_fqdn("34"),
            Err(DiscoveryError::BadMcc("34".into()))
        );
    }

    #[test]
    fn every_name_is_seven_labels() {
        // TS 23.003 §19.4.2.9.2: the operator FQDN is composed of seven labels.
        let name = epdg_fqdn(&plmn());
        assert_eq!(name.split('.').count(), 7);
        let country = visited_country_fqdn("345").unwrap();
        assert_eq!(country.split('.').count(), 7);
    }

    #[test]
    fn bad_plmns_are_rejected() {
        assert_eq!(
            PlmnId::new("34", "12"),
            Err(DiscoveryError::BadMcc("34".into()))
        );
        assert_eq!(
            PlmnId::new("345", "1"),
            Err(DiscoveryError::BadMnc("1".into()))
        );
        assert_eq!(
            PlmnId::new("345", "1234"),
            Err(DiscoveryError::BadMnc("1234".into()))
        );
        assert!(PlmnId::new("34a", "12").is_err());
    }

    #[test]
    fn the_plmn_is_not_carrier_specific() {
        // The module knows nothing about any operator; only the SIM's MCC/MNC.
        let a = PlmnId::new("001", "01").unwrap();
        let b = PlmnId::new("310", "260").unwrap();
        assert_ne!(epdg_fqdn(&a), epdg_fqdn(&b));
        assert!(epdg_fqdn(&a).ends_with(".pub.3gppnetwork.org"));
        assert!(epdg_fqdn(&b).ends_with(".pub.3gppnetwork.org"));
    }
}
