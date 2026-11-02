//! `P-Access-Network-Info`: telling the network how the UE is attached.
//!
//! A Wi-Fi calling UE registers over WLAN but is still a 3GPP subscriber, and
//! the P-CSCF needs to know which. RFC 3455 §5.4 defines the header; 3GPP
//! TS 24.229 fixes the parameter that goes with each access type:
//!
//! ```text
//! WLAN     P-Access-Network-Info: IEEE-802.11; i-wlan-node-id=000cf1126028
//! E-UTRAN  P-Access-Network-Info: 3GPP-E-UTRAN-FDD;
//!                                utran-cell-id-3gpp=1112233C476B4321
//! ```
//!
//! Two details come straight from TS 24.229 and are enforced here:
//!
//! * `i-wlan-node-id` is the AP's MAC as **bare hexadecimal, no delimiters**
//!   (the worked example in the spec turns `00-0C-F1-12-60-28` into
//!   `000cf1126028`).
//! * `utran-cell-id-3gpp` is MCC (3 decimal) + MNC (**2 or 3 decimal**, not
//!   zero-padded) + TAC (4 hex for EPC, 6 hex for 5GCN) + ECI (7 hex).

#![forbid(unsafe_code)]

/// The SIP header field name.
pub const HEADER_NAME: &str = "P-Access-Network-Info";

/// The access type token for WLAN (TS 24.229; RFC 3455 lists the 802.11
/// variants as extension tokens).
pub const ACCESS_IEEE_802_11: &str = "IEEE-802.11";
/// E-UTRAN FDD access type.
pub const ACCESS_EUTRAN_FDD: &str = "3GPP-E-UTRAN-FDD";
/// E-UTRAN TDD access type.
pub const ACCESS_EUTRAN_TDD: &str = "3GPP-E-UTRAN-TDD";

/// How the UE is attached to the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessNetwork {
    /// Wi-Fi. `ap_mac` is the BSSID of the access point when known; a UE that
    /// cannot see it omits the parameter entirely.
    Wlan { ap_mac: Option<[u8; 6]> },
    /// E-UTRAN, cellular.
    Eutran {
        mcc: String,
        mnc: String,
        /// Tracking Area Code; 16 bits on EPC, 24 bits on 5GCN.
        tac: u32,
        /// E-UTRAN Cell Identity.
        eci: u32,
        /// `true` for TDD, `false` for FDD.
        tdd: bool,
        /// Selecting 5GCN makes the TAC six hexadecimal digits instead of four.
        five_gc: bool,
    },
}

impl AccessNetwork {
    /// Wi-Fi access, describing the access point's BSSID.
    pub fn wlan(ap_mac: [u8; 6]) -> Self {
        AccessNetwork::Wlan {
            ap_mac: Some(ap_mac),
        }
    }

    /// Wi-Fi access where the BSSID is unavailable.
    pub fn wlan_unspecified() -> Self {
        AccessNetwork::Wlan { ap_mac: None }
    }

    /// The `P-Access-Network-Info` header value.
    pub fn header_value(&self) -> String {
        match self {
            AccessNetwork::Wlan { ap_mac } => match ap_mac {
                Some(mac) => format!(
                    "{ACCESS_IEEE_802_11}; i-wlan-node-id={}",
                    mac.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ),
                None => ACCESS_IEEE_802_11.to_string(),
            },
            AccessNetwork::Eutran {
                mcc,
                mnc,
                tac,
                eci,
                tdd,
                five_gc,
            } => {
                let token = if *tdd {
                    ACCESS_EUTRAN_TDD
                } else {
                    ACCESS_EUTRAN_FDD
                };
                let tac_digits = if *five_gc { 6 } else { 4 };
                format!(
                    "{token}; utran-cell-id-3gpp={mcc}{mnc}{tac:0tac_digits$X}{eci:07X}",
                    tac_digits = tac_digits
                )
            }
        }
    }

    /// Whether this access counts as 3GPP access for IMS purposes.
    pub fn is_3gpp(&self) -> bool {
        matches!(self, AccessNetwork::Eutran { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wlan_reports_the_ap_mac_without_delimiters() {
        // TS 24.229: AP MAC 00-0C-F1-12-60-28 -> "000cf1126028".
        let access = AccessNetwork::wlan([0x00, 0x0C, 0xF1, 0x12, 0x60, 0x28]);
        assert_eq!(
            access.header_value(),
            "IEEE-802.11; i-wlan-node-id=000cf1126028"
        );
        assert!(!access.is_3gpp());
    }

    #[test]
    fn wlan_without_a_bssid_is_just_the_access_type() {
        assert_eq!(
            AccessNetwork::wlan_unspecified().header_value(),
            "IEEE-802.11"
        );
    }

    #[test]
    fn eutran_concatenates_plmn_tac_and_eci() {
        // TS 24.229: MCC 111, MNC 22, TAC 33C4, ECI 76B4321 ->
        // "1112233C476B4321".
        let access = AccessNetwork::Eutran {
            mcc: "111".into(),
            mnc: "22".into(),
            tac: 0x33C4,
            eci: 0x76B4321,
            tdd: false,
            five_gc: false,
        };
        assert_eq!(
            access.header_value(),
            "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=1112233C476B4321"
        );
        assert!(access.is_3gpp());
    }

    #[test]
    fn the_mnc_is_not_zero_padded_here() {
        // Unlike the DNS forms, this field uses the MNC as it is carried on the
        // air: 2 or 3 digits, never padded.
        let access = AccessNetwork::Eutran {
            mcc: "310".into(),
            mnc: "26".into(),
            tac: 0x0001,
            eci: 0x0000001,
            tdd: false,
            five_gc: false,
        };
        assert!(access
            .header_value()
            .ends_with("utran-cell-id-3gpp=3102600010000001"));
    }

    #[test]
    fn a_five_gcn_tracking_area_is_six_hex_digits() {
        let access = AccessNetwork::Eutran {
            mcc: "001".into(),
            mnc: "01".into(),
            tac: 0x0B1A21,
            eci: 0x0000123,
            tdd: true,
            five_gc: true,
        };
        assert_eq!(
            access.header_value(),
            "3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=001010B1A210000123"
        );
    }

    #[test]
    fn small_values_are_zero_padded_to_their_field_width() {
        let access = AccessNetwork::Eutran {
            mcc: "001".into(),
            mnc: "01".into(),
            tac: 0,
            eci: 0,
            tdd: false,
            five_gc: false,
        };
        assert!(access
            .header_value()
            .ends_with("utran-cell-id-3gpp=0010100000000000"));
    }
}
