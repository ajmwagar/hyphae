//! PLMN identity: MCC plus MNC, as carried on the SIM (TS 23.003 §2.2).
//!
//! Every 3GPP discovery name — ePDG, BSF, and the rest — is built from this
//! type, so it lives here rather than in whichever crate happened to need it
//! first. Two rules are easy to get wrong and are enforced here instead of
//! being left to each caller: MCC and MNC are always **three digits** in DNS,
//! with a one-digit MNC zero-padded on the left, and neither may be empty.

/// Errors from building a PLMN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlmnError {
    /// MCC must be exactly three digits.
    BadMcc(String),
    /// MNC must be two or three digits.
    BadMnc(String),
}

impl core::fmt::Display for PlmnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlmnError::BadMcc(v) => {
                write!(f, "MCC must be three digits, got {v:?}")
            }
            PlmnError::BadMnc(v) => {
                write!(f, "MNC must be two or three digits, got {v:?}")
            }
        }
    }
}

impl std::error::Error for PlmnError {}

/// A PLMN identifier: MCC plus MNC, as carried on the SIM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlmnId {
    mcc: String,
    mnc: String,
}

impl PlmnId {
    /// Build a PLMN. `mcc` must be three digits; `mnc` two or three.
    pub fn new(mcc: &str, mnc: &str) -> Result<Self, PlmnError> {
        let mcc_digits = mcc.len() == 3 && mcc.bytes().all(|b| b.is_ascii_digit());
        if !mcc_digits {
            return Err(PlmnError::BadMcc(mcc.to_string()));
        }
        let mnc_digits = matches!(mnc.len(), 2 | 3) && mnc.bytes().all(|b| b.is_ascii_digit());
        if !mnc_digits {
            return Err(PlmnError::BadMnc(mnc.to_string()));
        }
        Ok(Self {
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
        })
    }

    /// The MCC as supplied.
    pub fn mcc(&self) -> &str {
        &self.mcc
    }

    /// The MNC as supplied (two or three digits).
    pub fn mnc(&self) -> &str {
        &self.mnc
    }

    /// The MNC as it appears in DNS: always three digits, zero-padded on the
    /// left (TS 23.003 §19.4.2.9.2).
    pub fn mnc_dns(&self) -> String {
        format!("{:0>3}", self.mnc)
    }

    /// `mnc<MNC>.mcc<MCC>`, the PLMN part of every operator 3GPP name.
    pub fn plmn_labels(&self) -> String {
        format!("mnc{}.mcc{}", self.mnc_dns(), self.mcc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_digit_mnc_is_padded() {
        let p = PlmnId::new("345", "12").unwrap();
        assert_eq!(p.plmn_labels(), "mnc012.mcc345");
    }

    #[test]
    fn three_digit_mnc_is_not_repadded() {
        let p = PlmnId::new("310", "260").unwrap();
        assert_eq!(p.plmn_labels(), "mnc260.mcc310");
    }

    #[test]
    fn bad_input_is_rejected() {
        assert_eq!(
            PlmnId::new("34", "12").unwrap_err(),
            PlmnError::BadMcc("34".into())
        );
        assert_eq!(
            PlmnId::new("345", "1").unwrap_err(),
            PlmnError::BadMnc("1".into())
        );
        assert_eq!(
            PlmnId::new("345", "1234").unwrap_err(),
            PlmnError::BadMnc("1234".into())
        );
        assert!(PlmnId::new("34a", "12").is_err());
    }
}
