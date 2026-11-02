//! `AUTHENTICATE` APDU coding, 3GPP TS 31.102 §7.1.2 (EVEN INS code).
//!
//! ## Command (TS 31.102 §7.1.2.1)
//!
//! ```text
//! CLA = 00            (TS 31.101)
//! INS = 88            AUTHENTICATE
//! P1  = 00
//! P2  = 01            3G/EPS/5G security context (b8=0, b3..b1 = 001)
//! Lc  = 22            length of the data field
//! Data= 10 <RAND:16> 10 <AUTN:16>     L1 || RAND || L2 || AUTN
//! Le  = 00
//! ```
//!
//! ## Response (TS 31.102 §7.1.2.1)
//!
//! Success, tag `DB`:
//!
//! ```text
//! DB  L3 <RES:L3>  L4 <CK:L4>  L5 <IK:L5>  [08 <KC:8>]
//! ```
//!
//! Synchronisation failure, tag `DC`:
//!
//! ```text
//! DC  L1 <AUTS:L1>
//! ```

#![forbid(unsafe_code)]

use crate::{AkaOutput, Autn, Rand, UsimError};

/// The `AUTHENTICATE` instruction code (TS 31.102 §7.1.2).
pub const INS_AUTHENTICATE: u8 = 0x88;
/// `P2` for the 3G/EPS/5G security context (table 7.1.2-1, `001`).
pub const P2_3G_CONTEXT: u8 = 0x01;
/// Tag for a successful 3G authentication response.
pub const TAG_SUCCESS_3G: u8 = 0xDB;
/// Tag for a synchronisation-failure response.
pub const TAG_SYNC_FAILURE: u8 = 0xDC;

/// A command APDU (ISO 7816-4 short form).
///
/// `data` is the command data field; `le` is only emitted when present, which
/// keeps this usable for both case-3 and case-4 commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl Apdu {
    /// Serialise to the short-form wire bytes (header, Lc, data, optional Le).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.data.len() + 1);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if !self.data.is_empty() || self.le.is_some() {
            // Lc is only present when there is data (ISO 7816-4 case 2 vs 3/4).
            if !self.data.is_empty() {
                out.push(self.data.len() as u8);
                out.extend_from_slice(&self.data);
            }
        }
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }
}

/// Build the `AUTHENTICATE` command for one 3G challenge (TS 31.102 §7.1.2.1).
///
/// The data field is `0x10 || RAND || 0x10 || AUTN`, so `Lc` is 34.
pub fn authenticate_command(rand: &Rand, autn: &Autn) -> Apdu {
    let mut data = Vec::with_capacity(2 + 16 + 16);
    data.push(rand.len() as u8);
    data.extend_from_slice(rand);
    data.push(autn.len() as u8);
    data.extend_from_slice(autn);
    Apdu {
        cla: 0x00,
        ins: INS_AUTHENTICATE,
        p1: 0x00,
        p2: P2_3G_CONTEXT,
        data,
        le: Some(0x00),
    }
}

/// A decoded `AUTHENTICATE` response body (the data field, without status words).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticateResponse {
    /// `DB` — RES/CK/IK, plus KC when the USIM exposes GSM conversion.
    Success(AkaOutput),
    /// `DC` — AUTS for network resynchronisation.
    SyncFailure { auts: [u8; 14] },
}

/// Decode an `AUTHENTICATE` response data field (TS 31.102 §7.1.2.1).
///
/// Every length field is bounds-checked; a truncated body is an error rather
/// than a silently short RES.
pub fn parse_authenticate_response(data: &[u8]) -> Result<AuthenticateResponse, UsimError> {
    let tag = *data.first().ok_or(UsimError::Malformed("empty response"))?;
    match tag {
        TAG_SUCCESS_3G => {
            let mut at = 1;
            let res = take_tlv(data, &mut at, "RES length")?;
            let ck = take_tlv(data, &mut at, "CK length")?;
            let ik = take_tlv(data, &mut at, "IK length")?;
            // Optional KC TLV (Service n°27). It is parsed and discarded: the
            // IMS/3G path does not use the GSM conversion.
            if at < data.len() {
                let _kc = take_tlv(data, &mut at, "KC length")?;
            }
            if ck.len() != 16 || ik.len() != 16 {
                return Err(UsimError::Malformed("CK/IK must be 16 octets"));
            }
            let mut ck_key = [0u8; 16];
            ck_key.copy_from_slice(ck);
            let mut ik_key = [0u8; 16];
            ik_key.copy_from_slice(ik);
            if res.len() < 4 || res.len() > 16 {
                return Err(UsimError::Malformed("RES must be 4..=16 octets"));
            }
            Ok(AuthenticateResponse::Success(AkaOutput::Success {
                res: res.to_vec(),
                ck: ck_key,
                ik: ik_key,
            }))
        }
        TAG_SYNC_FAILURE => {
            let mut at = 1;
            let auts = take_tlv(data, &mut at, "AUTS length")?;
            if auts.len() != 14 {
                return Err(UsimError::Malformed("AUTS must be 14 octets"));
            }
            let mut out = [0u8; 14];
            out.copy_from_slice(auts);
            Ok(AuthenticateResponse::SyncFailure { auts: out })
        }
        other => Err(UsimError::BadTag(other)),
    }
}

/// Read `L || value:L` starting at `*at`, advancing past it.
fn take_tlv<'a>(data: &'a [u8], at: &mut usize, what: &'static str) -> Result<&'a [u8], UsimError> {
    let len = *data.get(*at).ok_or(UsimError::Malformed(what))? as usize;
    let start = *at + 1;
    let end = start.checked_add(len).ok_or(UsimError::Malformed(what))?;
    let value = data.get(start..end).ok_or(UsimError::Malformed(what))?;
    *at = end;
    Ok(value)
}

/// Parse a card response `data || SW1 || SW2`, returning the body only when the
/// status word is `90 00` (TS 31.102 §7.1.2).
pub fn strip_status_word(response: &[u8]) -> Result<&[u8], UsimError> {
    if response.len() < 2 {
        return Err(UsimError::Malformed("response shorter than a status word"));
    }
    let (body, sw) = response.split_at(response.len() - 2);
    let (sw1, sw2) = (sw[0], sw[1]);
    if (sw1, sw2) != crate::sw::OK {
        return Err(UsimError::StatusWord { sw1, sw2 });
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_matches_ts_31_102_layout() {
        let rand = [0x11u8; 16];
        let autn = [0x22u8; 16];
        let apdu = authenticate_command(&rand, &autn);
        let bytes = apdu.to_bytes();
        assert_eq!(&bytes[..5], &[0x00, 0x88, 0x00, 0x01, 0x22]);
        assert_eq!(bytes[5], 0x10);
        assert_eq!(&bytes[6..22], &rand);
        assert_eq!(bytes[22], 0x10);
        assert_eq!(&bytes[23..39], &autn);
        assert_eq!(bytes[39], 0x00); // Le
        assert_eq!(bytes.len(), 40);
    }

    #[test]
    fn success_response_parses_res_ck_ik() {
        let mut body = vec![TAG_SUCCESS_3G];
        body.extend_from_slice(&[8]);
        body.extend_from_slice(&[0xAA; 8]); // RES
        body.extend_from_slice(&[16]);
        body.extend_from_slice(&[0xBB; 16]); // CK
        body.extend_from_slice(&[16]);
        body.extend_from_slice(&[0xCC; 16]); // IK
        match parse_authenticate_response(&body).unwrap() {
            AuthenticateResponse::Success(AkaOutput::Success { res, ck, ik }) => {
                assert_eq!(res, vec![0xAA; 8]);
                assert_eq!(ck, [0xBB; 16]);
                assert_eq!(ik, [0xCC; 16]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn optional_kc_is_tolerated() {
        let mut body = vec![TAG_SUCCESS_3G];
        body.extend_from_slice(&[8]);
        body.extend_from_slice(&[0xAA; 8]);
        body.extend_from_slice(&[16]);
        body.extend_from_slice(&[0xBB; 16]);
        body.extend_from_slice(&[16]);
        body.extend_from_slice(&[0xCC; 16]);
        body.extend_from_slice(&[8]);
        body.extend_from_slice(&[0xDD; 8]); // KC
        assert!(matches!(
            parse_authenticate_response(&body).unwrap(),
            AuthenticateResponse::Success(_)
        ));
    }

    #[test]
    fn sync_failure_parses_auts() {
        let mut body = vec![TAG_SYNC_FAILURE];
        body.push(14);
        body.extend_from_slice(&[0x77; 14]);
        match parse_authenticate_response(&body).unwrap() {
            AuthenticateResponse::SyncFailure { auts } => assert_eq!(auts, [0x77; 14]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn truncated_and_bad_tag_are_rejected() {
        assert_eq!(
            parse_authenticate_response(&[]).unwrap_err(),
            UsimError::Malformed("empty response")
        );
        assert_eq!(
            parse_authenticate_response(&[0x99]).unwrap_err(),
            UsimError::BadTag(0x99)
        );
        // Declares 16 CK octets but has none.
        let body = vec![TAG_SUCCESS_3G, 8, 1, 2, 3, 4, 5, 6, 7, 8, 16];
        assert!(matches!(
            parse_authenticate_response(&body).unwrap_err(),
            UsimError::Malformed(_)
        ));
    }

    #[test]
    fn status_word_is_stripped() {
        assert_eq!(strip_status_word(&[0xDB, 0x90, 0x00]).unwrap(), &[0xDB]);
        assert_eq!(
            strip_status_word(&[0xDB, 0x98, 0x62]).unwrap_err(),
            UsimError::StatusWord {
                sw1: 0x98,
                sw2: 0x62
            }
        );
    }
}
