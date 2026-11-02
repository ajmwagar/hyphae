//! ISIM access: the IMS identity files on the UICC (3GPP TS 31.103).
//!
//! A USIM is enough to *authenticate*, but not always enough to know who you
//! are. The private and public IMS identities live in a separate application,
//! the ISIM, selected by its own AID. When the card carries one, its values win
//! over anything derived from the IMSI — that is the difference between working
//! on a carrier that provisions an ISIM and one that does not.
//!
//! Files used here (TS 31.103 §4.2.2–4.2.4):
//!
//! | File | ID | Structure | Content |
//! |---|---|---|---|
//! | `EF_IMPI` | `6F02` | transparent | NAI, TLV tag `80`, UTF-8 |
//! | `EF_DOMAIN` | `6F03` | transparent | home network domain |
//! | `EF_IMPU` | `6F04` | **linear fixed** | SIP URI per record, TLV tag `80` |
//!
//! The AID prefix is the 3GPP ISIM application: RID `A000000087` with PIX
//! `1004` (ETSI TS 101 220 Annex E, table E.1). Selection by this 7-octet
//! prefix is a partial AID match, which ISO 7816-4 permits.

#![forbid(unsafe_code)]

use crate::apdu::strip_status_word;
use crate::apdu::{Apdu, INS_AUTHENTICATE};
use crate::{ApduChannel, UsimError};

/// The 7-octet ISIM application identifier prefix.
pub const ISIM_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04];
/// `EF_IMPI` — IMS private user identity (TS 31.103 §4.2.2).
pub const EF_IMPI: [u8; 2] = [0x6F, 0x02];
/// `EF_DOMAIN` — home network domain name (TS 31.103 §4.2.3).
pub const EF_DOMAIN: [u8; 2] = [0x6F, 0x03];
/// `EF_IMPU` — IMS public user identities, one per record (TS 31.103 §4.2.4).
pub const EF_IMPU: [u8; 2] = [0x6F, 0x04];

/// The BER-TLV tag wrapping every identity value in these files.
pub const TAG_IDENTITY: u8 = 0x80;

/// Errors from reading the ISIM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsimError {
    /// A file was not a well-formed TLV.
    Malformed(&'static str),
    /// A file held bytes that are not valid UTF-8.
    NotUtf8,
}

impl core::fmt::Display for IsimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IsimError::Malformed(what) => write!(f, "malformed ISIM file: {what}"),
            IsimError::NotUtf8 => f.write_str("ISIM identity is not valid UTF-8"),
        }
    }
}

impl std::error::Error for IsimError {}

/// `SELECT` by DF name (ISO 7816-4, P1 = 04).
pub fn select_aid(aid: &[u8]) -> Apdu {
    Apdu {
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: aid.to_vec(),
        le: Some(0x00),
    }
}

/// `SELECT` by file identifier (ISO 7816-4, P1 = 00).
pub fn select_ef(fid: [u8; 2]) -> Apdu {
    Apdu {
        cla: 0x00,
        ins: 0xA4,
        p1: 0x00,
        p2: 0x00,
        data: fid.to_vec(),
        le: Some(0x00),
    }
}

/// `READ BINARY` of a transparent file, from offset 0.
pub fn read_binary(length: u8) -> Apdu {
    Apdu {
        cla: 0x00,
        ins: 0xB0,
        p1: 0x00,
        p2: 0x00,
        data: Vec::new(),
        le: Some(length),
    }
}

/// `READ RECORD` of a linear fixed file, absolute addressing.
pub fn read_record(record: u8) -> Apdu {
    Apdu {
        cla: 0x00,
        ins: 0xB2,
        p1: record,
        p2: 0x04,
        data: Vec::new(),
        le: Some(0x00),
    }
}

/// Strip the `80` TLV wrapper from an ISIM file body.
///
/// The length is BER short form; the files here never need the long form, and
/// a long-form length is reported rather than guessed at.
pub fn unwrap_identity_tlv(body: &[u8]) -> Result<&[u8], IsimError> {
    let tag = *body.first().ok_or(IsimError::Malformed("empty file"))?;
    if tag != TAG_IDENTITY {
        return Err(IsimError::Malformed("unexpected TLV tag"));
    }
    let len_byte = *body.get(1).ok_or(IsimError::Malformed("missing length"))?;
    if len_byte & 0x80 != 0 {
        return Err(IsimError::Malformed("long-form length is not used here"));
    }
    let len = len_byte as usize;
    let value = body
        .get(2..2 + len)
        .ok_or(IsimError::Malformed("value truncated"))?;
    Ok(value)
}

/// An ISIM reached through an [`ApduChannel`].
pub struct Isim<C: ApduChannel> {
    channel: C,
}

impl<C: ApduChannel> Isim<C> {
    /// Wrap a channel. The caller is expected to have selected the application
    /// with [`Self::select`] before reading anything.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    /// Borrow the underlying channel.
    pub fn channel(&self) -> &C {
        &self.channel
    }

    /// Select the ISIM application by AID.
    ///
    /// Fails with [`UsimError::StatusWord`] when the card has no ISIM — which
    /// is the signal to fall back to IMSI-derived identities.
    pub fn select(&mut self) -> Result<(), UsimError> {
        self.transmit(&select_aid(&ISIM_AID)).map(|_| ())
    }

    /// The IMS private user identity (`EF_IMPI`).
    pub fn impi(&mut self) -> Result<String, UsimError> {
        let body = self.read_transparent(EF_IMPI)?;
        let value = unwrap_identity_tlv(&body).map_err(usim_error)?;
        core::str::from_utf8(value)
            .map(str::to_string)
            .map_err(|_| usim_error(IsimError::NotUtf8))
    }

    /// The home network domain (`EF_DOMAIN`), when the card provisions one.
    pub fn home_domain(&mut self) -> Result<Option<String>, UsimError> {
        match self.read_transparent(EF_DOMAIN) {
            Ok(body) => {
                let value = unwrap_identity_tlv(&body).map_err(usim_error)?;
                Ok(core::str::from_utf8(value).ok().map(str::to_string))
            }
            // No such file simply means this card does not carry one.
            Err(UsimError::StatusWord { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Every public identity in `EF_IMPU`, in record order.
    ///
    /// The first record is the default identity (TS 31.103 §4.2.4). Reading
    /// stops at the first record the card refuses to return.
    pub fn impu(&mut self) -> Result<Vec<String>, UsimError> {
        let mut out = Vec::new();
        for record in 1..=MAX_IMPU_RECORDS {
            let body = match self.read_record(record) {
                Ok(body) => body,
                Err(UsimError::StatusWord { .. }) => break,
                Err(e) => return Err(e),
            };
            if body.is_empty() {
                break;
            }
            let value = unwrap_identity_tlv(&body).map_err(usim_error)?;
            match core::str::from_utf8(value) {
                Ok(s) => out.push(s.to_string()),
                Err(_) => return Err(usim_error(IsimError::NotUtf8)),
            }
        }
        Ok(out)
    }

    /// Read a transparent file: select it, then read it whole.
    fn read_transparent(&mut self, fid: [u8; 2]) -> Result<Vec<u8>, UsimError> {
        self.transmit(&select_ef(fid))?;
        self.transmit(&read_binary(0x00))
    }

    fn read_record(&mut self, record: u8) -> Result<Vec<u8>, UsimError> {
        // A linear fixed file must be selected before its records are read.
        if record == 1 {
            self.transmit(&select_ef(EF_IMPU))?;
        }
        self.transmit(&read_record(record))
    }

    fn transmit(&mut self, command: &Apdu) -> Result<Vec<u8>, UsimError> {
        let response = self.channel.transmit(&command.to_bytes())?;
        strip_status_word(&response.to_wire()).map(|body| body.to_vec())
    }
}

/// Conventional upper bound; a card with more identities than this is not one
/// this tree claims to handle.
const MAX_IMPU_RECORDS: u8 = 16;

fn usim_error(e: IsimError) -> UsimError {
    UsimError::Malformed(match e {
        IsimError::Malformed(what) => what,
        IsimError::NotUtf8 => "ISIM identity is not valid UTF-8",
    })
}

/// Keep the AUTHENTICATE INS visible to readers of this module: the ISIM is
/// reached over the same channel, and mixing it up with an authentication
/// command would be a silent failure.
const _: u8 = INS_AUTHENTICATE;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::CardResponse;
    use crate::UsimError;

    /// A channel that answers a scripted list of responses.
    struct Scripted {
        responses: Vec<Vec<u8>>,
        pub seen: Vec<Vec<u8>>,
    }

    impl Scripted {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses,
                seen: Vec::new(),
            }
        }
    }

    impl ApduChannel for Scripted {
        fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError> {
            self.seen.push(command.to_vec());
            if self.responses.is_empty() {
                return Ok(CardResponse::status(0x6A, 0x82));
            }
            let wire = self.responses.remove(0);
            let (body, sw) = wire.split_at(wire.len() - 2);
            Ok(CardResponse {
                data: body.to_vec(),
                sw1: sw[0],
                sw2: sw[1],
            })
        }
    }

    fn ident(hex: &str) -> Vec<u8> {
        let mut out = vec![TAG_IDENTITY, (hex.len() / 2) as u8];
        for i in (0..hex.len()).step_by(2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
        }
        out
    }

    fn ok(mut body: Vec<u8>) -> Vec<u8> {
        body.extend_from_slice(&[0x90, 0x00]);
        body
    }

    #[test]
    fn impi_is_read_from_the_isim_application() {
        let impi = "234150123456789@ims.mnc015.mcc234.3gppnetwork.org";
        let mut isim = Isim::new(Scripted::new(vec![
            ok(vec![]),            // SELECT AID
            ok(vec![]),            // SELECT EF_IMPI
            ok(ident(&hex(impi))), // READ BINARY
        ]));
        isim.select().unwrap();
        assert_eq!(isim.impi().unwrap(), impi);
    }

    #[test]
    fn the_commands_are_the_ones_the_spec_describes() {
        let mut isim = Isim::new(Scripted::new(vec![
            ok(vec![]),
            ok(vec![]),
            ok(ident(&hex("a@b"))),
        ]));
        isim.select().unwrap();
        let _ = isim.impi().unwrap();
        let seen = &isim.channel().seen;

        // SELECT by DF name, AID A0000000871004 (TS 101 220 annex E).
        assert_eq!(
            seen[0],
            vec![0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04, 0x00]
        );
        // SELECT EF_IMPI = 6F02, then READ BINARY from offset 0.
        assert_eq!(
            seen[1],
            vec![0x00, 0xA4, 0x00, 0x00, 0x02, 0x6F, 0x02, 0x00]
        );
        assert_eq!(seen[2], vec![0x00, 0xB0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn impu_reads_records_until_the_card_stops() {
        let first = "sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org";
        let second = "sip:234150999999999@ims.mnc015.mcc234.3gppnetwork.org";
        let mut isim = Isim::new(Scripted::new(vec![
            ok(vec![]),              // SELECT AID
            ok(vec![]),              // SELECT EF_IMPU
            ok(ident(&hex(first))),  // record 1
            ok(ident(&hex(second))), // record 2
            vec![0x6A, 0x83],        // record 3: not found
        ]));
        isim.select().unwrap();
        assert_eq!(
            isim.impu().unwrap(),
            vec![first.to_string(), second.to_string()]
        );
        // Records are addressed absolutely starting at 1.
        let seen = &isim.channel().seen;
        assert_eq!(seen[2], vec![0x00, 0xB2, 0x01, 0x04, 0x00]);
        assert_eq!(seen[3], vec![0x00, 0xB2, 0x02, 0x04, 0x00]);
    }

    #[test]
    fn a_card_without_an_isim_reports_the_status_word() {
        let mut isim = Isim::new(Scripted::new(vec![vec![0x6A, 0x82]]));
        assert_eq!(
            isim.select(),
            Err(UsimError::StatusWord {
                sw1: 0x6A,
                sw2: 0x82
            })
        );
    }

    #[test]
    fn a_missing_domain_file_is_not_an_error() {
        let mut isim = Isim::new(Scripted::new(vec![
            ok(vec![]),       // SELECT EF_DOMAIN would succeed...
            vec![0x6A, 0x82], // ...but the read fails
        ]));
        assert_eq!(isim.home_domain().unwrap(), None);
    }

    #[test]
    fn a_bad_tlv_is_rejected() {
        assert_eq!(
            unwrap_identity_tlv(&[0x81, 0x01, 0xAA]),
            Err(IsimError::Malformed("unexpected TLV tag"))
        );
        assert_eq!(
            unwrap_identity_tlv(&[0x80, 0x05, 0x41]),
            Err(IsimError::Malformed("value truncated"))
        );
        assert_eq!(
            unwrap_identity_tlv(&[0x80, 0x81, 0x01, 0x41]),
            Err(IsimError::Malformed("long-form length is not used here"))
        );
        assert_eq!(unwrap_identity_tlv(&[0x80, 0x01, 0x41]), Ok(&[0x41u8][..]));
    }

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("{b:02x}")).collect()
    }
}
