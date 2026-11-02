//! QMI UIM card access: send TS 31.102 APDUs to the modem's USIM.
//!
//! Phones have no PC/SC reader, so the AKA APDU has to reach the card through
//! the modem. The modern path is QMI **UIM Send APDU** (service `0x0B`,
//! message `0x3B`): the host sends a raw APDU and the modem forwards it to the
//! UICC. That keeps [`crate::apdu`] as the only AKA codec — this module is just
//! the QMUX/QMI envelope around it.
//!
//! ```text
//! QMUX: 01 | len(2, LE) | control 00 | service 0B | client | QMI...
//! QMI:  00 | transaction(2, LE) | message 3B 00 | TLVs
//! TLV:  type(1) | length(2, LE) | value
//!
//! request  TLVs: 01 slot, 02 APDU (u16 len + bytes), 10 channel id
//! response TLVs: 02 operation result, 10 APDU response (u16 len + bytes)
//! ```
//!
//! The `/dev/cdc-wdm*` device is the pluggable boundary: implement
//! [`QmiExchange`] out of tree (or bind it to libqmi). This crate never opens
//! the device, so there is no FFI and no vendor code.

#![forbid(unsafe_code)]

use crate::card::CardResponse;
use crate::{ApduChannel, UsimError};

/// QMI service id for UIM.
pub const SERVICE_UIM: u8 = 0x0B;
/// QMI UIM "Send APDU" message id.
pub const MSG_SEND_APDU: u16 = 0x003B;

/// A transport that exchanges one QMUX frame with the modem.
pub trait QmiExchange {
    /// Send a QMUX request and return the raw QMUX response.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, UsimError>;
}

/// One QMI TLV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub kind: u8,
    pub value: Vec<u8>,
}

/// Encode a QMUX request frame (type `0x01`).
pub fn encode_qmux(
    service: u8,
    client_id: u8,
    transaction: u16,
    message: u16,
    tlvs: &[Tlv],
) -> Vec<u8> {
    let mut qmi = Vec::with_capacity(5 + tlvs.len() * 4);
    qmi.push(0x00); // QMI flags
    qmi.extend_from_slice(&transaction.to_le_bytes());
    qmi.extend_from_slice(&message.to_le_bytes());
    for tlv in tlvs {
        qmi.push(tlv.kind);
        qmi.extend_from_slice(&(tlv.value.len() as u16).to_le_bytes());
        qmi.extend_from_slice(&tlv.value);
    }

    let mut out = Vec::with_capacity(6 + qmi.len());
    out.push(0x01); // QMUX type: request
                    // Length covers control + service + client + the QMI message.
    out.extend_from_slice(&((3 + qmi.len()) as u16).to_le_bytes());
    out.push(0x00); // control
    out.push(service);
    out.push(client_id);
    out.extend_from_slice(&qmi);
    out
}

/// One decoded QMUX response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiResponse {
    pub service: u8,
    pub client_id: u8,
    pub transaction: u16,
    pub message: u16,
    pub tlvs: Vec<Tlv>,
}

/// Decode a QMUX response and its TLVs.
pub fn decode_qmux(frame: &[u8]) -> Result<QmiResponse, UsimError> {
    // Minimum: type + length + control + service + client + 5-byte QMI header.
    if frame.len() < 11 {
        return Err(UsimError::Malformed("QMUX frame too short"));
    }
    let length = u16::from_le_bytes([frame[1], frame[2]]) as usize;
    if frame.len() < 3 + length {
        return Err(UsimError::Malformed("QMUX length overruns frame"));
    }
    let service = frame[4];
    let client_id = frame[5];
    let qmi = &frame[6..3 + length];
    if qmi.len() < 5 {
        return Err(UsimError::Malformed("QMI message too short"));
    }
    let transaction = u16::from_le_bytes([qmi[1], qmi[2]]);
    let message = u16::from_le_bytes([qmi[3], qmi[4]]);
    let mut tlvs = Vec::new();
    let mut at = 5;
    while at < qmi.len() {
        if at + 3 > qmi.len() {
            return Err(UsimError::Malformed("TLV header truncated"));
        }
        let kind = qmi[at];
        let len = u16::from_le_bytes([qmi[at + 1], qmi[at + 2]]) as usize;
        let start = at + 3;
        let end = start
            .checked_add(len)
            .ok_or(UsimError::Malformed("TLV length overflow"))?;
        let value = qmi
            .get(start..end)
            .ok_or(UsimError::Malformed("TLV value truncated"))?;
        tlvs.push(Tlv {
            kind,
            value: value.to_vec(),
        });
        at = end;
    }
    Ok(QmiResponse {
        service,
        client_id,
        transaction,
        message,
        tlvs,
    })
}

/// Build the `Send APDU` request TLVs.
pub fn send_apdu_tlvs(slot: u8, channel: u8, apdu: &[u8]) -> Vec<Tlv> {
    let mut apdu_value = Vec::with_capacity(2 + apdu.len());
    apdu_value.extend_from_slice(&(apdu.len() as u16).to_le_bytes());
    apdu_value.extend_from_slice(apdu);
    vec![
        Tlv {
            kind: 0x01,
            value: vec![slot],
        },
        Tlv {
            kind: 0x02,
            value: apdu_value,
        },
        Tlv {
            kind: 0x10,
            value: vec![channel],
        },
    ]
}

/// Extract the APDU response bytes (`data || SW1 SW2`) from a `Send APDU`
/// response, checking the operation result first.
pub fn parse_send_apdu_response(response: &QmiResponse) -> Result<Vec<u8>, UsimError> {
    // Operation Result TLV 0x02: u16 result + u16 error.
    if let Some(op) = response.tlvs.iter().find(|t| t.kind == 0x02) {
        if op.value.len() >= 4 {
            let result = u16::from_le_bytes([op.value[0], op.value[1]]);
            let error = u16::from_le_bytes([op.value[2], op.value[3]]);
            if result != 0 {
                return Err(UsimError::StatusWord {
                    sw1: (error >> 8) as u8,
                    sw2: error as u8,
                });
            }
        }
    }
    let apdu = response
        .tlvs
        .iter()
        .find(|t| t.kind == 0x10)
        .ok_or(UsimError::Malformed("no APDU response TLV"))?;
    if apdu.value.len() < 2 {
        return Err(UsimError::Malformed("APDU response TLV too short"));
    }
    let len = u16::from_le_bytes([apdu.value[0], apdu.value[1]]) as usize;
    apdu.value
        .get(2..2 + len)
        .map(|v| v.to_vec())
        .ok_or(UsimError::Malformed("APDU response length overruns TLV"))
}

/// A [`ApduChannel`] that reaches the USIM through QMI UIM Send APDU.
pub struct QmiApdu<T: QmiExchange> {
    transport: T,
    client_id: u8,
    slot: u8,
    channel: u8,
    transaction: u16,
}

impl<T: QmiExchange> QmiApdu<T> {
    /// Wrap a QMUX transport. `client_id` is the UIM client allocated by
    /// `QMI_UIM_GET_CARD_STATUS`/`QMI_CTL_GET_CLIENT_ID`; `slot` is 1 or 2.
    pub fn new(transport: T, client_id: u8, slot: u8) -> Self {
        Self {
            transport,
            client_id,
            slot,
            channel: 0,
            transaction: 0,
        }
    }

    /// Use a non-zero logical channel.
    pub fn with_channel(mut self, channel: u8) -> Self {
        self.channel = channel;
        self
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: QmiExchange> ApduChannel for QmiApdu<T> {
    fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError> {
        self.transaction = self.transaction.wrapping_add(1);
        let tlvs = send_apdu_tlvs(self.slot, self.channel, command);
        let frame = encode_qmux(
            SERVICE_UIM,
            self.client_id,
            self.transaction,
            MSG_SEND_APDU,
            &tlvs,
        );
        let response = self.transport.exchange(&frame)?;
        let decoded = decode_qmux(&response)?;
        if decoded.message != MSG_SEND_APDU {
            return Err(UsimError::Malformed("unexpected QMI message id"));
        }
        let bytes = parse_send_apdu_response(&decoded)?;
        CardResponse::from_apdu_response(&bytes)
    }
}

impl CardResponse {
    /// Split `data || SW1 SW2` into a [`CardResponse`].
    pub fn from_apdu_response(bytes: &[u8]) -> Result<Self, UsimError> {
        if bytes.len() < 2 {
            return Err(UsimError::Malformed(
                "APDU response shorter than a status word",
            ));
        }
        let (data, sw) = bytes.split_at(bytes.len() - 2);
        Ok(CardResponse {
            data: data.to_vec(),
            sw1: sw[0],
            sw2: sw[1],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::authenticate_command;
    use crate::{sw, Usim};

    /// A loopback modem that answers Send APDU with a canned APDU response.
    struct FakeModem {
        apdu_response: Vec<u8>,
        seen: Vec<u8>,
    }

    impl QmiExchange for FakeModem {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, UsimError> {
            self.seen = request.to_vec();
            let mut value = Vec::new();
            value.extend_from_slice(&(self.apdu_response.len() as u16).to_le_bytes());
            value.extend_from_slice(&self.apdu_response);
            let ok = Tlv {
                kind: 0x02,
                value: vec![0, 0, 0, 0],
            };
            let apdu = Tlv { kind: 0x10, value };
            // Build a response frame: type 0x02, same service/client, QMI header.
            let mut qmi = vec![0x00, request[7], request[8], 0x3B, 0x00];
            for t in [ok, apdu] {
                qmi.push(t.kind);
                qmi.extend_from_slice(&(t.value.len() as u16).to_le_bytes());
                qmi.extend_from_slice(&t.value);
            }
            let mut out = vec![0x02];
            out.extend_from_slice(&((3 + qmi.len()) as u16).to_le_bytes());
            out.extend_from_slice(&[0x00, SERVICE_UIM, request[5]]);
            out.extend_from_slice(&qmi);
            Ok(out)
        }
    }

    #[test]
    fn qmux_request_has_the_expected_shape() {
        let tlvs = send_apdu_tlvs(1, 0, &[0x00, 0x88]);
        let frame = encode_qmux(SERVICE_UIM, 9, 0x0102, MSG_SEND_APDU, &tlvs);
        assert_eq!(frame[0], 0x01, "QMUX type request");
        assert_eq!(&frame[3..6], &[0x00, SERVICE_UIM, 9]);
        assert_eq!(&frame[7..9], &[0x02, 0x01], "transaction LE");
        assert_eq!(&frame[9..11], &[0x3B, 0x00], "message LE");
        // TLV 0x01 slot = 1
        assert_eq!(&frame[11..15], &[0x01, 0x01, 0x00, 0x01]);
        // Length field covers everything after itself.
        let len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
        assert_eq!(len + 3, frame.len());
    }

    #[test]
    fn send_apdu_round_trips_through_the_card_channel() {
        // A successful 3G AUTHENTICATE response body.
        let mut apdu_response = Vec::new();
        apdu_response.push(0xDB);
        apdu_response.push(8);
        apdu_response.extend_from_slice(&[0xA5; 8]); // RES
        apdu_response.push(16);
        apdu_response.extend_from_slice(&[0xB4; 16]); // CK
        apdu_response.push(16);
        apdu_response.extend_from_slice(&[0xF7; 16]); // IK
        apdu_response.extend_from_slice(&[0x90, 0x00]); // SW

        let modem = FakeModem {
            apdu_response,
            seen: Vec::new(),
        };
        let mut card = crate::UsimCard::new(QmiApdu::new(modem, 9, 1));
        let rand = [0x11u8; 16];
        let autn = [0x22u8; 16];
        let out = card.authenticate(&rand, &autn).unwrap();
        match out {
            crate::AkaOutput::Success { res, ck, ik } => {
                assert_eq!(res, vec![0xA5; 8]);
                assert_eq!(ck, [0xB4; 16]);
                assert_eq!(ik, [0xF7; 16]);
            }
            other => panic!("unexpected {other:?}"),
        }
        // The modem saw the TS 31.102 AUTHENTICATE APDU we built.
        let expected = authenticate_command(&rand, &autn).to_bytes();
        assert!(card
            .channel()
            .transport()
            .seen
            .windows(expected.len())
            .any(|w| w == expected.as_slice()));
    }

    #[test]
    fn operation_result_error_maps_to_a_status_word() {
        let response = QmiResponse {
            service: SERVICE_UIM,
            client_id: 1,
            transaction: 1,
            message: MSG_SEND_APDU,
            tlvs: vec![Tlv {
                kind: 0x02,
                value: vec![1, 0, 0x62, 0x98],
            }],
        };
        assert_eq!(
            parse_send_apdu_response(&response),
            Err(UsimError::StatusWord {
                sw1: 0x98,
                sw2: 0x62
            })
        );
    }

    #[test]
    fn malformed_frames_are_rejected() {
        assert!(decode_qmux(&[0x02, 0x00]).is_err());
        let mut frame = encode_qmux(SERVICE_UIM, 1, 1, MSG_SEND_APDU, &[]);
        frame[1] = 0xFF; // lie about the length
        assert!(decode_qmux(&frame).is_err());
    }

    #[test]
    fn status_word_helpers_agree() {
        let r = CardResponse::from_apdu_response(&[0xDB, 0x90, 0x00]).unwrap();
        assert_eq!((r.sw1, r.sw2), sw::OK);
        assert_eq!(r.data, vec![0xDB]);
    }
}
