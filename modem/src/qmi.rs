//! QMI over QRTR: frame codec, TLV codec, transaction correlation, errors.
//!
//! ## Wire format
//!
//! A QMI datagram on a QRTR socket is one frame with no QMUX header — the
//! QRTR port already says which service the message is for:
//!
//! ```text
//!   type        u8      0x00 request, 0x02 response, 0x04 indication
//!   transaction u16 LE  correlates a response with its request
//!   message     u16 LE  service message id, e.g. 0x0020 = WDS Start Network
//!   tlv_length  u16 LE  bytes of TLV data that follow
//!   TLVs        type u8 | length u16 LE | value
//! ```
//!
//! Values are not padded. The captured `WDS Get Current Settings` response is
//! seven header bytes and a seven-byte result TLV
//! (`02 04 00 | 01 00 0f 00`), with `tlv_length = 7`; the modem accepted the
//! request built the same way. Skipping `tlv_length` is not an option: the
//! same request without it was answered `NO_MEMORY` instead of `OUT_OF_CALL`.
//!
//! The 7-byte header is what libqrtr's `struct qmi_header` and libqmi's
//! `struct qmi_header` both describe, and what the MPSS firmware on the target
//! answers (see `modem/README.md` for the capture).
//!
//! ## Transaction correlation
//!
//! [`Client::call`] sends one request and then reads datagrams until the
//! response with the matching transaction id *and* message id arrives.
//! Indications are kept for the caller ([`Client::take_indications`]); strays
//! are dropped, so a late answer to an abandoned request cannot be mistaken
//! for the current one. The loop is bounded by a deadline, never by a retry
//! count, so a silent modem fails as [`crate::Error::Timeout`].

use std::time::{Duration, Instant};

use crate::error::{Error, ProtocolError};

/// Frame type: request (host to modem).
pub const REQUEST: u8 = 0x00;
/// Frame type: response (modem to host).
pub const RESPONSE: u8 = 0x02;
/// Frame type: indication (unsolicited, modem to host).
pub const INDICATION: u8 = 0x04;

/// The `result` TLV every response carries: `result u16 LE | error u16 LE`.
pub const TLV_RESULT: u8 = 0x02;

/// Header length: type, transaction, message id, TLV length.
pub const HEADER_LEN: usize = 7;

/// A QMI message the crate speaks: its wire id plus a name for diagnostics.
///
/// Message ids are per service, so the name has to travel with the id: `0x0020`
/// is `DPM Open Port` on service 47 and `WDS Start Network` on service 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Op {
    /// Human name, used verbatim in error messages.
    pub name: &'static str,
    /// The service message id.
    pub message: u16,
}

impl Op {
    /// Name a message id.
    pub const fn new(name: &'static str, message: u16) -> Self {
        Self { name, message }
    }
}

impl core::fmt::Display for Op {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} (0x{:04x})", self.name, self.message)
    }
}

/// One QMI type-length-value element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    /// TLV type, per service message.
    pub kind: u8,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// A TLV with a raw value.
    pub fn new(kind: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    /// A one-byte TLV (enums, booleans, masks).
    pub fn u8(kind: u8, value: u8) -> Self {
        Self::new(kind, vec![value])
    }

    /// A little-endian `u32` TLV.
    pub fn u32_le(kind: u8, value: u32) -> Self {
        Self::new(kind, value.to_le_bytes().to_vec())
    }

    /// A QMI string TLV: one length byte, then the bytes (no terminator).
    pub fn string(kind: u8, value: &str) -> Result<Self, Error> {
        let len = u8::try_from(value.len()).map_err(|_| Error::Malformed {
            what: "QMI string longer than 255 bytes",
        })?;
        let mut bytes = Vec::with_capacity(1 + value.len());
        bytes.push(len);
        bytes.extend_from_slice(value.as_bytes());
        Ok(Self::new(kind, bytes))
    }

    /// Read a little-endian `u32` value.
    pub fn as_u32_le(&self) -> Result<u32, Error> {
        let bytes: [u8; 4] = self
            .value
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed {
                what: "QMI TLV value is not 4 bytes",
            })?;
        Ok(u32::from_le_bytes(bytes))
    }
}

/// One decoded QMI frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// [`REQUEST`], [`RESPONSE`] or [`INDICATION`].
    pub kind: u8,
    /// Transaction id the frame belongs to.
    pub transaction: u16,
    /// Service message id.
    pub message: u16,
    /// TLVs, in wire order.
    pub tlvs: Vec<Tlv>,
}

impl Message {
    /// The first TLV of `kind`, if the modem sent one.
    pub fn tlv(&self, kind: u8) -> Option<&Tlv> {
        self.tlvs.iter().find(|tlv| tlv.kind == kind)
    }
}

/// Encode a request frame.
pub fn encode(op: Op, transaction: u16, tlvs: &[Tlv]) -> Result<Vec<u8>, Error> {
    let tlv_len: usize = tlvs.iter().map(|tlv| 3 + tlv.value.len()).sum();
    let tlv_len = u16::try_from(tlv_len).map_err(|_| Error::Malformed {
        what: "QMI message longer than 65535 bytes",
    })?;
    let mut frame = Vec::with_capacity(HEADER_LEN + usize::from(tlv_len));
    frame.push(REQUEST);
    frame.extend_from_slice(&transaction.to_le_bytes());
    frame.extend_from_slice(&op.message.to_le_bytes());
    frame.extend_from_slice(&tlv_len.to_le_bytes());
    for tlv in tlvs {
        frame.push(tlv.kind);
        frame.extend_from_slice(&(tlv.value.len() as u16).to_le_bytes());
        frame.extend_from_slice(&tlv.value);
    }
    Ok(frame)
}

/// Decode one frame, checking the header length against the datagram.
pub fn decode(datagram: &[u8]) -> Result<Message, Error> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::Malformed {
            what: "QMI frame shorter than the 7-byte header",
        });
    }
    let kind = datagram[0];
    let transaction = u16::from_le_bytes([datagram[1], datagram[2]]);
    let message = u16::from_le_bytes([datagram[3], datagram[4]]);
    let tlv_len = usize::from(u16::from_le_bytes([datagram[5], datagram[6]]));
    let end = HEADER_LEN + tlv_len;
    if datagram.len() != end {
        return Err(Error::Malformed {
            what: "QMI tlv_length does not match the datagram",
        });
    }

    let mut tlvs = Vec::new();
    let mut at = HEADER_LEN;
    while at < end {
        if at + 3 > end {
            return Err(Error::Malformed {
                what: "QMI TLV header truncated",
            });
        }
        let tlv_kind = datagram[at];
        let len = usize::from(u16::from_le_bytes([datagram[at + 1], datagram[at + 2]]));
        let start = at + 3;
        let stop = start + len;
        if stop > end {
            return Err(Error::Malformed {
                what: "QMI TLV value overruns the frame",
            });
        }
        tlvs.push(Tlv {
            kind: tlv_kind,
            value: datagram[start..stop].to_vec(),
        });
        at = stop;
    }

    Ok(Message {
        kind,
        transaction,
        message,
        tlvs,
    })
}

/// Read the mandatory `result` TLV of a response.
fn check_result(op: Op, response: &Message) -> Result<(), Error> {
    let tlv = response.tlv(TLV_RESULT).ok_or(Error::MissingTlv {
        op,
        tlv: TLV_RESULT,
    })?;
    if tlv.value.len() != 4 {
        return Err(Error::Malformed {
            what: "QMI result TLV is not 4 bytes",
        });
    }
    let result = u16::from_le_bytes([tlv.value[0], tlv.value[1]]);
    let code = u16::from_le_bytes([tlv.value[2], tlv.value[3]]);
    if result != 0 {
        return Err(Error::Modem {
            op,
            error: ProtocolError { code },
        });
    }
    Ok(())
}

/// The datagram boundary under a [`Client`].
///
/// The real implementation is a QRTR socket bound to one service port
/// (`crate::link`); tests use a scripted peer. Sending and receiving are
/// separate so a caller can re-read without re-sending.
pub trait Transport {
    /// Send one encoded frame.
    fn send(&mut self, frame: &[u8]) -> Result<(), Error>;
    /// Receive one datagram, waiting at most `timeout`.
    ///
    /// `Ok(None)` means the wait expired, not that the link failed.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, Error>;
}

/// One QMI client: a transport, a transaction counter and the indications the
/// modem pushed while we were waiting for something else.
pub struct Client<T> {
    transport: T,
    timeout: Duration,
    transaction: u16,
    indications: Vec<Message>,
}

impl<T: Transport> Client<T> {
    /// Wrap a transport. `timeout` bounds a whole request/response exchange.
    pub fn new(transport: T, timeout: Duration) -> Self {
        Self {
            transport,
            timeout,
            transaction: 0,
            indications: Vec::new(),
        }
    }

    /// Send `op` with `tlvs` and return its response, or an error.
    ///
    /// A response whose `result` TLV is not zero becomes
    /// [`Error::Modem`] carrying the QMI protocol error.
    pub fn call(&mut self, op: Op, tlvs: &[Tlv]) -> Result<Message, Error> {
        self.transaction = self.transaction.wrapping_add(1);
        let transaction = self.transaction;
        let frame = encode(op, transaction, tlvs)?;
        self.transport.send(&frame)?;

        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout { op });
            }
            let Some(datagram) = self.transport.recv(remaining)? else {
                return Err(Error::Timeout { op });
            };
            let message = decode(&datagram)?;
            if message.kind == INDICATION {
                self.indications.push(message);
                continue;
            }
            if message.kind != RESPONSE
                || message.transaction != transaction
                || message.message != op.message
            {
                continue;
            }
            check_result(op, &message)?;
            return Ok(message);
        }
    }

    /// Indications received while waiting, oldest first. Drains the queue.
    pub fn take_indications(&mut self) -> Vec<Message> {
        core::mem::take(&mut self.indications)
    }

    /// The transaction id of the last request, for logs and tests.
    pub fn transaction(&self) -> u16 {
        self.transaction
    }

    /// Borrow the transport (tests assert on what was sent).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{hex, Peer};

    const OP: Op = Op::new("test message", 0x002D);

    #[test]
    fn encode_writes_the_seven_byte_header_without_padding() {
        // The request the target firmware accepted for WDS Get Current Settings:
        // transaction 2, message 0x002d, one 4-byte TLV (request mask 0x2310).
        let frame = encode(OP, 2, &[Tlv::u32_le(0x10, 0x2310)]).unwrap();
        assert_eq!(hex(&frame), "0002002d00070010040010230000");
    }

    #[test]
    fn decode_reads_the_captured_out_of_call_response() {
        // WDS Get Current Settings on a client that owns no call.
        let raw: &[u8] = &[
            0x02, 0x02, 0x00, 0x2d, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x01, 0x00, 0x0f, 0x00,
        ];
        let message = decode(raw).unwrap();
        assert_eq!(message.kind, RESPONSE);
        assert_eq!(message.transaction, 2);
        assert_eq!(message.message, 0x002D);
        assert_eq!(
            message.tlvs,
            vec![Tlv::new(0x02, vec![0x01, 0x00, 0x0f, 0x00])]
        );
        assert_eq!(
            check_result(OP, &message),
            Err(Error::Modem {
                op: OP,
                error: ProtocolError::OUT_OF_CALL,
            })
        );
    }

    #[test]
    fn decode_reads_a_successful_response_with_a_trailing_tlv() {
        // Captured from the same modem: result 0/0 plus a one-byte TLV.
        let raw: &[u8] = &[
            0x02, 0x03, 0x00, 0x22, 0x00, 0x0b, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x01, 0x00, 0x01,
        ];
        let message = decode(raw).unwrap();
        assert_eq!(message.tlvs.len(), 2);
        assert_eq!(check_result(Op::new("any", 0x0022), &message), Ok(()));
    }

    #[test]
    fn malformed_frames_are_rejected() {
        // (description, bytes)
        let cases: &[(&str, &[u8])] = &[
            ("empty", &[]),
            ("short header", &[0x02, 0x01, 0x00, 0x2d]),
            (
                "tlv_length past the end",
                &[0x02, 0x01, 0x00, 0x2d, 0x00, 0x08, 0x00],
            ),
            (
                "trailing bytes after the TLVs",
                &[0x02, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x00, 0xff],
            ),
            (
                "truncated TLV header",
                &[0x02, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x00, 0x02, 0x00],
            ),
            (
                "TLV value overruns the frame",
                &[
                    0x02, 0x01, 0x00, 0x2d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x00, 0x00,
                ],
            ),
        ];
        for (what, bytes) in cases {
            assert!(decode(bytes).is_err(), "{what} should not decode");
        }
    }

    #[test]
    fn protocol_error_codes_have_names() {
        // The three the bearer path can surface, from the QMI protocol error
        // enum (as used by libqmi and the MPSS firmware).
        let cases = [
            (3u16, "INTERNAL"),
            (15, "OUT_OF_CALL"),
            (70, "INVALID_OPERATION"),
        ];
        for (code, name) in cases {
            assert_eq!(ProtocolError { code }.name(), Some(name));
        }
        assert_eq!(ProtocolError { code: 63_000 }.name(), None);
        assert_eq!(
            ProtocolError::INVALID_OPERATION.to_string(),
            "INVALID_OPERATION (70)"
        );
        assert_eq!(
            ProtocolError { code: 63_000 }.to_string(),
            "QMI error 63000"
        );
    }

    #[test]
    fn call_correlates_by_transaction_and_keeps_indications() {
        let indication = [
            0x04, 0x09, 0x00, 0x22, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let success = [
            0x02, 0x01, 0x00, 0x2d, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let peer = Peer::with_replies(&[&indication, &success]);
        let mut client = Client::new(peer, Duration::from_secs(1));
        let response = client.call(OP, &[]).unwrap();
        assert_eq!(response.transaction, 1);
        assert_eq!(client.transaction(), 1);
        assert_eq!(client.take_indications().len(), 1);
        assert!(client.take_indications().is_empty());
        assert_eq!(client.transport().sent.len(), 1);
    }

    #[test]
    fn stale_responses_are_ignored_until_the_right_one_arrives() {
        let stale = [
            0x02, 0x09, 0x00, 0x2d, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let wrong_message = [
            0x02, 0x01, 0x00, 0x21, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let right = [
            0x02, 0x01, 0x00, 0x2d, 0x00, 0x07, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let peer = Peer::with_replies(&[&stale, &wrong_message, &right]);
        let mut client = Client::new(peer, Duration::from_secs(1));
        assert!(client.call(OP, &[]).is_ok());
    }

    #[test]
    fn a_silent_modem_times_out() {
        let mut client = Client::new(Peer::default(), Duration::from_millis(1));
        assert_eq!(client.call(OP, &[]), Err(Error::Timeout { op: OP }));
    }

    #[test]
    fn missing_result_tlv_is_an_error() {
        let response = [0x02, 0x01, 0x00, 0x2d, 0x00, 0x00, 0x00];
        let mut client = Client::new(Peer::with_replies(&[&response]), Duration::from_secs(1));
        assert_eq!(
            client.call(OP, &[]),
            Err(Error::MissingTlv {
                op: OP,
                tlv: TLV_RESULT,
            })
        );
    }

    #[test]
    fn tlv_helpers_agree_on_the_wire_shape() {
        assert_eq!(Tlv::u8(0x19, 4).value, vec![4]);
        assert_eq!(Tlv::u32_le(0x29, 1472).value, vec![0xc0, 0x05, 0x00, 0x00]);
        assert_eq!(Tlv::string(0x14, "fast.t-mobile.com").unwrap().value, {
            let mut expected = vec![17u8];
            expected.extend_from_slice(b"fast.t-mobile.com");
            expected
        });
        assert_eq!(Tlv::u32_le(0x29, 1472).as_u32_le(), Ok(1472));
        assert!(Tlv::new(0x29, vec![0, 0]).as_u32_le().is_err());
        assert!(Tlv::string(0x14, &"a".repeat(256)).is_err());
    }
}
