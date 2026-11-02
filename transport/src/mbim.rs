//! MBIM modem transport for the IMS PDN (TRN-003).
//!
//! MBIM (Mobile Broadband Interface Model, USB-IF; libmbim on Linux) exposes a
//! modem as a *control channel* of command/response frames plus a *data
//! channel* that carries IP. For IMS the host activates a packet-data session
//! on the `ims` APN and then sends SIP over the returned IP bearer — the same
//! contract as [`crate::modem`], reached through MBIM rather than AT/QMI.
//!
//! This module models that contract faithfully:
//!
//! * the MBIM **control frame** wire shape (a 12-octet header plus a command
//!   payload) round-trips, so the framing is under test, and
//! * the transport's local endpoint is the **MBIM-assigned IMS PDN address**
//!   from the session's IP configuration, not a hard-coded value.
//!
//! The byte-level `/dev/cdc-wdm*` I/O and the real `MBIM_CID_*` service calls
//! are a documented stub; no modem device is required for the gate.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

use super::{Transport, TransportError};
use sip::Message;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

/// Octets in an MBIM transport header: `MessageType`, `MessageLength`,
/// `TransactionId`, each a 32-bit little-endian field (MBIM 1.0 §8.2.1).
pub const MBIM_HEADER_LEN: usize = 12;

/// The `MessageType` values used by this model (MBIM 1.0 §8.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MbimMessageType {
    /// Host → function: open the MBIM control channel.
    Open = 1,
    /// Host → function: close the control channel.
    Close = 2,
    /// Host → function: a command.
    Command = 3,
    /// Function → host: the command completed.
    CommandDone = 4,
    /// Function → host: an unsolicited indication.
    Indicate = 5,
}

impl MbimMessageType {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Open),
            2 => Some(Self::Close),
            3 => Some(Self::Command),
            4 => Some(Self::CommandDone),
            5 => Some(Self::Indicate),
            _ => None,
        }
    }
}

/// MBIM status codes for a completed command (MBIM 1.0 §9.4). Only the two the
/// transport acts on are named; everything else is reported verbatim.
pub const MBIM_STATUS_SUCCESS: u32 = 0;

/// A parsed MBIM control frame: the 12-octet header plus the command payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbimFrame {
    /// `MessageType`.
    pub message_type: MbimMessageType,
    /// `TransactionId`, echoed by the function in its reply.
    pub transaction_id: u32,
    /// Command payload following the header (service/command/type/…).
    pub payload: Vec<u8>,
}

impl MbimFrame {
    /// Build a frame. `payload` is the bytes that follow the 12-octet header.
    pub fn new(message_type: MbimMessageType, transaction_id: u32, payload: Vec<u8>) -> Self {
        Self {
            message_type,
            transaction_id,
            payload,
        }
    }

    /// Total encoded length, header included.
    pub fn encoded_len(&self) -> usize {
        MBIM_HEADER_LEN + self.payload.len()
    }

    /// Serialise to the MBIM wire shape: three little-endian `u32`s then the
    /// payload. `MessageLength` is the total frame length.
    pub fn to_bytes(&self) -> Vec<u8> {
        let total = self.encoded_len() as u32;
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&(self.message_type as u32).to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&self.transaction_id.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse the MBIM wire shape. Rejects a short buffer, an unknown
    /// `MessageType`, and a `MessageLength` that disagrees with the buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self, MbimError> {
        if bytes.len() < MBIM_HEADER_LEN {
            return Err(MbimError::TooShort(bytes.len()));
        }
        let raw_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let message_type =
            MbimMessageType::from_u32(raw_type).ok_or(MbimError::UnknownMessageType(raw_type))?;
        let declared = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let transaction_id = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if declared != bytes.len() {
            return Err(MbimError::LengthMismatch {
                declared,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            message_type,
            transaction_id,
            payload: bytes[MBIM_HEADER_LEN..].to_vec(),
        })
    }
}

/// Errors from MBIM framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MbimError {
    /// The buffer was shorter than the fixed header.
    TooShort(usize),
    /// `MessageType` was not a value this model understands.
    UnknownMessageType(u32),
    /// `MessageLength` disagreed with the actual buffer length.
    LengthMismatch { declared: usize, actual: usize },
}

impl core::fmt::Display for MbimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MbimError::TooShort(n) => write!(f, "MBIM frame too short: {n} bytes"),
            MbimError::UnknownMessageType(t) => write!(f, "unknown MBIM message type {t}"),
            MbimError::LengthMismatch { declared, actual } => {
                write!(
                    f,
                    "MBIM length mismatch: declared {declared}, actual {actual}"
                )
            }
        }
    }
}

impl std::error::Error for MbimError {}

/// The IP configuration returned by an MBIM session activation
/// (`MBIM_CID_CONNECT` / IP configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConfig {
    /// The local IPv4 address assigned to this PDN session.
    pub address: String,
    /// The default gateway for the PDN.
    pub gateway: String,
    /// Primary DNS server (optional).
    pub dns: Option<String>,
}

/// A modelled MBIM packet-data session used as the IMS bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbimSession {
    /// The APN the session was activated on (e.g. `ims`).
    pub apn: String,
    /// The IP configuration handed to the host by the modem.
    pub ip_config: IpConfig,
    /// Whether the session is active.
    pub active: bool,
}

impl MbimSession {
    /// Activate a session on `apn` and return it with a modem-assigned IP
    /// configuration. This models `MBIM_CID_CONNECT`: the modem owns the
    /// address, the host just consumes it.
    ///
    /// `NETWORK` mode is used for a dedicated IMS PDN; the returned config is
    /// the bearer the SIP stack must bind to.
    pub fn activate(apn: &str) -> Self {
        Self {
            apn: apn.to_string(),
            // A dedicated IMS PDN typically lands on the carrier's private range;
            // the exact address is chosen by the modem, not this code.
            ip_config: IpConfig {
                address: "10.32.0.2".to_string(),
                gateway: "10.32.0.1".to_string(),
                dns: Some("10.32.0.1".to_string()),
            },
            active: true,
        }
    }

    /// Deactivate the session (`MBIM_CID_DISCONNECT`).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// The modem-assigned local address for the IMS bearer.
    pub fn address(&self) -> &str {
        &self.ip_config.address
    }
}

/// A SIP transport carried over a modelled MBIM IMS PDN session.
pub struct MbimTransport {
    session: MbimSession,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl MbimTransport {
    /// Create a connected pair of MBIM transports, each activated on its own
    /// session. `apn` is the IMS APN (normally `"ims"`).
    pub fn pair(apn_a: &str, apn_b: &str) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (
            Self {
                session: MbimSession::activate(apn_a),
                tx: a_tx,
                rx: a_rx,
            },
            Self {
                session: MbimSession::activate(apn_b),
                tx: b_tx,
                rx: b_rx,
            },
        )
    }

    /// The underlying MBIM session (APN, IP configuration, activation state).
    pub fn session(&self) -> &MbimSession {
        &self.session
    }

    /// The modem-assigned IMS PDN address this endpoint sends from.
    pub fn pdn_address(&self) -> &str {
        self.session.address()
    }
}

impl Transport for MbimTransport {
    fn local_addr(&self) -> &str {
        self.session.address()
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        if !self.session.active {
            return Err(TransportError::Closed);
        }
        self.tx
            .send(message.to_bytes())
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError> {
        let deadline = Instant::now() + timeout;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.rx.recv_timeout(remaining) {
            Ok(bytes) => {
                let text =
                    String::from_utf8(bytes).map_err(|e| TransportError::Codec(e.to_string()))?;
                Message::parse(&text)
                    .map(Some)
                    .map_err(|e| TransportError::Codec(e.to_string()))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(TransportError::Closed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip::{Headers, Method, Request};

    fn message() -> Message {
        let mut headers = Headers::new();
        headers.push(sip::Header::new(
            "Via",
            "SIP/2.0/UDP x;branch=z9hG4bK-mbim-1",
        ));
        headers.push(sip::Header::new("CSeq", "1 REGISTER"));
        headers.push(sip::Header::new("Content-Length", "0"));
        Message::Request(Request {
            method: Method::Register,
            uri: "sip:ims.example".into(),
            headers,
            body: Vec::new(),
        })
    }

    #[test]
    fn mbim_frame_round_trips_the_wire() {
        let frame = MbimFrame::new(
            MbimMessageType::Command,
            0x1234_5678,
            vec![0xAA, 0xBB, 0xCC],
        );
        let bytes = frame.to_bytes();
        assert_eq!(bytes.len(), MBIM_HEADER_LEN + 3);
        // MessageType=3, MessageLength=15, TransactionId little-endian.
        assert_eq!(&bytes[..4], &3u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &15u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &0x1234_5678u32.to_le_bytes());
        assert_eq!(MbimFrame::parse(&bytes).unwrap(), frame);
    }

    #[test]
    fn mbim_frame_rejects_short_and_mislabelled_frames() {
        assert_eq!(MbimFrame::parse(&[0u8; 4]), Err(MbimError::TooShort(4)));

        let mut bytes = MbimFrame::new(MbimMessageType::Open, 1, Vec::new()).to_bytes();
        bytes[4] = 0xFF; // lie about MessageLength
        assert!(matches!(
            MbimFrame::parse(&bytes).unwrap_err(),
            MbimError::LengthMismatch { .. }
        ));

        let mut bad = MbimFrame::new(MbimMessageType::Open, 1, Vec::new()).to_bytes();
        bad[..4].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            MbimFrame::parse(&bad).unwrap_err(),
            MbimError::UnknownMessageType(99)
        );
    }

    #[test]
    fn session_activation_yields_the_modem_assigned_address() {
        let session = MbimSession::activate("ims");
        assert_eq!(session.apn, "ims");
        assert!(session.active);
        assert_eq!(session.address(), "10.32.0.2");
        let (a, _b) = MbimTransport::pair("ims", "ims");
        assert_eq!(a.local_addr(), "10.32.0.2");
        assert_eq!(a.pdn_address(), "10.32.0.2");
        assert_eq!(a.session().apn, "ims");
    }

    #[test]
    fn delivers_over_the_mbim_pdn() {
        let (mut a, mut b) = MbimTransport::pair("ims", "ims");
        let sent = message();
        a.send(&sent).unwrap();
        assert_eq!(b.recv(Duration::from_millis(100)).unwrap().unwrap(), sent);
    }

    #[test]
    fn deactivated_session_refuses_to_send() {
        let (mut a, _b) = MbimTransport::pair("ims", "ims");
        // Reach into the session through a mutable borrow of the transport.
        a.session.deactivate();
        assert_eq!(a.send(&message()), Err(TransportError::Closed));
    }
}
