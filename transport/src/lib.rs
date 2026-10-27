//! SIP transport boundary.
//!
//! The IMS state machine never touches a socket or a modem directly. It calls a
//! `Transport`, which serialises a [`sip::Message`] onto whatever path the
//! platform provides:
//!
//! ```text
//!   ims state machine
//!         │  sip::Message
//!         ▼
//!   Transport trait ── MockTransport      (tests, no modem)
//!                   ── UDP/TCP adapter    (std::net, later)
//!                   ── AT/QMI adapter     (modem-managed IMS PDN)
//!                   ── MTK CCCI adapter   (later; vendor channel, spec-free shim)
//! ```
//!
//! This crate is std-only and synchronous on purpose. Async runtimes are a
//! later decision, made once the protocol state machine is trusted.

#![forbid(unsafe_code)]

pub mod net;

use sip::Message;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The peer or the local side has gone away.
    Closed,
    /// Wire encoding/decoding failed.
    Codec(String),
    /// The platform adapter rejected the message.
    Rejected(String),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::Closed => f.write_str("transport closed"),
            TransportError::Codec(s) => write!(f, "transport codec error: {s}"),
            TransportError::Rejected(s) => write!(f, "transport rejected message: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A bidirectional, message-oriented SIP transport.
pub trait Transport {
    /// Human-readable local endpoint, useful in Via/Contact generation and logs.
    fn local_addr(&self) -> &str;
    /// Send one complete SIP message.
    fn send(&mut self, message: &Message) -> Result<(), TransportError>;
    /// Receive one message, waiting at most `timeout`.
    ///
    /// `Ok(None)` means "nothing arrived in time", not an error.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError>;
}

/// In-memory transport pair. `a.send()` is delivered to `b.recv()` and vice versa.
///
/// Messages are serialised and re-parsed on the way through, so tests exercise
/// the real wire codec rather than sharing Rust values.
pub struct MockTransport {
    endpoint: String,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl MockTransport {
    /// Create two connected endpoints, A and B.
    pub fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (
            Self {
                endpoint: "mock-a:5060".into(),
                tx: a_tx,
                rx: a_rx,
            },
            Self {
                endpoint: "mock-b:5060".into(),
                tx: b_tx,
                rx: b_rx,
            },
        )
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Transport for MockTransport {
    fn local_addr(&self) -> &str {
        &self.endpoint
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
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

    fn register() -> Message {
        let mut headers = Headers::new();
        headers.push(sip::Header::new(
            "Via",
            "SIP/2.0/UDP mock-a:5060;branch=z9hG4bK-mock-1",
        ));
        headers.push(sip::Header::new("Max-Forwards", "70"));
        headers.push(sip::Header::new(
            "From",
            "<sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org>;tag=t1",
        ));
        headers.push(sip::Header::new(
            "To",
            "<sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org>",
        ));
        headers.push(sip::Header::new("Call-ID", "mock-call-1"));
        headers.push(sip::Header::new("CSeq", "1 REGISTER"));
        headers.push(sip::Header::new("Content-Length", "0"));
        Message::Request(Request {
            method: Method::Register,
            uri: "sip:ims.mnc015.mcc234.3gppnetwork.org".into(),
            headers,
            body: Vec::new(),
        })
    }

    #[test]
    fn mock_delivers_after_wire_round_trip() {
        let (mut a, mut b) = MockTransport::pair();
        let sent = register();
        a.send(&sent).unwrap();
        let got = b.recv(Duration::from_millis(100)).unwrap().unwrap();
        assert_eq!(got, sent);
    }

    #[test]
    fn recv_times_out_without_error() {
        let (_a, mut b) = MockTransport::pair();
        assert_eq!(b.recv(Duration::from_millis(1)).unwrap(), None);
    }

    #[test]
    fn dropped_peer_is_closed() {
        let (mut a, b) = MockTransport::pair();
        drop(b);
        assert_eq!(a.send(&register()), Err(TransportError::Closed));
    }
}
