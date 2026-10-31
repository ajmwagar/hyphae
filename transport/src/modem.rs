//! AT/QMI modem-managed IMS PDN transport (TRN-001).
//!
//! On a real device the IMS voice path rides a modem-managed PDN: the modem
//! opens the `ims` APN data call (QMI `GetDataLoadingIPv4Address`, or AT
//! `+CGPADDR`) and hands the stack the PDN address, after which SIP is sent
//! over that bearer. This host-side implementation models that **contract**
//! faithfully:
//!
//! * the local endpoint is the **modem-assigned** PDN address, not a hard-coded
//!   one — the whole point of a modem-managed IMS PDN, and
//! * messages traverse a serialised loopback so the state machine is exercised
//!   over the real [`sip`] wire codec.
//!
//! The AT/QMI byte-level I/O is a documented stub; no modem device is required
//! for the gate.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

use super::{Transport, TransportError};
use sip::Message;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

/// A SIP transport backed by a (modelled) modem IMS PDN.
pub struct ModemTransport {
    /// The modem-assigned IMS PDN address (the `ims` APN bearer's local addr).
    local_addr: String,
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl ModemTransport {
    /// Create a connected pair whose local addresses are the modem-assigned IMS
    /// PDN addresses. `None` entries fall back to a conservative private-range
    /// placeholder so a test can omit them.
    pub fn pair(pdn_a: Option<&str>, pdn_b: Option<&str>) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (
            Self {
                local_addr: pdn_a.unwrap_or("10.0.0.2").into(),
                tx: a_tx,
                rx: a_rx,
            },
            Self {
                local_addr: pdn_b.unwrap_or("10.0.0.3").into(),
                tx: b_tx,
                rx: b_rx,
            },
        )
    }

    /// The modem-assigned IMS PDN address this endpoint sends from.
    pub fn pdn_address(&self) -> &str {
        &self.local_addr
    }
}

impl Transport for ModemTransport {
    fn local_addr(&self) -> &str {
        &self.local_addr
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        self.tx
            .send(message.to_bytes())
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError> {
        let deadline = std::time::Instant::now() + timeout;
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
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
            "SIP/2.0/UDP x;branch=z9hG4bK-modem-1",
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
    fn local_addr_is_the_modem_pdn_address() {
        let (a, _b) = ModemTransport::pair(Some("10.17.0.5"), Some("10.17.0.6"));
        assert_eq!(a.local_addr(), "10.17.0.5");
        assert_eq!(a.pdn_address(), "10.17.0.5");
        // A missing PDN report falls back to a placeholder, not a panic.
        let (a, _) = ModemTransport::pair(None, None);
        assert!(a.local_addr().starts_with("10.0.0."));
    }

    #[test]
    fn delivers_over_the_pdn_loopback() {
        let (mut a, mut b) = ModemTransport::pair(Some("10.17.0.5"), Some("10.17.0.6"));
        let sent = message();
        a.send(&sent).unwrap();
        assert_eq!(b.recv(Duration::from_millis(100)).unwrap().unwrap(), sent);
        assert_eq!(b.local_addr(), "10.17.0.6");
    }
}
