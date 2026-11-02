//! MTK CCCI backend as a **vendor-channel shim** (TRN-002).
//!
//! MediaTek's CCCI (Cross-Core Communication Interface) is the modem↔AP channel
//! exposed on the AP as `/dev/ccci_*` character devices. It is a **vendor**
//! interface: there is no public specification that this tree may implement
//! against, and no vendor source or header may enter the tree.
//!
//! This module therefore ships the *boundary only*:
//!
//! * [`VendorChannel`] — a small trait a downstream, separately-licensed
//!   adapter implements to move opaque frames over the real device.
//! * [`CcciTransport`] — a [`Transport`] that frames SIP messages with a
//!   **private, spec-free** length prefix (defined here, *not* the vendor wire
//!   format) and hands the frame to the channel.
//! * [`MockCcciChannel`] — an in-memory channel pair so the framing and the
//!   `Transport` contract can be tested on the host with no device.
//!
//! The contract this row claims is deliberate and narrow: SIP survives the
//! length-framed vendor-channel boundary unchanged. The vendor's own header
//! layout, ioctls and device numbers are **not** modelled, because modelling
//! them would require copying vendor material.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

use super::{Transport, TransportError};
use sip::Message;
use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

/// Octets in this tree's private channel framing header: a 16-bit big-endian
/// payload length.
///
/// This is **our** framing, chosen so the vendor channel boundary is testable.
/// It is explicitly *not* the CCCI on-wire header, which is vendor material.
pub const CHANNEL_LEN_PREFIX: usize = 2;

/// Largest frame this shim will carry; larger frames are rejected rather than
/// silently truncated.
pub const MAX_CHANNEL_FRAME: usize = 64 * 1024;

/// Errors from the private channel framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The frame is larger than [`MAX_CHANNEL_FRAME`].
    FrameTooLarge(usize),
    /// The buffer is shorter than the length prefix.
    ShortPrefix,
    /// The declared length disagrees with the bytes available.
    LengthMismatch { declared: usize, available: usize },
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChannelError::FrameTooLarge(n) => write!(f, "channel frame too large: {n} bytes"),
            ChannelError::ShortPrefix => f.write_str("channel frame shorter than its prefix"),
            ChannelError::LengthMismatch {
                declared,
                available,
            } => write!(
                f,
                "channel frame length mismatch: declared {declared}, available {available}"
            ),
        }
    }
}

impl std::error::Error for ChannelError {}

/// Frame `payload` with this tree's private 2-octet big-endian length prefix.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, ChannelError> {
    if payload.len() > MAX_CHANNEL_FRAME {
        return Err(ChannelError::FrameTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(CHANNEL_LEN_PREFIX + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parse one length-prefixed frame, returning the payload and the bytes consumed.
pub fn parse_frame(buf: &[u8]) -> Result<(&[u8], usize), ChannelError> {
    if buf.len() < CHANNEL_LEN_PREFIX {
        return Err(ChannelError::ShortPrefix);
    }
    let declared = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let available = buf.len() - CHANNEL_LEN_PREFIX;
    if declared > available {
        return Err(ChannelError::LengthMismatch {
            declared,
            available,
        });
    }
    Ok((
        &buf[CHANNEL_LEN_PREFIX..CHANNEL_LEN_PREFIX + declared],
        declared,
    ))
}

/// The vendor boundary: an opaque, length-framed message channel.
///
/// A downstream adapter implements this over the real `/dev/ccci_*` device.
/// This crate never opens the device itself, so no vendor code is needed here.
pub trait VendorChannel {
    /// Write one complete framed message.
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), TransportError>;
    /// Read one complete framed message, or `None` if nothing arrives in time.
    fn read_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError>;
}

/// An in-memory [`VendorChannel`] pair for host-side tests.
pub struct MockCcciChannel {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl MockCcciChannel {
    /// Create two connected channels.
    pub fn pair() -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel();
        let (b_tx, a_rx) = mpsc::channel();
        (Self { tx: a_tx, rx: a_rx }, Self { tx: b_tx, rx: b_rx })
    }
}

impl VendorChannel for MockCcciChannel {
    fn write_frame(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        self.tx
            .send(frame.to_vec())
            .map_err(|_| TransportError::Closed)
    }

    fn read_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        match self.rx.recv_timeout(timeout) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(TransportError::Closed),
        }
    }
}

/// A SIP [`Transport`] that frames over a [`VendorChannel`].
pub struct CcciTransport<C: VendorChannel> {
    endpoint: String,
    channel: C,
    /// Bytes read from the channel but not yet consumed by a full frame.
    pending: VecDeque<u8>,
}

impl<C: VendorChannel> CcciTransport<C> {
    /// Wrap a vendor channel. `channel_id` names it for `Via`/`Contact`/logs.
    pub fn new(channel_id: &str, channel: C) -> Self {
        Self {
            endpoint: format!("ccci:{channel_id}"),
            channel,
            pending: VecDeque::new(),
        }
    }

    /// The vendor channel, for adapter-specific inspection.
    pub fn channel(&self) -> &C {
        &self.channel
    }

    fn decode_pending(&mut self) -> Result<Option<Message>, TransportError> {
        let buf: Vec<u8> = self.pending.iter().copied().collect();
        match parse_frame(&buf) {
            Ok((payload, consumed)) => {
                let message = Message::parse_bytes(payload)
                    .map_err(|e| TransportError::Codec(e.to_string()))?;
                self.pending.drain(..consumed + CHANNEL_LEN_PREFIX);
                Ok(Some(message))
            }
            // A partial frame: wait for the rest.
            Err(ChannelError::ShortPrefix | ChannelError::LengthMismatch { .. }) => Ok(None),
            Err(e) => Err(TransportError::Codec(e.to_string())),
        }
    }
}

impl<C: VendorChannel> Transport for CcciTransport<C> {
    fn local_addr(&self) -> &str {
        &self.endpoint
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        let framed =
            frame(&message.to_bytes()).map_err(|e| TransportError::Codec(e.to_string()))?;
        self.channel.write_frame(&framed)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError> {
        if let Some(message) = self.decode_pending()? {
            return Ok(Some(message));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match self.channel.read_frame(remaining)? {
                Some(bytes) => {
                    self.pending.extend(bytes);
                    if let Some(message) = self.decode_pending()? {
                        return Ok(Some(message));
                    }
                    // Partial frame: keep reading until the deadline.
                }
                None => return Ok(None),
            }
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
            "SIP/2.0/UDP x;branch=z9hG4bK-ccci-1",
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
    fn framing_round_trips_and_validates() {
        let framed = frame(b"hello").unwrap();
        assert_eq!(&framed[..2], &[0x00, 0x05]);
        let (payload, consumed) = parse_frame(&framed).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(consumed, 5);

        assert_eq!(parse_frame(&[0x00]).unwrap_err(), ChannelError::ShortPrefix);
        assert_eq!(
            parse_frame(&[0x00, 0x09, 0x01]).unwrap_err(),
            ChannelError::LengthMismatch {
                declared: 9,
                available: 1
            }
        );
        let too_big = vec![0u8; MAX_CHANNEL_FRAME + 1];
        assert_eq!(
            frame(&too_big).unwrap_err(),
            ChannelError::FrameTooLarge(MAX_CHANNEL_FRAME + 1)
        );
    }

    #[test]
    fn sip_survives_the_vendor_channel_boundary() {
        let (ca, cb) = MockCcciChannel::pair();
        let mut a = CcciTransport::new("0", ca);
        let mut b = CcciTransport::new("1", cb);
        assert_eq!(a.local_addr(), "ccci:0");
        assert_eq!(b.local_addr(), "ccci:1");

        let sent = message();
        a.send(&sent).unwrap();
        assert_eq!(b.recv(Duration::from_millis(100)).unwrap().unwrap(), sent);
    }

    #[test]
    fn partial_frames_are_reassembled() {
        // Write a frame in two pieces and prove recv() stitches them back.
        let (ca, cb) = MockCcciChannel::pair();
        let mut reader = CcciTransport::new("1", cb);
        let framed = frame(&message().to_bytes()).unwrap();
        let (head, tail) = framed.split_at(3);
        let mut writer = ca;
        writer.write_frame(head).unwrap();
        writer.write_frame(tail).unwrap();
        let got = reader.recv(Duration::from_millis(100)).unwrap().unwrap();
        assert_eq!(got, message());
    }

    #[test]
    fn dropped_channel_is_closed() {
        let (ca, cb) = MockCcciChannel::pair();
        drop(cb);
        let mut a = CcciTransport::new("0", ca);
        assert_eq!(a.send(&message()), Err(TransportError::Closed));
    }

    #[test]
    fn vendor_channel_is_object_safe() {
        // Downstream adapters can be swapped at runtime behind a Box<dyn _>.
        let (ca, _cb) = MockCcciChannel::pair();
        let mut boxed: Box<dyn VendorChannel> = Box::new(ca);
        let framed = frame(b"x").unwrap();
        assert!(boxed.write_frame(&framed).is_ok());
    }
}
