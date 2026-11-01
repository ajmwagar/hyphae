//! IPsec ESP encapsulation for the IMS security mechanism (SEC-002).
//!
//! RFC 4303 defines the ESP transport-format frame. This module models that
//! wire shape and round-trips an inner packet so the IMS security association's
//! encapsulation can be exercised without a kernel SA:
//!
//! ```text
//!   +--------+--------+------+----------------+------+--------+----------+
//!   |  SPI   |  Seq   | IV   |   payload      | pad  | PadLen | NextHdr  |
//!   | 4 octets| 4 octets| 4   |  (inner packet) | 0..3 |  1     |  1       |
//!   +--------+--------+------+----------------+------+--------+----------+
//! ```
//!
//! The frame uses a zero IV (null encryption) and no integrity check value, so
//! the payload round-trips verbatim; that keeps the encapsulation shape under
//! test while the real crypto stays behind the stub. The IKEv2 SA negotiation
//! and key derivation are a documented stub pending the network layer.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

/// ESP header/trailer sizes for this lab frame.
pub const SPI_LEN: usize = 4;
pub const SEQ_LEN: usize = 4;
pub const IV_LEN: usize = 4;
pub const PAD_LEN_LEN: usize = 1;
pub const NEXT_HDR_LEN: usize = 1;

/// Default `Next Header` for SIP over UDP: UDP (17).
pub const NEXT_HDR_UDP: u8 = 17;

/// Errors from ESP (de)capsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EspError {
    /// The frame was shorter than the fixed header + trailer.
    TooShort(usize),
    /// The declared pad length overran the frame.
    BadPadLength { total: usize, pad: u8 },
}

impl core::fmt::Display for EspError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EspError::TooShort(n) => write!(f, "ESP frame too short: {n} bytes"),
            EspError::BadPadLength { total, pad } => {
                write!(f, "ESP pad length {pad} overruns {total}-byte frame")
            }
        }
    }
}

impl std::error::Error for EspError {}

/// A fixed-SPI, incrementing-sequence ESP encapsulator bound to one SA.
#[derive(Debug, Clone)]
pub struct EspEncapsulator {
    /// Security Parameter Index — identifies the SA to the peer.
    pub spi: u32,
    /// Sequence number, incremented per packet (RFC 4303 §2.3).
    pub seq: u32,
}

impl EspEncapsulator {
    pub fn new(spi: u32) -> Self {
        Self { spi, seq: 0 }
    }

    /// Wrap `inner` in an ESP transport frame and advance the sequence number.
    pub fn encapsulate(&mut self, inner: &[u8], next_hdr: u8) -> Vec<u8> {
        let mut frame = Vec::with_capacity(SPI_LEN + SEQ_LEN + IV_LEN + inner.len() + 2);
        frame.extend_from_slice(&self.spi.to_be_bytes());
        frame.extend_from_slice(&self.seq.to_be_bytes());
        frame.extend_from_slice(&[0u8; IV_LEN]); // null encryption IV
        frame.extend_from_slice(inner);
        // No padding for the lab frame; pad length is the count of pad octets.
        frame.push(0u8); // PadLen
        frame.push(next_hdr);
        self.seq = self.seq.wrapping_add(1);
        frame
    }

    /// Recover the SPI, sequence number and inner packet from a frame produced
    /// by [`EspEncapsulator::encapsulate`] (or any compatible ESP frame).
    pub fn decapsulate(frame: &[u8]) -> Result<(u32, u32, Vec<u8>, u8), EspError> {
        let header = SPI_LEN + SEQ_LEN + IV_LEN;
        if frame.len() < header + PAD_LEN_LEN + NEXT_HDR_LEN {
            return Err(EspError::TooShort(frame.len()));
        }
        let spi = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        let seq = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let pad = frame[frame.len() - 2];
        let next_hdr = frame[frame.len() - 1];
        let payload_end = frame
            .len()
            .checked_sub(PAD_LEN_LEN + NEXT_HDR_LEN + pad as usize)
            .ok_or(EspError::BadPadLength {
                total: frame.len(),
                pad,
            })?;
        if payload_end < header {
            return Err(EspError::BadPadLength {
                total: frame.len(),
                pad,
            });
        }
        Ok((spi, seq, frame[header..payload_end].to_vec(), next_hdr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_inner_packet() {
        let mut esp = EspEncapsulator::new(0x20000);
        let inner = b"SIP/2.0 request bytes";
        let frame = esp.encapsulate(inner, NEXT_HDR_UDP);
        let (spi, seq, recovered, next_hdr) = EspEncapsulator::decapsulate(&frame).unwrap();
        assert_eq!(spi, 0x20000);
        assert_eq!(seq, 0);
        assert_eq!(recovered, inner);
        assert_eq!(next_hdr, NEXT_HDR_UDP);
    }

    #[test]
    fn sequence_advances_per_packet() {
        let mut esp = EspEncapsulator::new(1);
        let a = esp.encapsulate(b"one", NEXT_HDR_UDP);
        let b = esp.encapsulate(b"two", NEXT_HDR_UDP);
        let (_, seq_a, _, _) = EspEncapsulator::decapsulate(&a).unwrap();
        let (_, seq_b, recovered_b, _) = EspEncapsulator::decapsulate(&b).unwrap();
        assert_eq!(seq_a, 0);
        assert_eq!(seq_b, 1);
        assert_eq!(recovered_b, b"two");
    }

    #[test]
    fn rejects_truncated_frame() {
        assert_eq!(
            EspEncapsulator::decapsulate(&[0, 1, 2]),
            Err(EspError::TooShort(3))
        );
    }
}
