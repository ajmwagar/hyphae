//! IMS media path — RTP/RTCP framing, AMR RTP placement, jitter buffer, PLC.
//!
//! Everything a voice call needs *around* the codec, without touching the
//! patent-encumbered speech codec itself. The codec stays behind
//! [`codec::Codec`]; the AMR payload layout stays in [`codec_amr`]. This crate
//! adds the RFC 3550 transport and the RFC 4867 §9 RTP placement on top.
//!
//! ```text
//!   codec-amr Payload ──▶ amr_rtp ──▶ packet (RTP) ──▶ wire (UDP)
//!   codec-amr Payload ◀── amr_rtp ◀── packet (RTP) ◀── jitter buffer
//!                                                    └─▶ plc (on loss)
//!   rtcp: Sender/Receiver reports for the same SSRC
//! ```
//!
//! ## What is and isn't here
//! * **Is**: RFC 3550 §5.3 header build/parse, RFC 4867 §9 octet-aligned AMR
//!   RTP placement, RTCP SR/RR, a sequence-number jitter buffer with playout
//!   delay and loss detection, and a small packet-loss-concealment helper.
//! * **Isn't**: the AMR-WB/EVS speech codec (that is `codec-amr`/`codec`,
//!   feature-gated), jitter *measurement* QoS loops, and real network I/O (that
//!   is `transport`). RTP runs over whatever datagram path the caller provides.
//!
//! ## Licensing boundary
//! This crate only frames and timestamps bytes; it never decodes speech. It is
//! royalty-free regardless of codec, and stays `#![forbid(unsafe_code)]`.

#![forbid(unsafe_code)]

pub mod amr_rtp;
pub mod audio;
pub mod jitter;
pub mod packet;
pub mod plc;
pub mod rtcp;

use std::fmt;

/// RTP version carried on the wire. RFC 3550 §5.1 fixes this at 2.
pub const RTP_VERSION: u8 = 2;

/// AMR-WB RTP clock rate (16 kHz wideband). RFC 4867 §5.1.
pub const AMR_WB_CLOCK_RATE: u32 = 16_000;
/// Samples per 20 ms AMR-WB frame at 16 kHz.
pub const AMR_WB_FRAME_SAMPLES: usize = 320;
/// Milliseconds per AMR-WB frame (the natural RTP timestamp step).
pub const AMR_WB_FRAME_MS: u64 = 20;
/// Default dynamic payload type for AMR-WB in an SDP offer (`a=rtpmap:97`).
pub const AMR_WB_PAYLOAD_TYPE: u8 = 97;

/// RTCP sender-report packet type. RFC 3550 §6.1.
pub const RTCP_SR: u8 = 200;
/// RTCP receiver-report packet type. RFC 3550 §6.2.
pub const RTCP_RR: u8 = 201;

/// Media-path errors. All are recoverable and caller-defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// A packet/header is shorter than the fixed RTP/RTCP size.
    TooShort { need: usize, have: usize },
    /// The RTP version is not 2.
    BadVersion(u8),
    /// A declared CSRC / extension length cannot fit in the buffer.
    Malformed(&'static str),
    /// An RTCP packet declared a version other than 2.
    BadRtcpVersion(u8),
    /// The payload is not valid for the codec (delegates to `codec-amr`).
    Payload(String),
    /// A jitter-buffer request cannot be satisfied (e.g. empty buffer).
    Empty,
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaError::TooShort { need, have } => {
                write!(f, "media packet too short: need {need} bytes, have {have}")
            }
            MediaError::BadVersion(v) => write!(f, "unsupported RTP version {v} (expected 2)"),
            MediaError::Malformed(s) => write!(f, "malformed media packet: {s}"),
            MediaError::BadRtcpVersion(v) => {
                write!(f, "unsupported RTCP version {v} (expected 2)")
            }
            MediaError::Payload(s) => write!(f, "media payload error: {s}"),
            MediaError::Empty => write!(f, "media buffer empty"),
        }
    }
}

impl std::error::Error for MediaError {}

impl From<codec_amr::rtp::AmrError> for MediaError {
    fn from(e: codec_amr::rtp::AmrError) -> Self {
        MediaError::Payload(e.to_string())
    }
}

/// One RTP timestamp tick in nanoseconds for a given clock rate.
///
/// Useful for playout-delay math without a floating point clock.
#[inline]
pub fn timestamp_to_nanos(clock_rate: u32, ticks: u32) -> u64 {
    (ticks as u64) * 1_000_000_000 / clock_rate as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amr_wb_frame_timestamp_step_is_20ms() {
        // 20 ms at 16 kHz is 320 ticks.
        assert_eq!(AMR_WB_FRAME_SAMPLES, 320);
        assert_eq!(
            timestamp_to_nanos(AMR_WB_CLOCK_RATE, AMR_WB_FRAME_SAMPLES as u32),
            20_000_000
        );
    }
}
