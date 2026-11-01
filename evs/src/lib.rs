//! EVS at the edge of the tree — **payload format only**.
//!
//! This crate is the pure-Rust, always-compiled RTP payload format for the
//! 3GPP Enhanced Voice Services (EVS) codec, following **TS 26.445 appendix A**
//! *Header-Full* format. It is the EVS analogue of the RFC 4867 module in
//! [`codec_amr`]: packet layout and frame classification for IMS/RTP, and
//! nothing else.
//!
//! [`rtp`] contains:
//! * the CMR byte (`H=1`, `T`, `D`) and its [`rtp::Cmr`] table,
//! * the ToC byte (`H=0`, `F`, `FT`),
//! * both EVS frame tables (Primary and AMR-WB IO),
//! * speech / SID / SPEECH_LOST / NO_DATA classification,
//! * single- and multi-frame serialise/parse round-trips with frame-size
//!   validation.
//!
//! ## What is deliberately not here
//! * **No speech codec.** This crate never encodes or decodes audio; it only
//!   lays out packets. There is no C, and the crate is `#![forbid(unsafe_code)]`.
//! * **Header-Compact, storage and multi-channel are rejected.** The
//!   patent-encumbered variants are returned as [`rtp::EvsError::Unsupported`]
//!   rather than guessed at (mirroring how `codec-amr` rejects RFC 4867
//!   bandwidth-efficient mode). See [`rtp::PayloadFormat`] and `PATENTS.md`.
//!
//! ## Licensing
//!
//! See `PATENTS.md`. EVS is in a patent pool (Via LA / Fraunhofer and others);
//! the Apache/GPL text of this tree does not grant them. The payload-format
//! module is public 3GPP specification work and carries no codec
//! implementation, but distributors still owe pool rights for any EVS use.

#![forbid(unsafe_code)]

pub mod rtp;

use std::fmt;

/// EVS RTP clock rate. TS 26.445 §5 fixes the EVS RTP payload at 48 kHz.
pub const CLOCK_RATE: u32 = 48_000;
/// Samples per 20 ms EVS frame at 48 kHz (the native EVS superframe clock).
pub const FRAME_SAMPLES: usize = 960;
/// One EVS Primary speech frame at 128 kbps is the largest defined frame:
/// 128 kbit/s × 20 ms = 320 octets.
pub const MAX_SPEECH_BYTES: usize = 320;

/// Error type for the EVS payload format.
///
/// These errors are about the *packet layout* only — unknown frame types,
/// wrong frame sizes, truncation, trailing bytes, and unsupported container
/// formats. They never describe speech-codec failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvsError {
    /// The payload had no CMR byte / no frames.
    Empty,
    /// A frame type is reserved or not defined for the chosen format.
    ReservedFrameType(u8),
    /// A frame's data length does not match its table-defined size.
    FrameSize {
        /// The offending frame type.
        ft: u8,
        /// Bytes required by the EVS table.
        expected: usize,
        /// Bytes actually present.
        got: usize,
    },
    /// An AMR-WB IO SID frame (`FT 25`) is missing its mandatory MSB=1 marker.
    BadSidMarker,
    /// The payload was cut short before a frame's data completed.
    Truncated {
        /// The offending frame type.
        ft: u8,
        /// Bytes required by the EVS table.
        expected: usize,
        /// Bytes still available.
        available: usize,
    },
    /// Bytes remained after the final (F=0) frame.
    TrailingBytes(usize),
    /// A container/format that this crate does not implement was requested.
    ///
    /// Returned for the Header-Compact format, the storage format, and
    /// multi-channel payloads, which need bit-packing or channel interleaving
    /// that must not be inferred from a Header-Full buffer.
    Unsupported,
}

impl fmt::Display for EvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvsError::Empty => f.write_str("empty EVS payload"),
            EvsError::ReservedFrameType(ft) => write!(f, "reserved EVS frame type {ft}"),
            EvsError::FrameSize { ft, expected, got } => {
                write!(f, "frame type {ft} needs {expected} bytes, got {got}")
            }
            EvsError::BadSidMarker => {
                f.write_str("AMR-WB IO SID frame missing its MSB=1 marker bit")
            }
            EvsError::Truncated {
                ft,
                expected,
                available,
            } => write!(
                f,
                "frame type {ft} truncated: need {expected} bytes, have {available}"
            ),
            EvsError::TrailingBytes(n) => write!(f, "{n} trailing payload bytes"),
            EvsError::Unsupported => {
                f.write_str("unsupported EVS payload format (compact/storage/multi-channel)")
            }
        }
    }
}

impl std::error::Error for EvsError {}
