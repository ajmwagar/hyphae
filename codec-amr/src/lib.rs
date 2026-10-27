//! AMR-WB at the edge of the tree.
//!
//! Two independent pieces live here:
//!
//! 1. [`rtp`] — a **pure-Rust RFC 4867** octet-aligned payload codec. This is
//!    IETF specification work, always compiled, no C, no patent surface.
//! 2. [`AmrWbCodec`] — an optional PCM↔AMR-WB backend. Off by default. With
//!    `--features amr-wb` it links the **system** libopencore-amrwb decoder;
//!    with `--features amr-wb-dlopen` it loads it at runtime.
//!
//! ## Unsafe policy
//!
//! The crate defaults to `#![forbid(unsafe_code)]`. Enabling either FFI feature
//! relaxes that to a crate-level exception **solely** for [`ffi`], where every
//! `unsafe` block carries a `SAFETY:` comment. No other module may use unsafe.
//!
//! ## Licensing
//!
//! See `PATENTS.md`. AMR-WB patents are not granted by Apache-2.0. The feature
//! is opt-in and this tree ships no C source, headers, or binaries.

#![cfg_attr(
    not(any(feature = "amr-wb", feature = "amr-wb-dlopen")),
    forbid(unsafe_code)
)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod rtp;

#[cfg(any(feature = "amr-wb", feature = "amr-wb-dlopen"))]
mod ffi;

use codec::{Codec, CodecError};

/// AMR-WB is 16 kHz mono, 20 ms frames.
pub const CLOCK_RATE: u32 = 16_000;
/// 20 ms × 16 kHz.
pub const FRAME_SAMPLES: usize = 320;
/// One AMR-WB speech frame at the highest mode is 60 octets.
pub const MAX_FRAME_BYTES: usize = 60;

/// The PCM↔AMR-WB codec.
///
/// Default build: construction succeeds, media operations return
/// [`CodecError::Unavailable`]. That keeps the public surface identical across
/// feature sets while making the missing backend loud at the call site.
pub struct AmrWbCodec {
    #[cfg(any(feature = "amr-wb", feature = "amr-wb-dlopen"))]
    backend: ffi::Decoder,
}

impl AmrWbCodec {
    /// Create the codec. On an FFI build this initialises the decoder.
    pub fn new() -> Result<Self, CodecError> {
        #[cfg(any(feature = "amr-wb", feature = "amr-wb-dlopen"))]
        {
            Ok(Self {
                backend: ffi::Decoder::new()?,
            })
        }
        #[cfg(not(any(feature = "amr-wb", feature = "amr-wb-dlopen")))]
        {
            Ok(Self {})
        }
    }

    /// Whether a real AMR-WB backend is compiled in.
    pub fn is_available() -> bool {
        cfg!(any(feature = "amr-wb", feature = "amr-wb-dlopen"))
    }
}

impl Default for AmrWbCodec {
    fn default() -> Self {
        Self::new().expect("AMR-WB decoder init failed")
    }
}

impl Codec for AmrWbCodec {
    fn name(&self) -> &'static str {
        "amr-wb"
    }

    fn clock_rate(&self) -> u32 {
        CLOCK_RATE
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn encode(&mut self, _pcm: &[i16], _out: &mut [u8]) -> Result<usize, CodecError> {
        // libopencore-amrwb is a decoder-only package. Encoders are a separate
        // patent/licensing decision and are deliberately not wired here.
        Err(CodecError::Unavailable(
            "AMR-WB encoding is not provided by libopencore-amrwb",
        ))
    }

    fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        #[cfg(any(feature = "amr-wb", feature = "amr-wb-dlopen"))]
        {
            self.backend.decode(packet, out)
        }
        #[cfg(not(any(feature = "amr-wb", feature = "amr-wb-dlopen")))]
        {
            let _ = (packet, out);
            Err(CodecError::Unavailable(
                "AMR-WB support not built: enable features `amr-wb` or `amr-wb-dlopen`",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_surface_exists_in_default_build() {
        let mut c = AmrWbCodec::new().unwrap();
        assert_eq!(c.name(), "amr-wb");
        assert_eq!(c.clock_rate(), 16_000);
        assert_eq!(c.frame_samples(), FRAME_SAMPLES);
        let mut out = [0u8; MAX_FRAME_BYTES];
        let e = c.encode(&[0i16; FRAME_SAMPLES], &mut out).unwrap_err();
        assert!(matches!(e, CodecError::Unavailable(_)));
        #[cfg(not(any(feature = "amr-wb", feature = "amr-wb-dlopen")))]
        {
            let mut pcm = [0i16; FRAME_SAMPLES];
            let e = c.decode(&[], &mut pcm).unwrap_err();
            assert!(matches!(e, CodecError::Unavailable(_)));
        }
    }
}
