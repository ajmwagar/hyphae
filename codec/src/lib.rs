//! Narrow codec boundary for the IMS client.
//!
//! The client only ever handles **PCM frames** (`i16`, interleaved, 48 kHz mono
//! in this revision). Whether those frames come from Opus, AMR-WB, EVS, or a
//! device-local vendor codec wrapped outside this tree is invisible here.
//!
//! ## Licensing boundary (binding; see `docs/adr-ims-codec-licensing.md`)
//! * This crate ships the trait and **Opus only** (royalty-free, RFC 6716).
//! * AMR-WB and EVS are **not** implemented here and must not be added to this
//!   tree. They belong in a separate, clearly patent-noticed package behind the
//!   same trait, or behind a device-local retrofit service.
//! * Nothing here knows about SIP, SDP or RTP. Payload types are carried in SDP
//!   by the `ims` crate.

#![forbid(unsafe_code)]

/// 20 ms at 48 kHz, mono. The frame size IMS/Opus uses in this revision.
pub const FRAME_SAMPLES: usize = 960;
/// 48 kHz is the native Opus and IMS clock rate.
pub const CLOCK_RATE: u32 = 48_000;
/// Upper bound for one compressed frame, keeping RTP under a safe MTU.
pub const MAX_FRAME_BYTES: usize = 1_275;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// Output slice cannot hold the encoded/decoded frame.
    BufferTooSmall { need: usize, have: usize },
    /// Input PCM length is not one legal frame.
    BadFrameSize { need: usize, have: usize },
    /// Backend rejected the data.
    Backend(&'static str),
    /// Backend could not be initialised.
    Init(&'static str),
    /// The codec/backend is not compiled in or not provided by the library.
    Unavailable(&'static str),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::BufferTooSmall { need, have } => {
                write!(f, "buffer too small: need {need}, have {have}")
            }
            CodecError::BadFrameSize { need, have } => {
                write!(f, "bad PCM frame size: need {need}, have {have}")
            }
            CodecError::Backend(msg) => write!(f, "codec backend error: {msg}"),
            CodecError::Init(msg) => write!(f, "codec init error: {msg}"),
            CodecError::Unavailable(msg) => write!(f, "codec unavailable: {msg}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// A media codec instance bound to one direction or duplex stream.
///
/// Implementations must be cheap to reset and must not block. A codec service
/// process (retrofit/libhybris backend) is adapted to this trait by the caller;
/// the trait itself stays in-process and object-safe.
pub trait Codec {
    /// Stable short name used in logs and diagnostics (e.g. `"opus"`).
    fn name(&self) -> &'static str;
    /// RTP clock rate in Hz.
    fn clock_rate(&self) -> u32;
    /// Number of PCM samples per frame per channel.
    fn frame_samples(&self) -> usize;
    /// Encode exactly one frame of PCM; returns bytes written.
    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError>;
    /// Decode one packet into PCM; returns samples written.
    fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError>;
}

/// Raw 16-bit little-endian PCM as a "codec".
///
/// This is **not** a carrier codec; it exists so the lab can exercise the media
/// path and the `Codec` trait without any native dependency. Never negotiate it
/// with a real IMS network.
#[derive(Debug, Default)]
pub struct PcmCodec;

impl PcmCodec {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for PcmCodec {
    fn name(&self) -> &'static str {
        "pcm-s16le"
    }

    fn clock_rate(&self) -> u32 {
        CLOCK_RATE
    }

    fn frame_samples(&self) -> usize {
        FRAME_SAMPLES
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        if pcm.len() != FRAME_SAMPLES {
            return Err(CodecError::BadFrameSize {
                need: FRAME_SAMPLES,
                have: pcm.len(),
            });
        }
        let need = pcm.len() * 2;
        if out.len() < need {
            return Err(CodecError::BufferTooSmall {
                need,
                have: out.len(),
            });
        }
        for (chunk, sample) in out.chunks_exact_mut(2).zip(pcm) {
            chunk.copy_from_slice(&sample.to_le_bytes());
        }
        Ok(need)
    }

    fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        if packet.len() % 2 != 0 {
            return Err(CodecError::Backend("odd PCM byte count"));
        }
        let samples = packet.len() / 2;
        if out.len() < samples {
            return Err(CodecError::BufferTooSmall {
                need: samples,
                have: out.len(),
            });
        }
        for (sample, chunk) in out.iter_mut().zip(packet.chunks_exact(2)) {
            *sample = i16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Ok(samples)
    }
}

/// Opus backend (royalty-free). Enabled with `--features opus`.
#[cfg(feature = "opus")]
pub mod opus_codec {
    use super::{Codec, CodecError, CLOCK_RATE, FRAME_SAMPLES};

    pub struct OpusCodec {
        encoder: opus::Encoder,
        decoder: opus::Decoder,
    }

    impl OpusCodec {
        /// 24 kbit/s VoIP mono, 20 ms frames — a reasonable VoLTE lab default.
        pub fn new() -> Result<Self, CodecError> {
            Self::with_bitrate(24_000)
        }

        pub fn with_bitrate(bitrate: i32) -> Result<Self, CodecError> {
            let mut encoder =
                opus::Encoder::new(CLOCK_RATE, opus::Channels::Mono, opus::Application::Voip)
                    .map_err(|_| CodecError::Init("opus encoder"))?;
            encoder
                .set_bitrate(opus::Bitrate::Bits(bitrate))
                .map_err(|_| CodecError::Init("opus bitrate"))?;
            let decoder = opus::Decoder::new(CLOCK_RATE, opus::Channels::Mono)
                .map_err(|_| CodecError::Init("opus decoder"))?;
            Ok(Self { encoder, decoder })
        }
    }

    impl Codec for OpusCodec {
        fn name(&self) -> &'static str {
            "opus"
        }

        fn clock_rate(&self) -> u32 {
            CLOCK_RATE
        }

        fn frame_samples(&self) -> usize {
            FRAME_SAMPLES
        }

        fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
            if pcm.len() != FRAME_SAMPLES {
                return Err(CodecError::BadFrameSize {
                    need: FRAME_SAMPLES,
                    have: pcm.len(),
                });
            }
            self.encoder
                .encode(pcm, out)
                .map_err(|_| CodecError::Backend("opus encode failed"))
        }

        fn decode(&mut self, packet: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
            if out.len() < FRAME_SAMPLES {
                return Err(CodecError::BufferTooSmall {
                    need: FRAME_SAMPLES,
                    have: out.len(),
                });
            }
            self.decoder
                .decode(packet, out, false)
                .map_err(|_| CodecError::Backend("opus decode failed"))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::MAX_FRAME_BYTES;

        #[test]
        fn opus_encode_decode_round_trip() {
            let mut c = OpusCodec::new().unwrap();
            assert_eq!(c.name(), "opus");
            assert_eq!(c.clock_rate(), CLOCK_RATE);
            assert_eq!(c.frame_samples(), FRAME_SAMPLES);
            let pcm = vec![0i16; FRAME_SAMPLES];
            let mut packet = vec![0u8; MAX_FRAME_BYTES];
            let n = c.encode(&pcm, &mut packet).unwrap();
            assert!(n > 0 && n <= MAX_FRAME_BYTES);
            let mut back = vec![0i16; FRAME_SAMPLES];
            let m = c.decode(&packet[..n], &mut back).unwrap();
            assert_eq!(m, FRAME_SAMPLES);
        }
    }
}

#[cfg(feature = "opus")]
pub use opus_codec::OpusCodec;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcm_round_trip() {
        let mut c = PcmCodec::new();
        let pcm: Vec<i16> = (0..FRAME_SAMPLES)
            .map(|i| (i as i16).wrapping_mul(7))
            .collect();
        let mut packet = vec![0u8; FRAME_SAMPLES * 2];
        let n = c.encode(&pcm, &mut packet).unwrap();
        assert_eq!(n, FRAME_SAMPLES * 2);
        let mut back = vec![0i16; FRAME_SAMPLES];
        let m = c.decode(&packet[..n], &mut back).unwrap();
        assert_eq!(m, FRAME_SAMPLES);
        assert_eq!(back, pcm);
    }

    #[test]
    fn rejects_bad_frame_and_small_buffer() {
        let mut c = PcmCodec::new();
        let mut out = [0u8; MAX_FRAME_BYTES];
        assert!(matches!(
            c.encode(&[0i16; 10], &mut out),
            Err(CodecError::BadFrameSize { .. })
        ));
        let mut tiny = [0u8; 4];
        assert!(matches!(
            c.encode(&[0i16; FRAME_SAMPLES], &mut tiny),
            Err(CodecError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn trait_is_object_safe() {
        let c: Box<dyn Codec> = Box::new(PcmCodec::new());
        assert_eq!(c.name(), "pcm-s16le");
        assert_eq!(c.clock_rate(), CLOCK_RATE);
        assert_eq!(c.frame_samples(), FRAME_SAMPLES);
    }
}
