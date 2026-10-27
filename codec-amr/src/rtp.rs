//! RFC 4867 AMR/AMR-WB RTP payload format — **octet-aligned mode only**.
//!
//! This module is pure Rust and always available. It contains no speech codec,
//! only the packet layout needed by IMS/RTP:
//!
//! ```text
//! +-------------------------------+
//! | CMR (4 bits) | reserved (4)   |  one octet, once per payload
//! +-------------------------------+
//! | ToC | speech data | ToC | ... |  one ToC per frame
//! +-------------------------------+
//! ToC octet: F(1) FT(4) Q(1) P(2)
//! ```
//!
//! * `CMR` — codec mode request (0..=8 for AMR-WB, 15 = no request).
//! * `F` — another frame follows this one.
//! * `FT` — frame type: 0..=8 speech modes, 9 SID, 14 lost, 15 no-data.
//! * `Q` — quality/confidence bit for SID or speech.
//! * `P` — padding bits on the final frame (0..=3).
//!
//! Bandwidth-efficient and the older "storage" format are **not implemented**;
//! [`PayloadMode::BandwidthEfficient`] and [`PayloadMode::Storage`] return
//! [`AmrError::UnsupportedMode`] rather than guessing at bit packing.

#![forbid(unsafe_code)]

/// RTP clock rate for AMR-WB.
pub const CLOCK_RATE: u32 = 16_000;
/// Samples per 20 ms AMR-WB frame.
pub const FRAME_SAMPLES: usize = 320;
/// Largest AMR-WB speech frame (23.85 kbit/s), in octets.
pub const MAX_SPEECH_BYTES: usize = 60;

/// Speech frame sizes in octets for FT 0..=8 (AMR-WB modes).
const SPEECH_BYTES: [usize; 9] = [17, 23, 32, 36, 40, 46, 50, 58, 60];
/// AMR-WB SID frame is 40 bits.
const SID_BYTES: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadMode {
    OctetAligned,
    /// RFC 4867 §3.4. Not implemented: bit-packed ToC/data needs a separate
    /// parser and must not be inferred from an octet-aligned buffer.
    BandwidthEfficient,
    /// Historic storage format; never valid on the wire.
    Storage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// FT 0..=8: one of the nine AMR-WB speech modes.
    Speech { mode: u8 },
    /// FT 9: comfort-noise SID.
    Sid,
    /// FT 15: no data (DTX).
    NoData,
    /// FT 14: speech lost (PLC should run).
    Lost,
    /// FT 10..=13: reserved for AMR-WB.
    Reserved { ft: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ft: u8,
    /// Q bit: speech quality or SID confidence.
    pub quality: bool,
    /// P bits: padding on the final frame (0..=3).
    pub padding: u8,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn speech(mode: u8, data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        if mode > 8 {
            return Err(AmrError::ReservedFrameType(mode));
        }
        let expected = frame_size(mode).unwrap();
        if data.len() != expected {
            return Err(AmrError::FrameSize {
                ft: mode,
                expected,
                got: data.len(),
            });
        }
        Ok(Self {
            ft: mode,
            quality,
            padding: 0,
            data,
        })
    }

    pub fn sid(data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        if data.len() != SID_BYTES {
            return Err(AmrError::FrameSize {
                ft: 9,
                expected: SID_BYTES,
                got: data.len(),
            });
        }
        Ok(Self {
            ft: 9,
            quality,
            padding: 0,
            data,
        })
    }

    pub fn no_data() -> Self {
        Self {
            ft: 15,
            quality: false,
            padding: 0,
            data: Vec::new(),
        }
    }

    pub fn lost() -> Self {
        Self {
            ft: 14,
            quality: false,
            padding: 0,
            data: Vec::new(),
        }
    }

    pub fn kind(&self) -> FrameKind {
        classify_ft(self.ft)
    }

    pub fn is_speech(&self) -> bool {
        matches!(self.kind(), FrameKind::Speech { .. })
    }

    pub fn speech_bits(&self) -> Option<usize> {
        let mode = match self.kind() {
            FrameKind::Speech { mode } => mode,
            _ => return None,
        };
        Some(speech_bits(mode))
    }
}

pub fn classify_ft(ft: u8) -> FrameKind {
    match ft {
        0..=8 => FrameKind::Speech { mode: ft },
        9 => FrameKind::Sid,
        14 => FrameKind::Lost,
        15 => FrameKind::NoData,
        other => FrameKind::Reserved { ft: other },
    }
}

/// Speech bits for AMR-WB mode 0..=8.
pub fn speech_bits(mode: u8) -> usize {
    // 132, 177, 253, 285, 317, 365, 397, 461, 477 bits.
    let bits = [132usize, 177, 253, 285, 317, 365, 397, 461, 477];
    bits.get(mode as usize).copied().unwrap_or(0)
}

/// Octets occupied by a frame's data field (excluding the ToC octet).
pub fn frame_size(ft: u8) -> Option<usize> {
    match ft {
        0..=8 => Some(SPEECH_BYTES[ft as usize]),
        9 => Some(SID_BYTES),
        14 | 15 => Some(0),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Codec mode request, 0..=15; 15 means "no request".
    pub cmr: u8,
    pub frames: Vec<Frame>,
}

impl Payload {
    pub fn new(cmr: u8, frames: Vec<Frame>) -> Self {
        Self {
            cmr: cmr & 0x0f,
            frames,
        }
    }

    pub fn single_speech(mode: u8, data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        Ok(Self {
            cmr: mode,
            frames: vec![Frame::speech(mode, data, quality)?],
        })
    }

    /// Parse the default octet-aligned representation.
    pub fn parse(payload: &[u8]) -> Result<Self, AmrError> {
        Self::parse_mode(payload, PayloadMode::OctetAligned)
    }

    pub fn parse_mode(payload: &[u8], mode: PayloadMode) -> Result<Self, AmrError> {
        match mode {
            PayloadMode::OctetAligned => parse_octet_aligned(payload),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AmrError> {
        self.to_bytes_mode(PayloadMode::OctetAligned)
    }

    pub fn to_bytes_mode(&self, mode: PayloadMode) -> Result<Vec<u8>, AmrError> {
        match mode {
            PayloadMode::OctetAligned => serialize_octet_aligned(self),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    pub fn has_speech(&self) -> bool {
        self.frames.iter().any(Frame::is_speech)
    }

    pub fn speech_modes(&self) -> Vec<u8> {
        self.frames
            .iter()
            .filter_map(|f| match f.kind() {
                FrameKind::Speech { mode } => Some(mode),
                _ => None,
            })
            .collect()
    }
}

fn parse_octet_aligned(payload: &[u8]) -> Result<Payload, AmrError> {
    if payload.is_empty() {
        return Err(AmrError::Empty);
    }
    let cmr = payload[0] >> 4;
    let mut offset = 1;
    let mut frames = Vec::new();
    let mut more = false;

    while offset < payload.len() {
        let toc = payload[offset];
        offset += 1;
        let f = toc & 0x80 != 0;
        let ft = (toc >> 3) & 0x0f;
        let quality = toc & 0x04 != 0;
        let padding = toc & 0x03;

        let size = frame_size(ft).ok_or(AmrError::ReservedFrameType(ft))?;
        if offset + size > payload.len() {
            return Err(AmrError::Truncated {
                ft,
                expected: size,
                available: payload.len() - offset,
            });
        }
        let data = payload[offset..offset + size].to_vec();
        offset += size;
        frames.push(Frame {
            ft,
            quality,
            padding,
            data,
        });
        more = f;
        if !f {
            break;
        }
    }

    if frames.is_empty() {
        return Err(AmrError::Empty);
    }
    if more {
        return Err(AmrError::Truncated {
            ft: frames.last().map(|f| f.ft).unwrap_or(15),
            expected: 1,
            available: 0,
        });
    }
    if offset != payload.len() {
        return Err(AmrError::TrailingBytes(payload.len() - offset));
    }
    Ok(Payload { cmr, frames })
}

fn serialize_octet_aligned(payload: &Payload) -> Result<Vec<u8>, AmrError> {
    if payload.frames.is_empty() {
        return Err(AmrError::Empty);
    }
    if payload.cmr > 15 {
        return Err(AmrError::InvalidCmr(payload.cmr));
    }
    let mut out = Vec::with_capacity(1 + payload.frames.len() * 2 + 64);
    out.push(payload.cmr << 4);
    let last = payload.frames.len() - 1;
    for (i, frame) in payload.frames.iter().enumerate() {
        let expected = frame_size(frame.ft).ok_or(AmrError::ReservedFrameType(frame.ft))?;
        if frame.data.len() != expected {
            return Err(AmrError::FrameSize {
                ft: frame.ft,
                expected,
                got: frame.data.len(),
            });
        }
        if frame.padding > 3 {
            return Err(AmrError::InvalidPadding(frame.padding));
        }
        if frame.padding != 0 && i != last {
            return Err(AmrError::InvalidPadding(frame.padding));
        }
        let f = i != last;
        let toc = (u8::from(f) << 7)
            | ((frame.ft & 0x0f) << 3)
            | (u8::from(frame.quality) << 2)
            | (frame.padding & 0x03);
        out.push(toc);
        out.extend_from_slice(&frame.data);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmrError {
    Empty,
    UnsupportedMode(PayloadMode),
    ReservedFrameType(u8),
    InvalidCmr(u8),
    InvalidPadding(u8),
    FrameSize {
        ft: u8,
        expected: usize,
        got: usize,
    },
    Truncated {
        ft: u8,
        expected: usize,
        available: usize,
    },
    TrailingBytes(usize),
}

impl core::fmt::Display for AmrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AmrError::Empty => f.write_str("empty AMR payload"),
            AmrError::UnsupportedMode(m) => write!(f, "unsupported AMR payload mode: {m:?}"),
            AmrError::ReservedFrameType(ft) => write!(f, "reserved AMR-WB frame type {ft}"),
            AmrError::InvalidCmr(cmr) => write!(f, "invalid CMR {cmr}"),
            AmrError::InvalidPadding(p) => write!(f, "invalid padding {p}"),
            AmrError::FrameSize { ft, expected, got } => {
                write!(f, "frame type {ft} needs {expected} bytes, got {got}")
            }
            AmrError::Truncated {
                ft,
                expected,
                available,
            } => write!(
                f,
                "frame type {ft} truncated: need {expected} bytes, have {available}"
            ),
            AmrError::TrailingBytes(n) => write!(f, "{n} trailing payload bytes"),
        }
    }
}

impl std::error::Error for AmrError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn speech(mode: u8) -> Vec<u8> {
        vec![0xA5; frame_size(mode).unwrap()]
    }

    #[test]
    fn golden_single_frame_octet_aligned() {
        // CMR=8, F=0, FT=8, Q=1, P=2 => 80 46 ...
        let mut payload = Payload::single_speech(8, speech(8), true).unwrap();
        payload.frames[0].padding = 2; // P=2 on the final frame.
        let bytes = payload.to_bytes().unwrap();
        assert_eq!(&bytes[..2], &[0x80, 0x46]);
        assert_eq!(bytes.len(), 2 + MAX_SPEECH_BYTES);
        assert_eq!(Payload::parse(&bytes).unwrap(), payload);
    }

    #[test]
    fn golden_multi_frame_f_bit() {
        // CMR=0, frame 0 (FT=0) with F=1 => 00 80 <17 bytes>;
        // frame 1 (FT=1, last) => 08 <23 bytes>.
        let p = Payload::new(
            0,
            vec![
                Frame::speech(0, speech(0), false).unwrap(),
                Frame::speech(1, speech(1), false).unwrap(),
            ],
        );
        let bytes = p.to_bytes().unwrap();
        assert_eq!(&bytes[..2], &[0x00, 0x80]);
        assert_eq!(bytes[1 + 1 + 17], 0x08);
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.speech_modes(), vec![0, 1]);
    }

    #[test]
    fn sid_no_data_and_lost_classification() {
        let p = Payload::new(
            15,
            vec![
                Frame::sid(vec![0x11; 5], true).unwrap(),
                Frame::no_data(),
                Frame::lost(),
            ],
        );
        let bytes = p.to_bytes().unwrap();
        // ToCs: F=1/FT=9/Q=1 => 0xCC, then 5 SID octets; F=1/FT=15 => 0xFF;
        // F=0/FT=14 => 0x70.
        assert_eq!(bytes[1], 0xCC);
        assert_eq!(bytes[7], 0xF8);
        assert_eq!(bytes[8], 0x70);
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(parsed.frames[0].kind(), FrameKind::Sid);
        assert_eq!(parsed.frames[1].kind(), FrameKind::NoData);
        assert_eq!(parsed.frames[2].kind(), FrameKind::Lost);
        assert!(!parsed.has_speech());
    }

    #[test]
    fn reserved_frame_type_is_rejected() {
        // CMR=0, ToC=F=0 FT=10 => 0x50.
        assert_eq!(
            Payload::parse(&[0x00, 0x50]).unwrap_err(),
            AmrError::ReservedFrameType(10)
        );
    }

    #[test]
    fn bandwidth_efficient_is_explicitly_unsupported() {
        assert_eq!(
            Payload::parse_mode(&[0x00, 0x00], PayloadMode::BandwidthEfficient),
            Err(AmrError::UnsupportedMode(PayloadMode::BandwidthEfficient))
        );
        assert_eq!(
            Payload::parse_mode(&[0x00, 0x00], PayloadMode::Storage),
            Err(AmrError::UnsupportedMode(PayloadMode::Storage))
        );
        let p = Payload::single_speech(0, speech(0), false).unwrap();
        assert_eq!(
            p.to_bytes_mode(PayloadMode::BandwidthEfficient),
            Err(AmrError::UnsupportedMode(PayloadMode::BandwidthEfficient))
        );
    }

    #[test]
    fn truncated_and_trailing_are_rejected() {
        let p = Payload::single_speech(0, speech(0), false).unwrap();
        let bytes = p.to_bytes().unwrap();
        assert!(matches!(
            Payload::parse(&bytes[..bytes.len() - 1]).unwrap_err(),
            AmrError::Truncated { .. }
        ));
        let mut extra = bytes.clone();
        extra.push(0xFF);
        assert!(matches!(
            Payload::parse(&extra).unwrap_err(),
            AmrError::TrailingBytes(1)
        ));
    }

    #[test]
    fn f_bit_on_last_frame_is_truncation() {
        // CMR=0, F=1 FT=15 => 0xF8 with no following ToC.
        assert!(matches!(
            Payload::parse(&[0x00, 0xF8]).unwrap_err(),
            AmrError::Truncated { .. }
        ));
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(Payload::parse(&[]).unwrap_err(), AmrError::Empty);
        assert_eq!(
            Payload::new(0, vec![]).to_bytes().unwrap_err(),
            AmrError::Empty
        );
    }

    #[test]
    fn all_wb_modes_round_trip() {
        for ft in 0..=8u8 {
            let p = Payload::single_speech(ft, speech(ft), ft % 2 == 0).unwrap();
            let bytes = p.to_bytes().unwrap();
            let parsed = Payload::parse(&bytes).unwrap();
            assert_eq!(parsed, p);
            assert_eq!(parsed.frames[0].speech_bits(), Some(speech_bits(ft)));
        }
    }
}
