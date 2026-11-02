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
/// RTP clock rate for AMR-NB (8 kHz).
pub const CLOCK_RATE_NB: u32 = 8_000;
/// Samples per 20 ms AMR-NB frame.
pub const FRAME_SAMPLES_NB: usize = 160;
/// Samples per 20 ms AMR-WB frame.
pub const FRAME_SAMPLES: usize = 320;

/// Which AMR variant a payload belongs to.
///
/// The two differ in more than sample rate: the frame-type numbering is
/// different, which is the trap. In **AMR-NB** FT 0..=7 are speech and **FT 8 is
/// SID**; in **AMR-WB** FT 0..=8 are speech and **FT 9 is SID**. An FT 8 frame
/// is a 12.2 kbit/s speech frame in one and a comfort-noise descriptor in the
/// other, so a payload cannot be interpreted without knowing its band.
///
/// Tables: TS 26.101 §4 (NB frame format), TS 26.201 (WB), summarised in
/// RFC 4867 Table 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    /// AMR narrowband, 8 kHz, 160 samples per 20 ms frame.
    Nb,
    /// AMR wideband, 16 kHz, 320 samples per 20 ms frame.
    Wb,
}

impl Band {
    /// RTP clock rate in Hz.
    pub fn clock_rate(self) -> u32 {
        match self {
            Band::Nb => 8_000,
            Band::Wb => 16_000,
        }
    }

    /// PCM samples per 20 ms frame, per channel.
    pub fn frame_samples(self) -> usize {
        match self {
            Band::Nb => 160,
            Band::Wb => 320,
        }
    }

    /// Largest speech frame in octets (12.2 kbit/s for NB, 23.85 for WB).
    pub fn max_speech_bytes(self) -> usize {
        match self {
            Band::Nb => 31,
            Band::Wb => 60,
        }
    }

    /// The speech frame types of this band, as a contiguous range.
    fn speech_fts(self) -> core::ops::RangeInclusive<u8> {
        match self {
            Band::Nb => 0..=7,
            Band::Wb => 0..=8,
        }
    }

    /// The frame type that carries SID (comfort noise).
    pub fn sid_ft(self) -> u8 {
        match self {
            Band::Nb => 8,
            Band::Wb => 9,
        }
    }

    fn speech_bytes_table(self) -> &'static [usize] {
        match self {
            // 95, 103, 118, 134, 148, 159, 204, 244 bits.
            Band::Nb => &[12, 13, 15, 17, 19, 20, 26, 31],
            // 132..477 bits.
            Band::Wb => &[17, 23, 32, 36, 40, 46, 50, 58, 60],
        }
    }

    fn speech_bits_table(self) -> &'static [usize] {
        match self {
            Band::Nb => &[95, 103, 118, 134, 148, 159, 204, 244],
            Band::Wb => &[132, 177, 253, 285, 317, 365, 397, 461, 477],
        }
    }

    /// Octets of a frame's data field, excluding the ToC octet.
    pub fn frame_size(self, ft: u8) -> Option<usize> {
        let table = self.speech_bytes_table();
        if self.speech_fts().contains(&ft) {
            return table.get(ft as usize).copied();
        }
        if ft == self.sid_ft() {
            // Both bands: a SID frame is 39 (NB) or 40 (WB) bits, which fits
            // in five octets either way.
            return Some(5);
        }
        match ft {
            14 | 15 => Some(0),
            _ => None,
        }
    }

    /// Speech bits of a mode, or 0 for anything that is not speech.
    pub fn speech_bits(self, mode: u8) -> usize {
        if !self.speech_fts().contains(&mode) {
            return 0;
        }
        self.speech_bits_table()
            .get(mode as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Classify a frame type within this band.
    pub fn classify(self, ft: u8) -> FrameKind {
        if self.speech_fts().contains(&ft) {
            return FrameKind::Speech { mode: ft };
        }
        if ft == self.sid_ft() {
            return FrameKind::Sid;
        }
        match ft {
            14 => FrameKind::Lost,
            15 => FrameKind::NoData,
            other => FrameKind::Reserved { ft: other },
        }
    }
}
/// Largest AMR-WB speech frame (23.85 kbit/s), in octets.
pub const MAX_SPEECH_BYTES: usize = 60;

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
    /// A speech frame in `band`.
    pub fn speech_in(band: Band, mode: u8, data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        let Some(expected) = band.frame_size(mode) else {
            return Err(AmrError::ReservedFrameType(mode));
        };
        if !matches!(band.classify(mode), FrameKind::Speech { .. }) {
            return Err(AmrError::ReservedFrameType(mode));
        }
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

    /// The AMR-WB speech constructor, kept for the existing callers.
    pub fn speech(mode: u8, data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        Self::speech_in(Band::Wb, mode, data, quality)
    }

    /// A SID frame in `band` (FT 8 in AMR-NB, FT 9 in AMR-WB).
    pub fn sid_in(band: Band, data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        let ft = band.sid_ft();
        let Some(expected) = band.frame_size(ft) else {
            return Err(AmrError::ReservedFrameType(ft));
        };
        if data.len() != expected {
            return Err(AmrError::FrameSize {
                ft,
                expected,
                got: data.len(),
            });
        }
        Ok(Self {
            ft,
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

    /// The AMR-WB SID constructor, kept for the existing callers.
    pub fn sid(data: Vec<u8>, quality: bool) -> Result<Self, AmrError> {
        Self::sid_in(Band::Wb, data, quality)
    }

    /// Classify this frame within `band`.
    pub fn kind_in(&self, band: Band) -> FrameKind {
        band.classify(self.ft)
    }

    /// Classify this frame as AMR-WB.
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

/// Classify a frame type as AMR-WB. AMR-NB callers must use
/// [`Band::classify`], because FT 8 is SID in NB and speech in WB.
pub fn classify_ft(ft: u8) -> FrameKind {
    Band::Wb.classify(ft)
}

/// Speech bits for an AMR-WB mode.
pub fn speech_bits(mode: u8) -> usize {
    Band::Wb.speech_bits(mode)
}

/// Octets of an AMR-WB frame's data field (excluding the ToC octet).
pub fn frame_size(ft: u8) -> Option<usize> {
    Band::Wb.frame_size(ft)
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

    /// Parse the default octet-aligned representation as AMR-WB.
    pub fn parse(payload: &[u8]) -> Result<Self, AmrError> {
        Self::parse_mode(payload, PayloadMode::OctetAligned)
    }

    /// Parse an octet-aligned payload in `band`, which decides how the frame
    /// types are read: FT 8 is SID in AMR-NB and speech in AMR-WB.
    pub fn parse_in(band: Band, payload: &[u8]) -> Result<Self, AmrError> {
        Self::parse_mode_in(band, payload, PayloadMode::OctetAligned)
    }

    /// Parse `payload` in `band` using `mode`.
    pub fn parse_mode_in(band: Band, payload: &[u8], mode: PayloadMode) -> Result<Self, AmrError> {
        match mode {
            PayloadMode::OctetAligned => parse_octet_aligned_in(band, payload),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    pub fn parse_mode(payload: &[u8], mode: PayloadMode) -> Result<Self, AmrError> {
        match mode {
            PayloadMode::OctetAligned => parse_octet_aligned_in(Band::Wb, payload),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    /// Serialise as AMR-WB.
    pub fn to_bytes(&self) -> Result<Vec<u8>, AmrError> {
        self.to_bytes_mode(PayloadMode::OctetAligned)
    }

    /// Serialise in `band`.
    pub fn to_bytes_in(&self, band: Band) -> Result<Vec<u8>, AmrError> {
        self.to_bytes_mode_in(band, PayloadMode::OctetAligned)
    }

    /// Serialise in `band` using `mode`.
    pub fn to_bytes_mode_in(&self, band: Band, mode: PayloadMode) -> Result<Vec<u8>, AmrError> {
        match mode {
            PayloadMode::OctetAligned => serialize_octet_aligned(band, self),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    pub fn to_bytes_mode(&self, mode: PayloadMode) -> Result<Vec<u8>, AmrError> {
        match mode {
            PayloadMode::OctetAligned => serialize_octet_aligned(Band::Wb, self),
            PayloadMode::BandwidthEfficient | PayloadMode::Storage => {
                Err(AmrError::UnsupportedMode(mode))
            }
        }
    }

    /// Whether any frame is speech, read as AMR-WB.
    pub fn has_speech(&self) -> bool {
        self.frames.iter().any(Frame::is_speech)
    }

    /// Whether any frame is speech in `band`.
    pub fn has_speech_in(&self, band: Band) -> bool {
        self.frames
            .iter()
            .any(|f| matches!(f.kind_in(band), FrameKind::Speech { .. }))
    }

    /// The speech modes present, read as AMR-WB.
    pub fn speech_modes(&self) -> Vec<u8> {
        self.speech_modes_in(Band::Wb)
    }

    /// The speech modes present in `band`. Narrowband FT 8 is SID, so it is
    /// excluded rather than reported as a 12.2 kbit/s frame.
    pub fn speech_modes_in(&self, band: Band) -> Vec<u8> {
        self.frames
            .iter()
            .filter_map(|f| match f.kind_in(band) {
                FrameKind::Speech { mode } => Some(mode),
                _ => None,
            })
            .collect()
    }
}

fn parse_octet_aligned_in(band: Band, payload: &[u8]) -> Result<Payload, AmrError> {
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

        let size = band.frame_size(ft).ok_or(AmrError::ReservedFrameType(ft))?;
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

fn serialize_octet_aligned(band: Band, payload: &Payload) -> Result<Vec<u8>, AmrError> {
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
        let expected = band
            .frame_size(frame.ft)
            .ok_or(AmrError::ReservedFrameType(frame.ft))?;
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

#[cfg(test)]
mod nb_tests {
    use super::*;

    /// RFC 4867 Table 1: AMR-NB frame sizes in octets for FT 0..=8.
    #[test]
    fn narrowband_frame_sizes_match_rfc_4867() {
        let expected = [12usize, 13, 15, 17, 19, 20, 26, 31];
        for (ft, size) in expected.iter().enumerate() {
            assert_eq!(Band::Nb.frame_size(ft as u8), Some(*size), "AMR-NB FT {ft}");
        }
        // FT 8 is SID in narrowband, not a 12.2 kbit/s speech mode.
        assert_eq!(Band::Nb.frame_size(8), Some(5));
        assert_eq!(Band::Nb.classify(8), FrameKind::Sid);
        assert_eq!(Band::Nb.sid_ft(), 8);
    }

    /// The trap: the same FT means different things in the two bands.
    #[test]
    fn frame_type_eight_differs_between_bands() {
        assert_eq!(Band::Nb.classify(8), FrameKind::Sid);
        assert_eq!(Band::Wb.classify(8), FrameKind::Speech { mode: 8 });
        assert_eq!(Band::Wb.classify(9), FrameKind::Sid);
        // FT 9 is reserved in narrowband.
        assert_eq!(Band::Nb.classify(9), FrameKind::Reserved { ft: 9 });
        assert_eq!(Band::Nb.frame_size(9), None);
    }

    #[test]
    fn narrowband_speech_bits_match_the_specification() {
        // 4.75, 5.15, 5.90, 6.70, 7.40, 7.95, 10.2 and 12.2 kbit/s.
        let bits = [95usize, 103, 118, 134, 148, 159, 204, 244];
        for (mode, want) in bits.iter().enumerate() {
            assert_eq!(Band::Nb.speech_bits(mode as u8), *want);
        }
        assert_eq!(Band::Nb.speech_bits(8), 0, "FT 8 is SID, not speech");
    }

    #[test]
    fn clock_rate_and_frame_size_follow_the_band() {
        assert_eq!(Band::Nb.clock_rate(), 8_000);
        assert_eq!(Band::Nb.frame_samples(), 160);
        assert_eq!(CLOCK_RATE_NB, 8_000);
        assert_eq!(FRAME_SAMPLES_NB, 160);
        assert_eq!(Band::Wb.clock_rate(), CLOCK_RATE);
        assert_eq!(Band::Wb.frame_samples(), FRAME_SAMPLES);
    }

    #[test]
    fn a_narrowband_payload_round_trips() {
        let speech = Frame::speech_in(Band::Nb, 7, vec![0x5A; 31], true).unwrap();
        let sid = Frame::sid_in(Band::Nb, vec![0x00; 5], true).unwrap();
        assert_eq!(sid.ft, 8, "narrowband SID is FT 8");
        let payload = Payload::new(7, vec![speech.clone(), sid.clone()]);

        let bytes = payload.to_bytes_in(Band::Nb).unwrap();
        // CMR octet, then one ToC octet per frame plus their data.
        assert_eq!(bytes.len(), 1 + 1 + 31 + 1 + 5);
        assert_eq!(bytes[0] >> 4, 7);

        let parsed = Payload::parse_in(Band::Nb, &bytes).unwrap();
        assert_eq!(parsed.frames.len(), 2);
        assert_eq!(parsed.frames[0], speech);
        assert_eq!(parsed.frames[1], sid);
        assert_eq!(parsed.speech_modes_in(Band::Nb), vec![7]);
        assert!(parsed.has_speech_in(Band::Nb));
    }

    /// The same octets read in the other band are a different conversation,
    /// which is why the band has to come from the SDP and not from the payload.
    #[test]
    fn the_same_bytes_parse_differently_in_each_band() {
        // FT 8 with 31 octets of data is a valid AMR-WB 23.85 kbit/s frame and
        // a malformed AMR-NB SID (which must be 5 octets).
        let mut bytes = vec![0x00u8];
        bytes.push(8 << 3);
        // AMR-WB FT 8 is the 23.85 kbit/s mode: 60 octets.
        bytes.extend_from_slice(&[0u8; 60]);

        assert!(Payload::parse_in(Band::Wb, &bytes).is_ok());
        // In narrowband FT 8 is SID: five octets, and the rest is trailing.
        assert!(Payload::parse_in(Band::Nb, &bytes).is_err());
    }
}
