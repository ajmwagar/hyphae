//! 3GPP TS 26.445 appendix A — **Header-Full** EVS RTP payload format.
//!
//! This module is pure Rust and always available. It contains no speech codec,
//! only the packet layout needed by IMS/RTP:
//!
//! ```text
//! +-------------------------------+
//! | CMR (8 bits)                   |  one octet, once per payload
//! +-------------------------------+
//! | ToC | data | ToC | data | ... |  one ToC + data per frame
//! +-------------------------------+
//! CMR octet:  H(1) T(3) D(4)     H=1
//! ToC octet:  H(1) F(1) FT(6)    H=0
//! ```
//!
//! * `CMR` — codec mode request. `H=1`; `T` selects the mode set (NB/WB/FB/IO),
//!   `D` selects the rate within it (or `15` = no request).
//! * `F` — another frame follows this one.
//! * `FT` — frame type: speech rate index, SID, SPEECH_LOST or NO_DATA.
//!
//! The two EVS payload halves are distinguished by the `FT` range:
//! * **EVS Primary** — `FT 0..=15` (`0..=11` speech, `12` SID, `14` lost,
//!   `15` no-data).
//! * **EVS AMR-WB IO** — `FT 16..=31` (`16..=24` speech, `25` SID, `30` lost,
//!   `31` no-data).
//!
//! The Header-Full ToC octet carries only `H`, `F` and `FT`: unlike RFC 4867's
//! AMR ToC there is no Q (quality) or P (padding) field, because every EVS
//! frame is already byte-aligned.
//!
//! Header-Compact, storage and multi-channel formats are **not implemented**;
//! they return [`EvsError::Unsupported`] rather than guessing at bit packing or
//! channel interleaving. This mirrors how `codec-amr` rejects RFC 4867
//! bandwidth-efficient mode.

#![forbid(unsafe_code)]

use super::EvsError;

/// RTP clock rate for EVS (TS 26.445 fixes the RTP payload at 48 kHz).
pub const CLOCK_RATE: u32 = 48_000;
/// Samples per 20 ms EVS frame at 48 kHz.
pub const FRAME_SAMPLES: usize = 960;
/// Largest EVS speech frame (Primary 128 kbit/s), in octets.
pub const MAX_SPEECH_BYTES: usize = 320;

/// EVS Primary speech frame sizes in octets for `FT 0..=11`.
///
/// Each size is the frame's bit count divided by 8; the bit count is the
/// table's rate (kbit/s) times 20 ms, i.e. `kbps * 2.5` octets.
const PRIMARY_SPEECH_BYTES: [usize; 12] = [7, 18, 20, 24, 33, 41, 61, 80, 120, 160, 240, 320];

/// EVS AMR-WB IO speech frame sizes in octets for `FT 16..=24`
/// (AMR-WB IO modes 0..=8). These are the octet-aligned AMR-WB frame sizes,
/// carried verbatim in the EVS IO payload.
const IO_SPEECH_BYTES: [usize; 9] = [17, 23, 32, 36, 40, 46, 50, 58, 60];

/// EVS Primary SID frame (`FT 12`): 2.4 kbit/s → 48 bits → 6 octets.
const PRIMARY_SID_BYTES: usize = 6;
/// EVS AMR-WB IO SID frame (`FT 25`): 56 bits → 7 octets. The MSB is a marker
/// bit set to 1 (see [`FrameKind::IoSid`]).
const IO_SID_BYTES: usize = 7;

/// The EVS mode set selected by the 3-bit `T` field of the CMR byte.
///
/// TS 26.445 Table A.3 defines every `T` value as follows:
///
/// | `T` | meaning |
/// |-----|---------|
/// | 000 | EVS Primary narrowband |
/// | 001 | EVS AMR-WB IO |
/// | 010 | EVS Primary wideband |
/// | 011 | EVS Primary super-wideband |
/// | 100 | EVS Primary fullband |
/// | 101 | wideband 13.2 kbit/s channel-aware |
/// | 110 | super-wideband 13.2 kbit/s channel-aware |
/// | 111 | no request (`D=1111`) / reserved |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeSet {
    /// `T=000`: EVS Primary narrowband.
    Nb = 0,
    /// `T=001`: EVS AMR-WB IO.
    Io = 1,
    /// `T=010`: EVS Primary wideband.
    Wb = 2,
    /// `T=011`: EVS Primary super-wideband.
    Swb = 3,
    /// `T=100`: EVS Primary fullband.
    Fb = 4,
    /// `T=101`: wideband 13.2 kbit/s channel-aware.
    WbChannelAware = 5,
    /// `T=110`: super-wideband 13.2 kbit/s channel-aware.
    SwbChannelAware = 6,
    /// `T=111`: the no-request / reserved code space.
    NoRequestSpace = 7,
}

impl ModeSet {
    /// Decode a 3-bit `T` field.
    pub fn from_t(t: u8) -> Option<Self> {
        match t {
            0 => Some(ModeSet::Nb),
            1 => Some(ModeSet::Io),
            2 => Some(ModeSet::Wb),
            3 => Some(ModeSet::Swb),
            4 => Some(ModeSet::Fb),
            5 => Some(ModeSet::WbChannelAware),
            6 => Some(ModeSet::SwbChannelAware),
            7 => Some(ModeSet::NoRequestSpace),
            _ => None,
        }
    }

    /// The `T` field value carried in the CMR byte.
    pub fn t(self) -> u8 {
        self as u8
    }
}

/// A decode of one CMR byte into the mode / bit-rate it requests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ModeRequest {
    /// An EVS Primary bit-rate request in kbit/s for the given bandwidth.
    Primary { bandwidth: Bandwidth, kbps: f32 },
    /// An EVS AMR-WB IO codec-mode request in kbit/s.
    Io { kbps: f32 },
    /// A 13.2 kbit/s channel-aware (partial-redundancy) request.
    ChannelAware {
        bandwidth: Bandwidth,
        /// `true` = high level (`CA-H`), `false` = low level (`CA-L`).
        high: bool,
        /// Partial-redundancy offset: 2, 3, 5 or 7 frames.
        offset: u8,
    },
    /// The explicit `NO_REQ` code point (`T=111`, `D=1111`).
    NoRequest,
}

impl ModeRequest {
    /// The requested source bit-rate in kbit/s, if one is implied.
    pub fn kbps(self) -> Option<f32> {
        match self {
            ModeRequest::Primary { kbps, .. } | ModeRequest::Io { kbps } => Some(kbps),
            ModeRequest::ChannelAware { .. } => Some(13.2),
            ModeRequest::NoRequest => None,
        }
    }
}

/// An EVS audio bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bandwidth {
    /// Narrowband (8 kHz audio).
    Narrowband,
    /// Wideband (16 kHz audio).
    Wideband,
    /// Super-wideband (32 kHz audio).
    SuperWideband,
    /// Fullband (48 kHz audio).
    Fullband,
}

/// A Codec Mode Request (CMR) byte from the EVS Header-Full payload.
///
/// Layout: `H(1)=1`, `T(3)`, `D(4)`. The `D` field's meaning depends on `T`;
/// see [`Cmr::request`] for the Table A.3 decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cmr {
    /// Mode set selected by the `T` field.
    pub mode_set: ModeSet,
    /// Rate index within the mode set (`D`, 0..=15).
    pub d: u8,
}

impl Cmr {
    /// Build a CMR from a mode set and `D` field. `d` is masked into 0..=15.
    pub fn new(mode_set: ModeSet, d: u8) -> Self {
        Self {
            mode_set,
            d: d & 0x0f,
        }
    }

    /// The `NO_REQ` byte (`T=111`, `D=1111`), meaning "no codec mode request".
    pub fn no_request() -> Self {
        Self {
            mode_set: ModeSet::NoRequestSpace,
            d: 15,
        }
    }

    /// Parse a CMR byte (`H=1`, `T`, `D`). Returns `None` if the high bit is not
    /// set (this is not a CMR byte).
    pub fn parse(byte: u8) -> Option<Self> {
        if byte & 0x80 == 0 {
            return None;
        }
        let t = (byte >> 4) & 0x07;
        let d = byte & 0x0f;
        ModeSet::from_t(t).map(|mode_set| Self { mode_set, d })
    }

    /// Serialise to the 8-bit CMR byte.
    pub fn to_byte(self) -> u8 {
        0x80 | ((self.mode_set.t() & 0x07) << 4) | (self.d & 0x0f)
    }

    /// Whether this byte is the explicit `NO_REQ` code point.
    pub fn is_no_request(self) -> bool {
        self.mode_set == ModeSet::NoRequestSpace && self.d == 15
    }

    /// Decode the requested mode / bit-rate per TS 26.445 Table A.3, or `None`
    /// for a reserved / not-defined `T`/`D` pair.
    pub fn request(self) -> Option<ModeRequest> {
        let d = self.d as usize;
        match self.mode_set {
            ModeSet::Nb => {
                const R: [f32; 7] = [5.9, 7.2, 8.0, 9.6, 13.2, 16.4, 24.4];
                R.get(d).map(|&kbps| ModeRequest::Primary {
                    bandwidth: Bandwidth::Narrowband,
                    kbps,
                })
            }
            ModeSet::Wb => {
                const R: [f32; 12] = [
                    5.9, 7.2, 8.0, 9.6, 13.2, 16.4, 24.4, 32.0, 48.0, 64.0, 96.0, 128.0,
                ];
                R.get(d).map(|&kbps| ModeRequest::Primary {
                    bandwidth: Bandwidth::Wideband,
                    kbps,
                })
            }
            ModeSet::Swb => {
                // D=0011..=1011 map to 9.6..=128 kbit/s.
                const R: [(usize, f32); 9] = [
                    (3, 9.6),
                    (4, 13.2),
                    (5, 16.4),
                    (6, 24.4),
                    (7, 32.0),
                    (8, 48.0),
                    (9, 64.0),
                    (10, 96.0),
                    (11, 128.0),
                ];
                R.iter()
                    .find(|(idx, _)| *idx == d)
                    .map(|&(_, kbps)| ModeRequest::Primary {
                        bandwidth: Bandwidth::SuperWideband,
                        kbps,
                    })
            }
            ModeSet::Fb => {
                const R: [(usize, f32); 7] = [
                    (5, 16.4),
                    (6, 24.4),
                    (7, 32.0),
                    (8, 48.0),
                    (9, 64.0),
                    (10, 96.0),
                    (11, 128.0),
                ];
                R.iter()
                    .find(|(idx, _)| *idx == d)
                    .map(|&(_, kbps)| ModeRequest::Primary {
                        bandwidth: Bandwidth::Fullband,
                        kbps,
                    })
            }
            ModeSet::Io => {
                const R: [f32; 9] = [6.6, 8.85, 12.65, 14.25, 15.85, 18.25, 19.85, 23.05, 23.85];
                R.get(d).map(|&kbps| ModeRequest::Io { kbps })
            }
            ModeSet::WbChannelAware => channel_aware(d, Bandwidth::Wideband),
            ModeSet::SwbChannelAware => channel_aware(d, Bandwidth::SuperWideband),
            ModeSet::NoRequestSpace => {
                // Only D=1111 is defined (NO_REQ); 0000..=1110 are reserved.
                if self.d == 15 {
                    Some(ModeRequest::NoRequest)
                } else {
                    None
                }
            }
        }
    }

    /// The requested source bit-rate in kbit/s, or `None` for no-request or a
    /// reserved code point.
    pub fn bitrate_kbps(self) -> Option<f32> {
        self.request().and_then(ModeRequest::kbps)
    }
}

/// Decode the `D` nibble of a channel-aware CMR (`T=101` or `T=110`).
///
/// `D=0bLLLO` where `LLL` is the level/offset index and `O` the last bit:
/// values 0..=3 are `CA-L-O2/O3/O5/O7`, 4..=7 are `CA-H-O2/O3/O5/O7`.
fn channel_aware(d: usize, bandwidth: Bandwidth) -> Option<ModeRequest> {
    const OFFSETS: [u8; 4] = [2, 3, 5, 7];
    if d > 7 {
        return None;
    }
    let high = d >= 4;
    let offset = OFFSETS[d & 0x03];
    Some(ModeRequest::ChannelAware {
        bandwidth,
        high,
        offset,
    })
}

/// The kind of an EVS frame, derived from its frame type (`FT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// EVS Primary speech (`FT 0..=11`); the value is the `FT` (rate) index.
    PrimarySpeech { ft: u8 },
    /// EVS AMR-WB IO speech (`FT 16..=24`); the value is the AMR-WB mode (0..=8).
    IoSpeech { mode: u8 },
    /// EVS Primary SID / BFI comfort frame (`FT 12`).
    PrimarySid,
    /// EVS AMR-WB IO SID comfort frame (`FT 25`).
    IoSid,
    /// SPEECH_LOST: a DTX bad-frame marker (`FT 14` primary, `FT 30` IO).
    Lost,
    /// NO_DATA: a DTX silent-frame marker (`FT 15` primary, `FT 31` IO).
    NoData,
    /// A frame type reserved / not defined in this revision.
    Reserved { ft: u8 },
}

/// Classify a frame type (`FT`, 6 bits) into its EVS kind.
///
/// `FT 0..=15` is the EVS Primary table; `FT 16..=31` is the EVS AMR-WB IO
/// table. `FT 13` and `FT 26..=29` are reserved.
pub fn classify_ft(ft: u8) -> FrameKind {
    match ft {
        0..=11 => FrameKind::PrimarySpeech { ft },
        12 => FrameKind::PrimarySid,
        13 => FrameKind::Reserved { ft },
        14 => FrameKind::Lost,
        15 => FrameKind::NoData,
        16..=24 => FrameKind::IoSpeech { mode: ft - 16 },
        25 => FrameKind::IoSid,
        26..=29 => FrameKind::Reserved { ft },
        30 => FrameKind::Lost,
        31 => FrameKind::NoData,
        _ => FrameKind::Reserved { ft },
    }
}

/// Octets occupied by a frame's data field (excluding the ToC octet).
///
/// Returns `None` for reserved frame types.
pub fn frame_size(ft: u8) -> Option<usize> {
    match classify_ft(ft) {
        FrameKind::PrimarySpeech { ft } => Some(PRIMARY_SPEECH_BYTES[ft as usize]),
        FrameKind::IoSpeech { mode } => Some(IO_SPEECH_BYTES[mode as usize]),
        FrameKind::PrimarySid => Some(PRIMARY_SID_BYTES),
        FrameKind::IoSid => Some(IO_SID_BYTES),
        FrameKind::Lost | FrameKind::NoData => Some(0),
        FrameKind::Reserved { .. } => None,
    }
}

/// EVS Primary speech rates (kbit/s) for `FT 0..=11`.
const PRIMARY_KBPS: [f32; 12] = [
    2.8, 7.2, 8.0, 9.6, 13.2, 16.4, 24.4, 32.0, 48.0, 64.0, 96.0, 128.0,
];
/// AMR-WB IO speech rates (kbit/s) for `FT 16..=24` (modes 0..=8), matching
/// RFC 4867 / TS 26.201.
const IO_KBPS: [f32; 9] = [6.6, 8.85, 12.65, 14.25, 15.85, 18.25, 19.85, 23.05, 23.85];

/// Downlink speech frame size in bits for a speech frame type, or `None` for a
/// non-speech or reserved frame. EVS Primary uses `kbps * 2.5` octets (i.e.
/// `kbps * 20` bits per 20 ms frame); the AMR-WB IO rates are the AMR-WB mode
/// rates.
pub fn speech_bits(ft: u8) -> Option<usize> {
    let kbps: f32 = match classify_ft(ft) {
        FrameKind::PrimarySpeech { ft } => PRIMARY_KBPS[ft as usize],
        FrameKind::IoSpeech { mode } => IO_KBPS[mode as usize],
        _ => return None,
    };
    Some((kbps * 20.0).round() as usize)
}

/// One EVS frame: its frame type and payload bytes.
///
/// The Header-Full ToC carries only `H`, `F` and `FT`; there is no per-frame Q
/// (quality/confidence) or P (padding) field. Frame content is byte-aligned, so
/// no per-frame padding is needed either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The 6-bit frame type.
    pub ft: u8,
    /// Frame payload (speech or SID bits); empty for SPEECH_LOST / NO_DATA.
    pub data: Vec<u8>,
}

impl Frame {
    /// Build an EVS speech frame (Primary `FT 0..=11` or AMR-WB IO `FT 16..=24`),
    /// validating that `data` matches the table-defined size.
    pub fn speech(ft: u8, data: Vec<u8>) -> Result<Self, EvsError> {
        let expected = frame_size(ft).ok_or(EvsError::ReservedFrameType(ft))?;
        if data.len() != expected {
            return Err(EvsError::FrameSize {
                ft,
                expected,
                got: data.len(),
            });
        }
        Ok(Self { ft, data })
    }

    /// Build an EVS Primary SID frame (`FT 12`, 6 octets).
    pub fn primary_sid(data: Vec<u8>) -> Result<Self, EvsError> {
        if data.len() != PRIMARY_SID_BYTES {
            return Err(EvsError::FrameSize {
                ft: 12,
                expected: PRIMARY_SID_BYTES,
                got: data.len(),
            });
        }
        Ok(Self { ft: 12, data })
    }

    /// Build an EVS AMR-WB IO SID frame (`FT 25`, 7 octets). The MSB of the
    /// first octet is a marker bit and must be set to 1, per TS 26.445.
    pub fn io_sid(data: Vec<u8>) -> Result<Self, EvsError> {
        if data.len() != IO_SID_BYTES {
            return Err(EvsError::FrameSize {
                ft: 25,
                expected: IO_SID_BYTES,
                got: data.len(),
            });
        }
        if data.first().map(|b| b & 0x80).unwrap_or(0) == 0 {
            return Err(EvsError::BadSidMarker);
        }
        Ok(Self { ft: 25, data })
    }

    /// A SPEECH_LOST frame (`FT 14` Primary / `FT 30` IO).
    pub fn lost(primary: bool) -> Self {
        Self {
            ft: if primary { 14 } else { 30 },
            data: Vec::new(),
        }
    }

    /// A NO_DATA frame (`FT 15` Primary / `FT 31` IO).
    pub fn no_data(primary: bool) -> Self {
        Self {
            ft: if primary { 15 } else { 31 },
            data: Vec::new(),
        }
    }

    /// The kind of this frame.
    pub fn kind(&self) -> FrameKind {
        classify_ft(self.ft)
    }

    /// Whether this frame carries speech (Primary or IO).
    pub fn is_speech(&self) -> bool {
        matches!(
            self.kind(),
            FrameKind::PrimarySpeech { .. } | FrameKind::IoSpeech { .. }
        )
    }

    /// Downlink speech frame size in bits for a speech frame, or `None`.
    pub fn speech_bits(&self) -> Option<usize> {
        speech_bits(self.ft)
    }
}

/// Which payload container a parse/serialise pass should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// TS 26.445 appendix A Header-Full format (the default; always available).
    HeaderFull,
    /// TS 26.445 appendix A Header-Compact format. Not implemented.
    HeaderCompact,
    /// The older storage format. Never valid on the wire. Not implemented.
    Storage,
    /// Multi-channel EVS payload. Not implemented (channel interleaving).
    MultiChannel,
}

/// A complete EVS Header-Full RTP payload: one CMR byte plus one or more frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Codec mode request (`H=1`, `T`, `D`); `d == 15` means no request.
    pub cmr: Cmr,
    /// Frames in wire order.
    pub frames: Vec<Frame>,
}

impl Payload {
    /// Build a payload from a CMR and frames without re-validating frame sizes.
    pub fn new(cmr: Cmr, frames: Vec<Frame>) -> Self {
        Self { cmr, frames }
    }

    /// A single-frame payload carrying one speech frame and a `NO_REQ` CMR.
    pub fn single_speech(ft: u8, data: Vec<u8>) -> Result<Self, EvsError> {
        Ok(Self {
            cmr: Cmr::no_request(),
            frames: vec![Frame::speech(ft, data)?],
        })
    }

    /// Parse the default Header-Full representation.
    pub fn parse(payload: &[u8]) -> Result<Self, EvsError> {
        Self::parse_mode(payload, PayloadFormat::HeaderFull)
    }

    /// Parse a specific container format. Only [`PayloadFormat::HeaderFull`] is
    /// implemented; the rest return [`EvsError::Unsupported`].
    pub fn parse_mode(payload: &[u8], format: PayloadFormat) -> Result<Self, EvsError> {
        match format {
            PayloadFormat::HeaderFull => parse_header_full(payload),
            PayloadFormat::HeaderCompact | PayloadFormat::Storage | PayloadFormat::MultiChannel => {
                Err(EvsError::Unsupported)
            }
        }
    }

    /// Serialise to the default Header-Full representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EvsError> {
        self.to_bytes_mode(PayloadFormat::HeaderFull)
    }

    /// Serialise to a specific container format. Only Header-Full is supported.
    pub fn to_bytes_mode(&self, format: PayloadFormat) -> Result<Vec<u8>, EvsError> {
        match format {
            PayloadFormat::HeaderFull => serialize_header_full(self),
            PayloadFormat::HeaderCompact | PayloadFormat::Storage | PayloadFormat::MultiChannel => {
                Err(EvsError::Unsupported)
            }
        }
    }

    /// Whether any frame carries speech.
    pub fn has_speech(&self) -> bool {
        self.frames.iter().any(Frame::is_speech)
    }

    /// The speech frame types present, in wire order.
    pub fn speech_frame_types(&self) -> Vec<u8> {
        self.frames
            .iter()
            .filter_map(|f| match f.kind() {
                FrameKind::PrimarySpeech { ft } => Some(ft),
                FrameKind::IoSpeech { mode } => Some(mode + 16),
                _ => None,
            })
            .collect()
    }
}

fn parse_header_full(payload: &[u8]) -> Result<Payload, EvsError> {
    if payload.is_empty() {
        return Err(EvsError::Empty);
    }
    // First octet is the CMR; it must have the H bit set.
    let cmr = Cmr::parse(payload[0]).ok_or(EvsError::ReservedFrameType(payload[0] & 0x7f))?;
    let mut offset = 1;
    let mut frames = Vec::new();
    let mut more = false;

    while offset < payload.len() {
        let toc = payload[offset];
        offset += 1;
        // A ToC byte has H=0; the FT is the low 6 bits and F the bit above it.
        if toc & 0x80 != 0 {
            return Err(EvsError::ReservedFrameType(toc & 0x7f));
        }
        let f = toc & 0x40 != 0;
        let ft = toc & 0x3f;

        let size = frame_size(ft).ok_or(EvsError::ReservedFrameType(ft))?;
        if offset + size > payload.len() {
            return Err(EvsError::Truncated {
                ft,
                expected: size,
                available: payload.len() - offset,
            });
        }
        let data = payload[offset..offset + size].to_vec();
        offset += size;
        frames.push(Frame { ft, data });
        more = f;
        if !f {
            break;
        }
    }

    if frames.is_empty() {
        return Err(EvsError::Empty);
    }
    if more {
        return Err(EvsError::Truncated {
            ft: frames.last().map(|f| f.ft).unwrap_or(15),
            expected: 1,
            available: 0,
        });
    }
    if offset != payload.len() {
        return Err(EvsError::TrailingBytes(payload.len() - offset));
    }
    Ok(Payload { cmr, frames })
}

fn serialize_header_full(payload: &Payload) -> Result<Vec<u8>, EvsError> {
    if payload.frames.is_empty() {
        return Err(EvsError::Empty);
    }
    let mut out = Vec::with_capacity(1 + payload.frames.len() * 2 + MAX_SPEECH_BYTES);
    out.push(payload.cmr.to_byte());
    let last = payload.frames.len() - 1;
    for (i, frame) in payload.frames.iter().enumerate() {
        let expected = frame_size(frame.ft).ok_or(EvsError::ReservedFrameType(frame.ft))?;
        if frame.data.len() != expected {
            return Err(EvsError::FrameSize {
                ft: frame.ft,
                expected,
                got: frame.data.len(),
            });
        }
        let f = i != last;
        // ToC: H=0, F, FT(6).
        let toc = ((u8::from(f) & 0x01) << 6) | (frame.ft & 0x3f);
        out.push(toc);
        out.extend_from_slice(&frame.data);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn primary_speech(ft: u8) -> Vec<u8> {
        vec![0xA5; frame_size(ft).unwrap()]
    }

    fn io_speech(mode: u8) -> Vec<u8> {
        vec![0xA5; IO_SPEECH_BYTES[mode as usize]]
    }

    #[test]
    fn cmr_byte_round_trips_all_mode_sets() {
        for t in 0..8u8 {
            let d = 3;
            let cmr = Cmr::parse(0x80 | (t << 4) | d).unwrap();
            assert_eq!(ModeSet::from_t(t).unwrap(), cmr.mode_set);
            assert_eq!(cmr.to_byte(), 0x80 | (t << 4) | d);
        }
    }

    #[test]
    fn cmr_no_request_is_t111_d15() {
        let cmr = Cmr::no_request();
        assert!(cmr.is_no_request());
        assert_eq!(cmr.to_byte(), 0xFF);
        assert_eq!(cmr.request(), Some(ModeRequest::NoRequest));
        assert!(cmr.bitrate_kbps().is_none());
        // D=15 with any other T is reserved, not a no-request.
        assert!(!Cmr::new(ModeSet::Wb, 15).is_no_request());
    }

    #[test]
    fn cmr_bitrate_matches_table_a3() {
        // T=000 (NB): D=0000 -> 5.9 VBR, D=0100 -> 13.2, D=0110 -> 24.4.
        assert_eq!(Cmr::new(ModeSet::Nb, 0).bitrate_kbps(), Some(5.9));
        assert_eq!(Cmr::new(ModeSet::Nb, 4).bitrate_kbps(), Some(13.2));
        assert_eq!(Cmr::new(ModeSet::Nb, 6).bitrate_kbps(), Some(24.4));
        assert_eq!(Cmr::new(ModeSet::Nb, 7).bitrate_kbps(), None);

        // T=001 (IO): D=0000 -> 6.6 ... D=1000 -> 23.85.
        assert_eq!(Cmr::new(ModeSet::Io, 0).bitrate_kbps(), Some(6.6));
        assert_eq!(Cmr::new(ModeSet::Io, 7).bitrate_kbps(), Some(23.05));
        assert_eq!(Cmr::new(ModeSet::Io, 8).bitrate_kbps(), Some(23.85));
        assert_eq!(Cmr::new(ModeSet::Io, 9).bitrate_kbps(), None);

        // T=010 (WB): D=0000 -> 5.9 ... D=1011 -> 128.
        assert_eq!(Cmr::new(ModeSet::Wb, 0).bitrate_kbps(), Some(5.9));
        assert_eq!(Cmr::new(ModeSet::Wb, 7).bitrate_kbps(), Some(32.0));
        assert_eq!(Cmr::new(ModeSet::Wb, 11).bitrate_kbps(), Some(128.0));
        assert_eq!(Cmr::new(ModeSet::Wb, 12).bitrate_kbps(), None);

        // T=011 (SWB): first defined D is 0011 -> 9.6, last 1011 -> 128.
        assert_eq!(Cmr::new(ModeSet::Swb, 2).bitrate_kbps(), None);
        assert_eq!(Cmr::new(ModeSet::Swb, 3).bitrate_kbps(), Some(9.6));
        assert_eq!(Cmr::new(ModeSet::Swb, 11).bitrate_kbps(), Some(128.0));

        // T=100 (FB): first defined D is 0101 -> 16.4 ... 1011 -> 128.
        assert_eq!(Cmr::new(ModeSet::Fb, 4).bitrate_kbps(), None);
        assert_eq!(Cmr::new(ModeSet::Fb, 5).bitrate_kbps(), Some(16.4));
        assert_eq!(Cmr::new(ModeSet::Fb, 11).bitrate_kbps(), Some(128.0));
    }

    #[test]
    fn cmr_channel_aware_levels_and_offsets() {
        // T=101 (WB CA): D=0000 -> CA-L-O2, D=0111 -> CA-H-O7.
        let low = Cmr::new(ModeSet::WbChannelAware, 0).request().unwrap();
        assert_eq!(
            low,
            ModeRequest::ChannelAware {
                bandwidth: Bandwidth::Wideband,
                high: false,
                offset: 2
            }
        );
        let high = Cmr::new(ModeSet::WbChannelAware, 7).request().unwrap();
        assert_eq!(
            high,
            ModeRequest::ChannelAware {
                bandwidth: Bandwidth::Wideband,
                high: true,
                offset: 7
            }
        );
        assert_eq!(high.kbps(), Some(13.2));
        // T=110 (SWB CA).
        assert_eq!(
            Cmr::new(ModeSet::SwbChannelAware, 2).request().unwrap(),
            ModeRequest::ChannelAware {
                bandwidth: Bandwidth::SuperWideband,
                high: false,
                offset: 5
            }
        );
    }

    #[test]
    fn io_speech_bits_match_amr_wb() {
        // FT 16..=24 speech bits: 132,177,253,285,317,365,397,461,477.
        let expected = [132, 177, 253, 285, 317, 365, 397, 461, 477];
        for (mode, &bits) in expected.iter().enumerate() {
            assert_eq!(speech_bits(16 + mode as u8), Some(bits));
        }
    }

    #[test]
    fn primary_speech_sizes_are_kbps_times_2_5() {
        for (ft, &size) in PRIMARY_SPEECH_BYTES.iter().enumerate() {
            assert_eq!(frame_size(ft as u8), Some(size));
            // octets = kbit/s × 2.5 for a 20 ms frame.
            assert_eq!(size, (PRIMARY_KBPS[ft] * 2.5).round() as usize);
        }
    }

    #[test]
    fn io_speech_sizes_match_amr_wb_octet_aligned() {
        for mode in 0..9u8 {
            assert_eq!(frame_size(16 + mode), Some(IO_SPEECH_BYTES[mode as usize]));
        }
    }

    #[test]
    fn classification_of_every_frame_type() {
        assert_eq!(classify_ft(0), FrameKind::PrimarySpeech { ft: 0 });
        assert_eq!(classify_ft(11), FrameKind::PrimarySpeech { ft: 11 });
        assert_eq!(classify_ft(12), FrameKind::PrimarySid);
        assert_eq!(classify_ft(13), FrameKind::Reserved { ft: 13 });
        assert_eq!(classify_ft(14), FrameKind::Lost);
        assert_eq!(classify_ft(15), FrameKind::NoData);
        assert_eq!(classify_ft(16), FrameKind::IoSpeech { mode: 0 });
        assert_eq!(classify_ft(24), FrameKind::IoSpeech { mode: 8 });
        assert_eq!(classify_ft(25), FrameKind::IoSid);
        assert_eq!(classify_ft(26), FrameKind::Reserved { ft: 26 });
        assert_eq!(classify_ft(29), FrameKind::Reserved { ft: 29 });
        assert_eq!(classify_ft(30), FrameKind::Lost);
        assert_eq!(classify_ft(31), FrameKind::NoData);
        assert_eq!(classify_ft(32), FrameKind::Reserved { ft: 32 });
    }

    #[test]
    fn single_frame_header_full_round_trip() {
        // CMR: H=1, T=2 (WB), D=7 (32 kbit/s) => 0xA7;
        // ToC: H=0, F=0, FT=7 => 0x07.
        let p = Payload::new(
            Cmr::new(ModeSet::Wb, 7),
            vec![Frame::speech(7, primary_speech(7)).unwrap()],
        );
        let bytes = p.to_bytes().unwrap();
        assert_eq!(&bytes[..2], &[0xA7, 0x07]);
        assert_eq!(bytes.len(), 2 + 80);
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.speech_frame_types(), vec![7]);
    }

    #[test]
    fn multi_frame_f_bit_glues_frames() {
        // Primary speech FT=0 then FT=4 (33 bytes) then AMR-WB IO mode 0 (FT=16).
        let p = Payload::new(
            Cmr::new(ModeSet::Io, 0),
            vec![
                Frame::speech(0, primary_speech(0)).unwrap(),
                Frame::speech(4, primary_speech(4)).unwrap(),
                Frame::speech(16, io_speech(0)).unwrap(),
            ],
        );
        let bytes = p.to_bytes().unwrap();
        // ToCs: F=1/FT=0 => 0x40; F=1/FT=4 => 0x44; F=0/FT=16 => 0x10.
        // Layout: CMR(1), ToC0(1), 7 bytes, ToC1(1), 33 bytes, ToC2(1), 17 bytes.
        assert_eq!(bytes[1], 0x40);
        assert_eq!(bytes[9], 0x44); // 1 + 1 + 7
        assert_eq!(bytes[43], 0x10); // 9 + 1 + 33
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(parsed, p);
        assert_eq!(parsed.speech_frame_types(), vec![0, 4, 16]);
    }

    #[test]
    fn sid_lost_nodata_classification() {
        let p = Payload::new(
            Cmr::no_request(),
            vec![
                Frame::primary_sid(vec![0x11; 6]).unwrap(),
                Frame::io_sid(vec![0x80; 7]).unwrap(),
                Frame::lost(true),
                Frame::no_data(false),
            ],
        );
        let bytes = p.to_bytes().unwrap();
        let parsed = Payload::parse(&bytes).unwrap();
        assert_eq!(parsed.frames[0].kind(), FrameKind::PrimarySid);
        assert_eq!(parsed.frames[1].kind(), FrameKind::IoSid);
        assert_eq!(parsed.frames[2].kind(), FrameKind::Lost);
        assert_eq!(parsed.frames[3].kind(), FrameKind::NoData);
        assert!(!parsed.has_speech());
        // Layout: CMR, ToC0 (primary SID FT=12, F=1) = 0x4C, 6 bytes, ToC1
        // (IO SID FT=25, F=1) = 0x59, 7 bytes, ToC2 (lost FT=14, F=1) = 0x4E,
        // ToC3 (no-data FT=31 IO, F=0) = 0x1F.
        assert_eq!(bytes[1], 0x4C);
        assert_eq!(bytes[8], 0x59); // 1 + 1 + 6
        assert_eq!(bytes[16], 0x4E); // 8 + 1 + 7
        assert_eq!(bytes[17], 0x1F); // 16 + 1
    }

    #[test]
    fn io_sid_requires_marker_bit() {
        assert_eq!(Frame::io_sid(vec![0x00; 7]), Err(EvsError::BadSidMarker));
        assert!(Frame::io_sid(vec![0x80; 7]).is_ok());
    }

    #[test]
    fn reserved_frame_type_is_rejected() {
        // CMR=WB/7 (0xA7), ToC F=0 FT=13 => 0x0D.
        assert_eq!(
            Payload::parse(&[0xA7, 0x0D]).unwrap_err(),
            EvsError::ReservedFrameType(13)
        );
    }

    #[test]
    fn wrong_frame_size_is_rejected() {
        let err = Payload::single_speech(7, vec![0u8; 79]).unwrap_err();
        assert_eq!(
            err,
            EvsError::FrameSize {
                ft: 7,
                expected: 80,
                got: 79
            }
        );
    }

    #[test]
    fn truncated_and_trailing_are_rejected() {
        let p = Payload::single_speech(7, primary_speech(7)).unwrap();
        let bytes = p.to_bytes().unwrap();
        assert!(matches!(
            Payload::parse(&bytes[..bytes.len() - 1]).unwrap_err(),
            EvsError::Truncated { .. }
        ));
        let mut extra = bytes.clone();
        extra.push(0x00);
        assert!(matches!(
            Payload::parse(&extra).unwrap_err(),
            EvsError::TrailingBytes(1)
        ));
    }

    #[test]
    fn f_bit_on_last_frame_is_truncation() {
        // CMR (WB/no-request), ToC F=1 FT=15 => 0x4F with no following ToC.
        assert!(matches!(
            Payload::parse(&[0x9F, 0x4F]).unwrap_err(),
            EvsError::Truncated { .. }
        ));
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(Payload::parse(&[]).unwrap_err(), EvsError::Empty);
        assert_eq!(
            Payload::new(Cmr::new(ModeSet::Wb, 0), vec![])
                .to_bytes()
                .unwrap_err(),
            EvsError::Empty
        );
    }

    #[test]
    fn header_full_to_byte_and_parse_are_inverse() {
        // A CMR byte has H=1; a ToC byte has H=0.
        let p = Payload::single_speech(4, primary_speech(4)).unwrap();
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes[0] & 0x80, 0x80); // CMR has H=1
        assert_eq!(bytes[1] & 0x80, 0x00); // ToC has H=0
        assert_eq!(Payload::parse(&bytes).unwrap(), p);
    }

    #[test]
    fn compact_storage_and_multichannel_are_unsupported() {
        for format in [
            PayloadFormat::HeaderCompact,
            PayloadFormat::Storage,
            PayloadFormat::MultiChannel,
        ] {
            assert_eq!(
                Payload::parse_mode(&[0xA7, 0x07], format),
                Err(EvsError::Unsupported)
            );
            let p = Payload::single_speech(7, primary_speech(7)).unwrap();
            assert_eq!(p.to_bytes_mode(format), Err(EvsError::Unsupported));
        }
    }

    #[test]
    fn all_primary_modes_round_trip() {
        for ft in 0..=11u8 {
            let p = Payload::single_speech(ft, primary_speech(ft)).unwrap();
            let bytes = p.to_bytes().unwrap();
            let parsed = Payload::parse(&bytes).unwrap();
            assert_eq!(parsed, p);
            assert_eq!(parsed.frames[0].speech_bits(), speech_bits(ft));
        }
    }

    #[test]
    fn all_io_modes_round_trip() {
        for mode in 0..9u8 {
            let p = Payload::single_speech(16 + mode, io_speech(mode)).unwrap();
            let bytes = p.to_bytes().unwrap();
            let parsed = Payload::parse(&bytes).unwrap();
            assert_eq!(parsed, p);
            assert_eq!(parsed.frames[0].speech_bits(), speech_bits(16 + mode));
        }
    }
}
