//! RFC 3550 §5.3 RTP packet — fixed header, CSRC list, extension, payload.
//!
//! This is the transport wrapper; it knows nothing about the payload codec.
//! The header is exactly 12 bytes plus 4 bytes per CSRC plus the optional
//! profile extension, matching the on-wire layout bit for bit.

use crate::{MediaError, RTP_VERSION};

/// Fixed RTP header size before any CSRC or extension bytes. RFC 3550 §5.3.
pub const FIXED_HEADER_BYTES: usize = 12;

/// First marker bit position inside byte 1 (the other 7 bits are the PT).
const MARKER_BIT: u8 = 0x80;
/// RTP version occupies the top two bits of byte 0.
const VERSION_MASK: u8 = 0xC0;
const PADDING_BIT: u8 = 0x20;
const EXTENSION_BIT: u8 = 0x10;
const CC_MASK: u8 = 0x0f;

/// A parsed or to-be-sent RTP packet: header fields plus the opaque payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    /// RTP version — always 2 on the wire; kept for round-trip validation.
    pub version: u8,
    /// Padding bit (RFC 3550 §5.3): last byte is padding count.
    pub padding: bool,
    /// Extension bit: a profile-defined extension header is present.
    pub extension: bool,
    /// Contributing source identifiers (0..=15), in wire order.
    pub csrc: Vec<u32>,
    /// Marker bit — semantics are payload-specific (e.g. frame boundary).
    pub marker: bool,
    /// Dynamic payload type (RTP map negotiated out of band, e.g. 97 = AMR-WB).
    pub payload_type: u8,
    /// Sequence number; increments by one per packet, wraps at 65536.
    pub sequence: u16,
    /// RTP timestamp at the sample the payload begins.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Profile-defined extension header (e.g. `0xBEDE`), present if `extension`.
    pub ext_header: Option<u16>,
    /// Extension payload, `ext_len * 4` bytes, present when `extension`.
    pub ext_data: Vec<u8>,
    /// The codec payload (e.g. an octet-aligned AMR frame set).
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Build a minimal packet with the given core fields and no CSRC/extension.
    pub fn new(payload_type: u8, sequence: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            csrc: Vec::new(),
            marker: false,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            ext_header: None,
            ext_data: Vec::new(),
            payload: Vec::new(),
        }
    }

    /// Encode the full on-wire byte sequence.
    pub fn encode(&self) -> Result<Vec<u8>, MediaError> {
        if self.csrc.len() > 15 {
            return Err(MediaError::Malformed("more than 15 CSRC identifiers"));
        }
        let mut out =
            Vec::with_capacity(FIXED_HEADER_BYTES + self.csrc.len() * 4 + 4 + self.payload.len());
        let b0 = (self.version & 0x03) << 6
            | u8::from(self.padding) << 5
            | u8::from(self.extension) << 4
            | (self.csrc.len() as u8 & CC_MASK);
        let b1 = (u8::from(self.marker) << 7) | (self.payload_type & 0x7f);
        out.push(b0);
        out.push(b1);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for csrc in &self.csrc {
            out.extend_from_slice(&csrc.to_be_bytes());
        }
        if self.extension {
            let ext_header = self.ext_header.unwrap_or(0);
            // The extension body must occupy a whole number of 32-bit words.
            let mut body = self.ext_data.clone();
            while body.len() % 4 != 0 {
                body.push(0);
            }
            let words = body.len() / 4;
            out.extend_from_slice(&ext_header.to_be_bytes());
            out.extend_from_slice(&(words as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse a packet from raw bytes.
    pub fn decode(data: &[u8]) -> Result<Self, MediaError> {
        if data.len() < FIXED_HEADER_BYTES {
            return Err(MediaError::TooShort {
                need: FIXED_HEADER_BYTES,
                have: data.len(),
            });
        }
        let b0 = data[0];
        let version = (b0 & VERSION_MASK) >> 6;
        if version != RTP_VERSION {
            return Err(MediaError::BadVersion(version));
        }
        let padding = b0 & PADDING_BIT != 0;
        let extension = b0 & EXTENSION_BIT != 0;
        let cc = (b0 & CC_MASK) as usize;
        let b1 = data[1];
        let marker = b1 & MARKER_BIT != 0;
        let payload_type = b1 & 0x7f;
        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut offset = FIXED_HEADER_BYTES;
        let need = offset + cc * 4;
        if data.len() < need {
            return Err(MediaError::Malformed("CSRC list exceeds packet"));
        }
        let mut csrc = Vec::with_capacity(cc);
        for _ in 0..cc {
            csrc.push(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        let mut ext_header = None;
        let mut ext_data = Vec::new();
        if extension {
            if data.len() < offset + 4 {
                return Err(MediaError::Malformed("extension header truncated"));
            }
            ext_header = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
            let words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            let end = offset + words * 4;
            if data.len() < end {
                return Err(MediaError::Malformed("extension body truncated"));
            }
            ext_data = data[offset..end].to_vec();
            offset = end;
        }

        let payload = if padding {
            if data.is_empty() {
                return Err(MediaError::TooShort { need: 1, have: 0 });
            }
            let pad = *data.last().unwrap();
            if pad as usize > data.len() {
                return Err(MediaError::Malformed("padding count exceeds packet"));
            }
            data[offset..data.len() - pad as usize].to_vec()
        } else {
            data[offset..].to_vec()
        };

        Ok(Self {
            version,
            padding,
            extension,
            csrc,
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            ext_header,
            ext_data,
            payload,
        })
    }

    /// Convenience for building a packet with a CSRC list (mixer scenario).
    pub fn with_csrc(mut self, csrc: Vec<u32>) -> Self {
        self.csrc = csrc;
        self
    }

    /// Attach a profile-defined extension (e.g. RFC 5285 one-byte header).
    pub fn with_extension(mut self, header: u16, data: Vec<u8>) -> Self {
        self.extension = true;
        self.ext_header = Some(header);
        self.ext_data = data;
        self
    }

    /// Attach the codec payload to a packet under construction.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_header_round_trip_no_options() {
        let p = RtpPacket::new(97, 1, 320, 0xDEADBEEF).with_payload(vec![1, 2, 3, 4]);
        let bytes = p.encode().unwrap();
        assert_eq!(bytes.len(), FIXED_HEADER_BYTES + 4);
        assert_eq!(bytes[0], 0x80); // V=2, no padding/ext, CC=0.
        assert_eq!(bytes[1], 0x61); // M=0, PT=97.
        assert_eq!(RtpPacket::decode(&bytes).unwrap(), p);
    }

    #[test]
    fn marker_and_payload_type_high_bit() {
        // PT=126 (7-bit), marker set => byte1 = 0xFE.
        let mut base = RtpPacket::new(126, 5, 0, 1);
        base.marker = true;
        let p = base.with_payload(vec![0xAA]);
        let bytes = p.encode().unwrap();
        assert_eq!(bytes[1], 0xFE);
        assert!(RtpPacket::decode(&bytes).unwrap().marker);
    }

    #[test]
    fn csrc_list_survives() {
        let p = RtpPacket::new(97, 1, 0, 1)
            .with_csrc(vec![11, 22, 33])
            .with_payload(vec![9]);
        let bytes = p.encode().unwrap();
        assert_eq!(bytes.len(), FIXED_HEADER_BYTES + 12 + 1);
        let q = RtpPacket::decode(&bytes).unwrap();
        assert_eq!(q.csrc, vec![11, 22, 33]);
        assert_eq!(q.payload, vec![9]);
    }

    #[test]
    fn extension_round_trips() {
        let p = RtpPacket::new(97, 1, 0, 1)
            .with_extension(0xBEDE, vec![0u8; 8])
            .with_payload(vec![7, 7]);
        let bytes = p.encode().unwrap();
        let q = RtpPacket::decode(&bytes).unwrap();
        assert!(q.extension);
        assert_eq!(q.ext_header, Some(0xBEDE));
        assert_eq!(q.ext_data, vec![0u8; 8]);
        assert_eq!(q.payload, vec![7, 7]);
    }

    #[test]
    fn short_packet_is_rejected() {
        assert_eq!(
            RtpPacket::decode(&[0x80, 0x61, 0x00]).unwrap_err(),
            MediaError::TooShort {
                need: FIXED_HEADER_BYTES,
                have: 3
            }
        );
    }

    #[test]
    fn bad_version_is_rejected() {
        let mut bytes = RtpPacket::new(97, 1, 0, 1).encode().unwrap();
        bytes[0] = 0x40; // V=1.
        assert_eq!(
            RtpPacket::decode(&bytes).unwrap_err(),
            MediaError::BadVersion(1)
        );
    }

    #[test]
    fn padding_is_honoured() {
        // Payload [5] with one pad byte and pad count 1.
        let p = RtpPacket::new(97, 1, 0, 1).with_payload(vec![5]);
        let mut bytes = p.encode().unwrap();
        // Manually set padding bit and append pad count.
        bytes[0] |= PADDING_BIT;
        bytes.push(1);
        let q = RtpPacket::decode(&bytes).unwrap();
        assert!(q.padding);
        assert_eq!(q.payload, vec![5]);
    }
}
