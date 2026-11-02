//! RFC 4867 §9 RTP placement for AMR/AMR-WB.
//!
//! The RTP payload is exactly the octet-aligned AMR payload produced by
//! [`codec_amr`]: one `CMR` octet, then one ToC octet per frame plus its data.
//! RTP adds the timestamp (the sampling instant of the first sample) and the
//! sequence number; the timestamp advances by [`AMR_WB_FRAME_SAMPLES`] for each
//! 20 ms frame carried, whether in one multi-frame packet or across several.

use crate::packet::RtpPacket;
use crate::{
    MediaError, AMR_NB_CLOCK_RATE, AMR_NB_FRAME_SAMPLES, AMR_NB_PAYLOAD_TYPE, AMR_WB_CLOCK_RATE,
    AMR_WB_FRAME_SAMPLES, AMR_WB_PAYLOAD_TYPE,
};
use codec_amr::rtp::{Band, Payload};

/// Stateless conversion between an AMR payload and its RTP envelope. Bound to a
/// negotiated payload type and SSRC.
#[derive(Debug, Clone)]
pub struct AmrRtp {
    pub payload_type: u8,
    pub clock_rate: u32,
    pub ssrc: u32,
    /// Which AMR variant the payload types are read as.
    pub band: Band,
    /// Samples per 20 ms frame in this band.
    pub frame_samples: usize,
}

impl AmrRtp {
    /// Default AMR-WB placement: dynamic PT 97, 16 kHz, caller-chosen SSRC.
    pub fn amr_wb(ssrc: u32) -> Self {
        Self {
            payload_type: AMR_WB_PAYLOAD_TYPE,
            clock_rate: AMR_WB_CLOCK_RATE,
            ssrc,
            band: Band::Wb,
            frame_samples: AMR_WB_FRAME_SAMPLES,
        }
    }

    /// Default AMR-NB placement: dynamic PT 96, 8 kHz, caller-chosen SSRC.
    ///
    /// This is the codec voicemail and MMS audio normally use.
    pub fn amr_nb(ssrc: u32) -> Self {
        Self {
            payload_type: AMR_NB_PAYLOAD_TYPE,
            clock_rate: AMR_NB_CLOCK_RATE,
            ssrc,
            band: Band::Nb,
            frame_samples: AMR_NB_FRAME_SAMPLES,
        }
    }

    /// RTP timestamp (in clock ticks) at the start of frame `index`.
    ///
    /// RFC 4867 §9.1: the timestamp reflects the sampling instant of the first
    /// sample in the payload; 20 ms frames step by 320 ticks at 16 kHz.
    pub fn timestamp_for(&self, index: u32) -> u32 {
        index * self.frame_samples as u32
    }

    /// Wrap an already-built AMR payload as the RTP payload octets.
    pub fn payload_bytes(&self, payload: &Payload) -> Result<Vec<u8>, MediaError> {
        Ok(payload.to_bytes_in(self.band)?)
    }

    /// Parse an incoming AMR RTP payload back into a [`codec_amr`] payload.
    pub fn parse_payload(&self, rtp_payload: &[u8]) -> Result<Payload, MediaError> {
        Ok(Payload::parse_in(self.band, rtp_payload)?)
    }
}

/// A sending RTP stream: owns the sequence number and timestamp so callers only
/// hand it frames. Sequence wraps per RFC 3550; timestamps do not wrap here.
#[derive(Debug)]
pub struct MediaEncoder {
    rtp: AmrRtp,
    sequence: u16,
    timestamp: u32,
}

impl MediaEncoder {
    pub fn new(rtp: AmrRtp) -> Self {
        // Start the sequence one past zero so an empty stream is distinguishable
        // from a never-sent stream, matching most stacks' initial behaviour.
        Self {
            rtp,
            sequence: 1,
            timestamp: 0,
        }
    }

    /// Encode one AMR payload (one or more frames) into a single RTP packet and
    /// advance the sequence and timestamp for the next call.
    pub fn encode(&mut self, payload: &Payload) -> Result<RtpPacket, MediaError> {
        let bytes = self.rtp.payload_bytes(payload)?;
        let frames = payload.frames.len() as u32;
        let mut packet = RtpPacket::new(
            self.rtp.payload_type,
            self.sequence,
            self.timestamp,
            self.rtp.ssrc,
        );
        // The marker bit marks a talk-spurt / frame boundary; set it on every
        // AMR packet, which is one talk-spurt unit here.
        packet.marker = true;
        packet.payload = bytes;

        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self
            .timestamp
            .wrapping_add(frames * self.rtp.frame_samples as u32);
        Ok(packet)
    }

    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec_amr::rtp::Frame;

    fn speech(mode: u8) -> Vec<u8> {
        vec![0x5A; codec_amr::rtp::frame_size(mode).unwrap()]
    }

    #[test]
    fn timestamp_steps_by_frame_count() {
        let enc = &mut MediaEncoder::new(AmrRtp::amr_wb(0x11223344));
        // First packet: one frame at ts=0.
        let p0 = enc
            .encode(&Payload::single_speech(8, speech(8), true).unwrap())
            .unwrap();
        assert_eq!(p0.timestamp, 0);
        assert_eq!(p0.sequence, 1);
        // Second packet: ts advances by one 20 ms frame = 320 ticks.
        let p1 = enc
            .encode(&Payload::single_speech(0, speech(0), true).unwrap())
            .unwrap();
        assert_eq!(p1.timestamp, 320);
        assert_eq!(p1.sequence, 2);
    }

    #[test]
    fn multi_frame_advances_timestamp_by_each_frame() {
        let enc = &mut MediaEncoder::new(AmrRtp::amr_wb(1));
        let p = enc
            .encode(&Payload::new(
                0,
                vec![
                    Frame::speech(0, speech(0), false).unwrap(),
                    Frame::speech(1, speech(1), false).unwrap(),
                    Frame::speech(2, speech(2), false).unwrap(),
                ],
            ))
            .unwrap();
        // Three 20 ms frames => 3 * 320 ticks in one packet's timestamp step.
        assert_eq!(p.timestamp, 0);
        let p2 = enc
            .encode(&Payload::single_speech(3, speech(3), false).unwrap())
            .unwrap();
        assert_eq!(p2.timestamp, 3 * 320);
    }

    #[test]
    fn wire_packet_carries_cmr_and_toc() {
        // CMR=8, single FT=8 speech frame => payload starts 0x80 0x08...
        let rtp = AmrRtp::amr_wb(0xAABBCCDD);
        let payload = Payload::single_speech(8, speech(8), true).unwrap();
        let bytes = rtp.payload_bytes(&payload).unwrap();
        assert_eq!(bytes[0], 0x80); // CMR=8, no F bit.
                                    // ToC: F=0, FT=8 (0x40), Q=1 (0x04), P=0 => 0x44.
        assert_eq!(bytes[1], 0x44);
        let packet = RtpPacket::new(rtp.payload_type, 1, 0, rtp.ssrc);
        assert_eq!(packet.payload_type, AMR_WB_PAYLOAD_TYPE);
    }

    #[test]
    fn encode_then_parse_round_trips() {
        let enc = &mut MediaEncoder::new(AmrRtp::amr_wb(7));
        let original = Payload::new(
            0,
            vec![
                Frame::speech(2, speech(2), true).unwrap(),
                Frame::speech(4, speech(4), false).unwrap(),
            ],
        );
        let packet = enc.encode(&original).unwrap();
        let rtp = AmrRtp::amr_wb(7);
        let parsed = rtp.parse_payload(&packet.payload).unwrap();
        assert_eq!(parsed, original);
        assert!(packet.marker);
    }

    #[test]
    fn sequence_wraps() {
        let enc = &mut MediaEncoder::new(AmrRtp::amr_wb(1));
        let mut seqs = Vec::new();
        for _ in 0..(u16::MAX as usize + 3) {
            let p = enc
                .encode(&Payload::single_speech(0, speech(0), false).unwrap())
                .unwrap();
            seqs.push(p.sequence);
        }
        // Started at 1; after 65538 packets the sequence wrapped past 65535 to 2.
        assert!(seqs.last().copied().unwrap() < 16, "sequence did not wrap");
    }
}

#[cfg(test)]
mod nb_tests {
    use super::*;
    use codec_amr::rtp::Frame;

    #[test]
    fn an_amr_nb_stream_uses_8khz_and_160_sample_frames() {
        let rtp = AmrRtp::amr_nb(0x1234);
        assert_eq!(rtp.clock_rate, 8_000);
        assert_eq!(rtp.frame_samples, 160);
        assert_eq!(rtp.payload_type, AMR_NB_PAYLOAD_TYPE);
        // 20 ms of 8 kHz is 160 ticks.
        assert_eq!(rtp.timestamp_for(0), 0);
        assert_eq!(rtp.timestamp_for(1), 160);
        assert_eq!(rtp.timestamp_for(50), 8_000);
    }

    #[test]
    fn narrowband_frames_are_parsed_as_narrowband() {
        let mut encoder = MediaEncoder::new(AmrRtp::amr_nb(7));
        // 12.2 kbit/s is 31 octets in AMR-NB.
        let frame = Frame::speech_in(Band::Nb, 7, vec![0x5A; 31], true).unwrap();
        let payload = Payload::new(7, vec![frame]);
        let packet = encoder.encode(&payload).unwrap();
        assert_eq!(packet.payload_type, AMR_NB_PAYLOAD_TYPE);
        assert_eq!(packet.timestamp, 0);

        let parsed = encoder.rtp.parse_payload(&packet.payload).unwrap();
        assert_eq!(parsed.speech_modes_in(Band::Nb), vec![7]);
        assert!(parsed.has_speech_in(Band::Nb));

        // The next frame advances by 160 ticks, not 320.
        let frame = Frame::speech_in(Band::Nb, 7, vec![0x5A; 31], true).unwrap();
        let packet = encoder.encode(&Payload::new(7, vec![frame])).unwrap();
        assert_eq!(packet.timestamp, 160);
    }

    #[test]
    fn a_narrowband_sid_frame_is_not_reported_as_speech() {
        let mut encoder = MediaEncoder::new(AmrRtp::amr_nb(7));
        let sid = Frame::sid_in(Band::Nb, vec![0u8; 5], true).unwrap();
        let packet = encoder.encode(&Payload::new(7, vec![sid])).unwrap();
        let parsed = encoder.rtp.parse_payload(&packet.payload).unwrap();
        assert!(!parsed.has_speech_in(Band::Nb));
        // Read as wideband it would look like a 12.2 kbit/s speech frame, which
        // is exactly why the band comes from the SDP and not the payload.
        assert!(parsed.has_speech_in(Band::Wb));
    }
}
