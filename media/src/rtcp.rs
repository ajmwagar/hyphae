//! RTCP sender/receiver reports (RFC 3550 §6.1–§6.4).
//!
//! Minimal but wire-exact: a header, the SR sender-info block, and zero or more
//! reception-statistics report blocks. This is enough to advertise transmit
//! counts and to report loss/jitter back to a sender — the pieces a lab or a
//! network analyzer checks. Sender-exchange (BYE, SDES) and compound-packet
//! pacing are out of scope.

use crate::{MediaError, RTCP_RR, RTCP_SR};

const RTCP_VERSION: u8 = 2;
/// Report block size (RFC 3550 §6.4.1): seven 32-bit words.
const REPORT_BLOCK_BYTES: usize = 28;

/// One reception-statistics block for a single SSRC (RFC 3550 §6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportBlock {
    /// SSRC of the source being reported on.
    pub ssrc: u32,
    /// Fraction of packets lost since the last report, 0..=255 (fixed-point).
    pub fraction_lost: u8,
    /// Cumulative packets lost (negative for negative loss), 24-bit signed.
    pub cumulative_lost: i32,
    /// Expected packets: `received + lost`.
    pub expected: u32,
    /// Packets actually received.
    pub received: u32,
    /// Interarrival jitter estimate, in the RTP clock units.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last SR/RR from this source.
    pub last_sender_report: u32,
    /// Delay, in 1/65536 s, between receiving that SR and sending this RR.
    pub delay: u32,
}

impl ReportBlock {
    fn to_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        // Byte 0: fraction lost. Bytes 1-3: 24-bit signed cumulative loss.
        out.push(self.fraction_lost);
        let cum = self.cumulative_lost & 0x00ff_ffff;
        out.push((cum >> 16) as u8);
        out.push((cum >> 8) as u8);
        out.push(cum as u8);
        out.extend_from_slice(&self.expected.to_be_bytes());
        out.extend_from_slice(&self.received.to_be_bytes());
        out.extend_from_slice(&self.jitter.to_be_bytes());
        out.extend_from_slice(&self.last_sender_report.to_be_bytes());
        out.extend_from_slice(&self.delay.to_be_bytes());
    }

    fn parse(data: &[u8], offset: &mut usize) -> Result<Self, MediaError> {
        let word = |data: &[u8], offset: &mut usize| -> u32 {
            let b = [
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ];
            *offset += 4;
            u32::from_be_bytes(b)
        };
        let ssrc = word(data, offset);
        let fraction_lost = data[*offset];
        let cum = ((data[*offset + 1] as u32) << 16)
            | ((data[*offset + 2] as u32) << 8)
            | (data[*offset + 3] as u32);
        *offset += 4;
        // Interpret the 24-bit field as signed.
        let cumulative_lost = if cum & 0x0080_0000 != 0 {
            (cum | 0xff00_0000) as i32
        } else {
            cum as i32
        };
        let expected = word(data, offset);
        let received = word(data, offset);
        let jitter = word(data, offset);
        let last_sender_report = word(data, offset);
        let delay = word(data, offset);
        Ok(Self {
            ssrc,
            fraction_lost,
            cumulative_lost,
            expected,
            received,
            jitter,
            last_sender_report,
            delay,
        })
    }
}

/// RTCP sender report (PT=200): transmit counts plus reception feedback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub ssrc: u32,
    /// NTP wall-clock seconds (upper 32 bits of the 64-bit NTP timestamp).
    pub ntp_seconds: u32,
    /// NTP fractional seconds (lower 32 bits).
    pub ntp_fraction: u32,
    /// RTP timestamp corresponding to the packet-count snapshot.
    pub rtp_timestamp: u32,
    /// Total RTP packets sent on this SSRC.
    pub packet_count: u32,
    /// Total RTP octets sent (payload only) on this SSRC.
    pub octet_count: u32,
    pub blocks: Vec<ReportBlock>,
}

/// RTCP receiver report (PT=201): reception feedback only, no sender info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub ssrc: u32,
    pub blocks: Vec<ReportBlock>,
}

/// Any RTCP report packet, for a single compound-packet slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    Sender(SenderReport),
    Receiver(ReceiverReport),
}

impl RtcpPacket {
    /// The SSRC that originated this report.
    pub fn ssrc(&self) -> u32 {
        match self {
            RtcpPacket::Sender(s) => s.ssrc,
            RtcpPacket::Receiver(r) => r.ssrc,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RtcpPacket::Sender(s) => s.to_bytes(),
            RtcpPacket::Receiver(r) => r.to_bytes(),
        }
    }

    /// Parse one RTCP packet from the front of `data`; returns it and the number
    /// of bytes consumed (so a compound packet can be walked).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), MediaError> {
        if data.len() < 8 {
            return Err(MediaError::TooShort {
                need: 8,
                have: data.len(),
            });
        }
        let rc = data[0] & 0x1f;
        let version = data[0] >> 6;
        if version != RTCP_VERSION {
            return Err(MediaError::BadRtcpVersion(version));
        }
        let pt = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let total = (length + 1) * 4;
        if data.len() < total {
            return Err(MediaError::TooShort {
                need: total,
                have: data.len(),
            });
        }
        let mut offset = 4;
        let ssrc = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        match pt {
            RTCP_SR => {
                let ntp_seconds = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                let ntp_fraction = u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let rtp_timestamp = u32::from_be_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]);
                let packet_count = u32::from_be_bytes([
                    data[offset + 12],
                    data[offset + 13],
                    data[offset + 14],
                    data[offset + 15],
                ]);
                let octet_count = u32::from_be_bytes([
                    data[offset + 16],
                    data[offset + 17],
                    data[offset + 18],
                    data[offset + 19],
                ]);
                offset += 20;
                let mut blocks = Vec::new();
                for _ in 0..rc {
                    blocks.push(ReportBlock::parse(data, &mut offset)?);
                }
                Ok((
                    RtcpPacket::Sender(SenderReport {
                        ssrc,
                        ntp_seconds,
                        ntp_fraction,
                        rtp_timestamp,
                        packet_count,
                        octet_count,
                        blocks,
                    }),
                    total,
                ))
            }
            RTCP_RR => {
                let mut blocks = Vec::new();
                for _ in 0..rc {
                    blocks.push(ReportBlock::parse(data, &mut offset)?);
                }
                Ok((RtcpPacket::Receiver(ReceiverReport { ssrc, blocks }), total))
            }
            other => Err(MediaError::Payload(format!("unsupported RTCP PT {other}"))),
        }
    }
}

impl SenderReport {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rc = self.blocks.len() as u8;
        let total = 8 + 20 + self.blocks.len() * REPORT_BLOCK_BYTES;
        let length = total / 4 - 1;
        let mut out = Vec::with_capacity(total);
        out.push((RTCP_VERSION << 6) | rc);
        out.push(RTCP_SR);
        out.extend_from_slice(&(length as u16).to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(&self.ntp_seconds.to_be_bytes());
        out.extend_from_slice(&self.ntp_fraction.to_be_bytes());
        out.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.octet_count.to_be_bytes());
        for b in &self.blocks {
            b.to_bytes(&mut out);
        }
        out
    }
}

impl ReceiverReport {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rc = self.blocks.len() as u8;
        let total = 8 + self.blocks.len() * REPORT_BLOCK_BYTES;
        let length = total / 4 - 1;
        let mut out = Vec::with_capacity(total);
        out.push((RTCP_VERSION << 6) | rc);
        out.push(RTCP_RR);
        out.extend_from_slice(&(length as u16).to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for b in &self.blocks {
            b.to_bytes(&mut out);
        }
        out
    }
}

/// Fraction of packets lost over a run, as a 0..=1 ratio (for building the
/// fixed-point `fraction_lost` byte: `round(frac * 255)`).
pub fn fraction_lost(expected: u32, received: u32) -> u8 {
    if expected == 0 {
        return 0;
    }
    let lost = expected.saturating_sub(received) as f64;
    let frac = lost / expected as f64;
    (frac * 255.0).round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_block() -> ReportBlock {
        ReportBlock {
            ssrc: 0x01020304,
            fraction_lost: 12,
            cumulative_lost: -3,
            expected: 100,
            received: 97,
            jitter: 42,
            last_sender_report: 0xAABBCCDD,
            delay: 1000,
        }
    }

    #[test]
    fn sender_report_round_trip() {
        let sr = SenderReport {
            ssrc: 0xdeadbeef,
            ntp_seconds: 0x0123_4567,
            ntp_fraction: 0x89ab_cdef,
            rtp_timestamp: 0x1122_3344,
            packet_count: 50,
            octet_count: 50 * 40,
            blocks: vec![sample_block()],
        };
        let bytes = sr.to_bytes();
        assert_eq!(bytes.len(), 56); // 8 + 20 + 28.
        assert_eq!(bytes[1], RTCP_SR);
        assert_eq!(bytes[0] >> 6, 2); // V=2.
        let (parsed, consumed) = RtcpPacket::parse(&bytes).unwrap();
        assert_eq!(consumed, 56);
        assert_eq!(parsed, RtcpPacket::Sender(sr));
    }

    #[test]
    fn receiver_report_round_trip() {
        let rr = ReceiverReport {
            ssrc: 0x1111_2222,
            blocks: vec![sample_block(), sample_block()],
        };
        let bytes = rr.to_bytes();
        assert_eq!(bytes.len(), 8 + 2 * 28);
        let (parsed, consumed) = RtcpPacket::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, RtcpPacket::Receiver(rr));
    }

    #[test]
    fn zero_block_reports_have_correct_length() {
        let sr = SenderReport {
            ssrc: 1,
            ntp_seconds: 0,
            ntp_fraction: 0,
            rtp_timestamp: 0,
            packet_count: 1,
            octet_count: 40,
            blocks: vec![],
        };
        let bytes = sr.to_bytes();
        assert_eq!(bytes.len(), 28);
        // length field (words 2-3) = total/4 - 1 = 6.
        assert_eq!((bytes[2] as u16) << 8 | bytes[3] as u16, 6);
    }

    #[test]
    fn signed_cumulative_loss_preserved() {
        let b = sample_block();
        let mut bytes = Vec::new();
        b.to_bytes(&mut bytes);
        let mut offset = 0;
        let q = ReportBlock::parse(&bytes, &mut offset).unwrap();
        assert_eq!(q.cumulative_lost, -3);
        assert_eq!(q.ssrc, 0x01020304);
    }

    #[test]
    fn fraction_lost_helper() {
        assert_eq!(fraction_lost(100, 97), 8); // 3/100 => 0.03 => round(7.65).
        assert_eq!(fraction_lost(100, 100), 0);
        assert_eq!(fraction_lost(10, 0), 255);
        assert_eq!(fraction_lost(0, 0), 0);
    }

    #[test]
    fn bad_rtcp_version_rejected() {
        let mut bytes = SenderReport {
            ssrc: 1,
            ntp_seconds: 0,
            ntp_fraction: 0,
            rtp_timestamp: 0,
            packet_count: 1,
            octet_count: 0,
            blocks: vec![],
        }
        .to_bytes();
        bytes[0] = (1 << 6) | (bytes[0] & 0x1f); // V=1.
        assert_eq!(
            RtcpPacket::parse(&bytes).unwrap_err(),
            MediaError::BadRtcpVersion(1)
        );
    }
}
