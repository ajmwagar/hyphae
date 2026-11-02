//! A two-way audio session: capture, encode, send, receive, decode, play.
//!
//! The pieces already existed separately — RTP framing, a jitter buffer, packet
//! loss concealment, a codec trait, and `AudioSink`/`AudioSource` boundaries —
//! and nothing joined them. This is the join.
//!
//! ## Shape
//!
//! The session is a **state machine driven by a clock**, not a thread and not a
//! task. [`MediaSession::tick`] takes "now" and returns the RTP packets to send;
//! [`MediaSession::on_rtp`] takes a received datagram. The caller owns the
//! socket and the device. That is the same division as everywhere else in this
//! tree: no runtime, no I/O in the protocol crates, and a deterministic
//! sequence you can test by moving a `Duration` forward.
//!
//! ```text
//!   Source ──▶ encode ──▶ RTP ──▶ caller sends
//!                                  caller receives ──▶ jitter ──▶ decode ──▶ Sink
//! ```
//!
//! ## What it does not do
//!
//! No RTCP scheduling, no rate adaptation, no encryption (SRTP), no mixing. The
//! jitter buffer absorbs reordering; a gap is concealed by [`Plc`] and counted,
//! because a call must not stop for a lost packet.

#![forbid(unsafe_code)]

use std::time::Instant;

use codec::Codec;

use crate::audio::{AudioError, AudioSink, AudioSource, Pacing};
use crate::jitter::JitterBuffer;
use crate::packet::RtpPacket;
use crate::plc::Plc;

/// How a session is wired to the stream it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    /// Synchronisation source for outgoing packets.
    pub ssrc: u32,
    /// RTP payload type negotiated in the SDP.
    pub payload_type: u8,
    /// RTP clock rate in Hz (from the codec).
    pub clock_rate: u32,
    /// PCM samples per frame per channel (from the codec).
    pub frame_samples: usize,
    /// Playout delay in packets, in frames of `frame_samples`.
    pub jitter_target: u16,
}

impl SessionConfig {
    /// Derive the clock and frame size from a codec.
    pub fn for_codec(codec: &dyn Codec, ssrc: u32, payload_type: u8) -> Self {
        Self {
            ssrc,
            payload_type,
            clock_rate: codec.clock_rate(),
            frame_samples: codec.frame_samples(),
            // Two frames of playout delay: enough to absorb reordering on a
            // Wi-Fi link without adding audible latency.
            jitter_target: 2,
        }
    }
}

/// What one [`MediaSession::tick`] produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MediaTick {
    /// RTP packets the caller should send, in order.
    pub send: Vec<RtpPacket>,
    /// Frames written to the sink.
    pub played: usize,
    /// Frames played as concealment because nothing had arrived yet.
    pub concealed: usize,
    /// Frames whose encode failed and were skipped.
    pub encode_failures: usize,
    /// Frames whose decode failed and were concealed instead.
    pub decode_failures: usize,
}

/// A fatal session error. Codec and jitter problems are counted, not fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The audio device failed.
    Audio(AudioError),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::Audio(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// One audio stream in each direction, tied to a codec and an audio device.
pub struct MediaSession {
    codec: Box<dyn Codec>,
    sink: Box<dyn AudioSink>,
    source: Box<dyn AudioSource>,
    jitter: JitterBuffer,
    plc: Plc,
    pacing: Pacing,
    config: SessionConfig,

    sequence: u16,
    timestamp: u32,
    /// Samples owed to the codec but not yet a whole frame.
    pending_samples: usize,
    /// Whether anything has ever arrived; concealment before that is silence,
    /// not a loss.
    receiving: bool,
    concealed: u64,
    encode_failures: u64,
    decode_failures: u64,
}

impl MediaSession {
    /// Create a session. The clock starts at `start`.
    pub fn new(
        config: SessionConfig,
        codec: Box<dyn Codec>,
        sink: Box<dyn AudioSink>,
        source: Box<dyn AudioSource>,
        start: Instant,
    ) -> Self {
        let jitter = JitterBuffer::new(config.jitter_target);
        Self {
            plc: Plc::new(codec.frame_samples()),
            pacing: Pacing::new(config.clock_rate, start),
            codec,
            sink,
            source,
            jitter,
            config,
            // Sequence numbers start at one, so an empty stream is
            // distinguishable from a stream that has never sent.
            sequence: 1,
            timestamp: 0,
            pending_samples: 0,
            receiving: false,
            concealed: 0,
            encode_failures: 0,
            decode_failures: 0,
        }
    }

    /// The configuration this session was built with.
    pub fn config(&self) -> SessionConfig {
        self.config
    }

    /// The next outgoing sequence number.
    pub fn sequence(&self) -> u16 {
        self.sequence
    }

    /// The next outgoing RTP timestamp.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Packets pushed into the jitter buffer so far.
    pub fn packets_received(&self) -> u64 {
        self.jitter.pushed()
    }

    /// Frames played as concealment over the whole session.
    pub fn concealed_frames(&self) -> u64 {
        self.concealed
    }

    /// Take the sequence numbers the jitter buffer has declared lost.
    pub fn take_losses(&mut self) -> Vec<u16> {
        self.jitter.take_losses()
    }

    /// A received RTP datagram.
    ///
    /// A datagram that does not parse is ignored rather than fatal: the far end
    /// can send anything, and a malformed packet must not end a call.
    pub fn on_rtp(&mut self, datagram: &[u8]) -> bool {
        let Ok(packet) = RtpPacket::decode(datagram) else {
            return false;
        };
        self.jitter.push(packet);
        self.receiving = true;
        true
    }

    /// Advance the session to `now`: send what is due and play what is ready.
    pub fn tick(&mut self, now: Instant) -> Result<MediaTick, SessionError> {
        let mut tick = MediaTick::default();

        let due = self.pacing.due(now);
        self.pending_samples += due;
        let frames = self.pending_samples / self.config.frame_samples;
        self.pending_samples %= self.config.frame_samples;

        for _ in 0..frames {
            // Capture and encode one frame.
            let mut pcm = vec![0i16; self.config.frame_samples];
            match self.source.read(&mut pcm, std::time::Duration::ZERO) {
                Ok(n) if n < pcm.len() => pcm[n..].fill(0),
                Ok(_) => {}
                // A device that fails to read is identical to a silent one for
                // the other end; the frame continues rather than stalling.
                Err(_) => pcm.fill(0),
            }

            let mut encoded = vec![0u8; self.codec.frame_samples() * 4];
            match self.codec.encode(&pcm, &mut encoded) {
                Ok(len) => {
                    let mut packet = RtpPacket::new(
                        self.config.payload_type,
                        self.sequence,
                        self.timestamp,
                        self.config.ssrc,
                    );
                    packet.payload = encoded[..len].to_vec();
                    tick.send.push(packet);
                    self.sequence = self.sequence.wrapping_add(1);
                    self.timestamp = self
                        .timestamp
                        .wrapping_add(self.config.frame_samples as u32);
                }
                Err(_) => {
                    // The sequence number does not advance: the frame was never
                    // sent, and a gap would be reported as loss by the far end.
                    self.encode_failures += 1;
                    tick.encode_failures += 1;
                }
            }

            // Play one frame.
            match self.jitter.pop() {
                Some(packet) => {
                    let mut decoded = vec![0i16; self.config.frame_samples];
                    match self.codec.decode(&packet.payload, &mut decoded) {
                        Ok(n) => {
                            decoded.truncate(n);
                            self.plc.note_good_frame(&decoded);
                            self.sink.write(&decoded).map_err(SessionError::Audio)?;
                            tick.played += 1;
                        }
                        Err(_) => {
                            self.decode_failures += 1;
                            tick.decode_failures += 1;
                            let concealed = self.plc.conceal_frame();
                            self.sink.write(&concealed).map_err(SessionError::Audio)?;
                            tick.played += 1;
                            tick.concealed += 1;
                        }
                    }
                }
                None if self.receiving => {
                    // Receiving, so an empty buffer is a gap: conceal it rather
                    // than emitting a hard discontinuity.
                    let concealed = self.plc.conceal_frame();
                    self.sink.write(&concealed).map_err(SessionError::Audio)?;
                    self.concealed += 1;
                    tick.played += 1;
                    tick.concealed += 1;
                }
                // Nothing has ever arrived: say nothing.
                None => {}
            }
        }

        Ok(tick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::{NullSink, SilentSource};
    use codec::PcmCodec;
    use std::time::Duration;

    fn config() -> SessionConfig {
        SessionConfig {
            ssrc: 0x1234,
            payload_type: 96,
            clock_rate: 48_000,
            frame_samples: 960,
            jitter_target: 2,
        }
    }

    fn session(start: Instant) -> MediaSession {
        MediaSession::new(
            config(),
            Box::new(PcmCodec::new()),
            Box::new(NullSink::default()),
            Box::new(SilentSource),
            start,
        )
    }

    #[test]
    fn ticks_produce_packets_at_the_frame_rate() {
        let start = Instant::now();
        let mut session = session(start);
        // Nothing is due before one frame of wall clock has passed.
        assert!(session.tick(start).unwrap().send.is_empty());
        // 20 ms at 48 kHz is exactly one 960-sample frame.
        let tick = session.tick(start + Duration::from_millis(20)).unwrap();
        assert_eq!(tick.send.len(), 1);
        assert_eq!(tick.send[0].sequence, 1);
        assert_eq!(tick.send[0].timestamp, 0);
        assert_eq!(tick.send[0].payload_type, 96);
        assert_eq!(tick.send[0].ssrc, 0x1234);

        let tick = session.tick(start + Duration::from_millis(40)).unwrap();
        assert_eq!(tick.send[0].sequence, 2);
        assert_eq!(tick.send[0].timestamp, 960);
    }

    #[test]
    fn a_long_gap_sends_the_frames_that_were_missed() {
        let start = Instant::now();
        let mut session = session(start);
        // 100 ms is five frames; the session catches up rather than dropping.
        let tick = session.tick(start + Duration::from_millis(100)).unwrap();
        assert_eq!(tick.send.len(), 5);
        let sequences: Vec<u16> = tick.send.iter().map(|p| p.sequence).collect();
        assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
        assert_eq!(tick.send[4].timestamp, 960 * 4);
    }

    #[test]
    fn a_partial_frame_is_carried_not_lost() {
        let start = Instant::now();
        let mut session = session(start);
        // 10 ms: half a frame, nothing to send yet.
        assert!(session
            .tick(start + Duration::from_millis(10))
            .unwrap()
            .send
            .is_empty());
        // Another 10 ms completes it.
        assert_eq!(
            session
                .tick(start + Duration::from_millis(20))
                .unwrap()
                .send
                .len(),
            1
        );
    }

    #[test]
    fn received_audio_is_played_and_gaps_are_concealed() {
        let start = Instant::now();
        let mut session = session(start);

        // Push four packets so the buffer is primed past the target delay.
        for seq in 1..=4u16 {
            let mut packet = RtpPacket::new(96, seq, u32::from(seq - 1) * 960, 0x99);
            packet.payload = vec![0x10; 1920];
            assert!(session.on_rtp(&packet.encode().unwrap()));
        }
        assert_eq!(session.packets_received(), 4);

        let tick = session.tick(start + Duration::from_millis(20)).unwrap();
        assert_eq!(tick.played, 1);
        assert_eq!(tick.concealed, 0);

        // Drop the next two packets: the buffer runs dry and the session
        // conceals rather than going silent.
        let mut packet = RtpPacket::new(96, 7, 6 * 960, 0x99);
        packet.payload = vec![0x10; 1920];
        assert!(session.on_rtp(&packet.encode().unwrap()));

        let mut concealed = 0;
        for step in 3..=8 {
            concealed += session
                .tick(start + Duration::from_millis(20 * step))
                .unwrap()
                .concealed;
        }
        assert!(concealed > 0, "a gap should be concealed, not silent");
        assert!(
            !session.take_losses().is_empty(),
            "the gap is reported as loss"
        );
    }

    #[test]
    fn nothing_is_played_before_anything_arrives() {
        let start = Instant::now();
        let mut session = session(start);
        let tick = session.tick(start + Duration::from_millis(20)).unwrap();
        assert_eq!(tick.played, 0);
        assert_eq!(tick.concealed, 0);
    }

    #[test]
    fn a_malformed_datagram_is_ignored_not_fatal() {
        let start = Instant::now();
        let mut session = session(start);
        assert!(!session.on_rtp(&[0u8; 3]));
        assert!(!session.on_rtp(b"not an rtp packet"));
        assert_eq!(session.packets_received(), 0);
        // The session still runs.
        assert_eq!(
            session
                .tick(start + Duration::from_millis(20))
                .unwrap()
                .send
                .len(),
            1
        );
    }

    #[test]
    fn the_config_follows_the_codec() {
        let codec = PcmCodec::new();
        let config = SessionConfig::for_codec(&codec, 7, 96);
        assert_eq!(config.clock_rate, codec.clock_rate());
        assert_eq!(config.frame_samples, codec.frame_samples());
        assert_eq!(config.ssrc, 7);
    }
}
