//! Call-audio plumbing: the seam between decoded PCM and a sound device.
//!
//! The codec side of this crate produces 16-bit mono PCM frames; the platform
//! side is a sound device, a modem voice channel, or a capture file. This module
//! defines that seam without linking any audio library:
//!
//! * [`AudioSink`] / [`AudioSource`] — what an output and an input device must
//!   implement. An ALSA/PulseAudio adapter implements these **out of tree**, the
//!   same way the CCCI and PC/SC adapters do, so the default build stays
//!   pure-Rust and `#![forbid(unsafe_code)]`.
//! * [`RingBuffer`] — the bounded frame queue between threads. Overflow drops a
//!   frame and counts it; underrun returns silence, which is what a jitter
//!   buffer does at the edge of a call.
//! * [`LoopbackSink`] / [`LoopbackSource`] — a connected pair for tests and for
//!   the lab, so the whole media path runs without a sound card.
//! * [`Wav`] — a 16-bit PCM capture sink, useful for debugging a call without a
//!   device.
//!
//! Nothing here starts a thread or opens a device.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Errors from the audio boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioError {
    /// The device rejected the write.
    Sink(String),
    /// The device rejected the read.
    Source(String),
    /// The device is closed.
    Closed,
}

impl core::fmt::Display for AudioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AudioError::Sink(s) => write!(f, "audio sink error: {s}"),
            AudioError::Source(s) => write!(f, "audio source error: {s}"),
            AudioError::Closed => f.write_str("audio device closed"),
        }
    }
}

impl std::error::Error for AudioError {}

/// An output device: one call to `write` is one frame group.
pub trait AudioSink {
    /// Write interleaved 16-bit PCM samples.
    fn write(&mut self, samples: &[i16]) -> Result<(), AudioError>;
    /// Flush any internal buffer (a no-op for most devices).
    fn flush(&mut self) -> Result<(), AudioError> {
        Ok(())
    }
}

/// An input device: fill `out` with up to `out.len()` samples.
pub trait AudioSource {
    /// Read interleaved 16-bit PCM into `out`, waiting at most `timeout`.
    /// Returns the number of samples written (0 on timeout).
    fn read(&mut self, out: &mut [i16], timeout: Duration) -> Result<usize, AudioError>;
}

/// A bounded inter-thread frame queue.
///
/// `capacity` is in samples. `push` drops the oldest sample on overflow and
/// counts it; `pop` fills the tail with silence on underrun and counts that too.
#[derive(Debug)]
pub struct RingBuffer {
    buffer: Vec<i16>,
    capacity: usize,
    dropped: u64,
    underruns: u64,
}

impl RingBuffer {
    /// Create a ring holding at most `capacity` samples.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity: capacity.max(1),
            dropped: 0,
            underruns: 0,
        }
    }

    /// Samples currently queued.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Samples dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Reads that ran short and were padded with silence.
    pub fn underruns(&self) -> u64 {
        self.underruns
    }

    /// Append samples, dropping the oldest on overflow.
    pub fn push(&mut self, samples: &[i16]) {
        for &s in samples {
            if self.buffer.len() == self.capacity {
                self.buffer.remove(0);
                self.dropped += 1;
            }
            self.buffer.push(s);
        }
    }

    /// Remove up to `out.len()` samples; pad the tail with silence.
    pub fn pop_into(&mut self, out: &mut [i16]) -> usize {
        let n = out.len().min(self.buffer.len());
        out[..n].copy_from_slice(&self.buffer[..n]);
        self.buffer.drain(..n);
        for slot in &mut out[n..] {
            *slot = 0;
        }
        if n < out.len() {
            self.underruns += 1;
        }
        n
    }
}

type Shared = Arc<Mutex<RingBuffer>>;

/// The writing half of a [`Loopback`] pair.
pub struct LoopbackSink(Shared);

/// The reading half of a [`Loopback`] pair.
pub struct LoopbackSource(Shared);

/// An in-memory sink/source pair.
pub struct Loopback;

impl Loopback {
    /// Create a connected pair with a queue of `capacity` samples.
    pub fn pair(capacity: usize) -> (LoopbackSink, LoopbackSource) {
        let shared = Arc::new(Mutex::new(RingBuffer::new(capacity)));
        (LoopbackSink(shared.clone()), LoopbackSource(shared))
    }
}

impl AudioSink for LoopbackSink {
    fn write(&mut self, samples: &[i16]) -> Result<(), AudioError> {
        self.0
            .lock()
            .map_err(|_| AudioError::Sink("loopback poisoned".into()))?
            .push(samples);
        Ok(())
    }
}

impl AudioSource for LoopbackSource {
    fn read(&mut self, out: &mut [i16], _timeout: Duration) -> Result<usize, AudioError> {
        let mut ring = self
            .0
            .lock()
            .map_err(|_| AudioError::Source("loopback poisoned".into()))?;
        Ok(ring.pop_into(out))
    }
}

/// A sink that discards everything (the lab default when no device exists).
#[derive(Debug, Default)]
pub struct NullSink {
    /// Frames written, for assertions.
    pub samples: u64,
}

impl AudioSink for NullSink {
    fn write(&mut self, samples: &[i16]) -> Result<(), AudioError> {
        self.samples += samples.len() as u64;
        Ok(())
    }
}

/// A source that always returns silence, i.e. a disconnected input.
#[derive(Debug, Default)]
pub struct SilentSource;

impl AudioSource for SilentSource {
    fn read(&mut self, out: &mut [i16], _timeout: Duration) -> Result<usize, AudioError> {
        for slot in out.iter_mut() {
            *slot = 0;
        }
        Ok(out.len())
    }
}

/// A 16-bit PCM mono capture sink. Buffers samples and writes a RIFF/WAVE file.
#[derive(Debug, Clone)]
pub struct Wav {
    sample_rate: u32,
    channels: u16,
    samples: Vec<i16>,
}

impl Wav {
    /// A mono capture at `sample_rate`.
    pub fn new(sample_rate: u32, channels: u16) -> Self {
        Self {
            sample_rate,
            channels: channels.max(1),
            samples: Vec::new(),
        }
    }

    /// Samples captured so far.
    pub fn samples(&self) -> &[i16] {
        &self.samples
    }

    /// Serialise a canonical 44-byte-header RIFF/WAVE file.
    pub fn to_bytes(&self) -> Vec<u8> {
        let block_align = 2 * self.channels;
        let byte_rate = self.sample_rate * u32::from(block_align);
        let data_len = (self.samples.len() * 2) as u32;
        let mut out = Vec::with_capacity(44 + data_len as usize);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.sample_rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&block_align.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        for s in &self.samples {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// Write the capture to any writer.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

impl AudioSink for Wav {
    fn write(&mut self, samples: &[i16]) -> Result<(), AudioError> {
        self.samples.extend_from_slice(samples);
        Ok(())
    }
}

/// A source backed by a fixed slice of samples (test vector playback).
#[derive(Debug, Clone)]
pub struct SliceSource {
    samples: Vec<i16>,
    at: usize,
}

impl SliceSource {
    pub fn new(samples: impl Into<Vec<i16>>) -> Self {
        Self {
            samples: samples.into(),
            at: 0,
        }
    }
}

impl AudioSource for SliceSource {
    fn read(&mut self, out: &mut [i16], _timeout: Duration) -> Result<usize, AudioError> {
        let remaining = &self.samples[self.at..];
        let n = out.len().min(remaining.len());
        out[..n].copy_from_slice(&remaining[..n]);
        self.at += n;
        for slot in &mut out[n..] {
            *slot = 0;
        }
        Ok(n)
    }
}

/// Playback pacing helper: tells the caller how many samples are due by `now`.
///
/// This is the piece a real device thread uses to drain a jitter buffer at the
/// frame rate instead of as fast as it can read.
#[derive(Debug, Clone)]
pub struct Pacing {
    started: Instant,
    sample_rate: u32,
    played: u64,
}

impl Pacing {
    pub fn new(sample_rate: u32, now: Instant) -> Self {
        Self {
            started: now,
            sample_rate,
            played: 0,
        }
    }

    /// How many samples are due at `now` beyond what was already taken.
    pub fn due(&mut self, now: Instant) -> usize {
        let elapsed = now.saturating_duration_since(self.started);
        let target = (elapsed.as_secs_f64() * f64::from(self.sample_rate)) as u64;
        let due = target.saturating_sub(self.played);
        self.played = target;
        due as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_over_and_under_run_are_counted() {
        let mut ring = RingBuffer::new(4);
        ring.push(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.dropped(), 2);
        let mut out = [0i16; 6];
        let n = ring.pop_into(&mut out);
        assert_eq!(n, 4);
        assert_eq!(out, [3, 4, 5, 6, 0, 0]);
        assert_eq!(ring.underruns(), 1);
    }

    #[test]
    fn loopback_carries_pcm_between_sink_and_source() {
        let (mut sink, mut source) = Loopback::pair(480);
        sink.write(&[10, 20, 30]).unwrap();
        let mut out = [0i16; 4];
        let n = source.read(&mut out, Duration::from_millis(10)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, [10, 20, 30, 0]);
    }

    #[test]
    fn wav_header_is_a_valid_riff_chunk() {
        let mut wav = Wav::new(16_000, 1);
        wav.write(&[1, -1, 2, -2]).unwrap();
        let bytes = wav.to_bytes();
        assert_eq!(&bytes[0..4], b"RIFF");
        assert_eq!(&bytes[8..12], b"WAVE");
        assert_eq!(&bytes[12..16], b"fmt ");
        assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), 1); // PCM
        assert_eq!(u16::from_le_bytes([bytes[22], bytes[23]]), 1); // mono
        assert_eq!(
            u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            16_000
        );
        assert_eq!(
            u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]),
            8
        );
        assert_eq!(bytes.len(), 44 + 8);
        assert_eq!(&bytes[36..40], b"data");
    }

    #[test]
    fn slice_source_pads_with_silence() {
        let mut src = SliceSource::new(vec![7, 8]);
        let mut out = [9i16; 4];
        assert_eq!(src.read(&mut out, Duration::from_millis(1)).unwrap(), 2);
        assert_eq!(out, [7, 8, 0, 0]);
        assert_eq!(src.read(&mut out, Duration::from_millis(1)).unwrap(), 0);
    }

    #[test]
    fn pacing_releases_samples_at_the_frame_rate() {
        let t0 = Instant::now();
        let mut pacing = Pacing::new(16_000, t0);
        assert_eq!(pacing.due(t0), 0);
        // 20 ms at 16 kHz is 320 samples.
        assert_eq!(pacing.due(t0 + Duration::from_millis(20)), 320);
        assert_eq!(pacing.due(t0 + Duration::from_millis(40)), 320);
        assert_eq!(pacing.due(t0 + Duration::from_millis(40)), 0);
    }

    #[test]
    fn null_sink_counts() {
        let mut sink = NullSink::default();
        sink.write(&[0; 320]).unwrap();
        assert_eq!(sink.samples, 320);
    }
}
