//! Packet-loss concealment (PLC).
//!
//! When the jitter buffer declares a packet lost, or the AMR decoder reports a
//! bad frame (FT=14), the media path must produce something rather than silence
//! (which clicks). This is a small gain-faded repetition PLC: it holds the last
//! good frame and decays its gain each concealed frame, the same family of
//! behaviour as the ETSI AMR bad-frame handler. It operates purely on PCM, so
//! it is codec-agnostic and needs no speech model.

/// Gain multiplier applied to the held frame on the first concealed frame, then
/// squared-away each further frame. Mirrors the ETSI "reduce the gain" step.
const FIRST_FADE: f32 = 0.5;

/// A PCM concealment helper bound to one frame size (samples per 20 ms frame).
#[derive(Debug, Clone)]
pub struct Plc {
    frame_samples: usize,
    last_frame: Vec<i16>,
    /// Number of frames since the last good frame; drives the fade.
    fade_frames: usize,
}

impl Plc {
    pub fn new(frame_samples: usize) -> Self {
        Self {
            frame_samples,
            last_frame: Vec::new(),
            fade_frames: 0,
        }
    }

    /// Record a good (successfully decoded) frame so future concealment can hold
    /// it. Resets the fade.
    pub fn note_good_frame(&mut self, pcm: &[i16]) {
        self.last_frame = pcm.to_vec();
        self.fade_frames = 0;
    }

    /// How many frames have been concealed since the last good one.
    pub fn fade_frames(&self) -> usize {
        self.fade_frames
    }

    /// Produce `frames` frames of concealed PCM: the held frame with gain
    /// `FIRST_FADE^n` on the n-th concealed frame. If no good frame has been
    /// seen yet, the output is silence.
    pub fn conceal(&mut self, frames: usize) -> Vec<i16> {
        let mut out = Vec::with_capacity(frames * self.frame_samples);
        for n in 0..frames {
            // Fade continues across calls: the k-th concealed frame overall is
            // `k+1` halvings down, so the first bad frame is already halved.
            let gain = FIRST_FADE.powi((self.fade_frames + n) as i32 + 1);
            for s in 0..self.frame_samples {
                let v = self.last_frame.get(s).copied().unwrap_or(0);
                let sample = (v as f32 * gain).round();
                out.push(clamp_i16(sample));
            }
        }
        self.fade_frames += frames;
        out
    }

    /// Conceal exactly one frame.
    pub fn conceal_frame(&mut self) -> Vec<i16> {
        self.conceal(1)
    }
}

#[inline]
fn clamp_i16(v: f32) -> i16 {
    v.clamp(i16::MIN as f32, i16::MAX as f32) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_prior_frame_yields_silence() {
        let mut plc = Plc::new(320);
        let out = plc.conceal(1);
        assert_eq!(out.len(), 320);
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn conceals_by_fading_the_last_frame() {
        let mut plc = Plc::new(4);
        // A simple ramp as the "last good frame".
        plc.note_good_frame(&[0, 100, 200, 400]);
        let first = plc.conceal(1);
        assert_eq!(first, vec![0, 50, 100, 200]); // half gain.
        let second = plc.conceal(1);
        assert_eq!(second, vec![0, 25, 50, 100]); // quarter gain.
        assert_eq!(plc.fade_frames(), 2);
    }

    #[test]
    fn multi_frame_conceal_keeps_length() {
        let mut plc = Plc::new(320);
        plc.note_good_frame(&[1; 320]);
        let out = plc.conceal(3);
        assert_eq!(out.len(), 3 * 320);
        assert!(out.iter().all(|&s| s >= 0));
    }

    #[test]
    fn good_frame_resets_fade() {
        let mut plc = Plc::new(2);
        plc.note_good_frame(&[10, 20]);
        let _ = plc.conceal(2);
        assert_eq!(plc.fade_frames(), 2);
        plc.note_good_frame(&[10, 20]);
        assert_eq!(plc.fade_frames(), 0);
    }
}
