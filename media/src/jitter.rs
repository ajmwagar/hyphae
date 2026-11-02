//! Sequence-number jitter buffer with a fixed playout delay.
//!
//! RTP arrives with variable delay; this buffer reorders it and releases packets
//! a fixed number behind the newest arrival, so a consumer sees in-order packets
//! with steady spacing. Packets that fall behind the playout cursor are declared
//! lost and surfaced to packet-loss concealment rather than played late.
//!
//! Sequence numbers are compared with wrap-around arithmetic (RFC 3550 §8.1),
//! so the buffer is correct across the 16-bit boundary.

use crate::packet::RtpPacket;
use std::collections::BTreeMap;

/// Outcome of pushing a packet into the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Accepted and buffered.
    Accepted,
    /// A packet with this sequence was already buffered (kept the first).
    Duplicate,
    /// Sequence is at or behind the playout cursor — too late to play.
    Old,
}

/// A fixed-delay reorder buffer keyed by RTP sequence number.
#[derive(Debug)]
pub struct JitterBuffer {
    target_delay: u16,
    buffer: BTreeMap<u16, RtpPacket>,
    /// Next sequence to be played out; `None` until the first packet arrives.
    cursor: Option<u16>,
    /// Highest sequence number seen (raw value; compared with wrap arithmetic).
    highest: Option<u16>,
    pushed: u64,
    delivered: u64,
    /// Sequence numbers past the cursor that were not delivered (declared lost).
    losses: Vec<u16>,
}

impl JitterBuffer {
    /// Create a buffer that holds `target_delay` packets behind the newest
    /// arrival before releasing the oldest. A delay of 0 releases as soon as a
    /// packet is the next in order.
    pub fn new(target_delay: u16) -> Self {
        Self {
            target_delay,
            buffer: BTreeMap::new(),
            cursor: None,
            highest: None,
            pushed: 0,
            delivered: 0,
            losses: Vec::new(),
        }
    }

    /// Insert a packet. Duplicate sequences keep the first arrival; packets
    /// behind the cursor are dropped as `Old`.
    pub fn push(&mut self, packet: RtpPacket) -> PushResult {
        self.pushed += 1;
        let seq = packet.sequence;
        if self.buffer.contains_key(&seq) {
            return PushResult::Duplicate;
        }
        // The first packet establishes the play anchor; ordering is forward from
        // there with wrap arithmetic, not by raw u16 value.
        if self.cursor.is_none() {
            self.cursor = Some(seq);
        }
        // Track the furthest-forward arrival so the delay check has a horizon.
        match self.highest {
            None => self.highest = Some(seq),
            Some(h) if wrapping_lt(h, seq) => self.highest = Some(seq),
            Some(_) => {}
        }
        // Strictly behind the playout cursor: the packet already passed.
        if let Some(cursor) = self.cursor {
            if wrapping_lt(seq, cursor) {
                return PushResult::Old;
            }
        }
        self.buffer.insert(seq, packet);
        PushResult::Accepted
    }

    /// Release the next in-order packet if the playout delay is satisfied, else
    /// `None`. When the cursor's packet is missing, it is declared lost and the
    /// cursor advances until a buffered packet is found; losses are reported by
    /// [`JitterBuffer::take_losses`].
    pub fn pop(&mut self) -> Option<RtpPacket> {
        if self.buffer.is_empty() {
            return None;
        }
        let cursor = self.cursor?;
        // Not ready until `target_delay` packets sit ahead of the cursor.
        if let Some(highest) = self.highest {
            if wrapping_distance(cursor, highest) < self.target_delay as usize {
                return None;
            }
        }
        // Find the buffered packet next in forward order from the cursor, which
        // handles wrap-around without a linear scan. Any gap before it is loss.
        let next = *self
            .buffer
            .keys()
            .min_by(|&&a, &&b| wrapping_distance(cursor, a).cmp(&wrapping_distance(cursor, b)))
            .unwrap();
        let gap = wrapping_distance(cursor, next);
        for i in 0..gap {
            self.losses.push(cursor.wrapping_add(i as u16));
        }
        let packet = self.buffer.remove(&next).expect("min was from buffer");
        self.cursor = Some(next.wrapping_add(1));
        self.delivered += 1;
        Some(packet)
    }

    /// Take the sequence numbers declared lost since the last call.
    pub fn take_losses(&mut self) -> Vec<u16> {
        core::mem::take(&mut self.losses)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    pub fn pushed(&self) -> u64 {
        self.pushed
    }
}

/// `a < b` under 16-bit wrap-around (RFC 3550 §8.1 ordering).
#[inline]
fn wrapping_lt(a: u16, b: u16) -> bool {
    (a as i16).wrapping_sub(b as i16) < 0
}

/// Signed distance `b - a` in the forward direction (how far ahead `b` is).
#[inline]
fn wrapping_distance(a: u16, b: u16) -> usize {
    (b as i16).wrapping_sub(a as i16) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(seq: u16) -> RtpPacket {
        RtpPacket::new(97, seq, seq as u32 * 320, 1)
    }

    #[test]
    fn reorders_out_of_order_arrival() {
        let mut jb = JitterBuffer::new(0);
        // Anchor is the first packet (1); a later-out-of-order arrival (2 after
        // 3) is still reordered into 1,2,3 for playout.
        assert_eq!(jb.push(pkt(1)), PushResult::Accepted);
        assert_eq!(jb.push(pkt(3)), PushResult::Accepted);
        assert_eq!(jb.push(pkt(2)), PushResult::Accepted);
        assert_eq!(jb.pop().unwrap().sequence, 1);
        assert_eq!(jb.pop().unwrap().sequence, 2);
        assert_eq!(jb.pop().unwrap().sequence, 3);
        assert_eq!(jb.pop(), None);
    }

    #[test]
    fn playout_delay_holds_packets() {
        let mut jb = JitterBuffer::new(2);
        jb.push(pkt(0));
        jb.push(pkt(1));
        // Only two buffered; cursor=0 needs 2 ahead => highest must be >= 2.
        assert_eq!(jb.pop(), None);
        jb.push(pkt(2));
        // Now highest=2, cursor=0, distance=2 >= delay => release seq 0.
        assert_eq!(jb.pop().unwrap().sequence, 0);
        // cursor=1, highest=2, distance=1 < 2 => hold.
        assert_eq!(jb.pop(), None);
        jb.push(pkt(3));
        assert_eq!(jb.pop().unwrap().sequence, 1);
    }

    #[test]
    fn missing_packet_is_declared_lost() {
        let mut jb = JitterBuffer::new(0);
        jb.push(pkt(1));
        jb.push(pkt(3));
        // cursor=1, delay 0 => deliver 1.
        assert_eq!(jb.pop().unwrap().sequence, 1);
        // Now cursor=2, highest=3, but 2 is missing => declare lost, deliver 3.
        assert_eq!(jb.pop().unwrap().sequence, 3);
        assert_eq!(jb.take_losses(), vec![2]);
    }

    #[test]
    fn duplicate_is_rejected() {
        let mut jb = JitterBuffer::new(0);
        assert_eq!(jb.push(pkt(5)), PushResult::Accepted);
        assert_eq!(jb.push(pkt(5)), PushResult::Duplicate);
        assert_eq!(jb.len(), 1);
    }

    #[test]
    fn sequence_wrap_is_handled() {
        let mut jb = JitterBuffer::new(0);
        // Anchor is 65534; 0 arrives before 65535. Forward-from-anchor order is
        // 65534, 65535, 0 across the 16-bit wrap boundary.
        assert_eq!(jb.push(pkt(u16::MAX - 1)), PushResult::Accepted);
        assert_eq!(jb.push(pkt(0)), PushResult::Accepted);
        assert_eq!(jb.push(pkt(u16::MAX)), PushResult::Accepted);
        assert_eq!(jb.pop().unwrap().sequence, u16::MAX - 1);
        assert_eq!(jb.pop().unwrap().sequence, u16::MAX);
        assert_eq!(jb.pop().unwrap().sequence, 0);
        assert_eq!(jb.pop(), None);
    }
}
