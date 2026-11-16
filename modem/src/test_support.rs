//! Helpers shared by the unit tests. Test-only; not part of the API.

use std::collections::VecDeque;
use std::time::Duration;

use crate::qmi::Transport;
use crate::Error;

/// A scripted QMI peer: records what was sent, replays datagrams, then lets
/// the wait expire.
#[derive(Default)]
pub struct Peer {
    /// Every frame the client sent, in order.
    pub sent: Vec<Vec<u8>>,
    /// Datagrams to hand back, oldest first.
    pub replies: VecDeque<Vec<u8>>,
}

impl Peer {
    /// A peer that answers with `replies`, in order.
    pub fn with_replies(replies: &[&[u8]]) -> Self {
        Self {
            sent: Vec::new(),
            replies: replies.iter().map(|reply| reply.to_vec()).collect(),
        }
    }
}

impl Transport for Peer {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.replies.pop_front())
    }
}

/// Parse a hex string into bytes. Whitespace is ignored, so a capture can be
/// pasted in wire order.
pub fn unhex(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(
        digits.len() % 2 == 0,
        "hex string has an odd number of digits"
    );
    digits
        .chunks(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("hex digits are ascii");
            u8::from_str_radix(text, 16).expect("valid hex digits")
        })
        .collect()
}

/// Render bytes as lower-case hex, for readable assertion failures.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{hex, unhex};

    #[test]
    fn hex_round_trips_and_ignores_whitespace() {
        let bytes = unhex("0a 00 00 00 ff");
        assert_eq!(bytes, vec![0x0a, 0x00, 0x00, 0x00, 0xff]);
        assert_eq!(hex(&bytes), "0a000000ff");
    }
}
