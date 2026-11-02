//! APDU exchange over a pluggable channel (PC/SC, modem card channel, test pipe).
//!
//! [`UsimCard`] wraps any [`ApduChannel`], builds the `AUTHENTICATE` command,
//! transmits it, strips the status word and decodes the response. This crate
//! never opens a reader itself: a real adapter implements [`ApduChannel`] out
//! of tree, so no `unsafe`/FFI is needed here.

#![forbid(unsafe_code)]

use crate::apdu::{authenticate_command, parse_authenticate_response};
use crate::{AkaOutput, Autn, Rand, Usim, UsimError};

/// A card response: the data field plus the two status-word bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardResponse {
    /// Response data field (may be empty).
    pub data: Vec<u8>,
    /// Status word byte 1.
    pub sw1: u8,
    /// Status word byte 2.
    pub sw2: u8,
}

impl CardResponse {
    /// Construct a successful response carrying `data`.
    pub fn ok(data: impl Into<Vec<u8>>) -> Self {
        Self {
            data: data.into(),
            sw1: crate::sw::OK.0,
            sw2: crate::sw::OK.1,
        }
    }

    /// Construct a response with an explicit status word.
    pub fn status(sw1: u8, sw2: u8) -> Self {
        Self {
            data: Vec::new(),
            sw1,
            sw2,
        }
    }

    /// The full `data || SW1 || SW2` wire bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.data);
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }
}

/// The transport to a USIM: send one command APDU, get one response.
pub trait ApduChannel {
    /// Transmit a command APDU (case 3/4 short form) and return the response.
    fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError>;
}

/// A USIM reached through an [`ApduChannel`].
pub struct UsimCard<C: ApduChannel> {
    channel: C,
}

impl<C: ApduChannel> UsimCard<C> {
    /// Wrap a channel.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    /// Borrow the underlying channel.
    pub fn channel(&self) -> &C {
        &self.channel
    }

    /// Borrow the channel mutably (for adapter-specific operations).
    pub fn channel_mut(&mut self) -> &mut C {
        &mut self.channel
    }
}

impl<C: ApduChannel> Usim for UsimCard<C> {
    fn authenticate(&mut self, rand: &Rand, autn: &Autn) -> Result<AkaOutput, UsimError> {
        let command = authenticate_command(rand, autn);
        let response = self.channel.transmit(&command.to_bytes())?;
        if (response.sw1, response.sw2) != crate::sw::OK {
            return Err(UsimError::StatusWord {
                sw1: response.sw1,
                sw2: response.sw2,
            });
        }
        match parse_authenticate_response(&response.data)? {
            crate::apdu::AuthenticateResponse::Success(out) => Ok(out),
            crate::apdu::AuthenticateResponse::SyncFailure { auts } => {
                Ok(AkaOutput::SyncFailure { auts })
            }
        }
    }
}

/// An in-memory channel backed by any [`Usim`] — the "card on a pipe" used for
/// end-to-end host tests without a reader.
pub struct LoopbackChannel<U: Usim> {
    card: U,
    /// Every command APDU seen, for assertions.
    pub seen: Vec<Vec<u8>>,
}

impl<U: Usim> LoopbackChannel<U> {
    /// Wrap a software card.
    pub fn new(card: U) -> Self {
        Self {
            card,
            seen: Vec::new(),
        }
    }
}

impl<U: Usim> ApduChannel for LoopbackChannel<U> {
    fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError> {
        self.seen.push(command.to_vec());
        // Re-encode the command back into RAND/AUTN and run the card.
        let (rand, autn) = decode_authenticate_command(command)?;
        let output = self.card.authenticate(&rand, &autn)?;
        Ok(match output {
            AkaOutput::Success { res, ck, ik } => CardResponse::ok(encode_success(&res, &ck, &ik)),
            AkaOutput::SyncFailure { auts } => {
                let mut body = vec![crate::apdu::TAG_SYNC_FAILURE, 14];
                body.extend_from_slice(&auts);
                CardResponse::ok(body)
            }
        })
    }
}

/// Decode an `AUTHENTICATE` command back into `(RAND, AUTN)`.
///
/// Useful for tests and for adapters that log the challenge. Rejects anything
/// that is not a well-formed 3G `AUTHENTICATE` command.
pub fn decode_authenticate_command(command: &[u8]) -> Result<(Rand, Autn), UsimError> {
    if command.len() != 40
        || command[0] != 0x00
        || command[1] != crate::apdu::INS_AUTHENTICATE
        || command[2] != 0x00
        || command[3] != crate::apdu::P2_3G_CONTEXT
        || command[4] != 0x22
        || command[5] != 0x10
        || command[22] != 0x10
    {
        return Err(UsimError::Malformed("not a 3G AUTHENTICATE command"));
    }
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&command[6..22]);
    let mut autn = [0u8; 16];
    autn.copy_from_slice(&command[23..39]);
    Ok((rand, autn))
}

/// Encode the `DB` success TLV body.
pub fn encode_success(res: &[u8], ck: &[u8; 16], ik: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 1 + res.len() + 1 + 16 + 1 + 16);
    body.push(crate::apdu::TAG_SUCCESS_3G);
    body.push(res.len() as u8);
    body.extend_from_slice(res);
    body.push(16);
    body.extend_from_slice(ck);
    body.push(16);
    body.extend_from_slice(ik);
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SoftwareUsim;
    use aka::{Amf, Key, Operator, Sqn};

    const K: Key = [
        0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6,
        0xbc,
    ];
    const OP: Operator = [
        0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3,
        0x18,
    ];
    const SQN: Sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    const RAND: Rand = [
        0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf,
        0x35,
    ];
    const AMF: Amf = [0xb9, 0xb9];

    /// Build a valid AUTN for SQN/AMF with the card's Milenage.
    fn autn_for() -> Autn {
        let mm = aka::Milenage::new(K, OP);
        let ak = mm.f2345(&RAND).3;
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = SQN[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&AMF);
        let mac = mm.compute(&RAND, &SQN, &AMF).mac_a;
        autn[8..].copy_from_slice(&mac);
        autn
    }

    #[test]
    fn card_round_trips_through_the_channel_and_the_apdu() {
        let usim = SoftwareUsim::new(K, OP, SQN);
        let autn = autn_for();
        let mut card = UsimCard::new(LoopbackChannel::new(usim));
        let out = card.authenticate(&RAND, &autn).unwrap();
        assert!(matches!(out, AkaOutput::Success { .. }));
        // The command really was the spec APDU.
        let seen = &card.channel().seen;
        assert_eq!(seen.len(), 1);
        assert_eq!(&seen[0][..5], &[0x00, 0x88, 0x00, 0x01, 0x22]);
    }

    #[test]
    fn status_word_errors_surface() {
        struct Reject;
        impl ApduChannel for Reject {
            fn transmit(&mut self, _c: &[u8]) -> Result<CardResponse, UsimError> {
                Ok(CardResponse::status(0x98, 0x62))
            }
        }
        let mut card = UsimCard::new(Reject);
        assert_eq!(
            card.authenticate(&RAND, &[0u8; 16]).unwrap_err(),
            UsimError::StatusWord {
                sw1: 0x98,
                sw2: 0x62
            }
        );
    }

    #[test]
    fn command_decoder_rejects_non_authenticate_bytes() {
        assert!(decode_authenticate_command(&[0x00, 0x88]).is_err());
        let good = crate::apdu::authenticate_command(&RAND, &RAND).to_bytes();
        assert_eq!(decode_authenticate_command(&good).unwrap(), (RAND, RAND));
    }
}
