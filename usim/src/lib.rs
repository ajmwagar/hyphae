//! USIM AKA adapter (3GPP TS 31.102 §7.1).
//!
//! The USIM is the root of trust for IMS-AKA: it holds K and runs the Milenage
//! function set when the ME asks it to `AUTHENTICATE` a challenge. This crate
//! models that boundary for the IMS client:
//!
//! * [`apdu`] — the **spec-exact** `AUTHENTICATE` command and response coding
//!   (TS 31.102 §7.1.2), pure bytes.
//! * [`Usim`] — the card boundary: given `RAND`/`AUTN`, return `RES`/`CK`/`IK`
//!   or a synchronisation failure carrying `AUTS`.
//! * [`SoftwareUsim`] — a Milenage-backed card for the lab and for tests, so the
//!   whole path runs on a host with no reader.
//! * [`UsimCard`] + [`ApduChannel`] — the APDU exchange over any transport
//!   (PC/SC, a modem card channel, a test pipe). This crate never opens a
//!   reader itself, so no `unsafe` and no C dependency is needed.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]`. A real PC/SC adapter
//! (`libpcsclite`) implements [`ApduChannel`] out of tree.
//!
//! ## Secrets
//!
//! `K`/`OPc` live only inside [`SoftwareUsim`] and are never formatted into an
//! error or a `Debug` output.

#![forbid(unsafe_code)]

pub mod apdu;
pub mod at;
pub mod card;
pub mod qmi;
pub mod software;

pub use apdu::{authenticate_command, parse_authenticate_response, Apdu, AuthenticateResponse};
pub use at::{AtApdu, AtChannel};
pub use card::{ApduChannel, CardResponse, LoopbackChannel, UsimCard};
pub use qmi::{QmiApdu, QmiExchange};
pub use software::SoftwareUsim;

/// A 128-bit RAND challenge.
pub type Rand = [u8; 16];
/// A 128-bit AUTN network authentication token.
pub type Autn = [u8; 16];
/// A 128-bit cipher key.
pub type Ck = [u8; 16];
/// A 128-bit integrity key.
pub type Ik = [u8; 16];

/// The result of a USIM `AUTHENTICATE` in the 3G/EPS/5G security context
/// (TS 31.102 §7.1.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkaOutput {
    /// RES (4–16 octets), CK and IK.
    Success { res: Vec<u8>, ck: Ck, ik: Ik },
    /// Sequence-number failure; the 14-octet AUTS lets the network resync.
    SyncFailure { auts: [u8; 14] },
}

impl AkaOutput {
    /// The RES, if the run succeeded.
    pub fn res(&self) -> Option<&[u8]> {
        match self {
            AkaOutput::Success { res, .. } => Some(res),
            AkaOutput::SyncFailure { .. } => None,
        }
    }
}

/// Errors from the USIM boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsimError {
    /// The card rejected the command with a status word.
    StatusWord { sw1: u8, sw2: u8 },
    /// The response tag was neither `DB` (success) nor `DC` (sync failure).
    BadTag(u8),
    /// The response was truncated or a length field overran the buffer.
    Malformed(&'static str),
    /// The USIM rejected the AUTN MAC (authentication failure).
    MacFailure,
    /// The channel was closed.
    Closed,
}

impl core::fmt::Display for UsimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UsimError::StatusWord { sw1, sw2 } => {
                write!(f, "USIM returned status word {sw1:02X}{sw2:02X}")
            }
            UsimError::BadTag(t) => write!(f, "USIM response tag {t:02X} is neither DB nor DC"),
            UsimError::Malformed(what) => write!(f, "malformed USIM response: {what}"),
            UsimError::MacFailure => f.write_str("USIM rejected the AUTN MAC (MAC-A mismatch)"),
            UsimError::Closed => f.write_str("USIM channel closed"),
        }
    }
}

impl std::error::Error for UsimError {}

/// The card boundary: authenticate a challenge and return the AKA vectors.
pub trait Usim {
    /// Run `AUTHENTICATE` for the 3G/EPS/5G context.
    fn authenticate(&mut self, rand: &Rand, autn: &Autn) -> Result<AkaOutput, UsimError>;
}

/// ISO 7816 status words this adapter understands (TS 31.102 §7.1.2).
pub mod sw {
    /// Normal processing.
    pub const OK: (u8, u8) = (0x90, 0x00);
    /// Authentication error, incorrect MAC.
    pub const AUTH_MAC_FAILURE: (u8, u8) = (0x98, 0x62);
    /// Key freshness failure.
    pub const KEY_FRESHNESS_FAILURE: (u8, u8) = (0x98, 0x65);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aka_output_accessors() {
        let ok = AkaOutput::Success {
            res: vec![1, 2, 3, 4, 5, 6, 7, 8],
            ck: [0; 16],
            ik: [0; 16],
        };
        assert_eq!(ok.res(), Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]));
        let sync = AkaOutput::SyncFailure { auts: [0; 14] };
        assert_eq!(sync.res(), None);
    }

    #[test]
    fn status_word_is_reported_verbatim() {
        let e = UsimError::StatusWord {
            sw1: 0x98,
            sw2: 0x62,
        };
        assert_eq!(e.to_string(), "USIM returned status word 9862");
    }
}
