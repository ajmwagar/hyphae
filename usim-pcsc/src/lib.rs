//! PC/SC card channel for a physical USIM.
//!
//! The core `usim` crate is pure Rust and deliberately does not link
//! `libpcsclite`. This crate is the optional hardware boundary: it connects to
//! a PC/SC reader, transmits one command APDU, and returns the data plus status
//! word through `usim::ApduChannel`.
//!
//! It is not a workspace member by default, so `cargo test --workspace` stays
//! pure Rust. Build/run it explicitly:
//!
//! ```sh
//! cargo run --manifest-path usim-pcsc/Cargo.toml -- list
//! cargo run --manifest-path usim-pcsc/Cargo.toml -- atr
//! cargo run --manifest-path usim-pcsc/Cargo.toml -- auth RAND_HEX AUTN_HEX
//! ```
//!
//! On Linux install `libpcsclite-dev` (and `pcscd`). On macOS the system PC/SC
//! framework is used. This crate owns the only `unsafe`/FFI dependency in the
//! hardware path.

use std::ffi::CString;

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use usim::{ApduChannel, CardResponse, UsimError};

/// Errors from opening or talking to a PC/SC reader.
#[derive(Debug)]
pub enum PcscError {
    /// PC/SC returned an error.
    Pcsc(pcsc::Error),
    /// There is no reader, or the named reader was not found.
    NoReader(String),
    /// The reader returned fewer than two status-word bytes.
    ShortResponse,
}

impl core::fmt::Display for PcscError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PcscError::Pcsc(e) => write!(f, "PC/SC: {e}"),
            PcscError::NoReader(why) => write!(f, "no usable PC/SC reader: {why}"),
            PcscError::ShortResponse => f.write_str("PC/SC response shorter than a status word"),
        }
    }
}

impl std::error::Error for PcscError {}

impl From<pcsc::Error> for PcscError {
    fn from(e: pcsc::Error) -> Self {
        PcscError::Pcsc(e)
    }
}

/// List the readers currently known to PC/SC.
pub fn list_readers() -> Result<Vec<String>, PcscError> {
    let ctx = Context::establish(Scope::User)?;
    let mut buf = [0u8; 4096];
    let readers = ctx.list_readers(&mut buf)?;
    Ok(readers
        .map(|name| name.to_string_lossy().into_owned())
        .collect())
}

/// A connected PC/SC card implementing [`usim::ApduChannel`].
pub struct PcscChannel {
    // The context must stay alive for the card handle.
    _ctx: Context,
    card: Card,
    reader: String,
}

impl PcscChannel {
    /// Connect to a named reader, or to the first available reader when
    /// `reader` is `None`. Shared mode leaves the card usable by another
    /// same-reader process.
    pub fn open(reader: Option<&str>) -> Result<Self, PcscError> {
        let ctx = Context::establish(Scope::User)?;
        let mut buf = [0u8; 4096];
        let names: Vec<String> = ctx
            .list_readers(&mut buf)?
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        let chosen = match reader {
            Some(want) => names
                .iter()
                .find(|name| name.as_str() == want)
                .cloned()
                .ok_or_else(|| PcscError::NoReader(format!("reader {want:?} not present")))?,
            None => names
                .into_iter()
                .next()
                .ok_or_else(|| PcscError::NoReader("no readers reported".into()))?,
        };
        let reader_c = CString::new(chosen.clone())
            .map_err(|_| PcscError::NoReader("reader name contains NUL".into()))?;
        let card = ctx.connect(&reader_c, ShareMode::Shared, Protocols::ANY)?;
        Ok(Self {
            _ctx: ctx,
            card,
            reader: chosen,
        })
    }

    /// The selected reader name.
    pub fn reader(&self) -> &str {
        &self.reader
    }

    /// The card ATR (Answer To Reset).
    pub fn atr(&self) -> Result<Vec<u8>, PcscError> {
        let status = self.card.status2_owned()?;
        Ok(status.atr().to_vec())
    }
}

/// Split a PC/SC response into its data field and status word.
///
/// Kept separate from the reader call so the wire rule is testable without
/// hardware. PC/SC returns `data || SW1 || SW2`.
pub fn split_response(response: &[u8]) -> Result<CardResponse, UsimError> {
    if response.len() < 2 {
        return Err(UsimError::Channel(PcscError::ShortResponse.to_string()));
    }
    let (data, sw) = response.split_at(response.len() - 2);
    Ok(CardResponse {
        data: data.to_vec(),
        sw1: sw[0],
        sw2: sw[1],
    })
}

impl ApduChannel for PcscChannel {
    fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError> {
        let mut recv = [0u8; 4096];
        let response = self
            .card
            .transmit(command, &mut recv)
            .map_err(|e| UsimError::Channel(e.to_string()))?;
        split_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_data_and_status_word() {
        let response = split_response(&[0xdb, 0x08, 0x11, 0x22, 0x90, 0x00]).unwrap();
        assert_eq!(response.data, vec![0xdb, 0x08, 0x11, 0x22]);
        assert_eq!((response.sw1, response.sw2), (0x90, 0x00));
    }

    #[test]
    fn accepts_a_bare_status_word() {
        let response = split_response(&[0x6a, 0x82]).unwrap();
        assert!(response.data.is_empty());
        assert_eq!((response.sw1, response.sw2), (0x6a, 0x82));
    }

    #[test]
    fn rejects_a_truncated_response() {
        assert!(split_response(&[0x90]).is_err());
        assert!(split_response(&[]).is_err());
    }
}
