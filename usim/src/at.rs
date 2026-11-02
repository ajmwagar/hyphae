//! `AT+CSIM` card access: send TS 31.102 APDUs over an AT command channel.
//!
//! Many modems expose the UICC with the GSM 27.007 `+CSIM` command instead of
//! (or as well as) QMI:
//!
//! ```text
//! host  AT+CSIM=<len>,"<hex-apdu>"
//! modem +CSIM: <len>,"<hex-response>"
//! ```
//!
//! `<len>` is the number of **characters** in the hex string (twice the byte
//! count). The response hex is `data || SW1 SW2`, exactly the card boundary this
//! crate already speaks.
//!
//! The AT channel is the pluggable boundary: implement [`AtChannel`] over
//! whatever serial/QMI-AT pipe the platform provides. No FFI here.

#![forbid(unsafe_code)]

use crate::card::CardResponse;
use crate::{ApduChannel, UsimError};

/// A transport that runs one AT command and returns the final response line(s).
pub trait AtChannel {
    /// Send `command` (without the trailing CR) and return the response text.
    fn command(&mut self, command: &str) -> Result<String, UsimError>;
}

/// Render `AT+CSIM` for one APDU.
pub fn csim_command(apdu: &[u8]) -> String {
    let hex = hex_upper(apdu);
    format!("AT+CSIM={},\"{hex}\"", hex.len())
}

/// Parse a `+CSIM: <len>,"<hex>"` response line into the APDU response bytes.
pub fn parse_csim_response(text: &str) -> Result<Vec<u8>, UsimError> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("+CSIM:"))
        .ok_or(UsimError::Malformed("no +CSIM response"))?
        .trim();
    let rest = line[6..].trim();
    let (len_str, tail) = rest
        .split_once(',')
        .ok_or(UsimError::Malformed("+CSIM missing length"))?;
    let declared: usize = len_str
        .trim()
        .parse()
        .map_err(|_| UsimError::Malformed("+CSIM length is not a number"))?;
    let quoted = tail
        .trim()
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or(UsimError::Malformed("+CSIM hex is not quoted"))?;
    let bytes = unhex(quoted)?;
    if quoted.len() != declared || bytes.len() * 2 != declared {
        return Err(UsimError::Malformed("+CSIM length disagrees with the hex"));
    }
    Ok(bytes)
}

/// A [`ApduChannel`] that reaches the USIM with `AT+CSIM`.
pub struct AtApdu<T: AtChannel> {
    channel: T,
}

impl<T: AtChannel> AtApdu<T> {
    pub fn new(channel: T) -> Self {
        Self { channel }
    }

    pub fn channel(&self) -> &T {
        &self.channel
    }
}

impl<T: AtChannel> ApduChannel for AtApdu<T> {
    fn transmit(&mut self, command: &[u8]) -> Result<CardResponse, UsimError> {
        let text = self.channel.command(&csim_command(command))?;
        let bytes = parse_csim_response(&text)?;
        CardResponse::from_apdu_response(&bytes)
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, UsimError> {
    if s.len() % 2 != 0 {
        return Err(UsimError::Malformed("odd-length hex"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(UsimError::Malformed("non-hex digit"))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(UsimError::Malformed("non-hex digit"))?;
        out.push((hi * 16 + lo) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::authenticate_command;

    struct FakeAt {
        reply: String,
        seen: String,
    }

    impl AtChannel for FakeAt {
        fn command(&mut self, command: &str) -> Result<String, UsimError> {
            self.seen = command.to_string();
            Ok(self.reply.clone())
        }
    }

    #[test]
    fn command_is_length_prefixed_uppercase_hex() {
        let apdu = authenticate_command(&[0x11; 16], &[0x22; 16]).to_bytes();
        let cmd = csim_command(&apdu);
        assert!(cmd.starts_with("AT+CSIM=80,\"0088"));
        assert!(cmd.ends_with('"'));
        // The declared length is the hex character count.
        let n: usize = cmd[8..10].parse().unwrap();
        assert_eq!(n, apdu.len() * 2);
    }

    #[test]
    fn response_parses_into_a_card_response() {
        let text = "+CSIM: 6,\"DB9000\"\r\nOK\r\n";
        assert_eq!(parse_csim_response(text).unwrap(), vec![0xDB, 0x90, 0x00]);
        assert_eq!(
            parse_csim_response("+CSIM: 4,\"9000\"").unwrap(),
            vec![0x90, 0x00]
        );
    }

    #[test]
    fn malformed_responses_are_rejected() {
        assert!(parse_csim_response("OK").is_err());
        assert!(parse_csim_response("+CSIM: 4,\"900\"").is_err());
        assert!(parse_csim_response("+CSIM: 8,\"9000\"").is_err());
        assert!(parse_csim_response("+CSIM: 4,\"ZZZZ\"").is_err());
    }

    #[test]
    fn adapter_runs_the_apdu_through_at() {
        let modem = FakeAt {
            reply: "+CSIM: 4,\"9000\"".into(),
            seen: String::new(),
        };
        let mut apdu = AtApdu::new(modem);
        let response = apdu.transmit(&[0x00, 0x88]).unwrap();
        assert_eq!((response.sw1, response.sw2), (0x90, 0x00));
        assert!(response.data.is_empty());
        assert_eq!(apdu.channel().seen, "AT+CSIM=4,\"0088\"");
    }
}
