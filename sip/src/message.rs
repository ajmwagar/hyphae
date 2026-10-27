//! RFC 3261 §7 message model and wire codec.

use crate::{invalid, ParseError};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Prack,
    Update,
    Info,
    Message,
    Subscribe,
    Notify,
    Refer,
    Publish,
    Other(String),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Register => "REGISTER",
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Options => "OPTIONS",
            Method::Prack => "PRACK",
            Method::Update => "UPDATE",
            Method::Info => "INFO",
            Method::Message => "MESSAGE",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Refer => "REFER",
            Method::Publish => "PUBLISH",
            Method::Other(s) => s,
        }
    }

    /// RFC 3261 §17.1.1: ACK and CANCEL are matched to the INVITE transaction.
    pub fn is_transaction_special(&self) -> bool {
        matches!(self, Method::Ack | Method::Cancel)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim() {
            "REGISTER" => Method::Register,
            "INVITE" => Method::Invite,
            "ACK" => Method::Ack,
            "BYE" => Method::Bye,
            "CANCEL" => Method::Cancel,
            "OPTIONS" => Method::Options,
            "PRACK" => Method::Prack,
            "UPDATE" => Method::Update,
            "INFO" => Method::Info,
            "MESSAGE" => Method::Message,
            "SUBSCRIBE" => Method::Subscribe,
            "NOTIFY" => Method::Notify,
            "REFER" => Method::Refer,
            "PUBLISH" => Method::Publish,
            other if !other.is_empty() => Method::Other(other.to_string()),
            _ => return Err(ParseError::Missing("method")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version;

impl Version {
    pub const MAJOR: u16 = 2;
    pub const MINOR: u16 = 0;
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/{}.{}", Self::MAJOR, Self::MINOR)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    /// Request-URI, kept as text (it need not be a parseable SIP URI for all roles).
    pub uri: String,
    pub headers: crate::Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: crate::Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let input = input.trim_start_matches('\u{feff}');
        let (head, body) = split_head_body(input);

        let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let start = lines
            .next()
            .ok_or(ParseError::Missing("start line"))?
            .trim_end();
        if start.is_empty() {
            return Err(ParseError::Missing("start line"));
        }

        let mut headers = crate::Headers::new();
        let mut current: Option<(String, String)> = None;
        for raw in lines {
            if raw.starts_with(' ') || raw.starts_with('\t') {
                // RFC 3261 §7.3.1 header folding (obs-fold).
                let Some((name, mut value)) = current.take() else {
                    return Err(invalid("header", "continuation without header"));
                };
                value.push(' ');
                value.push_str(raw.trim());
                current = Some((name, value));
                continue;
            }
            if let Some((name, value)) = current.take() {
                headers.push(crate::Header::new(name, value));
            }
            if raw.is_empty() {
                continue;
            }
            let (name, value) = raw
                .split_once(':')
                .ok_or_else(|| invalid("header", format!("missing colon in {raw:?}")))?;
            if name.is_empty() {
                return Err(ParseError::Missing("header name"));
            }
            current = Some((name.to_string(), value.trim().to_string()));
        }
        if let Some((name, value)) = current {
            headers.push(crate::Header::new(name, value));
        }

        let body = truncate_body(body, headers.content_length())?;

        if start.starts_with("SIP/") {
            let mut parts = start.splitn(3, ' ');
            let version = parts.next().unwrap_or_default();
            if version != "SIP/2.0" {
                return Err(invalid("version", version.to_string()));
            }
            let status = parts
                .next()
                .ok_or(ParseError::Missing("status code"))?
                .parse::<u16>()
                .map_err(|_| invalid("status code", start.to_string()))?;
            let reason = parts.next().unwrap_or("").to_string();
            Ok(Message::Response(Response {
                status,
                reason,
                headers,
                body,
            }))
        } else {
            let mut parts = start.splitn(3, ' ');
            let method = parts.next().ok_or(ParseError::Missing("method"))?.parse()?;
            let uri = parts
                .next()
                .ok_or(ParseError::Missing("request URI"))?
                .to_string();
            let version = parts.next().ok_or(ParseError::Missing("version"))?;
            if version != "SIP/2.0" {
                return Err(invalid("version", version.to_string()));
            }
            Ok(Message::Request(Request {
                method,
                uri,
                headers,
                body,
            }))
        }
    }

    pub fn headers(&self) -> &crate::Headers {
        match self {
            Message::Request(r) => &r.headers,
            Message::Response(r) => &r.headers,
        }
    }

    pub fn headers_mut(&mut self) -> &mut crate::Headers {
        match self {
            Message::Request(r) => &mut r.headers,
            Message::Response(r) => &mut r.headers,
        }
    }

    pub fn body(&self) -> &[u8] {
        match self {
            Message::Request(r) => &r.body,
            Message::Response(r) => &r.body,
        }
    }

    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(self.body()).ok()
    }

    /// Serialise with CRLF line endings and a correct Content-Length.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        let (start, headers, body) = match self {
            Message::Request(r) => (
                format!("{} {} SIP/2.0", r.method, r.uri),
                &r.headers,
                &r.body,
            ),
            Message::Response(r) => (
                format!("SIP/2.0 {} {}", r.status, r.reason),
                &r.headers,
                &r.body,
            ),
        };
        out.push_str(&start);
        out.push_str("\r\n");
        let mut wrote_length = false;
        for h in headers.iter() {
            if h.name.eq_ignore_ascii_case("content-length") {
                if wrote_length {
                    continue;
                }
                wrote_length = true;
                out.push_str(&format!("Content-Length: {}\r\n", body.len()));
                continue;
            }
            out.push_str(&h.name);
            out.push_str(": ");
            out.push_str(&h.value);
            out.push_str("\r\n");
        }
        if !wrote_length {
            out.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    pub fn to_text(&self) -> String {
        String::from_utf8(self.to_bytes()).unwrap_or_default()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

fn split_head_body(input: &str) -> (&str, &str) {
    if let Some(i) = input.find("\r\n\r\n") {
        (&input[..i], &input[i + 4..])
    } else if let Some(i) = input.find("\n\n") {
        (&input[..i], &input[i + 2..])
    } else {
        (input, "")
    }
}

fn truncate_body(body: &str, content_length: Option<usize>) -> Result<Vec<u8>, ParseError> {
    let bytes = body.as_bytes();
    match content_length {
        Some(n) if bytes.len() < n => Err(invalid(
            "Content-Length",
            format!("declared {n} but only {} body bytes present", bytes.len()),
        )),
        Some(n) => Ok(bytes[..n].to_vec()),
        None => Ok(bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTER: &str = "REGISTER sip:ims.mnc015.mcc234.3gppnetwork.org SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ims-1\r\n\
From: <sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org>;tag=from-1\r\n\
To: <sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org>\r\n\
Call-ID: call-1\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:234150123456789@192.0.2.10:5060>;expires=600000\r\n\
Content-Length: 0\r\n\r\n";

    #[test]
    fn parses_register() {
        let m = Message::parse(REGISTER).unwrap();
        let Message::Request(r) = &m else {
            panic!("request expected")
        };
        assert_eq!(r.method, Method::Register);
        assert_eq!(r.uri, "sip:ims.mnc015.mcc234.3gppnetwork.org");
        assert_eq!(r.headers.get("cseq"), Some("1 REGISTER"));
        assert_eq!(r.headers.get("CALL-ID"), Some("call-1"));
        let cseq = r.headers.cseq().unwrap();
        assert_eq!(cseq.seq, 1);
        assert_eq!(cseq.method, Method::Register);
    }

    #[test]
    fn serialises_with_crlf_and_content_length() {
        let m = Message::parse(REGISTER).unwrap();
        let text = m.to_text();
        assert!(text.contains("\r\nContent-Length: 0\r\n\r\n"));
        let reparsed = Message::parse(&text).unwrap();
        assert_eq!(reparsed, m);
    }

    #[test]
    fn parses_response_with_body() {
        let raw = "SIP/2.0 401 Unauthorized\r\n\
WWW-Authenticate: Digest realm=\"ims.mnc015.mcc234.3gppnetwork.org\", nonce=\"abc\"\r\n\
Content-Length: 5\r\n\r\nhello";
        let m = Message::parse(raw).unwrap();
        let Message::Response(r) = &m else {
            panic!("response expected")
        };
        assert_eq!(r.status, 401);
        assert_eq!(r.reason, "Unauthorized");
        assert_eq!(
            r.headers.get("www-authenticate").unwrap(),
            "Digest realm=\"ims.mnc015.mcc234.3gppnetwork.org\", nonce=\"abc\""
        );
        assert_eq!(m.body_text(), Some("hello"));
    }

    #[test]
    fn rejects_short_body() {
        let raw = "SIP/2.0 200 OK\r\nContent-Length: 10\r\n\r\nhi";
        assert!(Message::parse(raw).is_err());
    }

    #[test]
    fn folds_headers() {
        let raw = "SIP/2.0 200 OK\r\nSubject: one\r\n two\r\nContent-Length: 0\r\n\r\n";
        let m = Message::parse(raw).unwrap();
        assert_eq!(m.headers().get("subject"), Some("one two"));
    }
}
