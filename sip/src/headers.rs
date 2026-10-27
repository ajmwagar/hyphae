//! Header collection plus the typed headers used by the IMS flows.

use crate::{invalid, ParseError, SipUri};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers(Vec<Header>);

impl Headers {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, header: Header) {
        self.0.push(header);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|h| h.is(name)).map(|h| h.value.as_str())
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0
            .iter()
            .filter(move |h| h.is(name))
            .map(|h| h.value.as_str())
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(h) = self.0.iter_mut().find(|h| h.is(name)) {
            h.value = value;
        } else {
            self.0.push(Header::new(name, value));
        }
    }

    pub fn push_value(&mut self, name: &str, value: impl Into<String>) {
        self.0.push(Header::new(name, value));
    }

    pub fn remove(&mut self, name: &str) -> Option<String> {
        let i = self.0.iter().position(|h| h.is(name))?;
        Some(self.0.remove(i).value)
    }

    pub fn content_length(&self) -> Option<usize> {
        self.get("content-length")
            .or_else(|| self.get("l"))
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn cseq(&self) -> Option<CSeq> {
        self.get("cseq").and_then(|v| v.parse().ok())
    }

    pub fn via(&self) -> Option<Via> {
        self.get("via")
            .or_else(|| self.get("v"))
            .and_then(|v| Via::parse(v).ok())
    }

    /// Concatenated `feature-capability`/`Contact` values are caller's concern;
    /// this returns comma-separated Option-Tags from a Feature-Capability header.
    pub fn feature_caps(&self) -> Vec<String> {
        self.get_all("feature-capability")
            .flat_map(|v| v.split(','))
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    pub seq: u32,
    pub method: crate::Method,
}

impl CSeq {
    pub fn new(seq: u32, method: crate::Method) -> Self {
        Self { seq, method }
    }
}

impl fmt::Display for CSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.seq, self.method)
    }
}

impl std::str::FromStr for CSeq {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let seq = parts
            .next()
            .ok_or(ParseError::Missing("CSeq number"))?
            .parse()
            .map_err(|_| invalid("CSeq", s.to_string()))?;
        let method = parts
            .next()
            .ok_or(ParseError::Missing("CSeq method"))?
            .parse()?;
        Ok(Self { seq, method })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    /// e.g. `SIP/2.0/UDP`
    pub transport: String,
    /// e.g. `192.0.2.10:5060`
    pub sent_by: String,
    pub params: Vec<(String, Option<String>)>,
}

impl Via {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let (head, params) = split_once_params(s);
        let mut parts = head.split_whitespace();
        let transport = parts
            .next()
            .ok_or(ParseError::Missing("Via transport"))?
            .to_string();
        if !transport.to_ascii_uppercase().starts_with("SIP/2.0/") {
            return Err(invalid("Via", transport));
        }
        let sent_by = parts
            .next()
            .ok_or(ParseError::Missing("Via sent-by"))?
            .to_string();
        Ok(Self {
            transport,
            sent_by,
            params,
        })
    }

    pub fn branch(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("branch"))
            .and_then(|(_, v)| v.as_deref())
    }
}

/// A `From`/`To`/`Contact`-style name-addr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    pub display_name: Option<String>,
    pub uri: SipUri,
    pub params: Vec<(String, Option<String>)>,
}

impl NameAddr {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        let (display_name, rest) = if let Some(start) = s.find('<') {
            let end = s[start..]
                .find('>')
                .map(|i| start + i)
                .ok_or_else(|| invalid("name-addr", "unterminated <uri>"))?;
            let display = s[..start].trim().trim_matches('"').trim();
            (
                if display.is_empty() {
                    None
                } else {
                    Some(display.to_string())
                },
                &s[start + 1..end],
            )
        } else {
            (None, s)
        };
        let uri = SipUri::parse(rest)?;
        Ok(Self {
            display_name,
            uri,
            params: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub scheme: String,
    pub params: Vec<(String, String)>,
}

impl AuthChallenge {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn is_digest(&self) -> bool {
        self.scheme.eq_ignore_ascii_case("Digest")
    }
}

/// Parse a `WWW-Authenticate` / `Proxy-Authenticate` value.
pub fn parse_challenge(value: &str) -> Result<AuthChallenge, ParseError> {
    let value = value.trim();
    let (scheme, rest) = value
        .split_once(char::is_whitespace)
        .ok_or(ParseError::Missing("auth scheme"))?;
    let mut params = Vec::new();
    for part in split_commas(rest) {
        if let Some((k, v)) = part.split_once('=') {
            params.push((k.trim().to_string(), v.trim().trim_matches('"').to_string()));
        }
    }
    Ok(AuthChallenge {
        scheme: scheme.to_string(),
        params,
    })
}

/// Split on `;` outside quoted strings.
pub fn split_params(s: &str) -> Vec<&str> {
    split_outside_quotes(s, ';')
}

fn split_commas(s: &str) -> Vec<&str> {
    split_outside_quotes(s, ',')
}

fn split_outside_quotes(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c == sep && !in_quotes => {
                out.push(s[start..i].trim());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(s[start..].trim());
    out
}

fn split_once_params(s: &str) -> (&str, Vec<(String, Option<String>)>) {
    let mut it = split_outside_quotes(s, ';').into_iter();
    let head = it.next().unwrap_or("").trim();
    let params = it
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((n, v)) => (
                n.trim().to_string(),
                Some(v.trim().trim_matches('"').to_string()),
            ),
            None => (p.trim().to_string(), None),
        })
        .collect();
    (head, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Method;

    #[test]
    fn headers_are_case_insensitive() {
        let mut h = Headers::new();
        h.push(Header::new("WWW-Authenticate", "Digest"));
        assert_eq!(h.get("www-authenticate"), Some("Digest"));
        h.set("www-authenticate", "Digest2");
        assert_eq!(h.get("WWW-Authenticate"), Some("Digest2"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn parses_cseq() {
        let c: CSeq = "42 INVITE".parse().unwrap();
        assert_eq!(c.seq, 42);
        assert_eq!(c.method, Method::Invite);
        assert_eq!(c.to_string(), "42 INVITE");
    }

    #[test]
    fn parses_via_branch() {
        let v = Via::parse("SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-1;rport").unwrap();
        assert_eq!(v.transport, "SIP/2.0/TCP");
        assert_eq!(v.sent_by, "192.0.2.10:5060");
        assert_eq!(v.branch(), Some("z9hG4bK-1"));
    }

    #[test]
    fn parses_digest_challenge() {
        let c = parse_challenge(
            "Digest realm=\"ims.example\", nonce=\"bm9uY2U=\", algorithm=AKAv1-MD5, qop=\"auth\"",
        )
        .unwrap();
        assert!(c.is_digest());
        assert_eq!(c.param("realm"), Some("ims.example"));
        assert_eq!(c.param("algorithm"), Some("AKAv1-MD5"));
        assert_eq!(c.param("qop"), Some("auth"));
    }

    #[test]
    fn params_respect_quotes() {
        let s = "name=\"a;b\";tag=x";
        assert_eq!(split_params(s), vec!["name=\"a;b\"", "tag=x"]);
    }

    #[test]
    fn parses_name_addr() {
        let n = NameAddr::parse("\"Alice\" <sip:alice@example.com>").unwrap();
        assert_eq!(n.display_name.as_deref(), Some("Alice"));
        assert_eq!(n.uri.user.as_deref(), Some("alice"));
    }
}
