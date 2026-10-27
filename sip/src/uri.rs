//! RFC 3261 §19.1 SIP and SIPS URIs.

use crate::{invalid, ParseError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    pub secure: bool,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// URI parameters (`;transport=tcp`, `;lr`, ...) without the leading `;`.
    pub params: Vec<(String, Option<String>)>,
}

impl SipUri {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let input = input.trim();
        let (secure, rest) = if let Some(r) = input.strip_prefix("sip:") {
            (false, r)
        } else if let Some(r) = input.strip_prefix("sips:") {
            (true, r)
        } else {
            return Err(invalid("SIP-URI", "expected sip: or sips: scheme"));
        };

        // Header part is not part of a URI in a Request-URI, but name-addrs carry it.
        let (rest, _headers) = match rest.split_once('?') {
            Some((u, h)) => (u, Some(h)),
            None => (rest, None),
        };

        let (authority_and_user, params_raw) = split_first_params(rest);
        let (userinfo, hostport) = match authority_and_user.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority_and_user),
        };

        let (user, password) = match userinfo {
            None => (None, None),
            Some(u) => match u.split_once(':') {
                Some((user, pass)) => (Some(percent_decode(user)), Some(percent_decode(pass))),
                None => (Some(percent_decode(u)), None),
            },
        };

        let (host, port) = parse_hostport(hostport)?;
        if host.is_empty() {
            return Err(ParseError::Missing("SIP-URI host"));
        }

        let mut params = Vec::new();
        if !params_raw.is_empty() {
            for p in params_raw.split(';') {
                if p.is_empty() {
                    continue;
                }
                let (n, v) = match p.split_once('=') {
                    Some((n, v)) => (n.to_string(), Some(v.to_string())),
                    None => (p.to_string(), None),
                };
                params.push((n, v));
            }
        }

        Ok(Self {
            secure,
            user,
            password,
            host,
            port,
            params,
        })
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_deref())
    }

    /// The canonical `host[:port]` used for Via sent-by and Route matching.
    pub fn host_port(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }
}

fn split_first_params(s: &str) -> (&str, &str) {
    match s.split_once(';') {
        Some((a, p)) => (a, p),
        None => (s, ""),
    }
}

fn parse_hostport(s: &str) -> Result<(String, Option<u16>), ParseError> {
    // IPv6 literals: [::1]:5060
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| invalid("SIP-URI", "unterminated IPv6 literal"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => {
                Some(p.parse().map_err(|_| invalid("SIP-URI", "bad port"))?)
            }
            _ => None,
        };
        return Ok((format!("[{host}]"), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => Ok((
            h.to_string(),
            Some(p.parse().map_err(|_| invalid("SIP-URI", "bad port"))?),
        )),
        _ => Ok((s.to_string(), None)),
    }
}

fn percent_decode(s: &str) -> String {
    // URI user parts are commonly unescaped in IMSI@ims.mnc... identities, but
    // handle %XX anyway. Invalid escapes are kept verbatim.
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| -> Option<u8> {
                match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                }
            };
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.secure {
            write!(f, "sips:")?;
        } else {
            write!(f, "sip:")?;
        }
        if let Some(u) = &self.user {
            write!(f, "{u}")?;
            if let Some(p) = &self.password {
                write!(f, ":{p}")?;
            }
            write!(f, "@")?;
        }
        write!(f, "{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        for (n, v) in &self.params {
            write!(f, ";{n}")?;
            if let Some(v) = v {
                write!(f, "={v}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ims_impu() {
        let u = SipUri::parse("sip:234150123456789@ims.mnc015.mcc234.3gppnetwork.org").unwrap();
        assert_eq!(u.user.as_deref(), Some("234150123456789"));
        assert_eq!(u.host, "ims.mnc015.mcc234.3gppnetwork.org");
        assert!(!u.secure);
    }

    #[test]
    fn parses_port_and_params() {
        let u = SipUri::parse("sip:alice@[2001:db8::1]:5060;transport=tcp;lr").unwrap();
        assert_eq!(u.host, "[2001:db8::1]");
        assert_eq!(u.port, Some(5060));
        assert_eq!(u.param("transport"), Some("tcp"));
        assert!(u.params.iter().any(|(n, _)| n == "lr"));
    }

    #[test]
    fn round_trips() {
        let s = "sips:bob:secret@example.com:5061;transport=tls";
        let u = SipUri::parse(s).unwrap();
        assert_eq!(u.to_string(), s);
    }
}
