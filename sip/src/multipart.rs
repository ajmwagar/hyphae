//! `multipart/mixed` bodies (RFC 2046 §5.1.1) as SIP uses them.
//!
//! SIP can carry more than one body part in a single message — the emergency
//! INVITE is the case that forces it, because TS 24.229 §5.1.6.8.3 requires the
//! PIDF-LO location object *and* the SDP offer in the same request, with the
//! `Geolocation` header pointing at the location part by `cid`.
//!
//! The boundary is a caller-supplied string rather than a random token: this
//! tree has no RNG by design, and a deterministic boundary makes the serialised
//! message reproducible in tests.

/// One body part.
#[derive(Debug, Clone, Copy)]
pub struct Part<'a> {
    /// The part's `Content-Type`.
    pub content_type: &'a str,
    /// The `Content-ID` without angle brackets, e.g. `location@ue.example`.
    pub content_id: Option<&'a str>,
    /// A `Content-Disposition` value, e.g. `render; handling=optional`.
    pub disposition: Option<&'a str>,
    /// The part's body.
    pub body: &'a [u8],
}

impl<'a> Part<'a> {
    /// A part with a content type and body, no `Content-ID`.
    pub fn new(content_type: &'a str, body: &'a [u8]) -> Self {
        Self {
            content_type,
            content_id: None,
            disposition: None,
            body,
        }
    }

    /// Attach a `Content-ID`, which is what `cid:` references resolve to.
    pub fn with_content_id(mut self, id: &'a str) -> Self {
        self.content_id = Some(id);
        self
    }

    /// Attach a `Content-Disposition`.
    pub fn with_disposition(mut self, disposition: &'a str) -> Self {
        self.disposition = Some(disposition);
        self
    }
}

/// Errors from serialising a multipart body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    /// No parts, so there is nothing to serialise.
    Empty,
    /// A boundary must be non-empty and must not appear in a part's body.
    BadBoundary(String),
}

impl core::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MultipartError::Empty => write!(f, "multipart body has no parts"),
            MultipartError::BadBoundary(b) => {
                write!(f, "boundary {b:?} is empty or occurs inside a part")
            }
        }
    }
}

impl std::error::Error for MultipartError {}

/// The `Content-Type` value for a multipart body using `boundary`.
pub fn content_type(boundary: &str) -> String {
    format!("multipart/mixed; boundary={boundary}")
}

/// Serialise `parts` as a `multipart/mixed` body (RFC 2046 §5.1.1).
///
/// Each part is preceded by `--<boundary>` and the body ends with
/// `--<boundary>--`. Lines are CRLF, as RFC 3261 §7.3.1 requires for SIP bodies.
pub fn multipart_mixed(boundary: &str, parts: &[Part<'_>]) -> Result<Vec<u8>, MultipartError> {
    if parts.is_empty() {
        return Err(MultipartError::Empty);
    }
    if boundary.is_empty() {
        return Err(MultipartError::BadBoundary(boundary.to_string()));
    }
    let marker = format!("--{boundary}");
    for p in parts {
        if contains(p.body, marker.as_bytes()) {
            return Err(MultipartError::BadBoundary(boundary.to_string()));
        }
    }

    let mut out = String::new();
    for p in parts {
        out.push_str(&marker);
        out.push_str("\r\n");
        out.push_str(&format!("Content-Type: {}\r\n", p.content_type));
        if let Some(id) = p.content_id {
            out.push_str(&format!("Content-ID: <{id}>\r\n"));
        }
        if let Some(d) = p.disposition {
            out.push_str(&format!("Content-Disposition: {d}\r\n"));
        }
        out.push_str("\r\n");
        // Header block is ASCII by construction; bodies may be binary.
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(p.body);
        bytes.extend_from_slice(b"\r\n");
        out = String::from_utf8(bytes).map_err(|_| MultipartError::BadBoundary(boundary.into()))?;
    }
    out.push_str(&marker);
    out.push_str("--\r\n");
    Ok(out.into_bytes())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_parts_are_delimited_and_terminated() {
        let body = multipart_mixed(
            "fungos",
            &[
                Part::new("application/pidf+xml", b"<presence/>")
                    .with_content_id("loc@ue")
                    .with_disposition("render; handling=optional"),
                Part::new("application/sdp", b"v=0\r\n"),
            ],
        )
        .unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("--fungos\r\nContent-Type: application/pidf+xml\r\n"));
        assert!(text.contains("Content-ID: <loc@ue>\r\n"));
        assert!(text.contains("Content-Disposition: render; handling=optional\r\n"));
        assert!(text.contains("--fungos\r\nContent-Type: application/sdp\r\n"));
        assert!(text.ends_with("--fungos--\r\n"));
        // Both bodies survive.
        assert!(text.contains("<presence/>"));
        assert!(text.contains("v=0"));
    }

    #[test]
    fn a_boundary_inside_a_part_is_refused() {
        assert_eq!(
            multipart_mixed("xx", &[Part::new("text/plain", b"a--xx b")]),
            Err(MultipartError::BadBoundary("xx".into()))
        );
    }

    #[test]
    fn empty_input_is_refused() {
        assert_eq!(multipart_mixed("xx", &[]), Err(MultipartError::Empty));
        assert_eq!(
            multipart_mixed("", &[Part::new("text/plain", b"x")]),
            Err(MultipartError::BadBoundary(String::new()))
        );
    }
}
