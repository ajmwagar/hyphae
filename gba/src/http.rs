//! The HTTP boundary GBA runs over.
//!
//! The Ub and Ua reference points are HTTP (TS 24.109 §4, TS 33.220 §4.3–4.5).
//! This crate must not open a socket and must not decide which TLS stack the
//! project takes — so the transport is a trait, exactly like `Usim`,
//! `AtChannel` and `AudioSink`. The implementer supplies TLS; tests supply a
//! mock.
//!
//! Only the parts of HTTP/1.1 that GBA uses are modelled: a method, a URI, a
//! header list and a body. No chunked transfer, no redirects — a BSF answers in
//! one shot.

#![forbid(unsafe_code)]

/// An HTTP request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method, uppercase: `GET` for Ub, `POST` for most NAFs.
    pub method: String,
    /// The absolute URI (the BSF address) or absolute path.
    pub uri: String,
    /// Header fields, in order, as `(name, value)`.
    pub headers: Vec<(String, String)>,
    /// The entity body, empty when there is none.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A request with no headers or body.
    pub fn new(method: impl Into<String>, uri: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Append a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The first value of `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Header fields, in order.
    pub headers: Vec<(String, String)>,
    /// The entity body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Build a response.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Append a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The first value of `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `name`, case-insensitively, because a response may carry
    /// more than one `WWW-Authenticate`.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The body as text, or `None` if it is not UTF-8.
    pub fn body_text(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }
}

/// Errors from the HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The transport failed (DNS, TLS, connection, timeout).
    Transport(String),
    /// The response was not HTTP the caller can use.
    Protocol(String),
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HttpError::Transport(why) => write!(f, "HTTP transport: {why}"),
            HttpError::Protocol(why) => write!(f, "HTTP protocol: {why}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// An HTTP client. The implementer supplies the socket and the TLS stack.
pub trait HttpChannel {
    /// Perform one request and return the response.
    fn request(&mut self, request: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

impl<T: HttpChannel + ?Sized> HttpChannel for &mut T {
    fn request(&mut self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        (**self).request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_is_case_insensitive() {
        let response = HttpResponse::new(401)
            .header("WWW-Authenticate", "Digest realm=\"r\"")
            .header("www-authenticate", "Digest realm=\"s\"");
        assert_eq!(response.get("Www-Authenticate"), Some("Digest realm=\"r\""));
        assert_eq!(response.get_all("WWW-AUTHENTICATE").len(), 2);
    }

    #[test]
    fn bodies_round_trip_as_text() {
        let request = HttpRequest::new("POST", "/").body("x=1");
        assert_eq!(request.body, b"x=1");
        assert_eq!(HttpResponse::new(200).body("ok").body_text(), Some("ok"));
        assert_eq!(HttpResponse::new(200).body([0xffu8]).body_text(), None);
    }
}
