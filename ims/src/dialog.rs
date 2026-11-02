//! In-dialog request construction (RFC 3261 §12, RFC 3262 PRACK, RFC 3311 UPDATE).
//!
//! Dialog state is explicit; the caller supplies the transport. ACK uses the
//! INVITE CSeq without incrementing, every other in-dialog request increments.

use sip::{Header, Headers, Method, Request};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// 1xx with To-tag, before a final 2xx.
    Early,
    /// 2xx received and ACK owed/sent.
    Confirmed,
    /// BYE sent or received.
    Terminated,
}

#[derive(Debug, Clone)]
pub struct Dialog {
    pub call_id: String,
    pub local_uri: String,
    pub remote_uri: String,
    pub local_tag: String,
    pub remote_tag: String,
    pub route_set: Vec<String>,
    pub local_contact: String,
    pub user_agent: String,
    pub invite_cseq: u32,
    pub cseq: u32,
    pub state: DialogState,
    branch_counter: u32,
    /// The INVITE as it was sent, so CANCEL can reuse its branch, To, From and
    /// Call-ID verbatim (RFC 3261 §9.1).
    invite_sent: Option<Request>,
}

impl Dialog {
    pub fn new(
        call_id: impl Into<String>,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
        local_tag: impl Into<String>,
        remote_tag: impl Into<String>,
        local_contact: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            local_uri: local_uri.into(),
            remote_uri: remote_uri.into(),
            local_tag: local_tag.into(),
            remote_tag: remote_tag.into(),
            route_set: Vec::new(),
            local_contact: local_contact.into(),
            user_agent: "fungos-ims/0.1 (Linux)".into(),
            invite_cseq: 1,
            cseq: 1,
            state: DialogState::Early,
            branch_counter: 0,
            invite_sent: None,
        }
    }

    pub fn with_invite_cseq(mut self, cseq: u32) -> Self {
        self.invite_cseq = cseq;
        self.cseq = cseq;
        self
    }

    pub fn with_route_set(mut self, routes: Vec<String>) -> Self {
        self.route_set = routes;
        self
    }

    pub fn confirm(&mut self) {
        self.state = DialogState::Confirmed;
    }

    /// INVITE carrying an SDP offer: RFC 3261 §13, RFC 3264. Uses the INVITE
    /// CSeq and no To-tag (learned from the response); `Supported: 100rel`
    /// advertises reliable-provision handling for MTSI.
    pub fn invite(&mut self, offer: &crate::Sdp) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        let mut req = self.request(Method::Invite, uri, self.invite_cseq);
        req.headers
            .push(Header::new("Content-Type", "application/sdp"));
        req.headers.push(Header::new("Supported", "100rel"));
        req.body = offer.to_text().as_bytes().to_vec();
        req.headers
            .set("Content-Length", req.body.len().to_string());
        self.invite_sent = Some(req.clone());
        req
    }

    /// CANCEL for an unanswered INVITE: RFC 3261 §9.1.
    ///
    /// The Request-URI, Call-ID, From, To and CSeq *number* match the INVITE,
    /// and the Via branch is identical so the server can pair it with the
    /// INVITE transaction. Only the CSeq method changes to CANCEL, and the body
    /// is dropped. Returns `None` once a final response has been seen.
    pub fn cancel(&mut self) -> Option<Request> {
        if self.state != DialogState::Early {
            return None;
        }
        let mut req = self.invite_sent.clone()?;
        req.method = Method::Cancel;
        req.headers
            .set("CSeq", format!("{} CANCEL", self.invite_cseq));
        req.headers.remove("Content-Type");
        req.headers.remove("Contact");
        req.body = Vec::new();
        req.headers.set("Content-Length", "0");
        Some(req)
    }

    /// Adopt the callee's tag from a response's `To` header (RFC 3261 §12.1).
    /// The caller's dialog has no remote tag until the first tagged response.
    pub fn set_remote_tag(&mut self, to_header: &str) {
        self.remote_tag = extract_tag(to_header).unwrap_or_default();
    }

    /// ACK for a 2xx INVITE: RFC 3261 §13.2.2.4, same CSeq number.    /// ACK for a 2xx INVITE: RFC 3261 §13.2.2.4, same CSeq number.
    pub fn ack(&mut self) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.request(Method::Ack, uri, self.invite_cseq)
    }

    /// In-dialog re-INVITE carrying a new session description (RFC 3261 §14.1),
    /// used for hold/resume. Returns the CSeq so the matching ACK can reuse it.
    pub fn reinvite(&mut self, sdp: &str) -> (u32, Request) {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.cseq += 1;
        let cseq = self.cseq;
        let mut req = self.request(Method::Invite, uri, cseq);
        req.headers
            .push(Header::new("Content-Type", "application/sdp"));
        req.headers.push(Header::new("Supported", "100rel"));
        req.body = sdp.as_bytes().to_vec();
        req.headers
            .set("Content-Length", req.body.len().to_string());
        (cseq, req)
    }

    /// ACK for a re-INVITE: it must reuse the re-INVITE's CSeq number.
    pub fn ack_with_cseq(&mut self, cseq: u32) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.request(Method::Ack, uri, cseq)
    }

    /// PRACK for a reliable provisional response: RFC 3262 §4.
    pub fn prack(&mut self, rseq: u32) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.cseq += 1;
        let mut req = self.request(Method::Prack, uri, self.cseq);
        req.headers.push(Header::new(
            "RAck",
            format!("{} {} INVITE", rseq, self.invite_cseq),
        ));
        req
    }

    /// In-dialog UPDATE carrying an SDP offer/answer: RFC 3311 §5.1.
    pub fn update(&mut self, sdp: &str) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.cseq += 1;
        let mut req = self.request(Method::Update, uri, self.cseq);
        req.headers
            .push(Header::new("Content-Type", "application/sdp"));
        req.body = sdp.as_bytes().to_vec();
        req.headers
            .set("Content-Length", req.body.len().to_string());
        req
    }

    /// In-dialog PUBLISH (RFC 3903) carrying a body, e.g. an updated PIDF-LO
    /// during an emergency call (TS 24.229 §5.1.6.12.3).
    ///
    /// `event` is the event package name: RFC 3903 §4 makes the `Event` header
    /// mandatory, and the location publication is a presence publication, so
    /// callers normally pass `presence` (RFC 3856).
    pub fn publish(&mut self, event: &str, content_type: &str, body: Vec<u8>) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.cseq += 1;
        let mut req = self.request(Method::Publish, uri, self.cseq);
        req.headers.push(Header::new("Event", event));
        req.headers.push(Header::new("Content-Type", content_type));
        req.headers.set("Content-Length", body.len().to_string());
        req.body = body;
        req
    }

    /// In-dialog BYE: RFC 3261 §15.
    pub fn bye(&mut self) -> Request {
        let uri = self
            .route_set
            .first()
            .cloned()
            .unwrap_or_else(|| self.remote_uri.clone());
        self.cseq += 1;
        let req = self.request(Method::Bye, uri, self.cseq);
        self.state = DialogState::Terminated;
        req
    }

    fn request(&mut self, method: Method, uri: String, cseq: u32) -> Request {
        self.branch_counter += 1;
        let branch = format!("z9hG4bK-fungos-dlg-{}-{}", cseq, self.branch_counter);
        let mut headers = Headers::new();
        let host = self
            .local_contact
            .strip_prefix("sip:")
            .and_then(|s| s.split('@').nth(1))
            .unwrap_or(&self.local_contact);
        headers.push(Header::new(
            "Via",
            format!("SIP/2.0/UDP {host};branch={branch};rport"),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", self.local_uri, self.local_tag),
        ));
        // The initial INVITE has no To-tag; it is learned from the first response.
        let to = if self.remote_tag.is_empty() {
            format!("<{}>", self.remote_uri)
        } else {
            format!("<{}>;tag={}", self.remote_uri, self.remote_tag)
        };
        headers.push(Header::new("To", to));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{cseq} {method}")));
        for route in &self.route_set {
            headers.push(Header::new("Route", format!("<{route}>")));
        }
        if method != Method::Ack {
            headers.push(Header::new("Contact", format!("<{}>", self.local_contact)));
        }
        headers.push(Header::new("User-Agent", self.user_agent.clone()));
        headers.push(Header::new("Content-Length", "0"));
        Request {
            method,
            uri,
            headers,
            body: Vec::new(),
        }
    }
}

/// Extract the `tag` parameter from a `From`/`To` header value.
pub(crate) fn extract_tag(header: &str) -> Option<String> {
    for part in sip::split_params(header) {
        if let Some((key, value)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case("tag") {
                return Some(value.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip::Message;

    fn dialog() -> Dialog {
        let mut d = Dialog::new(
            "call-1",
            "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
            "local-tag",
            "remote-tag",
            "sip:001010000000001@192.0.2.10:5060",
        );
        d.confirm();
        d
    }

    #[test]
    fn prack_has_rack_and_increments_cseq() {
        let mut d = dialog().with_invite_cseq(10);
        let req = d.prack(180);
        assert_eq!(req.method, Method::Prack);
        assert_eq!(req.headers.get("rack"), Some("180 10 INVITE"));
        assert_eq!(req.headers.cseq().unwrap().seq, 11);
        assert!(req.headers.get("to").unwrap().contains("remote-tag"));
    }

    #[test]
    fn update_carries_sdp_and_content_type() {
        let mut d = dialog();
        let req = d.update("v=0\r\n");
        assert_eq!(req.method, Method::Update);
        assert_eq!(req.headers.get("content-type"), Some("application/sdp"));
        assert_eq!(req.body, b"v=0\r\n");
        assert_eq!(req.headers.cseq().unwrap().seq, 2);
    }

    #[test]
    fn bye_terminates_and_ack_reuses_invite_cseq() {
        let mut d = dialog().with_invite_cseq(7);
        let ack = d.ack();
        assert_eq!(ack.method, Method::Ack);
        assert_eq!(ack.headers.cseq().unwrap().seq, 7);
        assert!(ack.headers.get("contact").is_none());
        let bye = d.bye();
        assert_eq!(bye.method, Method::Bye);
        assert_eq!(bye.headers.cseq().unwrap().seq, 8);
        assert_eq!(d.state, DialogState::Terminated);
    }

    #[test]
    fn route_set_is_emitted() {
        let mut d = dialog().with_route_set(vec!["sip:orig@scscf.example;lr".into()]);
        let req = d.update("v=0\r\n");
        assert_eq!(
            req.headers.get("route"),
            Some("<sip:orig@scscf.example;lr>")
        );
        assert_eq!(req.uri, "sip:orig@scscf.example;lr");
    }

    #[test]
    fn wire_round_trip() {
        let mut d = dialog();
        let req = d.bye();
        let parsed = Message::parse(&Message::Request(req.clone()).to_text()).unwrap();
        assert_eq!(parsed, Message::Request(req));
    }
}
