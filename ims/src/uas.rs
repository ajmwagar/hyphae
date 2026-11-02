//! Incoming-call (UAS) state machine: INVITE / 180 / 200 / ACK / BYE.
//!
//! This is the callee side that [`crate::call`] does not cover. It owns response
//! construction and the dialog created from an incoming INVITE (RFC 3261 §13,
//! §12.1.1), RFC 3262 reliable provisionals, and RFC 3515/3261 CANCEL and BYE
//! teardown. No media flows through this crate — only SDP negotiation.
//!
//! ```text
//!   INVITE ──► IncomingCall::from_invite
//!                ├─ trying()      100 Trying
//!                ├─ ringing()     180 Ringing (RSeq when 100rel)
//!                ├─ answer()      200 OK + SDP answer
//!                └─ reject(486)   final non-2xx
//!   ACK    ──► on_request → Established
//!   PRACK  ──► on_request → 200 to PRACK
//!   BYE    ──► on_request → 200 to BYE, Terminated
//!   CANCEL ──► on_request → 200 to CANCEL + 487 to INVITE
//! ```

use crate::dialog::{extract_tag, Dialog, DialogState};
use crate::profile::ImsProfile;
use crate::sdp::Sdp;
use sip::{Header, Headers, Method, Request, Response};

/// Where the incoming call is in its life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UasState {
    /// INVITE received; no final response sent yet.
    Offered,
    /// 180 Ringing sent; still awaiting answer or CANCEL.
    Ringing,
    /// 200 OK sent; awaiting ACK.
    Accepted,
    /// ACK received; the dialog is confirmed.
    Confirmed,
    /// A final non-2xx was sent, or the dialog was torn down.
    Terminated,
}

/// What the caller should do after feeding a request to the UAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UasEvent {
    /// Send this response (e.g. 200 to PRACK/BYE/OPTIONS).
    Respond(Response),
    /// The ACK arrived; the dialog is confirmed.
    Established,
    /// The peer terminated the dialog with BYE.
    Terminated,
    /// The INVITE was cancelled: send these in order (200 to CANCEL, then 487
    /// to INVITE), then terminate the dialog.
    Cancelled { responses: Vec<Response> },
    /// Nothing to do for this request.
    Ignored,
}

/// Errors from parsing an incoming INVITE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UasError {
    /// A required header was missing or malformed.
    MissingHeader(&'static str),
    /// The SDP offer could not be parsed.
    BadOffer(String),
    /// The SDP answer could not be built (e.g. no common codec).
    BadAnswer(String),
    /// A request arrived in a state that cannot handle it.
    WrongState(&'static str),
}

impl core::fmt::Display for UasError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UasError::MissingHeader(h) => write!(f, "incoming INVITE missing header: {h}"),
            UasError::BadOffer(e) => write!(f, "incoming offer is not valid SDP: {e}"),
            UasError::BadAnswer(e) => write!(f, "cannot build the SDP answer: {e}"),
            UasError::WrongState(s) => write!(f, "request not valid in UAS state {s}"),
        }
    }
}

impl std::error::Error for UasError {}

/// The callee side of one incoming session.
#[derive(Debug, Clone)]
pub struct IncomingCall {
    profile: ImsProfile,
    dialog: Dialog,
    state: UasState,
    offer: Option<Sdp>,
    answer: Option<Sdp>,
    /// Whether the caller asked for reliable provisionals (RFC 3262).
    reliable: bool,
    /// Next `RSeq` to put in a reliable provisional.
    rseq: u32,
    /// The INVITE request, kept so CANCEL can be answered with matching headers.
    invite: Request,
    /// Record-Route entries to echo back, in the order received.
    record_route: Vec<String>,
}

impl IncomingCall {
    /// Build the callee-side dialog from an incoming INVITE (RFC 3261 §12.1.1).
    ///
    /// The local identity is the request's `To`; the remote identity is `From`.
    /// A fresh local tag is generated and used on every response.
    pub fn from_invite(request: &Request, profile: ImsProfile) -> Result<Self, UasError> {
        if request.method != Method::Invite {
            return Err(UasError::MissingHeader("INVITE"));
        }
        let to = request
            .headers
            .get("to")
            .ok_or(UasError::MissingHeader("To"))?;
        let from = request
            .headers
            .get("from")
            .ok_or(UasError::MissingHeader("From"))?;
        let call_id = request
            .headers
            .get("call-id")
            .ok_or(UasError::MissingHeader("Call-ID"))?;
        let cseq = request
            .headers
            .cseq()
            .ok_or(UasError::MissingHeader("CSeq"))?;

        let local_uri = sip::NameAddr::parse(to)
            .map(|n| n.uri.to_string())
            .map_err(|_| UasError::MissingHeader("To"))?;
        let remote_uri = sip::NameAddr::parse(from)
            .map(|n| n.uri.to_string())
            .map_err(|_| UasError::MissingHeader("From"))?;
        let remote_tag = extract_tag(from).ok_or(UasError::MissingHeader("From tag"))?;

        let local_tag = format!("uas-{}", profile.contact_port);
        let record_route: Vec<String> = request
            .headers
            .get_all("record-route")
            .map(str::to_string)
            .collect();

        // A UAS routes in-dialog requests over the Record-Route set in reverse.
        let route_set: Vec<String> = record_route.iter().rev().cloned().collect();

        let dialog = Dialog::new(
            call_id,
            local_uri,
            remote_uri,
            local_tag,
            remote_tag,
            profile.contact_uri(),
        )
        .with_invite_cseq(cseq.seq)
        .with_route_set(route_set);

        let offer = if request.body.is_empty() {
            None
        } else {
            let text = core::str::from_utf8(&request.body)
                .map_err(|_| UasError::BadOffer("body is not UTF-8".into()))?;
            Some(Sdp::parse(text).map_err(|e| UasError::BadOffer(e.to_string()))?)
        };

        let supported = request
            .headers
            .get_all("supported")
            .chain(request.headers.get_all("require"))
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("100rel"));

        Ok(Self {
            profile,
            dialog,
            state: UasState::Offered,
            offer,
            answer: None,
            reliable: supported,
            rseq: 1,
            invite: request.clone(),
            record_route,
        })
    }

    pub fn state(&self) -> UasState {
        self.state
    }

    pub fn dialog(&self) -> &Dialog {
        &self.dialog
    }

    /// The SDP offer carried by the INVITE, if any.
    pub fn offer(&self) -> Option<&Sdp> {
        self.offer.as_ref()
    }

    /// The SDP answer sent in the 200 OK, once [`IncomingCall::answer`] ran.
    pub fn answer(&self) -> Option<&Sdp> {
        self.answer.as_ref()
    }

    /// 100 Trying (RFC 3261 §17.2.1).
    pub fn trying(&self) -> Response {
        self.response(100, "Trying", &[], Vec::new())
    }

    /// 180 Ringing, carrying an `RSeq` when the caller asked for 100rel.
    pub fn ringing(&mut self) -> Response {
        self.state = UasState::Ringing;
        if self.reliable {
            let rseq = self.rseq;
            self.rseq += 1;
            self.response(
                180,
                "Ringing",
                &[("Require", "100rel"), ("RSeq", &rseq.to_string())],
                Vec::new(),
            )
        } else {
            self.response(180, "Ringing", &[], Vec::new())
        }
    }

    /// 200 OK with the negotiated SDP answer, and a `Contact` for the dialog.
    pub fn accept(&mut self) -> Result<Response, UasError> {
        if self.state == UasState::Terminated {
            return Err(UasError::WrongState("Terminated"));
        }
        let offer = self.offer.clone().ok_or(UasError::MissingHeader(
            "SDP offer (this UAS has no delayed-offer support)",
        ))?;
        let answer = Sdp::answer_amr_wb(&offer, &self.profile.contact_host)
            .map_err(|e| UasError::BadAnswer(e.to_string()))?;
        let body = answer.to_text().into_bytes();
        self.answer = Some(answer);
        self.state = UasState::Accepted;
        Ok(self.response(
            200,
            "OK",
            &[
                ("Contact", &format!("<{}>", self.profile.contact_uri())),
                ("Content-Type", "application/sdp"),
                ("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,MESSAGE"),
            ],
            body,
        ))
    }

    /// Send a final non-2xx (e.g. 486 Busy Here, 480 Temporarily Unavailable).
    pub fn reject(&mut self, status: u16, reason: &str) -> Response {
        self.state = UasState::Terminated;
        self.dialog.state = DialogState::Terminated;
        // A retry-after hint is useful for 486/480 but not mandatory.
        self.response(status, reason, &[], Vec::new())
    }

    /// Handle a request that arrived in this dialog.
    pub fn on_request(&mut self, request: &Request) -> Result<UasEvent, UasError> {
        match request.method {
            Method::Ack => {
                if self.state != UasState::Accepted {
                    return Err(UasError::WrongState("ACK before 200 OK"));
                }
                self.state = UasState::Confirmed;
                self.dialog.confirm();
                Ok(UasEvent::Established)
            }
            Method::Prack => {
                // 200 to the PRACK itself (RFC 3262 §4). RAck is on the request.
                Ok(UasEvent::Respond(self.response_to(request, 200, "OK", &[])))
            }
            Method::Update => Ok(UasEvent::Respond(self.response_to(request, 200, "OK", &[]))),
            Method::Info => Ok(UasEvent::Respond(self.response_to(request, 200, "OK", &[]))),
            Method::Options => {
                let allow = "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,MESSAGE";
                Ok(UasEvent::Respond(self.response_to(
                    request,
                    200,
                    "OK",
                    &[("Allow", allow)],
                )))
            }
            Method::Bye => {
                self.state = UasState::Terminated;
                self.dialog.state = DialogState::Terminated;
                let ack = self.response_to(request, 200, "OK", &[]);
                let _ = ack;
                Ok(UasEvent::Terminated)
            }
            Method::Cancel => {
                if matches!(self.state, UasState::Accepted | UasState::Confirmed) {
                    // RFC 3261 §9.2: a CANCEL after a final response is a no-op
                    // request; answer 200 but leave the session alone.
                    return Ok(UasEvent::Respond(self.response_to(request, 200, "OK", &[])));
                }
                let to_cancel = self.response_to(request, 200, "OK", &[]);
                let to_invite = self.response_to(&self.invite, 487, "Request Terminated", &[]);
                self.state = UasState::Terminated;
                self.dialog.state = DialogState::Terminated;
                Ok(UasEvent::Cancelled {
                    responses: vec![to_cancel, to_invite],
                })
            }
            _ => Ok(UasEvent::Ignored),
        }
    }

    /// Build the in-dialog BYE the callee sends to hang up.
    pub fn bye(&mut self) -> Option<Request> {
        if !matches!(self.state, UasState::Accepted | UasState::Confirmed) {
            return None;
        }
        self.state = UasState::Terminated;
        Some(self.dialog.bye())
    }

    /// A response that echoes the INVITE's dialog headers (Via/From/Call-ID/CSeq)
    /// and adds the local tag to `To`.
    fn response(
        &self,
        status: u16,
        reason: &str,
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Response {
        self.response_to_body(&self.invite, status, reason, extra, body)
    }

    fn response_to(
        &self,
        request: &Request,
        status: u16,
        reason: &str,
        extra: &[(&str, &str)],
    ) -> Response {
        self.response_to_body(request, status, reason, extra, Vec::new())
    }

    fn response_to_body(
        &self,
        request: &Request,
        status: u16,
        reason: &str,
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Response {
        let mut headers = Headers::new();
        // Every Via is echoed, in order (RFC 3261 §8.2.6.2).
        for via in request.headers.get_all("via") {
            headers.push(Header::new("Via", via));
        }
        if let Some(from) = request.headers.get("from") {
            headers.push(Header::new("From", from));
        }
        if let Some(to) = request.headers.get("to") {
            let tag = self.dialog.local_tag.clone();
            let value = if extract_tag(to).is_some() {
                to.to_string()
            } else {
                format!("{to};tag={tag}")
            };
            headers.push(Header::new("To", value));
        }
        if let Some(call_id) = request.headers.get("call-id") {
            headers.push(Header::new("Call-ID", call_id));
        }
        if let Some(cseq) = request.headers.get("cseq") {
            headers.push(Header::new("CSeq", cseq));
        }
        // Echo Record-Route in the order received (responses mirror requests).
        for rr in &self.record_route {
            headers.push(Header::new("Record-Route", rr));
        }
        for (name, value) in extra {
            headers.push(Header::new(*name, *value));
        }
        headers.push(Header::new("User-Agent", self.profile.user_agent.clone()));
        headers.push(Header::new("Content-Length", body.len().to_string()));
        Response {
            status,
            reason: reason.into(),
            headers,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ImsProfile;

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 49170 RTP/AVP 116 117\r\na=rtpmap:116 AMR-WB/16000/1\r\na=fmtp:116 mode-set=0,1,2,3,4,5,6,7;octet-align=1\r\na=rtpmap:117 telephone-event/16000\r\na=ptime:20\r\n";

    fn invite() -> Request {
        let mut headers = Headers::new();
        headers.push(Header::new(
            "Via",
            "SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-caller-1;rport",
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            "<sip:001010000000002@ims.example>;tag=caller-tag",
        ));
        headers.push(Header::new("To", "<sip:001010000000001@ims.example>"));
        headers.push(Header::new("Call-ID", "caller-call-1"));
        headers.push(Header::new("CSeq", "1 INVITE"));
        headers.push(Header::new(
            "Contact",
            "<sip:001010000000002@192.0.2.20:5060>",
        ));
        headers.push(Header::new("Supported", "100rel"));
        headers.push(Header::new("Content-Type", "application/sdp"));
        headers.push(Header::new(
            "Content-Length",
            OFFER.len().to_string().as_str(),
        ));
        Request {
            method: Method::Invite,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: OFFER.as_bytes().to_vec(),
        }
    }

    fn uas() -> IncomingCall {
        IncomingCall::from_invite(&invite(), ImsProfile::lab_default()).unwrap()
    }

    #[test]
    fn invite_builds_the_callee_dialog() {
        let u = uas();
        assert_eq!(u.state(), UasState::Offered);
        assert_eq!(u.dialog().call_id, "caller-call-1");
        assert_eq!(u.dialog().remote_tag, "caller-tag");
        assert_eq!(u.dialog().local_uri, "sip:001010000000001@ims.example");
        assert_eq!(u.dialog().remote_uri, "sip:001010000000002@ims.example");
        assert!(u.offer().is_some());
    }

    #[test]
    fn ringing_adds_the_local_tag_and_rseq() {
        let mut u = uas();
        let trying = u.trying();
        assert_eq!(trying.status, 100);
        let ringing = u.ringing();
        assert_eq!(ringing.status, 180);
        assert_eq!(u.state(), UasState::Ringing);
        // Reliable provisional: Require: 100rel + an RSeq.
        assert_eq!(ringing.headers.get("require"), Some("100rel"));
        assert!(ringing.headers.get("rseq").is_some());
        let to = ringing.headers.get("to").unwrap();
        assert!(to.contains("sip:001010000000001@ims.example"));
        assert!(to.contains("tag=uas-"));
        // The INVITE's dialog headers are echoed.
        assert_eq!(ringing.headers.get("call-id"), Some("caller-call-1"));
        assert_eq!(ringing.headers.get("cseq"), Some("1 INVITE"));
        assert!(ringing
            .headers
            .get("via")
            .unwrap()
            .contains("z9hG4bK-caller-1"));
    }

    #[test]
    fn answer_carries_sdp_and_contact() {
        let mut u = uas();
        u.ringing();
        let ok = u.accept().unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(u.state(), UasState::Accepted);
        assert_eq!(ok.headers.get("content-type"), Some("application/sdp"));
        assert!(ok.headers.get("contact").unwrap().starts_with("<sip:"));
        assert_eq!(
            ok.headers.get("content-length"),
            Some(ok.body.len().to_string().as_str())
        );
        let body = String::from_utf8(ok.body.clone()).unwrap();
        assert!(body.contains("m=audio"));
        assert!(body.contains("AMR-WB"));
        assert!(u.answer().is_some());
    }

    #[test]
    fn ack_confirms_and_bye_terminates() {
        let mut u = uas();
        u.ringing();
        let _ = u.accept().unwrap();

        let mut ack_headers = Headers::new();
        ack_headers.push(Header::new("CSeq", "1 ACK"));
        let ack = Request {
            method: Method::Ack,
            uri: "sip:001010000000001@ims.example".into(),
            headers: ack_headers,
            body: Vec::new(),
        };
        assert_eq!(u.on_request(&ack).unwrap(), UasEvent::Established);
        assert_eq!(u.state(), UasState::Confirmed);

        let mut bye_headers = Headers::new();
        bye_headers.push(Header::new("CSeq", "2 BYE"));
        let bye = Request {
            method: Method::Bye,
            uri: "sip:001010000000001@ims.example".into(),
            headers: bye_headers,
            body: Vec::new(),
        };
        assert_eq!(u.on_request(&bye).unwrap(), UasEvent::Terminated);
        assert_eq!(u.state(), UasState::Terminated);
    }

    #[test]
    fn prack_is_answered_with_200() {
        let mut u = uas();
        let _ = u.ringing();
        let mut headers = Headers::new();
        headers.push(Header::new("CSeq", "2 PRACK"));
        headers.push(Header::new("RAck", "1 1 INVITE"));
        let prack = Request {
            method: Method::Prack,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: Vec::new(),
        };
        match u.on_request(&prack).unwrap() {
            UasEvent::Respond(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.headers.get("cseq"), Some("2 PRACK"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn cancel_yields_200_and_487() {
        let mut u = uas();
        let _ = u.ringing();
        let mut headers = Headers::new();
        headers.push(Header::new("CSeq", "1 CANCEL"));
        let cancel = Request {
            method: Method::Cancel,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: Vec::new(),
        };
        match u.on_request(&cancel).unwrap() {
            UasEvent::Cancelled { responses } => {
                assert_eq!(responses[0].status, 200);
                assert_eq!(responses[1].status, 487);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(u.state(), UasState::Terminated);
    }

    #[test]
    fn accepted_call_ignores_late_cancel() {
        let mut u = uas();
        u.ringing();
        let _ = u.accept().unwrap();
        let mut headers = Headers::new();
        headers.push(Header::new("CSeq", "1 CANCEL"));
        let cancel = Request {
            method: Method::Cancel,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: Vec::new(),
        };
        match u.on_request(&cancel).unwrap() {
            // RFC 3261 §9.2: answer 200 but do not tear down the session.
            UasEvent::Respond(r) => assert_eq!(r.status, 200),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(u.state(), UasState::Accepted);
    }

    #[test]
    fn reject_is_a_final_non_2xx() {
        let mut u = uas();
        let busy = u.reject(486, "Busy Here");
        assert_eq!(busy.status, 486);
        assert_eq!(u.state(), UasState::Terminated);
        assert!(u.bye().is_none());
    }

    #[test]
    fn uas_can_initiate_bye_after_answer() {
        let mut u = uas();
        u.ringing();
        let _ = u.accept().unwrap();
        let bye = u.bye().expect("BYE after answer");
        assert_eq!(bye.method, Method::Bye);
        assert_eq!(bye.headers.get("call-id"), Some("caller-call-1"));
        assert!(u.bye().is_none(), "a second BYE must not be produced");
    }

    #[test]
    fn non_invite_is_rejected() {
        let mut req = invite();
        req.method = Method::Options;
        assert!(IncomingCall::from_invite(&req, ImsProfile::lab_default()).is_err());
    }
}
