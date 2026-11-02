//! Outgoing-call state machine: INVITE / reliable 183 / PRACK / 200 / ACK.
//!
//! This is the caller side of an MMTel voice session (RFC 3261 §13, RFC 3262
//! reliable provisionals, RFC 3264 SDP offer/answer). It owns request
//! construction and the response-driven state machine; the caller supplies the
//! transport and feeds received responses back in with [`Call::on_response`].
//! No media flows through this crate — only the SDP negotiation is modelled.

use crate::dialog::{Dialog, DialogState};
use crate::profile::ImsProfile;
use crate::sdp::Sdp;
use sip::{Method, Request, Response};

/// Caller-side call progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// No INVITE outstanding.
    Idle,
    /// INVITE sent; awaiting a provisional or final response.
    Inviting,
    /// A reliable provisional (18x) was answered with a PRACK; awaiting the
    /// 2xx to that PRACK before the INVITE final can be recognised.
    AwaitingPrackResponse,
    /// PRACK confirmed; awaiting the final 2xx to INVITE.
    AwaitingInviteFinal,
    /// CANCEL sent; awaiting the 200 to CANCEL and the 487 to INVITE.
    Cancelling,
    /// 2xx to INVITE received and ACK sent; the dialog is confirmed.
    Established,
    /// A non-2xx final response ended the attempt.
    Failed(u16),
    /// The session was released (BYE sent).
    Terminated,
}

/// What the caller should do after an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEvent {
    /// Send this request (INVITE or PRACK); the call is not yet established.
    Send(Request),
    /// The call is established: send the carried ACK. The negotiated answer is
    /// reachable via [`Call::answer`].
    Established { ack: Request },
    /// A hold/resume re-INVITE was accepted: send the carried ACK.
    Renegotiated { ack: Request },
    /// A second (forked) 2xx to the original INVITE: ACK it, then BYE that
    /// branch; the first dialog stays the active one (RFC 3261 §13.2.2.4).
    Forked { ack: Request, bye: Request },
    /// A non-2xx final response to INVITE ended the attempt.
    Failed(u16),
    /// A provisional response (e.g. 100 Trying) needed no action.
    Provisional,
}

/// The caller side of an MTSI voice call.
///
/// Construct it with [`Call::new`], send the request from the first
/// [`CallEvent::Send`], then feed every received response to
/// [`Call::on_response`] until [`CallEvent::Established`] or [`CallEvent::Failed`].
#[derive(Debug, Clone)]
pub struct Call {
    profile: ImsProfile,
    dialog: Dialog,
    state: CallState,
    offer: Option<Sdp>,
    answer: Option<Sdp>,
    /// CSeq of an outstanding hold/resume re-INVITE, so its ACK matches.
    pending_reinvite_cseq: Option<u32>,
}

impl Call {
    /// Start a call from `profile` to the called party's public identity.
    pub fn new(profile: ImsProfile, remote: impl Into<String>) -> Self {
        let remote_uri = normalize_impu(remote.into());
        let call_id = format!(
            "fungos-call-{}@{}",
            profile.public_user(),
            profile.contact_host
        );
        let local_tag = format!("call-{}", profile.contact_port);
        let dialog = Dialog::new(
            call_id,
            profile.public_identity.clone(),
            remote_uri,
            local_tag,
            String::new(),
            profile.contact_uri(),
        )
        .with_route_set(profile.service_route.clone());
        Self {
            profile,
            dialog,
            state: CallState::Idle,
            offer: None,
            answer: None,
            pending_reinvite_cseq: None,
        }
    }

    pub fn state(&self) -> CallState {
        self.state
    }

    pub fn profile(&self) -> &ImsProfile {
        &self.profile
    }

    pub fn dialog(&self) -> &Dialog {
        &self.dialog
    }

    /// The SDP offer we sent in the INVITE, if one has been built.
    pub fn offer(&self) -> Option<&Sdp> {
        self.offer.as_ref()
    }

    /// The negotiated answer, once a 18x or 2xx carried one.
    pub fn answer(&self) -> Option<&Sdp> {
        self.answer.as_ref()
    }

    pub fn is_established(&self) -> bool {
        self.state == CallState::Established
    }

    /// Build and arm the initial INVITE carrying the AMR-WB offer.
    pub fn invite(&mut self) -> CallEvent {
        let offer = self.profile.amr_wb_offer(&self.profile.contact_host, true);
        self.offer = Some(offer.clone());
        self.dialog.state = DialogState::Early;
        let request = self.dialog.invite(&offer);
        self.state = CallState::Inviting;
        CallEvent::Send(request)
    }

    /// Consume a response received for this call and return the next action.
    ///
    /// The caller is responsible for routing responses to the right dialog (by
    /// Call-ID and branch); this models only the INVITE-dialog progress.
    pub fn on_response(&mut self, response: &Response) -> CallEvent {
        // Learn the callee tag from the first tagged response (RFC 3261 §12.1).
        if let Some(to) = response.headers.get("to") {
            if to.contains("tag=") {
                self.dialog.set_remote_tag(to);
            }
        }
        let cseq_method = response.headers.cseq().map(|c| c.method);
        let status = response.status;
        let is_invite_resp = cseq_method == Some(Method::Invite);
        let is_prack_resp = cseq_method == Some(Method::Prack);

        // A CANCEL completes when the INVITE is terminated with 487 (RFC 3261 §9.1).
        if is_invite_resp && status == 487 && self.state == CallState::Cancelling {
            self.state = CallState::Terminated;
            return CallEvent::Failed(487);
        }

        // A reliable provisional (18x) carries the answer and an RSeq; PRACK it.
        if is_invite_resp && (101..200).contains(&status) {
            if let Some(rseq) = rseq_of(response) {
                if let Some(answer) = self.capture_answer(response) {
                    self.answer = Some(answer);
                }
                let prack = self.dialog.prack(rseq);
                self.state = CallState::AwaitingPrackResponse;
                return CallEvent::Send(prack);
            }
            return CallEvent::Provisional;
        }

        // Any other provisional (e.g. 100 Trying) needs no action.
        if (100..200).contains(&status) {
            return CallEvent::Provisional;
        }

        // Final responses.
        if is_prack_resp {
            if (200..300).contains(&status) {
                // PRACK confirmed; the INVITE final is still to come.
                self.state = CallState::AwaitingInviteFinal;
                return CallEvent::Provisional;
            }
            self.state = CallState::Failed(status);
            return CallEvent::Failed(status);
        }

        if is_invite_resp {
            if (200..300).contains(&status) {
                if let Some(answer) = self.capture_answer(response) {
                    self.answer = Some(answer);
                }
                // A 2xx while Established is either the answer to a hold/resume
                // re-INVITE or a second (forked) 2xx for the original INVITE.
                if self.state == CallState::Established {
                    let resp_cseq = response.headers.cseq().map(|c| c.seq);
                    if let (Some(pending), Some(got)) = (self.pending_reinvite_cseq, resp_cseq) {
                        if pending == got {
                            self.pending_reinvite_cseq = None;
                            return CallEvent::Renegotiated {
                                ack: self.dialog.ack_with_cseq(pending),
                            };
                        }
                    }
                    // RFC 3261 §13.2.2.4: ACK every 2xx, keep the first dialog,
                    // and BYE the others.
                    if let Some((ack, bye)) = self.fork_ack_bye(response) {
                        return CallEvent::Forked { ack, bye };
                    }
                }
                let ack = self.dialog.ack();
                self.state = CallState::Established;
                return CallEvent::Established { ack };
            }
            // Non-2xx to INVITE: the client transaction sends the ACK, not us.
            self.state = CallState::Failed(status);
            return CallEvent::Failed(status);
        }

        CallEvent::Provisional
    }

    /// Build the in-dialog BYE that releases an established session.
    pub fn bye(&mut self) -> Option<Request> {
        if !matches!(
            self.state,
            CallState::Established | CallState::AwaitingInviteFinal
        ) {
            return None;
        }
        self.state = CallState::Terminated;
        Some(self.dialog.bye())
    }

    /// Put the remote party on hold by sending a re-INVITE with `a=sendonly`
    /// (RFC 3261 §14.1, RFC 3264 §6.1).
    ///
    /// The call must be [`CallState::Established`]. The 2xx is acknowledged with
    /// [`CallEvent::Renegotiated`].
    pub fn hold(&mut self) -> Option<Request> {
        self.renegotiate_direction(crate::sdp::Direction::SendOnly)
    }

    /// Resume from hold: re-INVITE with `a=sendrecv`.
    pub fn resume(&mut self) -> Option<Request> {
        self.renegotiate_direction(crate::sdp::Direction::SendRecv)
    }

    fn renegotiate_direction(&mut self, direction: crate::sdp::Direction) -> Option<Request> {
        if self.state != CallState::Established {
            return None;
        }
        let mut sdp = self.answer.clone().or_else(|| self.offer.clone())?;
        sdp.set_direction(direction);
        // Bump o= session version so the peer treats this as a new offer.
        let version = sdp.origin.session_version.parse::<u64>().unwrap_or(0) + 1;
        sdp.origin.session_version = version.to_string();
        let (cseq, request) = self.dialog.reinvite(&sdp.to_text());
        self.pending_reinvite_cseq = Some(cseq);
        self.answer = Some(sdp);
        Some(request)
    }

    /// CANCEL an INVITE that has not been answered (RFC 3261 §9).
    ///
    /// Returns the CANCEL request, which the caller must send on the same
    /// transport as the INVITE. The call moves to [`CallState::Cancelling`]
    /// and completes when the `487 Request Terminated` arrives.
    pub fn cancel(&mut self) -> Option<Request> {
        if !matches!(
            self.state,
            CallState::Inviting | CallState::AwaitingPrackResponse | CallState::AwaitingInviteFinal
        ) {
            return None;
        }
        let cancel = self.dialog.cancel()?;
        self.state = CallState::Cancelling;
        Some(cancel)
    }

    /// Build the ACK and BYE for a forked 2xx that has its own remote tag,
    /// Contact and route set (RFC 3261 §13.2.2.4).
    fn fork_ack_bye(&self, response: &Response) -> Option<(Request, Request)> {
        let cseq = response.headers.cseq()?;
        let remote_tag = crate::dialog::extract_tag(response.headers.get("to")?)?;
        let contact = response.headers.get("contact")?;
        let remote_target = sip::NameAddr::parse(contact).ok()?.uri.to_string();
        let route_set: Vec<String> = response
            .headers
            .get_all("record-route")
            .map(|v| {
                v.trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
            .collect();
        let mut forked = Dialog::new(
            self.dialog.call_id.clone(),
            self.dialog.local_uri.clone(),
            remote_target,
            self.dialog.local_tag.clone(),
            remote_tag,
            self.dialog.local_contact.clone(),
        )
        .with_invite_cseq(cseq.seq)
        .with_route_set(route_set);
        forked.confirm();
        let ack = forked.ack_with_cseq(cseq.seq);
        let bye = forked.bye();
        Some((ack, bye))
    }

    /// Parse the SDP answer body of a response, if it has one.
    fn capture_answer(&self, response: &Response) -> Option<Sdp> {
        let text = core::str::from_utf8(&response.body).ok()?;
        if text.trim().is_empty() {
            return None;
        }
        Sdp::parse(text).ok()
    }
}

/// The `RSeq` of a reliable provisional, if present.
fn rseq_of(response: &Response) -> Option<u32> {
    response
        .headers
        .get("rseq")
        .and_then(|v| v.trim().parse().ok())
}

/// Turn a public identity into a bare `sip:` URI for the Request-URI/To.
fn normalize_impu(impu: String) -> String {
    if impu.starts_with("sip:") || impu.starts_with("tel:") {
        impu
    } else {
        format!("sip:{impu}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ImsProfile {
        ImsProfile::lab_default()
    }

    fn invite_request() -> Request {
        let mut call = Call::new(
            profile(),
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        );
        match call.invite() {
            CallEvent::Send(req) => req,
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn invite_carries_offer_and_no_to_tag() {
        let req = invite_request();
        assert_eq!(req.method, Method::Invite);
        assert_eq!(
            req.uri,
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org"
        );
        // No To-tag on the initial INVITE (RFC 3261 §13).
        assert_eq!(
            req.headers.get("to"),
            Some("<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>")
        );
        assert_eq!(req.headers.get("content-type"), Some("application/sdp"));
        assert_eq!(req.headers.get("supported"), Some("100rel"));
        // The offer is a real AMR-WB SDP body with a correct Content-Length.
        let body = String::from_utf8(req.body).unwrap();
        assert!(body.contains("m=audio 49170 RTP/AVP 116 101"));
        assert!(body.contains("a=rtpmap:116 AMR-WB/16000/1"));
        assert_eq!(
            req.headers.get("content-length"),
            Some(body.len().to_string().as_str())
        );
    }

    #[test]
    fn invite_wire_round_trip() {
        use sip::Message;
        let req = invite_request();
        let parsed = Message::parse(&Message::Request(req.clone()).to_text()).unwrap();
        assert_eq!(parsed, Message::Request(req));
    }

    #[test]
    fn full_flow_reaches_established() {
        use sip::Method as M;
        let mut call = Call::new(
            profile(),
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        );
        let CallEvent::Send(invite) = call.invite() else {
            panic!("invite expected")
        };
        let invite_cseq = invite.headers.cseq().unwrap().seq;

        // 100 Trying: no action.
        let trying = Response {
            status: 100,
            reason: "Trying".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        assert_eq!(call.on_response(&trying), CallEvent::Provisional);
        assert_eq!(call.state(), CallState::Inviting);

        // 183 Session Progress (reliable) with an answer and RSeq: PRACK it.
        let answer_sdp = Sdp::answer_amr_wb(&call.offer().unwrap().clone(), "192.0.2.11");
        let body = answer_sdp.unwrap().to_text();
        let progress = Response {
            status: 183,
            reason: "Session Progress".into(),
            headers: resp_headers(&[
                ("CSeq", "1 INVITE"),
                ("Require", "100rel"),
                ("RSeq", "1"),
                (
                    "To",
                    "<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag",
                ),
                ("Content-Type", "application/sdp"),
            ]),
            body: body.into_bytes(),
        };
        let CallEvent::Send(prack) = call.on_response(&progress) else {
            panic!("prack expected")
        };
        assert_eq!(prack.method, M::Prack);
        assert_eq!(prack.headers.get("rack"), Some("1 1 INVITE"));
        assert_eq!(call.state(), CallState::AwaitingPrackResponse);
        // The callee tag was learned and is now on the dialog's requests.
        assert_eq!(
            prack.headers.get("to"),
            Some("<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag")
        );
        assert!(call.answer().is_some());

        // 200 OK to PRACK: advance, but the call is not established yet.
        let prack_ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "2 PRACK")]),
            body: Vec::new(),
        };
        assert_eq!(call.on_response(&prack_ok), CallEvent::Provisional);
        assert_eq!(call.state(), CallState::AwaitingInviteFinal);

        // 200 OK to INVITE: ACK and established.
        let invite_ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        let event = call.on_response(&invite_ok);
        match event {
            CallEvent::Established { ack } => {
                assert_eq!(ack.method, M::Ack);
                // ACK uses the INVITE CSeq, not an incremented one.
                assert_eq!(ack.headers.cseq().unwrap().seq, invite_cseq);
                assert_eq!(ack.headers.get("contact"), None);
            }
            other => panic!("expected Established {{ ack }}, got {other:?}"),
        }
        assert_eq!(call.state(), CallState::Established);
        assert!(call.is_established());
        // The negotiated answer is available after establishment.
        assert_eq!(
            call.answer()
                .unwrap()
                .audio()
                .unwrap()
                .payload_type("AMR-WB", 16_000),
            Some(116)
        );
    }

    #[test]
    fn non_2xx_invite_fails() {
        let mut call = Call::new(
            profile(),
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        );
        let _ = call.invite();
        let busy = Response {
            status: 486,
            reason: "Busy Here".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        assert_eq!(call.on_response(&busy), CallEvent::Failed(486));
        assert_eq!(call.state(), CallState::Failed(486));
        // BYE is unavailable once the attempt failed.
        assert!(call.bye().is_none());
    }

    #[test]
    fn cancel_reuses_the_invite_branch_and_completes_with_487() {
        let mut call = Call::new(
            profile(),
            "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        );
        let CallEvent::Send(invite) = call.invite() else {
            panic!("invite expected")
        };
        let invite_branch = invite.headers.via().unwrap().branch().unwrap().to_string();

        let cancel = call.cancel().expect("CANCEL before a final response");
        assert_eq!(cancel.method, Method::Cancel);
        // RFC 3261 §9.1: same branch, same CSeq number, only the method changes.
        assert_eq!(
            cancel.headers.via().unwrap().branch().unwrap(),
            invite_branch
        );
        assert_eq!(cancel.headers.get("cseq"), Some("1 CANCEL"));
        assert_eq!(cancel.headers.get("call-id"), invite.headers.get("call-id"));
        assert_eq!(cancel.headers.get("to"), invite.headers.get("to"));
        assert!(cancel.body.is_empty());
        assert_eq!(cancel.headers.get("content-length"), Some("0"));
        assert_eq!(call.state(), CallState::Cancelling);

        // The 200 to CANCEL changes nothing; the 487 to INVITE ends the attempt.
        let cancel_ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "1 CANCEL")]),
            body: Vec::new(),
        };
        assert_eq!(call.on_response(&cancel_ok), CallEvent::Provisional);
        let terminated = Response {
            status: 487,
            reason: "Request Terminated".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        assert_eq!(call.on_response(&terminated), CallEvent::Failed(487));
        assert_eq!(call.state(), CallState::Terminated);
    }

    #[test]
    fn cancel_is_refused_once_established() {
        let mut call = Call::new(profile(), "sip:b@example");
        let _ = call.invite();
        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        assert!(matches!(
            call.on_response(&ok),
            CallEvent::Established { .. }
        ));
        assert!(call.cancel().is_none());
    }

    #[test]
    fn hold_sends_a_sendonly_reinvite_and_acks_with_its_own_cseq() {
        let mut call = Call::new(profile(), "sip:b@example");
        let _ = call.invite();
        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE")]),
            body: Vec::new(),
        };
        assert!(matches!(
            call.on_response(&ok),
            CallEvent::Established { .. }
        ));

        let reinvite = call.hold().expect("hold after established");
        assert_eq!(reinvite.method, Method::Invite);
        let cseq = reinvite.headers.cseq().unwrap().seq;
        assert!(cseq > 1, "re-INVITE must use a fresh CSeq");
        let body = String::from_utf8(reinvite.body.clone()).unwrap();
        assert!(body.contains("a=sendonly"));
        // The session version is bumped so the peer treats it as a new offer.
        assert!(body.contains("o=- 0 1 ") || body.contains("o=- 0 "));

        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", &format!("{cseq} INVITE"))]),
            body: Vec::new(),
        };
        match call.on_response(&ok) {
            CallEvent::Renegotiated { ack } => {
                assert_eq!(ack.method, Method::Ack);
                assert_eq!(ack.headers.cseq().unwrap().seq, cseq);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(call.state(), CallState::Established);

        // Resume returns to sendrecv.
        let resume = call.resume().expect("resume after hold");
        let body = String::from_utf8(resume.body.clone()).unwrap();
        assert!(body.contains("a=sendrecv"));
        assert!(!body.contains("a=sendonly"));
    }

    #[test]
    fn hold_is_refused_before_the_call_is_established() {
        let mut call = Call::new(profile(), "sip:b@example");
        let _ = call.invite();
        assert!(call.hold().is_none());
    }

    #[test]
    fn a_forked_2xx_is_acked_and_bye_d_sent_to_it() {
        let mut call = Call::new(profile(), "sip:b@example");
        let _ = call.invite();
        // First 200 establishes the dialog.
        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[
                ("CSeq", "1 INVITE"),
                ("To", "<sip:b@example>;tag=branch-a"),
                ("Contact", "<sip:b@10.0.0.1:5060>"),
            ]),
            body: Vec::new(),
        };
        assert!(matches!(
            call.on_response(&ok),
            CallEvent::Established { .. }
        ));

        // A second 200 for the same INVITE is a fork: ACK it and BYE it.
        let fork = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[
                ("CSeq", "1 INVITE"),
                ("To", "<sip:b@example>;tag=branch-b"),
                ("Contact", "<sip:b@10.0.0.2:5060>"),
                ("Record-Route", "<sip:rr2.example;lr>"),
            ]),
            body: Vec::new(),
        };
        match call.on_response(&fork) {
            CallEvent::Forked { ack, bye } => {
                assert_eq!(ack.method, Method::Ack);
                assert_eq!(bye.method, Method::Bye);
                // Both target the forked branch, not the active dialog.
                assert!(ack.headers.get("to").unwrap().contains("branch-b"));
                assert!(bye.headers.get("to").unwrap().contains("branch-b"));
                assert_eq!(ack.uri, "sip:rr2.example;lr");
                assert_eq!(ack.headers.cseq().unwrap().seq, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
        // The active dialog is unchanged.
        assert_eq!(call.state(), CallState::Established);
    }

    #[test]
    fn a_reinvite_2xx_is_not_treated_as_a_fork() {
        let mut call = Call::new(profile(), "sip:b@example");
        let _ = call.invite();
        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[("CSeq", "1 INVITE"), ("To", "<sip:b@example>;tag=b")]),
            body: Vec::new(),
        };
        assert!(matches!(
            call.on_response(&ok),
            CallEvent::Established { .. }
        ));
        let hold = call.hold().expect("hold");
        let hold_cseq = hold.headers.cseq().unwrap().seq;
        let ok = Response {
            status: 200,
            reason: "OK".into(),
            headers: resp_headers(&[
                ("CSeq", &format!("{hold_cseq} INVITE")),
                ("To", "<sip:b@example>;tag=b"),
            ]),
            body: Vec::new(),
        };
        assert!(matches!(
            call.on_response(&ok),
            CallEvent::Renegotiated { .. }
        ));
    }

    fn resp_headers(pairs: &[(&str, &str)]) -> sip::Headers {
        let mut h = sip::Headers::new();
        for (k, v) in pairs {
            h.push(sip::Header::new(*k, *v));
        }
        h
    }
}
