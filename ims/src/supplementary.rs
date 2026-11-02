//! Client-side supplementary services: hold/resume and call waiting.
//!
//! These are the UE behaviours that MMTel/AS services drive, implemented as
//! local session management. The MMTel application server itself is a **network
//! element** and is not modelled here; what a client must do in response to the
//! resulting signalling is.
//!
//! * **Hold/resume** — a re-INVITE (or UPDATE) offering `a=sendonly` /
//!   `a=sendrecv` (RFC 3261 §14.1, RFC 3264 §6.1). See [`Call::hold`] and
//!   [`Call::resume`]; the UAS side answers via [`crate::IncomingCall::renegotiate`].
//! * **Call waiting** — an INVITE arriving while another call is established.
//!   [`accept_waiting`] holds the active call and answers the new one;
//!   [`decline_waiting`] rejects it with `486 Busy Here`.

use crate::call::{Call, CallState};
use crate::uas::{IncomingCall, UasError};
use sip::{Request, Response};

/// The requests/responses a call-waiting accept has to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallWaitingActions {
    /// The re-INVITE that puts the active call on hold (`a=sendonly`).
    pub hold: Request,
    /// The `200 OK` that answers the waiting call.
    pub answer: Response,
}

/// Whether an incoming INVITE should be treated as call waiting, i.e. there is
/// already an established call.
pub fn is_call_waiting(active: Option<&Call>) -> bool {
    matches!(active.map(Call::state), Some(CallState::Established))
}

/// Accept a waiting call: hold the active session and answer the new one.
///
/// The caller sends `actions.hold`, completes the hold re-INVITE/ACK, then sends
/// `actions.answer`. The new call's dialog is confirmed when its ACK arrives.
pub fn accept_waiting(
    active: &mut Call,
    incoming: &mut IncomingCall,
) -> Result<CallWaitingActions, UasError> {
    if !is_call_waiting(Some(active)) {
        return Err(UasError::WrongState("no established call to hold"));
    }
    let hold = active
        .hold()
        .ok_or(UasError::WrongState("hold re-INVITE was refused"))?;
    // `accept` needs the incoming offer; a delayed-offer INVITE is not modelled.
    let answer = incoming.accept()?;
    Ok(CallWaitingActions { hold, answer })
}

/// Decline a waiting call with `486 Busy Here` (RFC 3261 §21.4.24).
///
/// A device that does not support call waiting uses this instead of
/// [`accept_waiting`].
pub fn decline_waiting(incoming: &mut IncomingCall) -> Response {
    incoming.reject(486, "Busy Here")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ImsProfile;
    use crate::sdp::Direction;
    use sip::{Header, Headers, Method};

    fn invite() -> sip::Request {
        let offer = sdp_offer();
        let mut headers = Headers::new();
        headers.push(Header::new(
            "From",
            "<sip:001010000000002@ims.example>;tag=caller-tag",
        ));
        headers.push(Header::new("To", "<sip:001010000000001@ims.example>"));
        headers.push(Header::new("Call-ID", "waiting-1"));
        headers.push(Header::new("CSeq", "1 INVITE"));
        headers.push(Header::new("Content-Type", "application/sdp"));
        sip::Request {
            method: Method::Invite,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: offer.into_bytes(),
        }
    }

    fn sdp_offer() -> String {
        let offer = crate::Sdp::amr_wb_offer(&[0, 1, 2], true, "192.0.2.20");
        offer.to_text()
    }

    /// Drive a `Call` to Established with a canned 200 OK.
    fn established_call() -> Call {
        let mut call = Call::new(ImsProfile::lab_default(), "sip:001010000000009@ims.example");
        let _ = call.invite();
        let mut headers = Headers::new();
        headers.push(Header::new("CSeq", "1 INVITE"));
        headers.push(Header::new(
            "To",
            "<sip:001010000000009@ims.example>;tag=remote",
        ));
        let answer = crate::Sdp::answer_amr_wb(&call.offer().unwrap().clone(), "192.0.2.11")
            .unwrap()
            .to_text();
        headers.push(Header::new("Content-Type", "application/sdp"));
        let ok = sip::Response {
            status: 200,
            reason: "OK".into(),
            headers,
            body: answer.into_bytes(),
        };
        let _ = call.on_response(&ok);
        assert_eq!(call.state(), CallState::Established);
        call
    }

    #[test]
    fn waiting_is_detected_when_a_call_is_established() {
        assert!(!is_call_waiting(None));
        let mut fresh = Call::new(ImsProfile::lab_default(), "sip:x@example");
        let _ = fresh.invite();
        assert!(!is_call_waiting(Some(&fresh)));
        assert!(is_call_waiting(Some(&established_call())));
    }

    #[test]
    fn accepting_holds_the_active_call_and_answers_the_new_one() {
        let mut active = established_call();
        let mut incoming = IncomingCall::from_invite(&invite(), ImsProfile::lab_default()).unwrap();

        let actions = accept_waiting(&mut active, &mut incoming).unwrap();
        // The active call is put on hold with a sendonly re-INVITE.
        assert_eq!(actions.hold.method, Method::Invite);
        let body = String::from_utf8(actions.hold.body.clone()).unwrap();
        assert!(body.contains("a=sendonly"));
        assert_eq!(
            active.answer().map(crate::Sdp::direction),
            Some(Direction::SendOnly)
        );
        // The waiting call is answered with SDP.
        assert_eq!(actions.answer.status, 200);
        assert_eq!(
            actions.answer.headers.get("content-type"),
            Some("application/sdp")
        );
    }

    #[test]
    fn decline_returns_486() {
        let mut incoming = IncomingCall::from_invite(&invite(), ImsProfile::lab_default()).unwrap();
        let response = decline_waiting(&mut incoming);
        assert_eq!(response.status, 486);
        assert_eq!(response.reason, "Busy Here");
    }

    #[test]
    fn accepting_without_an_active_call_is_an_error() {
        let mut idle = Call::new(ImsProfile::lab_default(), "sip:x@example");
        let mut incoming = IncomingCall::from_invite(&invite(), ImsProfile::lab_default()).unwrap();
        assert!(accept_waiting(&mut idle, &mut incoming).is_err());
    }
}
