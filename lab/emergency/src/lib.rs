//! A stand-in E-CSCF: the emergency core, faked well enough to exercise us.
//!
//! The UE side of emergency calling is buildable and testable without a PSAP,
//! but not without *something* answering. This is that something: it accepts an
//! emergency registration and an emergency INVITE, records exactly what it was
//! sent, and can refuse the registration the way a network that forbids
//! third-party emergency registration would.
//!
//! ## Scope
//!
//! It is a **state machine, not a proxy**. It does not select a PSAP, does not
//! query LoST, does not relay media, and has no idea what a location means. Its
//! only job is to answer the way TS 24.229 says a P-CSCF/E-CSCF may, so the UE
//! side can be driven end to end.
//!
//! ## Safety
//!
//! Nothing here can reach a PSAP. The tests drive it over `127.0.0.1`, and it
//! never originates a request — it only answers.

#![forbid(unsafe_code)]

use sip::{Header, Headers, Method, Request, Response};

/// How the stand-in answers an emergency registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Accept it, as a network that supports emergency registration does.
    Accept,
    /// Refuse with 403 + `anonymous-emergencycall`, which is what TS 24.229
    /// §5.1.6.2 says makes the UE fall back to an unregistered emergency call.
    RejectAnonymous,
}

/// What the stand-in saw in one request, so a test can assert on the message
/// rather than on a string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// `REGISTER` or `INVITE`.
    pub method: String,
    /// The Request-URI.
    pub uri: String,
    /// Whether a `Contact` carried the `sos` URI parameter (§5.1.6.2 a).
    pub contact_sos: bool,
    /// The `Geolocation` header value, when present (RFC 6442).
    pub geolocation: Option<String>,
    /// The `Geolocation-Routing` header value.
    pub geolocation_routing: Option<String>,
    /// The message `Content-Type`.
    pub content_type: Option<String>,
    /// The `P-Access-Network-Info` value.
    pub pani: Option<String>,
    /// The `Priority` value.
    pub priority: Option<String>,
    /// The `Resource-Priority` value — which a UE must never send (§4.7).
    pub resource_priority: Option<String>,
    /// The `From` header value, verbatim.
    pub from: String,
    /// The `P-Preferred-Identity` value.
    pub preferred_identity: Option<String>,
    /// The `Recv-Info` value.
    pub recv_info: Option<String>,
    /// Whether the body carried a PIDF location object.
    pub has_pidf: bool,
    /// Whether the body carried an SDP offer.
    pub has_sdp: bool,
    /// Whether the body is multipart.
    pub multipart: bool,
}

impl Observation {
    fn of(request: &Request) -> Self {
        let body = String::from_utf8_lossy(&request.body);
        let content_type = request.headers.get("content-type").map(str::to_string);
        Self {
            method: request.method.to_string(),
            uri: request.uri.clone(),
            contact_sos: request
                .headers
                .get("contact")
                .map(|c| c.contains(";sos"))
                .unwrap_or(false),
            geolocation: request.headers.get("geolocation").map(str::to_string),
            geolocation_routing: request
                .headers
                .get("geolocation-routing")
                .map(str::to_string),
            content_type: content_type.clone(),
            pani: request
                .headers
                .get("p-access-network-info")
                .map(str::to_string),
            priority: request.headers.get("priority").map(str::to_string),
            resource_priority: request.headers.get("resource-priority").map(str::to_string),
            from: request.headers.get("from").unwrap_or("").to_string(),
            preferred_identity: request
                .headers
                .get("p-preferred-identity")
                .map(str::to_string),
            recv_info: request.headers.get("recv-info").map(str::to_string),
            has_pidf: body.contains("<presence") || body.contains("application/pidf+xml"),
            has_sdp: body.contains("v=0"),
            multipart: content_type
                .as_deref()
                .map(|c| c.starts_with("multipart/mixed"))
                .unwrap_or(false),
        }
    }
}

/// The stand-in E-CSCF.
#[derive(Debug, Clone)]
pub struct StandInEcscf {
    policy: Policy,
    /// Everything the stand-in has been sent, in order.
    pub observations: Vec<Observation>,
    local_contact: String,
}

impl StandInEcscf {
    /// A stand-in that answers from `local_contact` (a `sip:` URI).
    pub fn new(policy: Policy, local_contact: impl Into<String>) -> Self {
        Self {
            policy,
            observations: Vec::new(),
            local_contact: local_contact.into(),
        }
    }

    /// The last observation, if any.
    pub fn last(&self) -> Option<&Observation> {
        self.observations.last()
    }

    /// Handle a `REGISTER` (`§5.1.6.2`).
    ///
    /// A registration without the `sos` Contact parameter is not an emergency
    /// registration and is rejected as unsupported by this stand-in — the point
    /// is to test the emergency path, not a normal one.
    pub fn on_register(&mut self, request: &Request) -> Response {
        let observation = Observation::of(request);
        let is_emergency = observation.contact_sos;
        self.observations.push(observation);

        if !is_emergency {
            return self.answer(request, 400, "Bad Request", &[], Vec::new());
        }
        match self.policy {
            Policy::Accept => {
                let contact = format!("<{}>;sos", self.local_contact);
                self.answer(request, 200, "OK", &[("Contact", &contact)], Vec::new())
            }
            Policy::RejectAnonymous => self.answer(
                request,
                403,
                "Forbidden",
                &[("Content-Type", ims::ims3gpp::IMS3GPP_MIME)],
                anonymous_emergency_xml().into_bytes(),
            ),
        }
    }

    /// Handle an emergency `INVITE` (`§5.1.6.8.3`), answering 200 OK with an
    /// SDP answer.
    pub fn on_invite(&mut self, request: &Request) -> Response {
        self.observations.push(Observation::of(request));
        let contact = format!("<{}>", self.local_contact);
        self.answer(
            request,
            200,
            "OK",
            &[("Contact", &contact), ("Content-Type", "application/sdp")],
            LAB_SDP_ANSWER.as_bytes().to_vec(),
        )
    }

    /// Handle a mid-call location `PUBLISH` (`§5.1.6.12.3`).
    pub fn on_publish(&mut self, request: &Request) -> Response {
        self.observations.push(Observation::of(request));
        self.answer(request, 200, "OK", &[("SIP-ETag", "lab-1")], Vec::new())
    }

    /// A response that echoes the dialog headers and adds a local `To` tag.
    fn answer(
        &self,
        request: &Request,
        status: u16,
        reason: &str,
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Response {
        let mut headers = Headers::new();
        for via in request.headers.get_all("via") {
            headers.push(Header::new("Via", via));
        }
        if let Some(from) = request.headers.get("from") {
            headers.push(Header::new("From", from));
        }
        if let Some(to) = request.headers.get("to") {
            let value = if to.contains("tag=") {
                to.to_string()
            } else {
                format!("{to};tag=ecscf-lab")
            };
            headers.push(Header::new("To", value));
        }
        if let Some(call_id) = request.headers.get("call-id") {
            headers.push(Header::new("Call-ID", call_id));
        }
        if let Some(cseq) = request.headers.get("cseq") {
            headers.push(Header::new("CSeq", cseq));
        }
        for (name, value) in extra {
            headers.push(Header::new(*name, *value));
        }
        headers.push(Header::new("Content-Length", body.len().to_string()));
        Response {
            status,
            reason: reason.to_string(),
            headers,
            body,
        }
    }
}

/// The `alternative-service` body of TS 24.229 §7.6 that asks for an
/// unregistered emergency call.
pub fn anonymous_emergency_xml() -> String {
    concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<ims-3gpp version=\"1\">\n",
        "  <alternative-service>\n",
        "    <type>emergency</type>\n",
        "    <reason>emergency registration is not permitted</reason>\n",
        "    <action>anonymous-emergencycall</action>\n",
        "  </alternative-service>\n",
        "</ims-3gpp>\n"
    )
    .to_string()
}

/// A fixed AMR-WB answer for the stand-in's 200 OK.
pub const LAB_SDP_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 127.0.0.1\r\n",
    "s=-\r\n",
    "c=IN IP4 127.0.0.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 98\r\n",
    "a=rtpmap:98 AMR-WB/16000/1\r\n",
    "a=sendrecv\r\n",
);

/// Whether a request is one this stand-in claims to handle.
pub fn handles(request: &Request) -> bool {
    matches!(
        request.method,
        Method::Register | Method::Invite | Method::Publish
    )
}
