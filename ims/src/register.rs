//! IMS REGISTER flow: Security-Client, 401/407 challenge, AKA digest, Service-Route.
//!
//! Spec references: 3GPP TS 24.229 §5.1.1 (initial REGISTER and feature tags),
//! TS 33.203 §7 (IMS-AKA), RFC 3310 (digest), RFC 3329 (Security-Client),
//! RFC 3608 (Service-Route), RFC 3261 §10 (registration).

use crate::auth::authorization_value;
use crate::profile::ImsProfile;
use aka::Rand;
use sip::{AuthChallenge, Header, Headers, Method, Request, Response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub status: u16,
    /// 401 uses WWW-Authenticate; 407 uses Proxy-Authenticate.
    pub proxy: bool,
    pub challenge: AuthChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationState {
    Idle,
    Registering,
    Challenged(Challenge),
    Registered,
    Deregistering,
    Failed(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationEvent {
    /// Answer with a REGISTER carrying Authorization/Proxy-Authorization.
    Challenge(Challenge),
    Registered,
    /// Any other non-2xx final response.
    Failed(u16),
}

#[derive(Debug, Clone)]
pub struct Registration {
    profile: ImsProfile,
    state: RegistrationState,
    call_id: String,
    from_tag: String,
    cseq: u32,
    branch_counter: u32,
    /// Security-Server values learned from the challenge, echoed as Security-Verify.
    security_server: Vec<String>,
}

impl Registration {
    pub fn new(profile: ImsProfile) -> Self {
        let call_id = format!(
            "fungos-ims-{}@{}",
            profile.public_user(),
            profile.contact_host
        );
        let from_tag = format!("fungos-{}", profile.contact_port);
        Self::with_identifiers(profile, call_id, from_tag)
    }

    pub fn with_identifiers(
        profile: ImsProfile,
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
    ) -> Self {
        Self {
            profile,
            state: RegistrationState::Idle,
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            cseq: 0,
            branch_counter: 0,
            security_server: Vec::new(),
        }
    }

    pub fn profile(&self) -> &ImsProfile {
        &self.profile
    }

    pub fn profile_mut(&mut self) -> &mut ImsProfile {
        &mut self.profile
    }

    pub fn state(&self) -> &RegistrationState {
        &self.state
    }

    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    pub fn from_tag(&self) -> &str {
        &self.from_tag
    }

    pub fn cseq(&self) -> u32 {
        self.cseq
    }

    /// Build the initial REGISTER (TS 24.229 §5.1.1.2).
    pub fn register_request(&mut self) -> Request {
        self.state = RegistrationState::Registering;
        let mut req = self.request(Method::Register, self.profile.register_uri());
        self.apply_register_headers(&mut req, self.profile.register_expires);
        req
    }

    /// Deregister: REGISTER with `Expires: 0` (RFC 3261 §10.2.2).
    pub fn deregister_request(&mut self) -> Request {
        self.state = RegistrationState::Deregistering;
        let mut req = self.request(Method::Register, self.profile.register_uri());
        self.apply_register_headers(&mut req, 0);
        req
    }

    /// Build the challenged REGISTER. `res` is the 8-byte AKA RES from the USIM.
    pub fn authorize(&mut self, challenge: &Challenge, res: &[u8], cnonce: &str) -> Request {
        self.authorize_with_expires(challenge, res, cnonce, self.profile.register_expires)
    }

    /// Build the challenged deregistration (`Expires: 0`).
    pub fn authorize_deregister(
        &mut self,
        challenge: &Challenge,
        res: &[u8],
        cnonce: &str,
    ) -> Request {
        self.authorize_with_expires(challenge, res, cnonce, 0)
    }

    fn authorize_with_expires(
        &mut self,
        challenge: &Challenge,
        res: &[u8],
        cnonce: &str,
        expires: u32,
    ) -> Request {
        let mut req = self.request(Method::Register, self.profile.register_uri());
        self.apply_register_headers(&mut req, expires);
        let auth = authorization_value(
            &challenge.challenge,
            &self.profile,
            res,
            &Method::Register,
            &self.profile.register_uri(),
            cnonce,
        );
        let name = if challenge.proxy {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };
        req.headers.push(Header::new(name, auth));
        for server in &self.security_server {
            req.headers
                .push(Header::new("Security-Verify", server.clone()));
        }
        self.state = if expires == 0 {
            RegistrationState::Deregistering
        } else {
            RegistrationState::Registering
        };
        req
    }

    /// Consume a response to REGISTER.
    pub fn on_response(&mut self, response: &Response) -> RegistrationEvent {
        if (200..300).contains(&response.status) {
            let routes = response
                .headers
                .get_all("service-route")
                .filter_map(|v| sip::NameAddr::parse(v).ok())
                .map(|n| n.uri.to_string())
                .collect::<Vec<_>>();
            if !routes.is_empty() {
                self.profile.set_service_route(routes);
            }
            self.state = RegistrationState::Registered;
            return RegistrationEvent::Registered;
        }

        if response.status == 401 || response.status == 407 {
            let proxy = response.status == 407;
            let header = if proxy {
                "proxy-authenticate"
            } else {
                "www-authenticate"
            };
            if let Some(value) = response.headers.get(header) {
                if let Ok(challenge) = sip::parse_challenge(value) {
                    self.security_server = response
                        .headers
                        .get_all("security-server")
                        .map(str::to_string)
                        .collect();
                    let c = Challenge {
                        status: response.status,
                        proxy,
                        challenge,
                    };
                    self.state = RegistrationState::Challenged(c.clone());
                    return RegistrationEvent::Challenge(c);
                }
            }
        }

        self.state = RegistrationState::Failed(response.status);
        RegistrationEvent::Failed(response.status)
    }

    /// A USIM/ISIM challenge normally arrives as `RAND`+`AUTN`; this helper is
    /// for tests and for integrations that keep them together.
    pub fn rand_autn_from_response(response: &Response) -> Option<(Rand, [u8; 16])> {
        // Lab-only convenience: nonce carries base64 of RAND||AUTN in the test
        // fixtures. Real deployments feed RAND/AUTN from the USIM API instead.
        let nonce = response
            .headers
            .get("www-authenticate")
            .or_else(|| response.headers.get("proxy-authenticate"))
            .and_then(|v| sip::parse_challenge(v).ok())
            .and_then(|c| c.param("nonce").map(str::to_string))?;
        let bytes = base64_decode(&nonce)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut rand = [0u8; 16];
        rand.copy_from_slice(&bytes[..16]);
        let mut autn = [0u8; 16];
        autn.copy_from_slice(&bytes[16..]);
        Some((rand, autn))
    }

    fn request(&mut self, method: Method, uri: String) -> Request {
        self.cseq += 1;
        self.branch_counter += 1;
        let branch = format!("z9hG4bK-fungos-{}-{}", self.cseq, self.branch_counter);
        let mut headers = Headers::new();
        headers.push(Header::new(
            "Via",
            format!(
                "SIP/2.0/{} {}:{};branch={branch};rport",
                self.profile.transport, self.profile.contact_host, self.profile.contact_port
            ),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", self.profile.public_identity, self.from_tag),
        ));
        headers.push(Header::new(
            "To",
            format!("<{}>", self.profile.public_identity),
        ));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} {}", self.cseq, method)));
        headers.push(Header::new("User-Agent", self.profile.user_agent.clone()));
        let supported = self.profile.supported.join(",");
        if !supported.is_empty() {
            headers.push(Header::new("Supported", supported));
        }
        headers.push(Header::new("Content-Length", "0"));
        Request {
            method,
            uri,
            headers,
            body: Vec::new(),
        }
    }

    fn apply_register_headers(&self, req: &mut Request, expires: u32) {
        req.headers.push(Header::new(
            "Contact",
            format!(
                "<{}>;expires={}{}",
                self.profile.contact_uri(),
                expires,
                self.profile.feature_contact_params()
            ),
        ));
        req.headers
            .push(Header::new("Expires", expires.to_string()));
        for s in &self.profile.security_clients {
            req.headers
                .push(Header::new("Security-Client", s.header_value()));
        }
        req.headers.push(Header::new(
            "Allow",
            "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,MESSAGE",
        ));
    }
}

/// Minimal base64 decoder for the lab `nonce` convention; not a general codec.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for c in s.bytes() {
        buffer = (buffer << 6) | val(c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip::Message;

    fn response(status: u16, headers: &[(&str, &str)]) -> Response {
        let mut h = Headers::new();
        for (n, v) in headers {
            h.push(Header::new(*n, *v));
        }
        Response {
            status,
            reason: "test".into(),
            headers: h,
            body: Vec::new(),
        }
    }

    #[test]
    fn initial_register_has_security_client_and_contact() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let req = r.register_request();
        assert_eq!(req.method, Method::Register);
        assert_eq!(req.uri, "sip:ims.mnc001.mcc001.3gppnetwork.org");
        assert!(req
            .headers
            .get("security-client")
            .unwrap()
            .contains("algorithm=hmac-md5-96"));
        assert!(req
            .headers
            .get("contact")
            .unwrap()
            .contains("expires=600000"));
        assert!(req.headers.get("contact").unwrap().contains("icsi.mmtel"));
        assert_eq!(req.headers.cseq().unwrap().seq, 1);
        assert!(req.headers.get("via").unwrap().contains("rport"));
    }

    #[test]
    fn handles_401_then_authorizes() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let _ = r.register_request();
        let resp = response(
            401,
            &[(
                "WWW-Authenticate",
                "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"bm9uY2U=\", algorithm=AKAv1-MD5, qop=\"auth\"",
            )],
        );
        let RegistrationEvent::Challenge(c) = r.on_response(&resp) else {
            panic!("challenge expected")
        };
        assert!(!c.proxy);
        assert_eq!(r.state(), &RegistrationState::Challenged(c.clone()));
        let auth = r.authorize(&c, &[0u8; 8], "cnonce-1");
        assert!(auth
            .headers
            .get("authorization")
            .unwrap()
            .starts_with("Digest username="));
        assert!(auth
            .headers
            .get("authorization")
            .unwrap()
            .contains("algorithm=AKAv1-MD5"));
        assert_eq!(auth.headers.cseq().unwrap().seq, 2);
    }

    #[test]
    fn handles_407_proxy_challenge() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let _ = r.register_request();
        let resp = response(
            407,
            &[(
                "Proxy-Authenticate",
                "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"x\", algorithm=AKAv1-MD5",
            )],
        );
        let RegistrationEvent::Challenge(c) = r.on_response(&resp) else {
            panic!("challenge expected")
        };
        assert!(c.proxy);
        let auth = r.authorize(&c, &[1u8; 8], "c");
        assert!(auth.headers.get("proxy-authorization").is_some());
    }

    #[test]
    fn ok_sets_registered_and_service_route() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let _ = r.register_request();
        let resp = response(
            200,
            &[(
                "Service-Route",
                "<sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>",
            )],
        );
        assert_eq!(r.on_response(&resp), RegistrationEvent::Registered);
        assert_eq!(r.state(), &RegistrationState::Registered);
        assert_eq!(
            r.profile().service_route,
            vec!["sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr"]
        );
    }

    #[test]
    fn deregister_sets_expires_zero() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let _ = r.register_request();
        assert_eq!(
            r.on_response(&response(200, &[])),
            RegistrationEvent::Registered
        );
        let req = r.deregister_request();
        assert_eq!(req.headers.get("expires"), Some("0"));
        assert!(req.headers.get("contact").unwrap().contains("expires=0"));
    }

    #[test]
    fn wire_round_trip_of_register() {
        let mut r = Registration::new(ImsProfile::lab_default());
        let req = r.register_request();
        let parsed = Message::parse(&Message::Request(req.clone()).to_text()).unwrap();
        assert_eq!(parsed, Message::Request(req));
    }
}
