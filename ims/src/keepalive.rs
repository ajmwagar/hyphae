//! Out-of-dialog `OPTIONS` keepalive (RFC 3261 §11, 3GPP TS 24.229 §5.1.2.2).
//!
//! A UE keeps its NAT binding and P-CSCF path alive by sending `OPTIONS` ping
//! requests and expecting a `200 OK`. This module builds the ping, decides when
//! one is due, and tracks consecutive failures so the caller can tear down and
//! re-register. It owns no timer thread: the caller drives it with `now`.

use crate::profile::ImsProfile;
use sip::{Header, Headers, Method, Request, Response};
use std::time::{Duration, Instant};

/// Default ping interval (half of a typical 30 s NAT binding refresh).
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);
/// Consecutive failures before the path is declared dead.
pub const DEFAULT_MAX_FAILURES: u32 = 3;

/// The outcome of one keepalive exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveStatus {
    /// A 2xx arrived; the path is healthy.
    Alive,
    /// A non-2xx or a timeout; still retrying.
    Unhealthy(u16),
    /// Too many consecutive failures: the path is down.
    Dead,
}

/// OPTIONS keepalive state for one outbound signalling path.
#[derive(Debug, Clone)]
pub struct Keepalive {
    profile: ImsProfile,
    call_id: String,
    from_tag: String,
    cseq: u32,
    branch_counter: u32,
    interval: Duration,
    last_sent: Option<Instant>,
    failures: u32,
    max_failures: u32,
}

impl Keepalive {
    pub fn new(profile: ImsProfile) -> Self {
        let call_id = format!(
            "fungos-keepalive-{}@{}",
            profile.public_user(),
            profile.contact_host
        );
        Self {
            from_tag: format!("fungos-ka-{}", profile.contact_port),
            profile,
            call_id,
            cseq: 0,
            branch_counter: 0,
            interval: DEFAULT_INTERVAL,
            last_sent: None,
            failures: 0,
            max_failures: DEFAULT_MAX_FAILURES,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_max_failures(mut self, max: u32) -> Self {
        self.max_failures = max.max(1);
        self
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Consecutive failures so far.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn is_dead(&self) -> bool {
        self.failures >= self.max_failures
    }

    /// Whether a ping is due at `now` (the first call is always due).
    pub fn due(&self, now: Instant) -> bool {
        match self.last_sent {
            None => true,
            Some(last) => now.duration_since(last) >= self.interval,
        }
    }

    /// Build the next `OPTIONS` ping and record that it was sent.
    ///
    /// `target` is the remote URI to ping (usually the P-CSCF or the
    /// registered IMPU).
    pub fn ping(&mut self, target: &str, now: Instant) -> Request {
        self.cseq += 1;
        self.branch_counter += 1;
        self.last_sent = Some(now);
        let branch = format!("z9hG4bK-fungos-ka-{}-{}", self.cseq, self.branch_counter);
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
        headers.push(Header::new("To", format!("<{target}>")));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} OPTIONS", self.cseq)));
        headers.push(Header::new(
            "Contact",
            format!("<{}>", self.profile.contact_uri()),
        ));
        headers.push(Header::new(
            "Allow",
            "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,MESSAGE,OPTIONS",
        ));
        headers.push(Header::new("User-Agent", self.profile.user_agent.clone()));
        headers.push(Header::new("Content-Length", "0"));
        Request {
            method: Method::Options,
            uri: target.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    /// Feed a response to a ping back in.
    pub fn on_response(&mut self, response: &Response) -> KeepaliveStatus {
        if (200..300).contains(&response.status) {
            self.failures = 0;
            KeepaliveStatus::Alive
        } else {
            self.failures += 1;
            if self.is_dead() {
                KeepaliveStatus::Dead
            } else {
                KeepaliveStatus::Unhealthy(response.status)
            }
        }
    }

    /// Record that no response arrived before the timeout.
    pub fn on_timeout(&mut self) -> KeepaliveStatus {
        self.failures += 1;
        if self.is_dead() {
            KeepaliveStatus::Dead
        } else {
            KeepaliveStatus::Unhealthy(408)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ImsProfile {
        ImsProfile::lab_default()
    }

    fn response(status: u16) -> Response {
        Response {
            status,
            reason: " ".into(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn ping_is_a_well_formed_options_request() {
        let mut ka = Keepalive::new(profile());
        let now = Instant::now();
        let ping = ka.ping("sip:pcscf.example", now);
        assert_eq!(ping.method, Method::Options);
        assert_eq!(ping.uri, "sip:pcscf.example");
        assert_eq!(ping.headers.get("cseq"), Some("1 OPTIONS"));
        assert!(ping
            .headers
            .get("via")
            .unwrap()
            .contains("branch=z9hG4bK-fungos-ka-1"));
        assert!(ping
            .headers
            .get("to")
            .unwrap()
            .contains("sip:pcscf.example"));
        assert_eq!(ping.headers.get("content-length"), Some("0"));
        // CSeq and branch advance per ping.
        let next = ka.ping("sip:pcscf.example", now);
        assert_eq!(next.headers.get("cseq"), Some("2 OPTIONS"));
        assert_ne!(next.headers.get("via"), ping.headers.get("via"));
    }

    #[test]
    fn due_follows_the_interval() {
        let mut ka = Keepalive::new(profile()).with_interval(Duration::from_secs(10));
        let t0 = Instant::now();
        assert!(ka.due(t0), "the first ping is always due");
        let _ = ka.ping("sip:x", t0);
        assert!(!ka.due(t0 + Duration::from_secs(5)));
        assert!(ka.due(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn failures_accumulate_to_dead_and_reset_on_success() {
        let mut ka = Keepalive::new(profile()).with_max_failures(2);
        assert_eq!(ka.on_timeout(), KeepaliveStatus::Unhealthy(408));
        assert!(!ka.is_dead());
        // A success clears the count.
        assert_eq!(ka.on_response(&response(200)), KeepaliveStatus::Alive);
        assert_eq!(ka.failures(), 0);
        // Two failures in a row are fatal.
        assert_eq!(ka.on_timeout(), KeepaliveStatus::Unhealthy(408));
        assert_eq!(ka.on_timeout(), KeepaliveStatus::Dead);
        assert!(ka.is_dead());
    }

    #[test]
    fn non_2xx_is_unhealthy_but_not_fatal_at_first() {
        let mut ka = Keepalive::new(profile()).with_max_failures(3);
        assert_eq!(
            ka.on_response(&response(503)),
            KeepaliveStatus::Unhealthy(503)
        );
        assert_eq!(ka.failures(), 1);
        assert_eq!(ka.on_response(&response(200)), KeepaliveStatus::Alive);
    }
}
