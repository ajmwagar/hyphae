//! Voice continuity: EPS fallback to CS and mid-call media liveness.
//!
//! Two separate mechanisms share this module because the platform treats them
//! the same way — "this call needs the circuit-switched radio".
//!
//! * **EPS fallback** (3GPP TS 23.216, TS 24.229 §5.1.3): when the network
//!   cannot serve a VoLTE call it rejects the INVITE (typically `488` or `580`,
//!   or `503` with `Retry-After`). The UE then falls back to CS for that call.
//!   [`classify_invite_failure`] turns the final response into a
//!   [`FallbackReason`].
//! * **SRVCC eligibility** (TS 23.216): a call whose media has died but whose
//!   signalling is intact is the candidate for a single-radio handover.
//!   [`ContinuityMonitor`] tracks RTP/RTCP liveness and reports
//!   [`ContinuityEvent::Lost`].
//!
//! Neither performs a handover: this crate has no radio. It classifies and
//! reports, and the platform decides.

#![forbid(unsafe_code)]

use sip::Response;
use std::time::{Duration, Instant};

/// Why a call could not continue over IMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// The network rejected the session and the UE should use CS for this call
    /// (EPS fallback, TS 23.216 §6.2).
    EpsFallback,
    /// The service is temporarily unavailable; retry over IMS after the hinted
    /// delay (`503` + `Retry-After`).
    ServiceNotProvided { retry_after_s: Option<u32> },
    /// The media path was lost mid-call; the signalling may still be usable for
    /// an SRVCC handover.
    MediaLost,
}

/// Classify a final INVITE response as a voice-continuity event.
///
/// * `488 Not Acceptable Here` and `580 Precondition Failure` — the network
///   cannot provide the requested IMS session, so the call falls back to CS.
/// * `503 Service Unavailable` — retry over IMS after `Retry-After`, do not drop
///   to CS yet.
/// * anything else — `None`; this is an ordinary failure.
pub fn classify_invite_failure(response: &Response) -> Option<FallbackReason> {
    match response.status {
        488 | 580 => Some(FallbackReason::EpsFallback),
        503 => Some(FallbackReason::ServiceNotProvided {
            retry_after_s: retry_after(response),
        }),
        _ => None,
    }
}

/// The `Retry-After` value in seconds, when present and numeric.
pub fn retry_after(response: &Response) -> Option<u32> {
    response
        .headers
        .get("retry-after")
        .and_then(|v| v.trim().parse().ok())
}

/// Media liveness for one call.
///
/// Feed it every received RTP/RTCP packet; poll it from the media loop. Half the
/// timeout is reported as [`ContinuityEvent::Degraded`] so the UE can start
/// looking for a handover target before the call actually breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityEvent {
    /// Media is arriving on time.
    Healthy,
    /// Media has been quiet for a while; a handover target is worth finding.
    Degraded,
    /// Media has stopped. SRVCC is the only way to keep the call.
    Lost,
}

/// Tracks RTP/RTCP liveness for one media session.
#[derive(Debug, Clone)]
pub struct ContinuityMonitor {
    timeout: Duration,
    started: Option<Instant>,
    last_activity: Option<Instant>,
}

impl ContinuityMonitor {
    /// A monitor that calls media lost after `timeout` of silence.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            started: None,
            last_activity: None,
        }
    }

    /// Start the session at `now` (called when the dialog is confirmed).
    pub fn start(&mut self, now: Instant) {
        self.started = Some(now);
        self.last_activity = Some(now);
    }

    /// Record that a media packet arrived at `now`.
    pub fn on_activity(&mut self, now: Instant) {
        if self.started.is_none() {
            self.started = Some(now);
        }
        self.last_activity = Some(now);
    }

    /// Time since the last media packet.
    pub fn silence(&self, now: Instant) -> Duration {
        match self.last_activity {
            Some(last) => now.saturating_duration_since(last),
            None => Duration::ZERO,
        }
    }

    /// Classify the session at `now`.
    pub fn poll(&self, now: Instant) -> ContinuityEvent {
        if self.started.is_none() {
            return ContinuityEvent::Healthy;
        }
        let silence = self.silence(now);
        if silence >= self.timeout {
            ContinuityEvent::Lost
        } else if silence >= self.timeout / 2 {
            ContinuityEvent::Degraded
        } else {
            ContinuityEvent::Healthy
        }
    }

    /// The configured timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip::{Headers, Response};

    fn response(status: u16, headers: &[(&str, &str)]) -> Response {
        let mut h = Headers::new();
        for (k, v) in headers {
            h.push(sip::Header::new(*k, *v));
        }
        Response {
            status,
            reason: " ".into(),
            headers: h,
            body: Vec::new(),
        }
    }

    #[test]
    fn rejects_that_need_cs_are_classified() {
        assert_eq!(
            classify_invite_failure(&response(488, &[])),
            Some(FallbackReason::EpsFallback)
        );
        assert_eq!(
            classify_invite_failure(&response(580, &[])),
            Some(FallbackReason::EpsFallback)
        );
        // 503 is a retry, not a CS fallback.
        assert_eq!(
            classify_invite_failure(&response(503, &[("Retry-After", "30")])),
            Some(FallbackReason::ServiceNotProvided {
                retry_after_s: Some(30)
            })
        );
        assert_eq!(
            classify_invite_failure(&response(503, &[])),
            Some(FallbackReason::ServiceNotProvided {
                retry_after_s: None
            })
        );
        // Ordinary failures are not continuity events.
        assert_eq!(classify_invite_failure(&response(486, &[])), None);
        assert_eq!(classify_invite_failure(&response(404, &[])), None);
        assert_eq!(classify_invite_failure(&response(200, &[])), None);
    }

    #[test]
    fn monitor_degrades_then_loses() {
        let t0 = Instant::now();
        let mut monitor = ContinuityMonitor::new(Duration::from_secs(6));
        assert_eq!(monitor.poll(t0), ContinuityEvent::Healthy);
        monitor.start(t0);
        assert_eq!(
            monitor.poll(t0 + Duration::from_secs(2)),
            ContinuityEvent::Healthy
        );
        // Half the timeout is degraded...
        assert_eq!(
            monitor.poll(t0 + Duration::from_secs(3)),
            ContinuityEvent::Degraded
        );
        // ...and the full timeout is lost.
        assert_eq!(
            monitor.poll(t0 + Duration::from_secs(6)),
            ContinuityEvent::Lost
        );
    }

    #[test]
    fn activity_resets_the_monitor() {
        let t0 = Instant::now();
        let mut monitor = ContinuityMonitor::new(Duration::from_secs(6));
        monitor.start(t0);
        assert_eq!(
            monitor.poll(t0 + Duration::from_secs(5)),
            ContinuityEvent::Degraded
        );
        monitor.on_activity(t0 + Duration::from_secs(5));
        assert_eq!(
            monitor.poll(t0 + Duration::from_secs(5)),
            ContinuityEvent::Healthy
        );
        assert_eq!(
            monitor.silence(t0 + Duration::from_secs(7)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn retry_after_is_parsed() {
        assert_eq!(
            retry_after(&response(503, &[("Retry-After", " 120 ")])),
            Some(120)
        );
        assert_eq!(
            retry_after(&response(503, &[("Retry-After", "soon")])),
            None
        );
        assert_eq!(retry_after(&response(503, &[])), None);
    }
}
