//! Message Waiting Indication: the "you have voicemail" subscription.
//!
//! Voicemail itself is an application server in the network — it answers the
//! call, plays a greeting and records the message. The UE's part is much
//! smaller: it subscribes to its own message summary and renders the counts.
//!
//! * **Event package**: `message-summary` (RFC 3842 §7.1).
//! * **Body**: `application/simple-message-summary` (RFC 3842 §5.2), one status
//!   line, an optional account, per-class counts, and optional message headers.
//!
//! ```text
//! Messages-Waiting: yes
//! Message-Account: sip:alice@vmail.example.com
//! Voice-Message: 2/8 (0/2)
//! ```
//!
//! The notifier MUST send a NOTIFY immediately after accepting the
//! subscription (§3.8), so the first update never waits for a message to
//! arrive.
//!
//! ## What this is not
//!
//! Visual voicemail — the list of messages with audio and metadata — is an
//! application protocol layered on IMAP (OMTP VVM) or a carrier's own HTTP API.
//! None of it is 3GPP, so none of it is here; it belongs beside the entitlement
//! material in `docs/facts/`.

#![forbid(unsafe_code)]

use sip::{Header, Headers, Method, Request};

/// The `message-summary` event package name (RFC 3842 §7.1).
pub const MESSAGE_SUMMARY_EVENT: &str = "message-summary";

/// The MIME type of the summary body (RFC 3842 §7.2).
pub const MESSAGE_SUMMARY_MIME: &str = "application/simple-message-summary";

/// A message context class (RFC 3458 §6.2, used by RFC 3842 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageClass {
    /// Voice mail.
    Voice,
    /// Facsimile.
    Fax,
    /// A page.
    Pager,
    /// Multimedia.
    Multimedia,
    /// Text.
    Text,
    /// The catch-all `None` class.
    None,
}

impl MessageClass {
    /// Parse a context class, case-insensitively (RFC 3842 §5.2: "all
    /// productions described here are case insensitive").
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "voice-message" => MessageClass::Voice,
            "fax-message" => MessageClass::Fax,
            "pager-message" => MessageClass::Pager,
            "multimedia-message" => MessageClass::Multimedia,
            "text-message" => MessageClass::Text,
            "none" => MessageClass::None,
            _ => return None,
        })
    }

    /// The canonical spelling used in a body.
    pub fn as_str(self) -> &'static str {
        match self {
            MessageClass::Voice => "Voice-Message",
            MessageClass::Fax => "Fax-Message",
            MessageClass::Pager => "Pager-Message",
            MessageClass::Multimedia => "Multimedia-Message",
            MessageClass::Text => "Text-Message",
            MessageClass::None => "None",
        }
    }
}

/// The counts for one message context class (RFC 3842 §5.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// `newmsgs`.
    pub new: u32,
    /// `oldmsgs`.
    pub old: u32,
    /// `new-urgentmsgs`, when the parenthesised group is present.
    pub new_urgent: Option<u32>,
    /// `old-urgentmsgs`, when the parenthesised group is present.
    pub old_urgent: Option<u32>,
}

impl Counts {
    /// New plus old, saturating.
    pub fn total(&self) -> u32 {
        self.new.saturating_add(self.old)
    }
}

/// A parsed `application/simple-message-summary` body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageSummary {
    /// The `Messages-Waiting` status. `None` only if a body omitted the line,
    /// which RFC 3842 §5.2 does not allow but which is cheaper to tolerate than
    /// to reject outright.
    pub waiting: Option<bool>,
    /// The `Message-Account`, without angle brackets (RFC 3842 §3.3).
    pub account: Option<String>,
    /// Per-class counts, in the order they appeared.
    pub classes: Vec<(MessageClass, Counts)>,
    /// Optional RFC 2822-style headers describing newly added messages.
    pub headers: Vec<(String, String)>,
}

impl MessageSummary {
    /// The counts for one class.
    pub fn counts(&self, class: MessageClass) -> Option<Counts> {
        self.classes
            .iter()
            .find(|(c, _)| *c == class)
            .map(|(_, counts)| *counts)
    }

    /// The voice-message counts, which is what a phone shows.
    pub fn voice(&self) -> Option<Counts> {
        self.counts(MessageClass::Voice)
    }

    /// Whether a new message is waiting, per the status line when present and
    /// otherwise inferred from the counts.
    pub fn has_messages(&self) -> bool {
        match self.waiting {
            Some(waiting) => waiting,
            None => self.classes.iter().any(|(_, c)| c.new > 0),
        }
    }

    /// The number of new messages across every class.
    pub fn new_total(&self) -> u32 {
        self.classes
            .iter()
            .fold(0u32, |acc, (_, c)| acc.saturating_add(c.new))
    }

    /// Parse a summary body.
    pub fn parse(body: &str) -> Result<Self, MwiError> {
        let mut summary = MessageSummary::default();
        let mut lines = body.lines().peekable();
        let mut status_seen = false;

        while let Some(line) = lines.next() {
            let line = line.trim_end_matches('\r');
            if line.trim().is_empty() {
                // A blank line starts the optional RFC 2822-style headers.
                for header in lines.by_ref() {
                    let header = header.trim_end_matches('\r');
                    if header.trim().is_empty() {
                        continue;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        summary
                            .headers
                            .push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
                break;
            }

            let Some((name, value)) = line.split_once(':') else {
                return Err(MwiError::BadLine(line.to_string()));
            };
            let name = name.trim();
            let value = value.trim();

            if name.eq_ignore_ascii_case("Messages-Waiting") {
                summary.waiting = Some(match value.to_ascii_lowercase().as_str() {
                    "yes" => true,
                    "no" => false,
                    other => return Err(MwiError::BadStatus(other.to_string())),
                });
                status_seen = true;
            } else if name.eq_ignore_ascii_case("Message-Account") {
                summary.account = Some(value.to_string());
            } else if let Some(class) = MessageClass::parse(name) {
                summary.classes.push((class, parse_counts(value)?));
            }
            // Any other line is not part of the grammar; ignore it rather than
            // fail the whole update, which would hide a perfectly good count.
        }

        if !status_seen {
            return Err(MwiError::MissingStatus);
        }
        Ok(summary)
    }
}

fn parse_counts(value: &str) -> Result<Counts, MwiError> {
    let (main, urgent) = match value.split_once('(') {
        Some((main, rest)) => {
            let rest = rest
                .strip_suffix(')')
                .ok_or_else(|| MwiError::BadCount(value.to_string()))?;
            (main, Some(rest))
        }
        None => (value, None),
    };

    let (new, old) = split_pair(main, value)?;
    let (new_urgent, old_urgent) = match urgent {
        Some(text) => {
            let (a, b) = split_pair(text, value)?;
            (Some(a), Some(b))
        }
        None => (None, None),
    };
    Ok(Counts {
        new,
        old,
        new_urgent,
        old_urgent,
    })
}

fn split_pair(text: &str, original: &str) -> Result<(u32, u32), MwiError> {
    let (a, b) = text
        .split_once('/')
        .ok_or_else(|| MwiError::BadCount(original.to_string()))?;
    Ok((count(a, original)?, count(b, original)?))
}

/// RFC 3842 §3.3: a counter above `2^32 - 1` is treated as `2^32 - 1`.
fn count(text: &str, original: &str) -> Result<u32, MwiError> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MwiError::BadCount(original.to_string()));
    }
    Ok(text.parse::<u32>().unwrap_or(u32::MAX))
}

/// Errors from a message summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MwiError {
    /// The mandatory `Messages-Waiting` status line was absent.
    MissingStatus,
    /// The status value was neither `yes` nor `no`.
    BadStatus(String),
    /// A line was not `name: value`.
    BadLine(String),
    /// A counter was not `new/old` with digits.
    BadCount(String),
}

impl core::fmt::Display for MwiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MwiError::MissingStatus => f.write_str("missing Messages-Waiting status line"),
            MwiError::BadStatus(v) => write!(f, "Messages-Waiting must be yes or no, got {v:?}"),
            MwiError::BadLine(v) => write!(f, "not a message-summary line: {v:?}"),
            MwiError::BadCount(v) => write!(f, "bad message count: {v:?}"),
        }
    }
}

impl std::error::Error for MwiError {}

/// The `Subscription-State` of a NOTIFY (RFC 6665 §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionState {
    /// `active`.
    Active,
    /// `pending`.
    Pending,
    /// `terminated`.
    Terminated,
    /// Anything else, kept verbatim.
    Other(String),
}

impl SubscriptionState {
    fn parse(value: &str) -> Self {
        match value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "active" => SubscriptionState::Active,
            "pending" => SubscriptionState::Pending,
            "terminated" => SubscriptionState::Terminated,
            other => SubscriptionState::Other(other.to_string()),
        }
    }
}

/// A NOTIFY carrying a message summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummaryNotify {
    /// The subscription state the notifier reports.
    pub subscription_state: SubscriptionState,
    /// The parsed summary.
    pub summary: MessageSummary,
}

/// The UE side of the `message-summary` subscription.
///
/// Holds the dialog identifiers so successive SUBSCRIBEs share a Call-ID and
/// increase the CSeq, which is what makes a refresh a refresh rather than a new
/// subscription.
#[derive(Debug, Clone)]
pub struct MessageSummaryClient {
    aor: String,
    contact: String,
    local_tag: String,
    call_id: String,
    cseq: u32,
    /// The last summary received, for rendering.
    pub last: Option<MessageSummary>,
}

impl MessageSummaryClient {
    /// A client subscribing on behalf of `aor`, reachable at `contact`.
    pub fn new(
        aor: impl Into<String>,
        contact: impl Into<String>,
        local_tag: impl Into<String>,
        call_id: impl Into<String>,
    ) -> Self {
        Self {
            aor: aor.into(),
            contact: contact.into(),
            local_tag: local_tag.into(),
            call_id: call_id.into(),
            cseq: 1,
            last: None,
        }
    }

    /// The account being watched.
    pub fn aor(&self) -> &str {
        &self.aor
    }

    /// Build the initial SUBSCRIBE, or a refresh when called again.
    ///
    /// `expires` is in seconds and is the caller's policy; the notifier may
    /// shorten it.
    pub fn subscribe(&mut self, expires: u32) -> Request {
        let cseq = self.cseq;
        self.cseq = self.cseq.wrapping_add(1);
        let mut request = self.base(cseq);
        request
            .headers
            .push(Header::new("Expires", expires.to_string()));
        request
    }

    /// Unsubscribe: RFC 3842 §3.6 says to do this on deregistration, with an
    /// `Expires` of zero.
    pub fn unsubscribe(&mut self) -> Request {
        let cseq = self.cseq;
        self.cseq = self.cseq.wrapping_add(1);
        let mut request = self.base(cseq);
        request.headers.push(Header::new("Expires", "0"));
        request
    }

    /// Handle an incoming NOTIFY.
    ///
    /// Returns `None` for anything that is not a `message-summary` NOTIFY —
    /// which includes a NOTIFY for another event package, since a UE may hold
    /// several subscriptions at once.
    pub fn on_notify(&mut self, request: &Request) -> Option<MessageSummaryNotify> {
        if request.method != Method::Notify {
            return None;
        }
        let event = request.headers.get("event")?;
        if !event
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case(MESSAGE_SUMMARY_EVENT)
        {
            return None;
        }
        if !request
            .headers
            .get("content-type")?
            .to_ascii_lowercase()
            .contains(MESSAGE_SUMMARY_MIME)
        {
            return None;
        }
        let body = core::str::from_utf8(&request.body).ok()?;
        let summary = MessageSummary::parse(body).ok()?;
        let state = SubscriptionState::parse(request.headers.get("subscription-state")?);
        self.last = Some(summary.clone());
        Some(MessageSummaryNotify {
            subscription_state: state,
            summary,
        })
    }

    fn base(&self, cseq: u32) -> Request {
        let host = self
            .contact
            .strip_prefix("sip:")
            .and_then(|s| s.split('@').nth(1))
            .unwrap_or(&self.contact)
            .to_string();
        let mut headers = Headers::new();
        headers.push(Header::new(
            "Via",
            format!("SIP/2.0/UDP {host};branch=z9hG4bK-fungos-mwi-{cseq};rport"),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", self.aor, self.local_tag),
        ));
        headers.push(Header::new("To", format!("<{}>", self.aor)));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{cseq} SUBSCRIBE")));
        headers.push(Header::new("Contact", format!("<{}>", self.contact)));
        headers.push(Header::new("Event", MESSAGE_SUMMARY_EVENT));
        headers.push(Header::new("Accept", MESSAGE_SUMMARY_MIME));
        headers.push(Header::new("Content-Length", "0"));
        Request {
            method: Method::Subscribe,
            uri: self.aor.clone(),
            headers,
            body: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_rfc_3842_example() {
        // RFC 3842 §3.8 example NOTIFY body.
        let body = "Messages-Waiting: yes\r\n\
                    Message-Account: sip:alice@vmail.example.com\r\n\
                    Voice-Message: 2/8 (0/2)\r\n";
        let summary = MessageSummary::parse(body).unwrap();
        assert_eq!(summary.waiting, Some(true));
        assert_eq!(
            summary.account.as_deref(),
            Some("sip:alice@vmail.example.com")
        );
        assert_eq!(
            summary.voice(),
            Some(Counts {
                new: 2,
                old: 8,
                new_urgent: Some(0),
                old_urgent: Some(2),
            })
        );
        assert!(summary.has_messages());
        assert_eq!(summary.new_total(), 2);
    }

    #[test]
    fn accepts_a_fax_and_a_boolean_only_summary() {
        // RFC 3842 §3.3: the boolean-only form is allowed.
        let boolean = MessageSummary::parse("Messages-Waiting: yes\r\n").unwrap();
        assert_eq!(boolean.waiting, Some(true));
        assert_eq!(boolean.classes.len(), 0);
        assert!(boolean.has_messages());

        let fax = MessageSummary::parse("Messages-Waiting: yes\r\nFax-Message: 2/4\r\n").unwrap();
        assert_eq!(
            fax.counts(MessageClass::Fax),
            Some(Counts {
                new: 2,
                old: 4,
                new_urgent: None,
                old_urgent: None,
            })
        );
        assert_eq!(fax.voice(), None);
    }

    #[test]
    fn productions_are_case_insensitive() {
        let body = "messages-waiting: YES\r\nvoice-message: 1/0\r\n";
        let summary = MessageSummary::parse(body).unwrap();
        assert_eq!(summary.waiting, Some(true));
        assert_eq!(summary.voice().unwrap().new, 1);
    }

    #[test]
    fn a_count_larger_than_u32_is_clamped_to_the_maximum() {
        // RFC 3842 §3.3: subscribers MUST treat a larger value as 2^32-1.
        let body = "Messages-Waiting: yes\r\nVoice-Message: 4294967296/0\r\n";
        let summary = MessageSummary::parse(body).unwrap();
        assert_eq!(summary.voice().unwrap().new, u32::MAX);
    }

    #[test]
    fn malformed_bodies_are_rejected_where_it_matters() {
        assert_eq!(
            MessageSummary::parse("Voice-Message: 1/0\r\n"),
            Err(MwiError::MissingStatus)
        );
        assert_eq!(
            MessageSummary::parse("Messages-Waiting: maybe\r\n"),
            Err(MwiError::BadStatus("maybe".into()))
        );
        assert_eq!(
            MessageSummary::parse("Messages-Waiting: yes\r\nVoice-Message: 1\r\n"),
            Err(MwiError::BadCount("1".into()))
        );
        assert!(matches!(
            MessageSummary::parse("Messages-Waiting: yes\r\nVoice-Message: 1/0 (0)\r\n"),
            Err(MwiError::BadCount(_))
        ));
    }

    #[test]
    fn an_unknown_class_line_does_not_lose_the_counts_around_it() {
        let body = "Messages-Waiting: yes\r\n\
                    Voice-Message: 3/1\r\n\
                    Video-Message: 1/1\r\n\
                    Fax-Message: 0/2\r\n";
        let summary = MessageSummary::parse(body).unwrap();
        assert_eq!(summary.voice().unwrap().new, 3);
        assert_eq!(summary.counts(MessageClass::Fax).unwrap().old, 2);
    }

    #[test]
    fn optional_message_headers_are_captured_after_the_blank_line() {
        let body = "Messages-Waiting: yes\r\n\
                    Voice-Message: 1/0\r\n\
                    \r\n\
                    From: Bob <sip:bob@example.com>\r\n\
                    Subject: call me back\r\n";
        let summary = MessageSummary::parse(body).unwrap();
        assert_eq!(
            summary.headers,
            vec![
                ("From".to_string(), "Bob <sip:bob@example.com>".to_string()),
                ("Subject".to_string(), "call me back".to_string()),
            ]
        );
        assert_eq!(summary.voice().unwrap().new, 1);
    }

    fn notify(event: &str, content_type: &str, state: &str, body: &str) -> Request {
        let mut headers = Headers::new();
        headers.push(Header::new("Via", "SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-n"));
        headers.push(Header::new("From", "<sip:vm@example.com>;tag=v"));
        headers.push(Header::new("To", "<sip:alice@example.com>;tag=a"));
        headers.push(Header::new("Call-ID", "mwi-1"));
        headers.push(Header::new("CSeq", "2 NOTIFY"));
        headers.push(Header::new("Event", event));
        headers.push(Header::new("Subscription-State", state));
        headers.push(Header::new("Content-Type", content_type));
        Request {
            method: Method::Notify,
            uri: "sip:alice@example.com".into(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_message_summary_notify_is_recognised() {
        let mut client = MessageSummaryClient::new(
            "sip:alice@example.com",
            "sip:alice@192.0.2.10:5060",
            "a",
            "mwi-1",
        );
        let request = notify(
            MESSAGE_SUMMARY_EVENT,
            MESSAGE_SUMMARY_MIME,
            "active;expires=3600",
            "Messages-Waiting: yes\r\nVoice-Message: 2/8 (0/2)\r\n",
        );
        let update = client.on_notify(&request).unwrap();
        assert_eq!(update.subscription_state, SubscriptionState::Active);
        assert_eq!(update.summary.voice().unwrap().new, 2);
        // The client remembers it for rendering.
        assert_eq!(client.last.unwrap().new_total(), 2);
    }

    #[test]
    fn other_event_packages_are_not_ours() {
        let mut client = MessageSummaryClient::new("sip:a@b", "sip:a@192.0.2.10:5060", "t", "c");
        let request = notify(
            "presence",
            MESSAGE_SUMMARY_MIME,
            "active",
            "Messages-Waiting: yes\r\n",
        );
        assert!(client.on_notify(&request).is_none());
    }

    #[test]
    fn a_terminated_subscription_is_reported_as_such() {
        let mut client = MessageSummaryClient::new("sip:a@b", "sip:a@192.0.2.10:5060", "t", "c");
        let request = notify(
            MESSAGE_SUMMARY_EVENT,
            MESSAGE_SUMMARY_MIME,
            "terminated;reason=timeout",
            "Messages-Waiting: no\r\nVoice-Message: 0/3\r\n",
        );
        let update = client.on_notify(&request).unwrap();
        assert_eq!(update.subscription_state, SubscriptionState::Terminated);
        assert!(!update.summary.has_messages());
    }

    #[test]
    fn subscribe_and_unsubscribe_share_the_dialog() {
        let mut client = MessageSummaryClient::new(
            "sip:alice@example.com",
            "sip:alice@192.0.2.10:5060",
            "a",
            "mwi-1",
        );
        let first = client.subscribe(3600);
        assert_eq!(first.method, Method::Subscribe);
        assert_eq!(first.uri, "sip:alice@example.com");
        assert_eq!(first.headers.get("event"), Some(MESSAGE_SUMMARY_EVENT));
        assert_eq!(first.headers.get("accept"), Some(MESSAGE_SUMMARY_MIME));
        assert_eq!(first.headers.get("expires"), Some("3600"));
        assert_eq!(first.headers.get("cseq"), Some("1 SUBSCRIBE"));
        assert!(first.headers.get("from").unwrap().contains("tag=a"));

        let refresh = client.subscribe(3600);
        assert_eq!(refresh.headers.get("cseq"), Some("2 SUBSCRIBE"));
        assert_eq!(refresh.headers.get("call-id"), Some("mwi-1"));

        // RFC 3842 §3.6: unsubscribe with Expires 0 on deregistration.
        let stop = client.unsubscribe();
        assert_eq!(stop.headers.get("expires"), Some("0"));
        assert_eq!(stop.headers.get("cseq"), Some("3 SUBSCRIBE"));
        assert_eq!(stop.headers.get("call-id"), Some("mwi-1"));
    }
}
