//! The 3GPP IM CN subsystem XML body (TS 24.229 §7.6).
//!
//! A network can answer a request with `application/3gpp-ims+xml` carrying an
//! `<alternative-service>`: *"not this way, try that way instead"*. The UE is
//! supposed to act on it, and for emergency calls the action decides whether it
//! falls back to an unauthenticated emergency call, retries an emergency
//! registration in another VPLMN, or gives up.
//!
//! ```xml
//! <ims-3gpp version="1">
//!   <alternative-service>
//!     <type>emergency</type>
//!     <reason>...</reason>
//!     <action>anonymous-emergencycall</action>
//!   </alternative-service>
//! </ims-3gpp>
//! ```
//!
//! This is a deliberately small, strict extractor rather than a general XML
//! parser: it looks for exactly the elements it needs, requires them to be
//! well-formed enough to be unambiguous, and returns `None` for anything else.
//! A body we cannot read confidently must not move the UE into a different
//! emergency procedure.

#![forbid(unsafe_code)]

/// MIME type of the IM CN subsystem XML body (TS 24.229 §7.6.4).
pub const IMS3GPP_MIME: &str = "application/3gpp-ims+xml";

/// What the `<type>` element said (TS 24.229 §7.6.3 table 7.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlternativeType {
    /// The service suggested instead is an emergency service.
    Emergency,
    /// The network suggests S-CSCF restoration.
    Restoration,
}

/// What the `<action>` element said (TS 24.229 §7.6.3 table 7.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlternativeAction {
    /// Perform an emergency registration.
    EmergencyRegistration,
    /// Perform an initial registration.
    InitialRegistration,
    /// Place the call without registration (`§5.1.6.8.2`).
    AnonymousEmergencyCall,
}

/// An `<alternative-service>` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlternativeService {
    /// The `<type>` value.
    pub kind: AlternativeType,
    /// The `<action>` value, when present. §5.1.6.8.3 says to treat a missing
    /// action as "not one of the three known ones", so it is optional here.
    pub action: Option<AlternativeAction>,
}

/// Parse an IM CN subsystem XML body and return its `<alternative-service>`.
///
/// Returns `None` when the body is not an `<ims-3gpp>` document, or when the
/// `<type>` is missing or is not one of the two values table 7.6.2 allows.
pub fn parse_alternative_service(body: &[u8]) -> Option<AlternativeService> {
    let text = core::str::from_utf8(body).ok()?;
    let inner = element(text, "alternative-service")?;

    let kind = match trim(element(inner, "type")?)? {
        "emergency" => AlternativeType::Emergency,
        "restoration" => AlternativeType::Restoration,
        _ => return None,
    };

    // An `<action>` that is present but outside table 7.6.3 is a schema
    // violation, not an absent action: fail the whole parse rather than
    // quietly treating it as "no action suggested".
    let action = match element(inner, "action") {
        None => None,
        Some(raw) => Some(match trim(raw)? {
            "emergency-registration" => AlternativeAction::EmergencyRegistration,
            "initial-registration" => AlternativeAction::InitialRegistration,
            "anonymous-emergencycall" => AlternativeAction::AnonymousEmergencyCall,
            _ => return None,
        }),
    };

    Some(AlternativeService { kind, action })
}

/// The text between the first `<name>` and its matching `</name>`.
///
/// Nested elements of the same name are not handled, because none of the
/// elements this module reads can nest.
fn element<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let start = text.find(&open)?;
    // Skip any attributes up to the end of the opening tag.
    let after_open = start + open.len();
    let gt = text[after_open..].find('>')? + after_open + 1;
    let end = text[gt..].find(&close)? + gt;
    text.get(gt..end)
}

fn trim(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ims-3gpp version="1">
  <alternative-service>
    <type>emergency</type>
    <reason>emergency sessions are not allowed in this network</reason>
    <action>anonymous-emergencycall</action>
  </alternative-service>
</ims-3gpp>"#;

    #[test]
    fn parses_the_anonymous_emergency_call_action() {
        assert_eq!(
            parse_alternative_service(BODY.as_bytes()),
            Some(AlternativeService {
                kind: AlternativeType::Emergency,
                action: Some(AlternativeAction::AnonymousEmergencyCall),
            })
        );
    }

    #[test]
    fn action_is_optional() {
        let body = r#"<ims-3gpp version="1"><alternative-service>
            <type>restoration</type><reason>x</reason>
        </alternative-service></ims-3gpp>"#;
        assert_eq!(
            parse_alternative_service(body.as_bytes()),
            Some(AlternativeService {
                kind: AlternativeType::Restoration,
                action: None,
            })
        );
    }

    #[test]
    fn unknown_type_or_action_is_refused() {
        let bad_type = r#"<ims-3gpp><alternative-service><type>other</type>
            </alternative-service></ims-3gpp>"#;
        assert_eq!(parse_alternative_service(bad_type.as_bytes()), None);

        let bad_action = r#"<ims-3gpp><alternative-service><type>emergency</type>
            <action>do-something-else</action></alternative-service></ims-3gpp>"#;
        assert_eq!(parse_alternative_service(bad_action.as_bytes()), None);
    }

    #[test]
    fn non_xml_and_missing_elements_are_refused() {
        assert_eq!(parse_alternative_service(b""), None);
        assert_eq!(parse_alternative_service(b"not xml at all"), None);
        assert_eq!(
            parse_alternative_service(b"<ims-3gpp version=\"1\"/>"),
            None
        );
        assert_eq!(parse_alternative_service(&[0xff, 0xfe]), None);
    }
}
