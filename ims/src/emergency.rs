//! Emergency session identity and routing (E911-001), 3GPP TS 24.229 §5.1.6.
//!
//! ## Safety: this module never places a call
//!
//! Everything here *builds SIP messages and returns bytes*. There is no I/O, no
//! socket, and no timer in this crate, so nothing in this module can dial a
//! real emergency number. The only component in the tree that transmits is the
//! `cli` binary, and its `emergency` subcommand refuses every transport except
//! the in-memory mock. See `cli/src/main.rs`.
//!
//! Do not add a send path here. Emergency calling is regulated, and a test
//! harness must never reach a live PSAP.
//!
//! ## What is modelled
//!
//! * **Service URNs** (RFC 5031): `urn:service:sos` and the registered
//!   `sos.*` sub-services that TS 24.229 uses as the Request-URI of an
//!   emergency INVITE.
//! * **Emergency identity** (TS 24.229 §5.1.6.2): a registered IMPU, or a
//!   temporary identity derived from the IMSI when the UE is not registered.
//! * **Location** (RFC 4119 / RFC 5491 PIDF-LO): a geodetic point that the UE
//!   attaches so the network can route the call.
//! * **Emergency INVITE** (TS 24.229 §5.1.6.3): Request-URI = service URN,
//!   `Resource-Priority: esnet.0` (RFC 4412), and the PIDF-LO body with
//!   `Geolocation-Routing: yes` (RFC 6442).

#![forbid(unsafe_code)]

use sip::{Header, Headers, Method, Request};

/// The root emergency service URN (RFC 5031 §3.2).
pub const SOS_ROOT: &str = "urn:service:sos";

/// The IANA-registered emergency services under `urn:service:sos`.
///
/// Source: RFC 5031 §3.2 (the `sos.` subtree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SosService {
    /// `urn:service:sos` — general emergency.
    Sos,
    /// `urn:service:sos.ambulance`.
    Ambulance,
    /// `urn:service:sos.animal-control`.
    AnimalControl,
    /// `urn:service:sos.fire`.
    Fire,
    /// `urn:service:sos.gas`.
    Gas,
    /// `urn:service:sos.marine`.
    Marine,
    /// `urn:service:sos.mountain`.
    Mountain,
    /// `urn:service:sos.physician`.
    Physician,
    /// `urn:service:sos.poison`.
    Poison,
    /// `urn:service:sos.police`.
    Police,
}

impl SosService {
    /// The canonical URN string for this service.
    pub fn as_str(self) -> &'static str {
        match self {
            SosService::Sos => "urn:service:sos",
            SosService::Ambulance => "urn:service:sos.ambulance",
            SosService::AnimalControl => "urn:service:sos.animal-control",
            SosService::Fire => "urn:service:sos.fire",
            SosService::Gas => "urn:service:sos.gas",
            SosService::Marine => "urn:service:sos.marine",
            SosService::Mountain => "urn:service:sos.mountain",
            SosService::Physician => "urn:service:sos.physician",
            SosService::Poison => "urn:service:sos.poison",
            SosService::Police => "urn:service:sos.police",
        }
    }

    /// Parse a `urn:service:sos[.sub]` string. Matching is case-insensitive
    /// because URN schemes and NIDs are case-insensitive (RFC 8141 §3).
    pub fn parse(value: &str) -> Result<Self, EmergencyError> {
        let lower = value.trim().to_ascii_lowercase();
        Ok(match lower.as_str() {
            "urn:service:sos" => SosService::Sos,
            "urn:service:sos.ambulance" => SosService::Ambulance,
            "urn:service:sos.animal-control" => SosService::AnimalControl,
            "urn:service:sos.fire" => SosService::Fire,
            "urn:service:sos.gas" => SosService::Gas,
            "urn:service:sos.marine" => SosService::Marine,
            "urn:service:sos.mountain" => SosService::Mountain,
            "urn:service:sos.physician" => SosService::Physician,
            "urn:service:sos.poison" => SosService::Poison,
            "urn:service:sos.police" => SosService::Police,
            _ => return Err(EmergencyError::UnknownService(value.to_string())),
        })
    }

    /// Whether `value` is any emergency service URN this tree recognises.
    pub fn is_emergency_urn(value: &str) -> bool {
        Self::parse(value).is_ok()
    }
}

/// Errors from emergency-session construction.
#[derive(Debug, Clone, PartialEq)]
pub enum EmergencyError {
    /// The string was not a `urn:service:sos[.sub]` URN.
    UnknownService(String),
    /// A geodetic location was outside its valid range.
    BadLocation { latitude: f64, longitude: f64 },
    /// The identity was neither a `sip:` nor a `tel:` URI.
    BadIdentity(String),
    /// The SDP/body was not valid UTF-8 (internal invariant).
    BodyEncoding,
}

impl core::fmt::Display for EmergencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EmergencyError::UnknownService(s) => write!(f, "unknown emergency service URN: {s}"),
            EmergencyError::BadLocation {
                latitude,
                longitude,
            } => write!(
                f,
                "location out of range: latitude {latitude}, longitude {longitude}"
            ),
            EmergencyError::BadIdentity(s) => write!(f, "bad emergency identity: {s}"),
            EmergencyError::BodyEncoding => f.write_str("emergency body was not UTF-8"),
        }
    }
}

impl std::error::Error for EmergencyError {}

/// A WGS-84 geodetic location for the PIDF-LO (RFC 5491 §2.1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Geolocation {
    /// Latitude in decimal degrees, -90.0..=90.0.
    pub latitude: f64,
    /// Longitude in decimal degrees, -180.0..=180.0.
    pub longitude: f64,
    /// Optional horizontal uncertainty in metres (RFC 5491 `radius`).
    pub radius_m: Option<f64>,
}

impl Geolocation {
    /// Build a location, validating the WGS-84 ranges.
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, EmergencyError> {
        if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
            return Err(EmergencyError::BadLocation {
                latitude,
                longitude,
            });
        }
        Ok(Self {
            latitude,
            longitude,
            radius_m: None,
        })
    }

    /// Attach a horizontal uncertainty radius (metres).
    pub fn with_radius(mut self, radius_m: f64) -> Self {
        self.radius_m = Some(radius_m);
        self
    }

    /// Render a minimal PIDF-LO document (RFC 4119 + RFC 5491 geodetic).
    ///
    /// The point uses `EPSG::4326` (WGS-84) and `gml:pos` is `"lat lon"`, per
    /// RFC 5491 §2.1.1.
    pub fn to_pidf_lo(&self, entity: &str) -> String {
        let radius = match self.radius_m {
            Some(r) => format!("<gs:radius uom=\"urn:ogc:def:uom:EPSG::9001\">{r:.1}</gs:radius>"),
            None => String::new(),
        };
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"",
                " xmlns:gp=\"urn:ietf:params:xml:ns:pidf:geopriv10\"",
                " xmlns:gml=\"http://www.opengis.net/gml\"",
                " xmlns:gs=\"http://www.opengis.net/pidflo/1.0\"",
                " entity=\"{entity}\">\n",
                "  <tuple id=\"loc1\">\n",
                "    <status>\n",
                "      <gp:geopriv>\n",
                "        <gp:location-info>\n",
                "          <gs:Circle srsName=\"urn:ogc:def:crs:EPSG::4326\">\n",
                "            <gml:pos>{lat:.6} {lon:.6}</gml:pos>\n",
                "            {radius}\n",
                "          </gs:Circle>\n",
                "        </gp:location-info>\n",
                "        <gp:usage-rules/>\n",
                "      </gp:geopriv>\n",
                "    </status>\n",
                "  </tuple>\n",
                "</presence>\n"
            ),
            entity = entity,
            lat = self.latitude,
            lon = self.longitude,
            radius = radius,
        )
    }
}

/// How the UE identifies itself in an emergency session (TS 24.229 §5.1.6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmergencyIdentity {
    /// A normally registered public user identity (`sip:`/`tel:` URI).
    Registered(String),
    /// A temporary identity derived from the IMSI when the UE is not
    /// registered, per TS 24.229 §5.1.6.2.3.
    Temporary(String),
}

impl EmergencyIdentity {
    /// The identity URI placed in `From`/`To` and `P-Preferred-Identity`.
    pub fn uri(&self) -> &str {
        match self {
            EmergencyIdentity::Registered(uri) | EmergencyIdentity::Temporary(uri) => uri,
        }
    }

    /// Whether this is the unregistered temporary identity.
    pub fn is_temporary(&self) -> bool {
        matches!(self, EmergencyIdentity::Temporary(_))
    }

    /// Derive the temporary emergency identity for an unregistered UE:
    /// `sip:<IMSI>@<serving-domain>` (TS 24.229 §5.1.6.2.3).
    pub fn temporary_from_imsi(imsi: &str, serving_domain: &str) -> Self {
        EmergencyIdentity::Temporary(format!("sip:{imsi}@{serving_domain}"))
    }

    /// Validate and wrap a registered identity.
    pub fn registered(uri: impl Into<String>) -> Result<Self, EmergencyError> {
        let uri = uri.into();
        if !(uri.starts_with("sip:") || uri.starts_with("tel:")) {
            return Err(EmergencyError::BadIdentity(uri));
        }
        Ok(EmergencyIdentity::Registered(uri))
    }
}

/// Builds the emergency INVITE described by TS 24.229 §5.1.6.3.
///
/// Construction is pure: [`EmergencyRequest::invite`] returns a `Request` and
/// performs no I/O. See the module-level safety note.
#[derive(Debug, Clone)]
pub struct EmergencyRequest {
    urn: SosService,
    identity: EmergencyIdentity,
    local_contact: String,
    local_tag: String,
    call_id: String,
    cseq: u32,
    geolocation: Option<Geolocation>,
    /// `Resource-Priority` value. TS 24.229 §5.1.6.3 mandates `esnet.0`.
    resource_priority: String,
    service_route: Vec<String>,
    offer_sdp: Option<String>,
}

impl EmergencyRequest {
    /// Create an emergency request to `urn` from `identity`.
    pub fn new(
        urn: SosService,
        identity: EmergencyIdentity,
        contact_host: &str,
        contact_port: u16,
    ) -> Self {
        let local_contact = format!(
            "sip:{}@{contact_host}:{contact_port}",
            identity_user(&identity)
        );
        Self {
            urn,
            identity,
            local_contact,
            local_tag: format!("emerg-{contact_port}"),
            call_id: format!("fungos-emergency-{contact_port}@{contact_host}"),
            cseq: 1,
            geolocation: None,
            resource_priority: "esnet.0".to_string(),
            service_route: Vec::new(),
            offer_sdp: None,
        }
    }

    /// Attach the UE's location (RFC 4119 PIDF-LO body).
    pub fn with_geolocation(mut self, location: Geolocation) -> Self {
        self.geolocation = Some(location);
        self
    }

    /// Use a Service-Route set learned from REGISTER (RFC 3608).
    pub fn with_service_route(mut self, routes: Vec<String>) -> Self {
        self.service_route = routes;
        self
    }

    /// Attach an SDP offer body produced elsewhere (e.g. `ImsProfile`).
    pub fn with_offer_sdp(mut self, sdp: impl Into<String>) -> Self {
        self.offer_sdp = Some(sdp.into());
        self
    }

    /// The service URN this request targets.
    pub fn urn(&self) -> SosService {
        self.urn
    }

    /// The identity used in `From`/`To`.
    pub fn identity(&self) -> &EmergencyIdentity {
        &self.identity
    }

    /// Build the emergency INVITE.
    ///
    /// The Request-URI is the service URN; the request carries
    /// `Resource-Priority: esnet.0`, and a PIDF-LO body plus
    /// `Geolocation-Routing: yes` when a location is attached.
    pub fn invite(&self) -> Result<Request, EmergencyError> {
        let target = self
            .service_route
            .first()
            .cloned()
            .unwrap_or_else(|| self.urn.as_str().to_string());

        let mut headers = Headers::new();
        let host = self
            .local_contact
            .strip_prefix("sip:")
            .and_then(|s| s.split('@').nth(1))
            .unwrap_or(&self.local_contact);
        headers.push(Header::new(
            "Via",
            format!("SIP/2.0/UDP {host};branch=z9hG4bK-fungos-emerg-1;rport"),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", self.identity.uri(), self.local_tag),
        ));
        headers.push(Header::new("To", format!("<{}>", self.urn.as_str())));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} INVITE", self.cseq)));
        for route in &self.service_route {
            headers.push(Header::new("Route", format!("<{route}>")));
        }
        headers.push(Header::new("Contact", format!("<{}>", self.local_contact)));
        headers.push(Header::new(
            "P-Preferred-Identity",
            format!("<{}>", self.identity.uri()),
        ));
        // TS 24.229 §5.1.6.3: emergency sessions request priority esnet.0.
        headers.push(Header::new("Resource-Priority", &self.resource_priority));
        headers.push(Header::new("Supported", "100rel, precondition"));

        let body = match (&self.geolocation, &self.offer_sdp) {
            (Some(location), _) => {
                // Location is authoritative for emergency routing.
                headers.push(Header::new("Geolocation-Routing", "yes"));
                headers.push(Header::new("Content-Type", "application/pidf+xml"));
                location.to_pidf_lo(self.identity.uri()).into_bytes()
            }
            (None, Some(sdp)) => {
                headers.push(Header::new("Content-Type", "application/sdp"));
                sdp.clone().into_bytes()
            }
            (None, None) => Vec::new(),
        };
        headers.push(Header::new("Content-Length", body.len().to_string()));

        Ok(Request {
            method: Method::Invite,
            uri: target,
            headers,
            body,
        })
    }
}

fn identity_user(identity: &EmergencyIdentity) -> &str {
    let uri = identity.uri();
    uri.strip_prefix("sip:")
        .unwrap_or(uri)
        .split('@')
        .next()
        .unwrap_or(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_registered_sos_urns_parse() {
        for service in [
            SosService::Sos,
            SosService::Ambulance,
            SosService::AnimalControl,
            SosService::Fire,
            SosService::Gas,
            SosService::Marine,
            SosService::Mountain,
            SosService::Physician,
            SosService::Poison,
            SosService::Police,
        ] {
            assert_eq!(SosService::parse(service.as_str()).unwrap(), service);
            assert!(SosService::is_emergency_urn(service.as_str()));
        }
        // URNs are case-insensitive.
        assert_eq!(
            SosService::parse("URN:SERVICE:SOS").unwrap(),
            SosService::Sos
        );
        assert!(!SosService::is_emergency_urn("urn:service:sos.nope"));
        assert!(!SosService::is_emergency_urn("sip:911@example.net"));
    }

    #[test]
    fn geolocation_validates_range_and_renders_pidf_lo() {
        assert!(matches!(
            Geolocation::new(91.0, 0.0),
            Err(EmergencyError::BadLocation { .. })
        ));
        assert!(matches!(
            Geolocation::new(0.0, 181.0),
            Err(EmergencyError::BadLocation { .. })
        ));
        let loc = Geolocation::new(48.8584, 2.2945).unwrap().with_radius(50.0);
        let xml = loc.to_pidf_lo("sip:user@example.net");
        assert!(xml.contains("<gml:pos>48.858400 2.294500</gml:pos>"));
        assert!(xml.contains("urn:ogc:def:crs:EPSG::4326"));
        assert!(xml.contains("entity=\"sip:user@example.net\""));
        assert!(xml.contains("<gs:radius"));
    }

    #[test]
    fn temporary_identity_is_derived_from_the_imsi() {
        let id = EmergencyIdentity::temporary_from_imsi(
            "001010000000001",
            "ims.mnc001.mcc001.3gppnetwork.org",
        );
        assert!(id.is_temporary());
        assert_eq!(
            id.uri(),
            "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
        );
        assert!(matches!(
            EmergencyIdentity::registered("911@example.net"),
            Err(EmergencyError::BadIdentity(_))
        ));
    }

    #[test]
    fn emergency_invite_has_urn_ruri_and_resource_priority() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .invite()
            .unwrap();
        assert_eq!(req.method, Method::Invite);
        assert_eq!(req.uri, "urn:service:sos");
        assert_eq!(req.headers.get("resource-priority"), Some("esnet.0"));
        assert!(req.headers.get("to").unwrap().contains("urn:service:sos"));
        assert_eq!(req.headers.get("content-length"), Some("0"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn geolocation_is_attached_as_pidf_lo() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let loc = Geolocation::new(51.5, -0.12).unwrap();
        let req = EmergencyRequest::new(SosService::Fire, id, "192.0.2.10", 5060)
            .with_geolocation(loc)
            .invite()
            .unwrap();
        assert_eq!(req.uri, "urn:service:sos.fire");
        assert_eq!(
            req.headers.get("content-type"),
            Some("application/pidf+xml")
        );
        assert_eq!(req.headers.get("geolocation-routing"), Some("yes"));
        let body = String::from_utf8(req.body.clone()).unwrap();
        assert!(body.contains("<gml:pos>51.500000 -0.120000</gml:pos>"));
        assert_eq!(
            req.headers.get("content-length"),
            Some(req.body.len().to_string().as_str())
        );
    }

    #[test]
    fn service_route_is_used_as_request_uri() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_service_route(vec!["sip:orig@scscf.example;lr".into()])
            .invite()
            .unwrap();
        assert_eq!(req.uri, "sip:orig@scscf.example;lr");
        // The URN still identifies the emergency target in To.
        assert!(req.headers.get("to").unwrap().contains("urn:service:sos"));
    }
}
