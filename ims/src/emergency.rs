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
//! * **Emergency registration** (TS 24.229 §5.1.6.2): a REGISTER whose
//!   `Contact` carries the `sos` URI parameter, unauthenticated, with `From`
//!   and `To` set to the identity from item b.
//! * **Emergency INVITE** (TS 24.229 §5.1.6.8.3): Request-URI = service URN,
//!   the PIDF-LO in a body part referenced by `cid:` from `Geolocation`, the
//!   SDP offer alongside it, and `Geolocation-Routing: yes` (RFC 6442).
//!
//! Two things this module deliberately does **not** do, because TS 24.229 says
//! the UE must not: it sends no `Service: sos` header (the marker is the
//! `sos` URI parameter on the Contact), and it sends no `Resource-Priority`
//! `esnet` namespace (§4.7: "There is no usage of this namespace from the UE,
//! and when this namespace is used, the trust domain implementation is set to
//! remove it if it occurs from the UE").

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
    /// `urn:service:sos.ecall.manual` (TS 24.229 §5.1.6.8.1).
    EcallManual,
    /// `urn:service:sos.ecall.automatic` (TS 24.229 §5.1.6.8.1).
    EcallAutomatic,
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
            SosService::EcallManual => "urn:service:sos.ecall.manual",
            SosService::EcallAutomatic => "urn:service:sos.ecall.automatic",
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
            "urn:service:sos.ecall.manual" => SosService::EcallManual,
            "urn:service:sos.ecall.automatic" => SosService::EcallAutomatic,
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
    /// A multipart body could not be serialised.
    Multipart(sip::multipart::MultipartError),
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
            EmergencyError::Multipart(e) => write!(f, "multipart body: {e}"),
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
    /// `P-Access-Network-Info` value, when the access network can describe
    /// itself (TS 24.229 §5.1.6.8.3 item 4).
    pani: Option<String>,
    /// Whether to ask for current-location discovery during the call
    /// (TS 24.229 §5.1.6.8.3 item 10, §5.1.6.12).
    current_location_discovery: bool,
    /// `Some(instance)` when this is an unregistered emergency call
    /// (TS 24.229 §5.1.6.8.2), where `instance` is the RFC 5626 instance ID.
    anonymous_instance: Option<String>,
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
            pani: None,
            current_location_discovery: false,
            anonymous_instance: None,
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

    /// Attach a `P-Access-Network-Info` value (TS 24.229 §5.1.6.8.3 item 4).
    ///
    /// The header carries whatever location identifier the access technology
    /// defines — a cell id, a line id, or the identity of the WLAN access
    /// point — and the network may use it for routing.
    pub fn with_pani(mut self, pani: impl Into<String>) -> Self {
        self.pani = Some(pani.into());
        self
    }

    /// Ask the network to be able to push an updated location during the call
    /// (TS 24.229 §5.1.6.8.3 item 10).
    ///
    /// This adds `Recv-Info: g.3gpp.current-location-discovery` and an `Accept`
    /// for the matching XML type. It is only meaningful where the IP-CAN
    /// supports current-location discovery.
    pub fn with_current_location_discovery(mut self) -> Self {
        self.current_location_discovery = true;
        self
    }

    /// Build the *unregistered* emergency call of TS 24.229 §5.1.6.8.2.
    ///
    /// Use this when the network answered the emergency registration with a
    /// 403/420 and an `<action>anonymous-emergencycall</action>` — see
    /// [`EmergencyFallback`]. It changes three things:
    ///
    /// * `From` becomes `"Anonymous" <sip:anonymous@anonymous.invalid>`, the
    ///   form TS 24.229 itself uses for an anonymous identity;
    /// * `P-Preferred-Identity` is dropped, because there is no registered
    ///   identity to prefer;
    /// * the `Contact` gains the RFC 5626 `+sip.instance` media feature tag and
    ///   the `Via` gains `rport`/`keep`, because the dialog lives on an
    ///   unprotected port that has to stay reachable for the PSAP to call back.
    pub fn anonymous(mut self, instance_id: impl Into<String>) -> Self {
        self.anonymous_instance = Some(instance_id.into());
        self
    }

    /// Whether this request is the unregistered form.
    pub fn is_anonymous(&self) -> bool {
        self.anonymous_instance.is_some()
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
    /// The Request-URI is the service URN and the `To` header carries the same
    /// URN (TS 24.229 §5.1.6.8.3 items 2 and 3). When a location is attached,
    /// the PIDF-LO goes in a body part whose `Content-ID` the `Geolocation`
    /// header references with `cid:`, together with
    /// `Geolocation-Routing: yes` (item 7 and 8). If there is also an SDP
    /// offer, both parts travel in a `multipart/mixed` body — an emergency
    /// INVITE carries location *and* media, never one instead of the other.
    ///
    /// No `Resource-Priority` is added: TS 24.229 §4.7 states there is no usage
    /// of the `esnet` namespace from the UE, and that the trust domain is set
    /// to remove it if a UE sends it.
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
            .unwrap_or(&self.local_contact)
            .to_string();
        // A Content-ID has no port to disambiguate: keep the bare host.
        let cid_host = host.split(':').next().unwrap_or(&host).to_string();
        headers.push(Header::new(
            "Via",
            if self.is_anonymous() {
                // §5.1.6.8.2 item 7: `rport` and `keep` on an unprotected port,
                // so the dialog survives and stays reachable.
                format!("SIP/2.0/UDP {host};branch=z9hG4bK-fungos-emerg-1;rport;keep")
            } else {
                format!("SIP/2.0/UDP {host};branch=z9hG4bK-fungos-emerg-1;rport")
            },
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        // §5.1.6.8.2 item 1: an unregistered emergency call is sent as
        // "Anonymous"; §5.1.6.8.3 item 1: otherwise the registered identity.
        let from_uri = if self.is_anonymous() {
            "sip:anonymous@anonymous.invalid".to_string()
        } else {
            self.identity.uri().to_string()
        };
        let from = if self.is_anonymous() {
            format!("\"Anonymous\" <{from_uri}>;tag={}", self.local_tag)
        } else {
            format!("<{from_uri}>;tag={}", self.local_tag)
        };
        headers.push(Header::new("From", from));
        headers.push(Header::new("To", format!("<{}>", self.urn.as_str())));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} INVITE", self.cseq)));
        for route in &self.service_route {
            headers.push(Header::new("Route", format!("<{route}>")));
        }
        // §5.1.6.8.2 item 6: the Contact carries a `sip.instance` media feature
        // tag on an unprotected port, and no GRUU.
        let contact = match &self.anonymous_instance {
            Some(instance) => format!(
                "<{};+sip.instance=\"<urn:uuid:{instance}>\">",
                self.local_contact
            ),
            None => format!("<{}>", self.local_contact),
        };
        headers.push(Header::new("Contact", contact));
        // §5.1.6.8.2 item 5 only defines an equipment identifier for access
        // technologies that specify one; with no registered identity there is
        // nothing to prefer, so the header is omitted.
        if !self.is_anonymous() {
            headers.push(Header::new(
                "P-Preferred-Identity",
                format!("<{}>", self.identity.uri()),
            ));
        }
        if let Some(pani) = &self.pani {
            headers.push(Header::new("P-Access-Network-Info", pani.clone()));
        }
        if self.current_location_discovery {
            headers.push(Header::new(
                "Recv-Info",
                "g.3gpp.current-location-discovery",
            ));
            headers.push(Header::new(
                "Accept",
                "application/vnd.3gpp.current-location-discovery+xml",
            ));
        }
        headers.push(Header::new("Supported", "100rel, precondition"));
        // TS 24.229 §5.1.6.8.3 NOTE 5: RFC 3261 suggests `Priority: emergency`.
        // It has no effect inside the IM CN subsystem, but it makes a capture
        // unambiguous about what kind of call this is.
        headers.push(Header::new("Priority", "emergency"));

        let pidf = self
            .geolocation
            .map(|l| l.to_pidf_lo(self.identity.uri()).into_bytes());
        let sdp = self.offer_sdp.clone().map(String::into_bytes);

        let body = match (pidf, sdp) {
            (Some(pidf), Some(sdp)) => {
                let cid = format!("emergency-location@{}", cid_host);
                headers.push(Header::new("Geolocation", format!("<cid:{cid}>")));
                headers.push(Header::new("Geolocation-Routing", "yes"));
                headers.push(Header::new(
                    "Content-Type",
                    sip::multipart::content_type(EMERGENCY_BOUNDARY),
                ));
                sip::multipart::multipart_mixed(
                    EMERGENCY_BOUNDARY,
                    &[
                        sip::Part::new("application/pidf+xml", &pidf)
                            .with_content_id(&cid)
                            .with_disposition("render; handling=optional"),
                        sip::Part::new("application/sdp", &sdp),
                    ],
                )
                .map_err(EmergencyError::Multipart)?
            }
            (Some(pidf), None) => {
                let cid = format!("emergency-location@{}", cid_host);
                headers.push(Header::new("Geolocation", format!("<cid:{cid}>")));
                headers.push(Header::new("Geolocation-Routing", "yes"));
                headers.push(Header::new("Content-ID", format!("<{cid}>")));
                headers.push(Header::new(
                    "Content-Disposition",
                    "render; handling=optional",
                ));
                headers.push(Header::new("Content-Type", "application/pidf+xml"));
                pidf
            }
            (None, Some(sdp)) => {
                headers.push(Header::new("Content-Type", "application/sdp"));
                sdp
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

/// The deterministic multipart boundary the emergency body uses.
///
/// This tree has no RNG by design, and a fixed boundary keeps captures and
/// tests reproducible. [`sip::multipart::multipart_mixed`] refuses to serialise
/// if the marker happens to occur inside a part.
pub const EMERGENCY_BOUNDARY: &str = "fungos-emergency";

/// Builds the initial emergency `REGISTER` described by TS 24.229 §5.1.6.2.
///
/// Like [`EmergencyRequest`], this is construction only: it returns a `Request`
/// and performs no I/O.
///
/// Two things make an emergency registration different from a normal one, and
/// both are here rather than left to the caller:
///
/// * the `Contact` carries the **`sos` URI parameter** (item a, and
///   §7.2A.13), which is what marks the contact as usable only for emergency
///   service — there is no `Service:` header involved;
/// * `From` and `To` carry the identity from item b: the first provisioned
///   public identity, else the default identity from a normal registration,
///   else the temporary identity derived from the IMSI.
///
/// The request deliberately carries **no `Authorization` header**. An initial
/// emergency registration is unauthenticated; if the network answers 403/420
/// with an `alternative-service` of type `emergency` and action
/// `anonymous-emergencycall`, the UE proceeds with §5.1.6.8.2 instead.
#[derive(Debug, Clone)]
pub struct EmergencyRegistration {
    identity: EmergencyIdentity,
    contact: String,
    local_tag: String,
    call_id: String,
    cseq: u32,
    expires: u32,
    pani: Option<String>,
}

impl EmergencyRegistration {
    /// Create an emergency registration for `identity` from `contact_host`.
    ///
    /// `expires` is in seconds and is operator policy; TS 24.229 does not fix
    /// it, so it is a parameter rather than a constant.
    pub fn new(
        identity: EmergencyIdentity,
        contact_host: &str,
        contact_port: u16,
        expires: u32,
    ) -> Self {
        let user = identity_user(&identity);
        Self {
            contact: format!("sip:{user}@{contact_host}:{contact_port}"),
            identity,
            local_tag: format!("emerg-reg-{contact_port}"),
            call_id: format!("fungos-emergency-reg-{contact_port}@{contact_host}"),
            cseq: 1,
            expires,
            pani: None,
        }
    }

    /// Attach a `P-Access-Network-Info` value.
    pub fn with_pani(mut self, pani: impl Into<String>) -> Self {
        self.pani = Some(pani.into());
        self
    }

    /// The `Contact` URI including the `sos` parameter.
    pub fn contact(&self) -> &str {
        &self.contact
    }

    /// The identity used in `From` and `To`.
    pub fn identity(&self) -> &EmergencyIdentity {
        &self.identity
    }

    /// Build the REGISTER request. `registrar` is the Request-URI — normally
    /// `sip:<home domain>`.
    pub fn register(&self, registrar: &str, contact_host: &str, contact_port: u16) -> Request {
        let mut headers = Headers::new();
        headers.push(Header::new(
            "Via",
            format!(
                "SIP/2.0/UDP {contact_host}:{contact_port};branch=z9hG4bK-fungos-emerg-reg-1;rport"
            ),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", self.identity.uri(), self.local_tag),
        ));
        // §5.1.6.2 b: From and To carry the same identity for a REGISTER.
        headers.push(Header::new("To", format!("<{}>", self.identity.uri())));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} REGISTER", self.cseq)));
        // §5.1.6.2 a and §7.2A.13: the `sos` URI parameter, not a header.
        headers.push(Header::new("Contact", format!("<{};sos>", self.contact)));
        headers.push(Header::new("Expires", self.expires.to_string()));
        if let Some(pani) = &self.pani {
            headers.push(Header::new("P-Access-Network-Info", pani.clone()));
        }
        headers.push(Header::new("Content-Length", "0"));

        Request {
            method: Method::Register,
            uri: registrar.to_string(),
            headers,
            body: Vec::new(),
        }
    }
}

/// What to do after the network refuses a step of the emergency procedure.
///
/// The network answers with an `application/3gpp-ims+xml` body carrying an
/// `<alternative-service>` ([`crate::ims3gpp`]) that says what to try instead.
/// This type is the decision, not the action: it never sends anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyFallback {
    /// TS 24.229 §5.1.6.2: the emergency registration was refused with 403 or
    /// 420 and an `anonymous-emergencycall` action. Place the call without
    /// registration, per §5.1.6.8.2 — see [`EmergencyRequest::anonymous`].
    AnonymousEmergencyCall,
    /// TS 24.229 §5.1.6.8.3: a 380 (Alternative Service) suggests a new initial
    /// emergency registration, possibly in another VPLMN.
    EmergencyRegistration,
}

/// Decide what an emergency response asks the UE to do (TS 24.229 §5.1.6.2,
/// §5.1.6.8.3).
///
/// Returns `None` for every other response, including a well-formed XML body
/// whose action does not apply to this situation. `None` means "nothing to
/// fall back to", never "retry anyway".
///
/// The caller must have established that the request really was the emergency
/// one: §5.1.6.2 frames these responses as coming back to a REGISTER whose
/// `Contact` carries the `sos` URI parameter. That check needs the request, so
/// it is not repeated here.
pub fn emergency_fallback(response: &sip::Response) -> Option<EmergencyFallback> {
    let content_type = response.headers.get("content-type")?;
    if !content_type.contains(crate::ims3gpp::IMS3GPP_MIME) {
        return None;
    }
    let service = crate::ims3gpp::parse_alternative_service(&response.body)?;
    if service.kind != crate::ims3gpp::AlternativeType::Emergency {
        return None;
    }
    match (response.status, service.action) {
        (403 | 420, Some(crate::ims3gpp::AlternativeAction::AnonymousEmergencyCall)) => {
            Some(EmergencyFallback::AnonymousEmergencyCall)
        }
        (380, Some(crate::ims3gpp::AlternativeAction::EmergencyRegistration)) => {
            Some(EmergencyFallback::EmergencyRegistration)
        }
        _ => None,
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
    fn emergency_invite_targets_the_urn_and_never_sends_esnet() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .invite()
            .unwrap();
        assert_eq!(req.method, Method::Invite);
        assert_eq!(req.uri, "urn:service:sos");
        assert!(req.headers.get("to").unwrap().contains("urn:service:sos"));
        assert_eq!(req.headers.get("priority"), Some("emergency"));
        // TS 24.229 §4.7: there is no usage of the esnet namespace from the UE,
        // and the trust domain removes it if a UE sends it.
        assert_eq!(req.headers.get("resource-priority"), None);
        assert_eq!(req.headers.get("content-length"), Some("0"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn geolocation_is_referenced_by_cid_not_carried_bare() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let loc = Geolocation::new(51.5, -0.12).unwrap();
        let req = EmergencyRequest::new(SosService::Fire, id, "192.0.2.10", 5060)
            .with_geolocation(loc)
            .invite()
            .unwrap();
        assert_eq!(req.uri, "urn:service:sos.fire");
        // RFC 6442: the Geolocation header points at the body part by Content-ID.
        assert_eq!(
            req.headers.get("geolocation"),
            Some("<cid:emergency-location@192.0.2.10>")
        );
        assert_eq!(req.headers.get("geolocation-routing"), Some("yes"));
        assert_eq!(
            req.headers.get("content-id"),
            Some("<emergency-location@192.0.2.10>")
        );
        assert_eq!(
            req.headers.get("content-disposition"),
            Some("render; handling=optional")
        );
        assert_eq!(
            req.headers.get("content-type"),
            Some("application/pidf+xml")
        );
        let body = String::from_utf8(req.body.clone()).unwrap();
        assert!(body.contains("<gml:pos>51.500000 -0.120000</gml:pos>"));
        assert_eq!(
            req.headers.get("content-length"),
            Some(req.body.len().to_string().as_str())
        );
    }

    #[test]
    fn location_and_sdp_travel_together_in_a_multipart_body() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let loc = Geolocation::new(51.5, -0.12).unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_geolocation(loc)
            .with_offer_sdp("v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\n")
            .invite()
            .unwrap();
        assert_eq!(
            req.headers.get("content-type"),
            Some("multipart/mixed; boundary=fungos-emergency")
        );
        let body = String::from_utf8(req.body.clone()).unwrap();
        // The PIDF-LO part is the one the Geolocation header names.
        assert!(body.contains("Content-ID: <emergency-location@192.0.2.10>"));
        assert!(body.contains("Content-Disposition: render; handling=optional"));
        assert!(body.contains("Content-Type: application/pidf+xml"));
        // The SDP offer is not dropped: an emergency call needs media too.
        assert!(body.contains("Content-Type: application/sdp"));
        assert!(body.contains("v=0"));
        assert!(body.ends_with("--fungos-emergency--\r\n"));
    }

    #[test]
    fn no_location_means_no_geolocation_headers() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_offer_sdp("v=0\r\n")
            .invite()
            .unwrap();
        // TS 24.229 §5.1.6.8.3 item 9.
        assert_eq!(req.headers.get("geolocation"), None);
        assert_eq!(req.headers.get("geolocation-routing"), None);
        assert_eq!(req.headers.get("content-type"), Some("application/sdp"));
    }

    #[test]
    fn pani_and_current_location_discovery_are_opt_in() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let plain = EmergencyRequest::new(SosService::Sos, id.clone(), "192.0.2.10", 5060)
            .invite()
            .unwrap();
        assert_eq!(plain.headers.get("p-access-network-info"), None);
        assert_eq!(plain.headers.get("recv-info"), None);

        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_pani("IEEE-802.11; i-wlan-node-id=001122334455")
            .with_current_location_discovery()
            .invite()
            .unwrap();
        assert_eq!(
            req.headers.get("p-access-network-info"),
            Some("IEEE-802.11; i-wlan-node-id=001122334455")
        );
        assert_eq!(
            req.headers.get("recv-info"),
            Some("g.3gpp.current-location-discovery")
        );
        assert_eq!(
            req.headers.get("accept"),
            Some("application/vnd.3gpp.current-location-discovery+xml")
        );
    }

    #[test]
    fn ecall_urns_are_recognised() {
        assert_eq!(
            SosService::parse("urn:service:sos.ecall.manual").unwrap(),
            SosService::EcallManual
        );
        assert_eq!(
            SosService::parse("URN:SERVICE:SOS.ECALL.AUTOMATIC").unwrap(),
            SosService::EcallAutomatic
        );
        assert_eq!(
            SosService::EcallManual.as_str(),
            "urn:service:sos.ecall.manual"
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

    #[test]
    fn emergency_registration_marks_the_contact_with_the_sos_parameter() {
        let id = EmergencyIdentity::temporary_from_imsi(
            "001010000000001",
            "ims.mnc001.mcc001.3gppnetwork.org",
        );
        let reg = EmergencyRegistration::new(id, "192.0.2.10", 5060, 600)
            .with_pani("IEEE-802.11; i-wlan-node-id=001122334455");
        let req = reg.register("sip:ims.mnc001.mcc001.3gppnetwork.org", "192.0.2.10", 5060);
        assert_eq!(req.method, Method::Register);
        assert_eq!(req.uri, "sip:ims.mnc001.mcc001.3gppnetwork.org");
        // §5.1.6.2 a: the marker lives in the Contact URI parameter.
        assert_eq!(
            req.headers.get("contact"),
            Some("<sip:001010000000001@192.0.2.10:5060;sos>")
        );
        // §5.1.6.2 b: From and To carry the same identity.
        let from = req.headers.get("from").unwrap();
        let to = req.headers.get("to").unwrap();
        assert!(from.contains("sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"));
        assert!(to.contains("sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"));
        assert_eq!(req.headers.get("expires"), Some("600"));
        assert_eq!(
            req.headers.get("p-access-network-info"),
            Some("IEEE-802.11; i-wlan-node-id=001122334455")
        );
        assert_eq!(req.headers.get("content-length"), Some("0"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn emergency_registration_is_unauthenticated() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRegistration::new(id, "192.0.2.10", 5060, 600).register(
            "sip:ims.example",
            "192.0.2.10",
            5060,
        );
        assert_eq!(req.headers.get("authorization"), None);
        assert_eq!(req.headers.get("proxy-authorization"), None);
        // And it is not a "Service: sos" registration: that header is not used.
        assert_eq!(req.headers.get("service"), None);
    }
    fn xml_response(status: u16, body: &str) -> sip::Response {
        let mut headers = Headers::new();
        headers.push(Header::new("Content-Type", crate::ims3gpp::IMS3GPP_MIME));
        sip::Response {
            status,
            reason: String::new(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    const ANON_XML: &str = r#"<ims-3gpp version="1"><alternative-service>
        <type>emergency</type><reason>no emergency registration here</reason>
        <action>anonymous-emergencycall</action></alternative-service></ims-3gpp>"#;

    const REREG_XML: &str = r#"<ims-3gpp version="1"><alternative-service>
        <type>emergency</type><reason>try another network</reason>
        <action>emergency-registration</action></alternative-service></ims-3gpp>"#;

    #[test]
    fn forbidden_or_bad_extension_with_anonymous_action_falls_back() {
        assert_eq!(
            emergency_fallback(&xml_response(403, ANON_XML)),
            Some(EmergencyFallback::AnonymousEmergencyCall)
        );
        assert_eq!(
            emergency_fallback(&xml_response(420, ANON_XML)),
            Some(EmergencyFallback::AnonymousEmergencyCall)
        );
    }

    #[test]
    fn a_380_suggesting_re_registration_is_a_different_fallback() {
        assert_eq!(
            emergency_fallback(&xml_response(380, REREG_XML)),
            Some(EmergencyFallback::EmergencyRegistration)
        );
        // The mapping is by status as well as action.
        assert_eq!(emergency_fallback(&xml_response(403, REREG_XML)), None);
        assert_eq!(emergency_fallback(&xml_response(380, ANON_XML)), None);
    }

    #[test]
    fn a_response_without_the_xml_body_falls_back_to_nothing() {
        let mut headers = Headers::new();
        headers.push(Header::new("Content-Type", "text/plain"));
        let plain = sip::Response {
            status: 403,
            reason: String::new(),
            headers,
            body: ANON_XML.as_bytes().to_vec(),
        };
        assert_eq!(emergency_fallback(&plain), None);
    }

    #[test]
    fn the_unregistered_call_is_anonymous_with_an_instance_id() {
        let id = EmergencyIdentity::temporary_from_imsi(
            "001010000000001",
            "ims.mnc001.mcc001.3gppnetwork.org",
        );
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .anonymous("6f9c2b1e-0000-4000-8000-000000000001")
            .invite()
            .unwrap();
        assert!(req
            .headers
            .get("from")
            .unwrap()
            .starts_with("\"Anonymous\" <sip:anonymous@anonymous.invalid>;tag="));
        // §5.1.6.8.2 item 1 and, by consequence, no preferred identity.
        assert_eq!(req.headers.get("p-preferred-identity"), None);
        // Item 6: `+sip.instance` on the Contact, and no GRUU.
        assert!(req
            .headers
            .get("contact")
            .unwrap()
            .contains("+sip.instance=\"<urn:uuid:6f9c2b1e-0000-4000-8000-000000000001>\""));
        // Item 7: an unprotected port that stays reachable.
        assert!(req.headers.get("via").unwrap().ends_with(";rport;keep"));
        // The URN is unchanged.
        assert_eq!(req.uri, "urn:service:sos");
    }

    #[test]
    fn the_registered_call_keeps_its_identity_and_preferred_identity() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .invite()
            .unwrap();
        assert!(!req
            .headers
            .get("from")
            .unwrap()
            .starts_with("\"Anonymous\""));
        assert!(req.headers.get("p-preferred-identity").is_some());
        assert!(!req.headers.get("via").unwrap().contains(";keep"));
    }
}
