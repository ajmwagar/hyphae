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

/// The info package name for current-location discovery during an emergency
/// call (TS 24.229 §5.1.6.12.2, quoted in the `Info-Package` header).
pub const CURRENT_LOCATION_INFO_PACKAGE: &str = "g.3gpp.current-location-discovery";

/// The MIME type of the `requestForLocationInformation` body (TS 24.229
/// §7.12.2.2.4) and of the `Accept` we offered in the INVITE.
pub const CURRENT_LOCATION_MIME: &str = "application/vnd.3gpp.current-location-discovery+xml";

/// The presence event package (RFC 3856), used as the `Event` of the location
/// PUBLISH (RFC 3903 §4 requires one).
pub const LOCATION_EVENT_PACKAGE: &str = "presence";

/// A `requestForLocationInformation` received inside an emergency dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationRequest {
    /// The request asked for a single update (`<oneShot/>`, §7.12.2.2.4).
    pub one_shot: bool,
}

/// Recognise a current-location INFO request (TS 24.229 §5.1.6.12.2).
///
/// Returns `None` for anything that is not exactly that request: the method
/// must be INFO, `Info-Package` must name the current-location package,
/// `Content-Type` must be the matching XML type, and the body must be a
/// `requestForLocationInformation` document. Being strict matters here — the
/// answer is the user's location, and it must not be sent in response to
/// something we merely think is a location request.
pub fn parse_location_request(request: &sip::Request) -> Option<LocationRequest> {
    if request.method != sip::Method::Info {
        return None;
    }
    if !request
        .headers
        .get("info-package")?
        .split(',')
        .any(|p| p.trim().eq_ignore_ascii_case(CURRENT_LOCATION_INFO_PACKAGE))
    {
        return None;
    }
    if !request
        .headers
        .get("content-type")?
        .to_ascii_lowercase()
        .contains(CURRENT_LOCATION_MIME)
    {
        return None;
    }
    let body = core::str::from_utf8(&request.body).ok()?;
    if !body.contains("<requestForLocationInformation") {
        return None;
    }
    Some(LocationRequest {
        one_shot: body.contains("<oneShot"),
    })
}

/// Render a PIDF document that carries **no** location object.
///
/// TS 24.229 §5.1.6.12.3: when the UE has no location and is not going to get
/// one, it still publishes — with a PIDF body that contains no location. That
/// is how the network learns to stop asking, which is better than silence.
pub fn pidf_without_location(entity: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"{entity}\">\n",
            "  <tuple id=\"loc1\">\n",
            "    <status>\n",
            "      <basic>closed</basic>\n",
            "    </status>\n",
            "  </tuple>\n",
            "</presence>\n"
        ),
        entity = entity
    )
}

/// Build the in-dialog PUBLISH that reports the current location
/// (TS 24.229 §5.1.6.12.3).
///
/// `location` is `None` when the UE has no fix and will not obtain one; the
/// PUBLISH is still sent, with [`pidf_without_location`].
pub fn location_publish(
    dialog: &mut crate::Dialog,
    entity: &str,
    location: Option<Location>,
) -> sip::Request {
    let body = match location {
        Some(location) => location.to_pidf(entity),
        None => pidf_without_location(entity),
    };
    dialog.publish(
        LOCATION_EVENT_PACKAGE,
        "application/pidf+xml",
        body.into_bytes(),
    )
}

/// The XML namespace of the civic address (RFC 5139 §2). The conventional
/// prefix is `cac`.
pub const CIVIC_NS: &str = "urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr";

/// Escape text for XML character data and attribute values.
///
/// A civic address is typed by a person and an `entity` is a SIP URI, so both
/// contain `&`, `<` or a quote sooner or later. Without this, a street name can
/// break the PIDF-LO — or inject markup into it.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A civic address (RFC 5139 §2).
///
/// The fields are the elements of the RFC 5139 schema, in schema order: the
/// document is an `xs:sequence`, so the order of the emitted elements is not
/// cosmetic. Every field is optional because a civic address is a
/// best-effort description — a user may know their street but not their
/// building.
///
/// ```text
/// country, A1..A6, PRM, PRD, RD, STS, POD, POM, RDSEC, RDBR, RDSUBBR,
/// HNO, HNS, LMK, LOC, FLR, NAM, PC, BLD, UNIT, ROOM, SEAT, PLC, PCN,
/// POBOX, ADDCODE
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CivicAddress {
    /// `xml:lang` of the address fields (RFC 5139 §3.1).
    language: Option<String>,
    /// ISO 3166-1 alpha-2 country code.
    country: Option<String>,
    /// A1..A6: the national administrative subdivisions, most general first.
    a: [Option<String>; 6],
    /// PRM: pre-modifier.
    pre_modifier: Option<String>,
    /// PRD: leading street direction.
    pre_direction: Option<String>,
    /// RD: road or street name.
    road: Option<String>,
    /// STS: street suffix.
    street_suffix: Option<String>,
    /// POD: trailing street suffix.
    post_direction: Option<String>,
    /// POM: post-modifier.
    post_modifier: Option<String>,
    /// RDSEC, RDBR, RDSUBBR: road section, branch and sub-branch.
    road_section: Option<String>,
    road_branch: Option<String>,
    road_sub_branch: Option<String>,
    /// HNO: house number.
    house_number: Option<String>,
    /// HNS: house number suffix.
    house_number_suffix: Option<String>,
    /// LMK: landmark.
    landmark: Option<String>,
    /// LOC: additional location information.
    additional: Option<String>,
    /// FLR: floor.
    floor: Option<String>,
    /// NAM: name of the place.
    name: Option<String>,
    /// PC: postal code.
    postal_code: Option<String>,
    /// BLD: building.
    building: Option<String>,
    /// UNIT: unit.
    unit: Option<String>,
    /// ROOM: room.
    room: Option<String>,
    /// SEAT: seat.
    seat: Option<String>,
    /// PLC: place type.
    place_type: Option<String>,
    /// PCN: postal community name.
    postal_community: Option<String>,
    /// POBOX: post office box.
    post_office_box: Option<String>,
    /// ADDCODE: additional code.
    additional_code: Option<String>,
}

impl CivicAddress {
    /// An empty address: nothing is rendered until a field is set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a textual field, normalising it the way `xs:token` requires.
    ///
    /// `xs:token` collapses runs of whitespace and trims the ends, so a value
    /// that is only whitespace becomes absent rather than an empty element.
    fn set(slot: &mut Option<String>, value: impl Into<String>) {
        let value = value.into();
        let normalised = value.split_whitespace().collect::<Vec<_>>().join(" ");
        *slot = if normalised.is_empty() {
            None
        } else {
            Some(normalised)
        };
    }

    /// The language of the address fields (`xml:lang`, RFC 5139 §3.1).
    pub fn language(mut self, language: impl Into<String>) -> Self {
        Self::set(&mut self.language, language);
        self
    }

    /// The ISO 3166-1 alpha-2 country code.
    ///
    /// Returns an error for anything that is not two uppercase ASCII letters,
    /// which is what the RFC 5139 schema allows (`[A-Z]{2}`).
    pub fn country(mut self, country: impl Into<String>) -> Result<Self, EmergencyError> {
        let country = country.into().trim().to_string();
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(EmergencyError::BadCountry(country));
        }
        self.country = Some(country);
        Ok(self)
    }

    /// Set administrative area `n` (1..=6), most general first.
    ///
    /// `n` is the digit of the `A<n>` element: `A1` is usually a state or
    /// province, `A3` a city, `A4` a district.
    pub fn area(mut self, n: usize, value: impl Into<String>) -> Self {
        if (1..=6).contains(&n) {
            Self::set(&mut self.a[n - 1], value);
        }
        self
    }

    /// `PRM`, the pre-modifier.
    pub fn pre_modifier(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.pre_modifier, value);
        self
    }

    /// `PRD`, the leading street direction.
    pub fn pre_direction(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.pre_direction, value);
        self
    }

    /// `RD`, the road or street name.
    pub fn road(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.road, value);
        self
    }

    /// `STS`, the street suffix.
    pub fn street_suffix(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.street_suffix, value);
        self
    }

    /// `POD`, the trailing street suffix.
    pub fn post_direction(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.post_direction, value);
        self
    }

    /// `POM`, the post-modifier.
    pub fn post_modifier(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.post_modifier, value);
        self
    }

    /// `HNO`, the house number.
    pub fn house_number(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.house_number, value);
        self
    }

    /// `HNS`, the house number suffix.
    pub fn house_number_suffix(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.house_number_suffix, value);
        self
    }

    /// `LMK`, a landmark.
    pub fn landmark(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.landmark, value);
        self
    }

    /// `LOC`, additional location information.
    pub fn additional(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.additional, value);
        self
    }

    /// `FLR`, the floor.
    pub fn floor(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.floor, value);
        self
    }

    /// `NAM`, the name of the place.
    pub fn name(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.name, value);
        self
    }

    /// `PC`, the postal code.
    pub fn postal_code(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.postal_code, value);
        self
    }

    /// `BLD`, the building.
    pub fn building(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.building, value);
        self
    }

    /// `UNIT`, the unit.
    pub fn unit(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.unit, value);
        self
    }

    /// `ROOM`, the room.
    pub fn room(mut self, value: impl Into<String>) -> Self {
        Self::set(&mut self.room, value);
        self
    }

    /// Whether the address carries anything at all.
    ///
    /// An address with no fields is not worth sending: it would assert that the
    /// UE knows where it is while saying nothing.
    pub fn is_empty(&self) -> bool {
        let filled = |s: &Option<String>| s.is_some();
        self.country.is_none()
            && !self.a.iter().any(filled)
            && ![
                &self.pre_modifier,
                &self.pre_direction,
                &self.road,
                &self.street_suffix,
                &self.post_direction,
                &self.post_modifier,
                &self.road_section,
                &self.road_branch,
                &self.road_sub_branch,
                &self.house_number,
                &self.house_number_suffix,
                &self.landmark,
                &self.additional,
                &self.floor,
                &self.name,
                &self.postal_code,
                &self.building,
                &self.unit,
                &self.room,
                &self.seat,
                &self.place_type,
                &self.postal_community,
                &self.post_office_box,
                &self.additional_code,
            ]
            .iter()
            .any(|slot| filled(slot))
    }

    /// The `civicAddress` element, in RFC 5139 schema order.
    fn to_xml(&self) -> String {
        let mut out = String::from("<cac:civicAddress");
        if let Some(lang) = &self.language {
            out.push_str(&format!(" xml:lang=\"{}\"", xml_escape(lang)));
        }
        out.push_str(">\n");

        let element = |out: &mut String, name: &str, value: &Option<String>| {
            if let Some(value) = value {
                out.push_str(&format!(
                    "          <cac:{name}>{}</cac:{name}>\n",
                    xml_escape(value)
                ));
            }
        };

        element(&mut out, "country", &self.country);
        for (i, value) in self.a.iter().enumerate() {
            element(&mut out, &format!("A{}", i + 1), value);
        }
        element(&mut out, "PRM", &self.pre_modifier);
        element(&mut out, "PRD", &self.pre_direction);
        element(&mut out, "RD", &self.road);
        element(&mut out, "STS", &self.street_suffix);
        element(&mut out, "POD", &self.post_direction);
        element(&mut out, "POM", &self.post_modifier);
        element(&mut out, "RDSEC", &self.road_section);
        element(&mut out, "RDBR", &self.road_branch);
        element(&mut out, "RDSUBBR", &self.road_sub_branch);
        element(&mut out, "HNO", &self.house_number);
        element(&mut out, "HNS", &self.house_number_suffix);
        element(&mut out, "LMK", &self.landmark);
        element(&mut out, "LOC", &self.additional);
        element(&mut out, "FLR", &self.floor);
        element(&mut out, "NAM", &self.name);
        element(&mut out, "PC", &self.postal_code);
        element(&mut out, "BLD", &self.building);
        element(&mut out, "UNIT", &self.unit);
        element(&mut out, "ROOM", &self.room);
        element(&mut out, "SEAT", &self.seat);
        element(&mut out, "PLC", &self.place_type);
        element(&mut out, "PCN", &self.postal_community);
        element(&mut out, "POBOX", &self.post_office_box);
        element(&mut out, "ADDCODE", &self.additional_code);

        out.push_str("        </cac:civicAddress>\n");
        out
    }
}

/// A location the UE can convey: either a point or a civic address.
///
/// TS 24.229 does not care which — the `Geolocation` header points at the body
/// part either way. Which one the UE has depends on the access network: GNSS gives a point, and a user-entered address (or the
/// carrier's registered E911 address) gives a civic address.
#[derive(Debug, Clone, PartialEq)]
pub enum Location {
    /// A WGS-84 point (RFC 5491 §2.1).
    Geodetic(Geolocation),
    /// A civic address (RFC 5139). Boxed because a civic address carries
    /// 26 optional strings and a point carries three numbers.
    Civic(Box<CivicAddress>),
}

impl Location {
    /// A geodetic location.
    pub fn geodetic(location: Geolocation) -> Self {
        Location::Geodetic(location)
    }

    /// A civic address.
    pub fn civic(address: CivicAddress) -> Self {
        Location::Civic(Box::new(address))
    }

    /// Render the PIDF document for this location.
    pub fn to_pidf(&self, entity: &str) -> String {
        match self {
            Location::Geodetic(g) => g.to_pidf_lo(entity),
            Location::Civic(c) => civic_pidf(c, entity),
        }
    }
}

/// Render a PIDF-LO carrying a civic address (RFC 4119 + RFC 5139).
pub fn civic_pidf(address: &CivicAddress, entity: &str) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"",
            " xmlns:gp=\"urn:ietf:params:xml:ns:pidf:geopriv10\"",
            " xmlns:cac=\"{ns}\"",
            " entity=\"{entity}\">\n",
            "  <tuple id=\"loc1\">\n",
            "    <status>\n",
            "      <gp:geopriv>\n",
            "        <gp:location-info>\n",
            "{address}",
            "        </gp:location-info>\n",
            "        <gp:usage-rules/>\n",
            "      </gp:geopriv>\n",
            "    </status>\n",
            "  </tuple>\n",
            "</presence>\n"
        ),
        ns = CIVIC_NS,
        entity = xml_escape(entity),
        address = address.to_xml(),
    )
}
/// [`location_publish`], taking the fix from a [`crate::location::LocationSource`].
pub fn location_publish_from(
    dialog: &mut crate::Dialog,
    entity: &str,
    source: &mut impl crate::location::LocationSource,
) -> sip::Request {
    location_publish(dialog, entity, source.current())
}

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
    /// An ISO 3166-1 country code was not two uppercase letters.
    BadCountry(String),
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
            EmergencyError::BadCountry(c) => {
                write!(f, "country {c:?} is not a two-letter ISO 3166-1 code")
            }
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
            entity = xml_escape(entity),
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
    location: Option<Location>,
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
            location: None,
            pani: None,
            current_location_discovery: false,
            anonymous_instance: None,
            service_route: Vec::new(),
            offer_sdp: None,
        }
    }

    /// Attach the UE's location (RFC 4119 PIDF-LO body).
    pub fn with_geolocation(mut self, location: Geolocation) -> Self {
        self.location = Some(Location::Geodetic(location));
        self
    }

    /// Attach a civic address instead of a point (RFC 5139).
    ///
    /// This is the case that matters on Wi-Fi calling: a user knows their
    /// address, and there is often no GNSS fix indoors at all.
    pub fn with_civic_address(mut self, address: CivicAddress) -> Self {
        self.location = if address.is_empty() {
            None
        } else {
            Some(Location::civic(address))
        };
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

    /// Attach whatever fix the source can offer, if any.
    ///
    /// A source with no usable fix leaves the request without a `Geolocation`
    /// header, which is what §5.1.6.8.3 item 9 asks for — an absent location
    /// is a valid answer, an invented one is not.
    pub fn with_location_source(
        mut self,
        source: &mut impl crate::location::LocationSource,
    ) -> Self {
        self.location = source.current();
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
            .location
            .as_ref()
            .map(|l| l.to_pidf(self.identity.uri()).into_bytes());
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

    fn location_info(body: &str) -> sip::Request {
        let mut headers = Headers::new();
        headers.push(Header::new("Via", "SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-x"));
        headers.push(Header::new("From", "<sip:psap@ims.example>;tag=a"));
        headers.push(Header::new("To", "<sip:001010000000001@ims.example>;tag=b"));
        headers.push(Header::new("Call-ID", "c"));
        headers.push(Header::new("CSeq", "2 INFO"));
        headers.push(Header::new("Info-Package", CURRENT_LOCATION_INFO_PACKAGE));
        headers.push(Header::new("Content-Type", CURRENT_LOCATION_MIME));
        sip::Request {
            method: Method::Info,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    const ONE_SHOT: &str = r#"<?xml version="1.0"?>
<requestForLocationInformation><oneShot/></requestForLocationInformation>"#;

    #[test]
    fn a_current_location_info_request_is_recognised() {
        assert_eq!(
            parse_location_request(&location_info(ONE_SHOT)),
            Some(LocationRequest { one_shot: true })
        );
    }

    #[test]
    fn a_lookalike_request_is_not() {
        // Wrong method.
        let mut req = location_info(ONE_SHOT);
        req.method = Method::Message;
        assert_eq!(parse_location_request(&req), None);

        // Wrong info package.
        let mut req = location_info(ONE_SHOT);
        req.headers.set("Info-Package", "g.3gpp.app_ref");
        assert_eq!(parse_location_request(&req), None);

        // Wrong body type.
        let mut req = location_info(ONE_SHOT);
        req.headers.set("Content-Type", "application/sdp");
        assert_eq!(parse_location_request(&req), None);

        // Right headers, body that is not the document.
        let mut req = location_info("<something-else/>");
        req.headers.set("Content-Type", CURRENT_LOCATION_MIME);
        assert_eq!(parse_location_request(&req), None);
    }

    fn emergency_dialog() -> crate::Dialog {
        let mut d = crate::Dialog::new(
            "call-1",
            "sip:001010000000001@ims.example",
            "sip:psap@ims.example",
            "local-tag",
            "remote-tag",
            "sip:001010000000001@192.0.2.10:5060",
        );
        d.confirm();
        d
    }

    #[test]
    fn the_location_publish_is_an_in_dialog_presence_publish() {
        let mut dialog = emergency_dialog();
        let before = dialog.cseq;
        let request = location_publish(
            &mut dialog,
            "sip:001010000000001@ims.example",
            Some(Location::Geodetic(Geolocation::new(51.5, -0.12).unwrap())),
        );
        assert_eq!(request.method, Method::Publish);
        assert_eq!(dialog.cseq, before + 1);
        // RFC 3903 §4: PUBLISH needs an Event header; this is a presence
        // publication (RFC 3856).
        assert_eq!(request.headers.get("event"), Some(LOCATION_EVENT_PACKAGE));
        assert_eq!(
            request.headers.get("content-type"),
            Some("application/pidf+xml")
        );
        // In-dialog: both tags, the caller's Call-ID.
        assert!(request
            .headers
            .get("from")
            .unwrap()
            .contains("tag=local-tag"));
        assert!(request
            .headers
            .get("to")
            .unwrap()
            .contains("tag=remote-tag"));
        assert_eq!(request.headers.get("call-id"), Some("call-1"));
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(body.contains("<gml:pos>51.500000 -0.120000</gml:pos>"));
        assert_eq!(
            request.headers.get("content-length"),
            Some(request.body.len().to_string().as_str())
        );
    }

    #[test]
    fn no_location_still_publishes_but_carries_no_location_object() {
        let mut dialog = emergency_dialog();
        let request = location_publish(&mut dialog, "sip:001010000000001@ims.example", None);
        let body = String::from_utf8(request.body).unwrap();
        // §5.1.6.12.3 NOTE: a PIDF body with no location object.
        assert!(body.contains("<presence"));
        assert!(!body.contains("location-info"));
        assert!(!body.contains("<gml:pos>"));
    }
}

#[cfg(test)]
mod location_source_tests {
    use super::*;
    use crate::location::FixedLocation;

    #[test]
    fn a_source_with_no_fix_leaves_the_request_without_a_geolocation_header() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let mut source = FixedLocation::unavailable();
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_location_source(&mut source)
            .invite()
            .unwrap();
        assert_eq!(req.headers.get("geolocation"), None);
        assert_eq!(req.headers.get("geolocation-routing"), None);
    }

    #[test]
    fn a_source_with_a_fix_supplies_the_geolocation_header() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let mut source = FixedLocation::at(Geolocation::new(51.5, -0.12).unwrap());
        let req = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_location_source(&mut source)
            .invite()
            .unwrap();
        assert_eq!(
            req.headers.get("geolocation"),
            Some("<cid:emergency-location@192.0.2.10>")
        );
        assert_eq!(req.headers.get("geolocation-routing"), Some("yes"));
    }

    #[test]
    fn the_publish_helper_takes_the_same_source() {
        let mut dialog = crate::Dialog::new(
            "call-1",
            "sip:001010000000001@ims.example",
            "sip:psap@ims.example",
            "b",
            "a",
            "sip:001010000000001@192.0.2.10:5060",
        );
        dialog.confirm();
        let mut source = FixedLocation::unavailable();
        let publish =
            location_publish_from(&mut dialog, "sip:001010000000001@ims.example", &mut source);
        let body = String::from_utf8(publish.body).unwrap();
        assert!(body.contains("<presence"));
        assert!(!body.contains("location-info"));
    }
}

#[cfg(test)]
mod civic_tests {
    use super::*;

    fn address() -> CivicAddress {
        CivicAddress::new()
            .language("en-US")
            .country("US")
            .unwrap()
            .area(1, "CA")
            .area(3, "San Francisco")
            .road("Market Street")
            .house_number("123")
            .postal_code("94103")
    }

    #[test]
    fn a_civic_address_renders_in_schema_order() {
        let xml = civic_pidf(&address(), "sip:alice@example.net");
        // RFC 4119 envelope with the RFC 5139 namespace bound as `cac`.
        assert!(xml.contains(&format!("xmlns:cac=\"{CIVIC_NS}\"")));
        assert!(xml.contains("<cac:civicAddress xml:lang=\"en-US\">"));
        // RFC 5139 §2 is an xs:sequence: country, A1, A3, RD, HNO, PC.
        let order = [
            "<cac:country>US</cac:country>",
            "<cac:A1>CA</cac:A1>",
            "<cac:A3>San Francisco</cac:A3>",
            "<cac:RD>Market Street</cac:RD>",
            "<cac:HNO>123</cac:HNO>",
            "<cac:PC>94103</cac:PC>",
        ];
        let mut at = 0;
        for fragment in order {
            let found = xml[at..]
                .find(fragment)
                .unwrap_or_else(|| panic!("missing or out of order: {fragment}"));
            at += found + fragment.len();
        }
    }

    #[test]
    fn unset_fields_are_omitted_not_emitted_empty() {
        let xml = civic_pidf(&address(), "sip:alice@example.net");
        assert!(!xml.contains("<cac:A2>"));
        assert!(!xml.contains("<cac:LMK>"));
        assert!(!xml.contains("<cac:BLD>"));
    }

    #[test]
    fn text_is_xml_escaped_in_elements_and_attributes() {
        let address = CivicAddress::new()
            .country("US")
            .unwrap()
            .road("A & B <script>")
            .additional("\"quoted\" 'single'");
        let xml = civic_pidf(&address, "sip:alice&bob@example.net");
        // The street name cannot break out of its element...
        assert!(xml.contains("<cac:RD>A &amp; B &lt;script&gt;</cac:RD>"));
        assert!(xml.contains("<cac:LOC>&quot;quoted&quot; &apos;single&apos;</cac:LOC>"));
        // ...and an entity with `&` cannot break the attribute.
        assert!(xml.contains("entity=\"sip:alice&amp;bob@example.net\""));
        assert!(!xml.contains("<script>"));
    }

    #[test]
    fn a_whitespace_only_field_is_absent() {
        let address = CivicAddress::new().country("US").unwrap().road("   ");
        assert!(!address.is_empty());
        let xml = civic_pidf(&address, "sip:a@example.net");
        assert!(!xml.contains("<cac:RD>"));
    }

    #[test]
    fn whitespace_is_collapsed_like_an_xs_token() {
        let address = CivicAddress::new()
            .country("US")
            .unwrap()
            .road("  123   Main   Street ");
        let xml = civic_pidf(&address, "sip:a@example.net");
        assert!(xml.contains("<cac:RD>123 Main Street</cac:RD>"));
    }

    #[test]
    fn a_country_code_must_be_two_uppercase_letters() {
        assert_eq!(
            CivicAddress::new().country("us").unwrap_err(),
            EmergencyError::BadCountry("us".into())
        );
        assert!(CivicAddress::new().country("USA").is_err());
        assert!(CivicAddress::new().country("").is_err());
    }

    #[test]
    fn an_empty_address_is_not_sent_at_all() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let request = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_civic_address(CivicAddress::new())
            .invite()
            .unwrap();
        // Nothing to say means no Geolocation header (item 9), not an empty one.
        assert_eq!(request.headers.get("geolocation"), None);
        assert!(request.body.is_empty());
    }

    #[test]
    fn a_civic_address_travels_in_the_location_body_part() {
        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let request = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_civic_address(address())
            .with_offer_sdp("v=0\r\n")
            .invite()
            .unwrap();
        assert_eq!(
            request.headers.get("content-type"),
            Some("multipart/mixed; boundary=fungos-emergency")
        );
        assert_eq!(
            request.headers.get("geolocation"),
            Some("<cid:emergency-location@192.0.2.10>")
        );
        let body = String::from_utf8(request.body).unwrap();
        assert!(body.contains("Content-ID: <emergency-location@192.0.2.10>"));
        assert!(body.contains("<cac:civicAddress"));
        assert!(body.contains("<cac:PC>94103</cac:PC>"));
        assert!(body.contains("v=0"));
    }

    #[test]
    fn a_civic_source_supplies_the_location() {
        use crate::location::{FixedLocation, LocationSource};
        let mut source = FixedLocation::civic(address());
        assert_eq!(source.current(), Some(Location::civic(address())));

        let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
        let request = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
            .with_location_source(&mut source)
            .invite()
            .unwrap();
        assert_eq!(
            request.headers.get("geolocation"),
            Some("<cid:emergency-location@192.0.2.10>")
        );
        assert!(String::from_utf8(request.body)
            .unwrap()
            .contains("<cac:civicAddress"));
    }

    #[test]
    fn the_mid_call_publish_can_carry_a_civic_address() {
        let mut dialog = crate::Dialog::new(
            "call-1",
            "sip:001010000000001@ims.example",
            "sip:psap@ims.example",
            "b",
            "a",
            "sip:001010000000001@192.0.2.10:5060",
        );
        dialog.confirm();
        let publish = location_publish(
            &mut dialog,
            "sip:001010000000001@ims.example",
            Some(Location::civic(address())),
        );
        let body = String::from_utf8(publish.body).unwrap();
        assert!(body.contains("<cac:civicAddress"));
        assert!(body.contains("<cac:HNO>123</cac:HNO>"));
    }
}
