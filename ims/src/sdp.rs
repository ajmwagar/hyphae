//! SDP (RFC 4566) parsing, serialisation and MTSI audio offer/answer.
//!
//! Codec *names* appear here because SDP negotiates them; no codec is
//! implemented in this crate. The AMR-WB payload format itself is RFC 4867 and
//! lives in the `codec-amr` crate.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub session_id: String,
    pub session_version: String,
    pub net_type: String,
    pub addr_type: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub net_type: String,
    pub addr_type: String,
    pub address: String,
}

impl Connection {
    pub fn ip4(address: impl Into<String>) -> Self {
        Self {
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: address.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: String,
    pub value: Option<String>,
}

impl Attribute {
    pub fn new(name: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            value: value.map(Into::into),
        }
    }
}

/// RFC 4566 §6 / RFC 3264 §6.1 media direction. Absent means `sendrecv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    /// The answer direction for an offer (RFC 3264 §6.1), used for hold: an
    /// offer of `sendonly` is answered `recvonly`, and `inactive` stays
    /// `inactive`.
    pub fn answer_to(offer: Direction) -> Self {
        match offer {
            Direction::SendRecv => Direction::SendRecv,
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::Inactive => Direction::Inactive,
        }
    }
}

impl Media {
    /// The `a=sendrecv`/`a=sendonly`/`a=recvonly`/`a=inactive` direction.
    ///
    /// Direction attributes are flags (no value), so this tests presence rather
    /// than `attribute()` (which returns the value and is `None` for a flag).
    pub fn direction(&self) -> Direction {
        let has = |name: &str| {
            self.attributes
                .iter()
                .any(|a| a.name.eq_ignore_ascii_case(name))
        };
        if has("sendonly") {
            Direction::SendOnly
        } else if has("recvonly") {
            Direction::RecvOnly
        } else if has("inactive") {
            Direction::Inactive
        } else {
            Direction::SendRecv
        }
    }

    /// Replace the direction attribute, keeping only one of the four.
    pub fn set_direction(&mut self, direction: Direction) {
        self.attributes.retain(|a| {
            !matches!(
                a.name.as_str(),
                "sendrecv" | "sendonly" | "recvonly" | "inactive"
            )
        });
        self.attributes
            .push(Attribute::new(direction.as_str(), None::<String>));
    }
}

impl Sdp {
    /// Set the direction on every media line (used for hold/resume offers).
    pub fn set_direction(&mut self, direction: Direction) {
        for media in &mut self.media {
            media.set_direction(direction);
        }
    }

    /// The direction of the first audio media line.
    pub fn direction(&self) -> Direction {
        self.audio()
            .map(Media::direction)
            .unwrap_or(Direction::SendRecv)
    }
}

/// RFC 3312 precondition direction value (`send`, `recv`, `sendrecv`, `none`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecondDir {
    Send,
    Recv,
    SendRecv,
    None,
}

impl PrecondDir {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "send" => Some(Self::Send),
            "recv" => Some(Self::Recv),
            "sendrecv" => Some(Self::SendRecv),
            "none" => Some(Self::None),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
            Self::SendRecv => "sendrecv",
            Self::None => "none",
        }
    }
}

/// RFC 3312 media preconditions for a single `m=` line, as used by IMS session
/// preconditions (TS 24.229 §5.1.3). `status` reflects the local readiness;
/// `confirmed` is set once the remote side has acknowledged its media is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Precondition {
    /// `a=createmedia`: media direction to establish before the answer is sent.
    pub createmedia: Option<PrecondDir>,
    /// `a=status`: local precondition status.
    pub status: Option<PrecondDir>,
    /// `a=confirmed`: the remote has confirmed its media resources.
    pub confirmed: Option<PrecondDir>,
}

impl Precondition {
    /// Whether local media resources are ready: `status` is `sendrecv`.
    pub fn met(&self) -> bool {
        matches!(self.status, Some(PrecondDir::SendRecv))
    }
    fn from_media(m: &Media) -> Self {
        Self {
            createmedia: m.attribute("createmedia").and_then(PrecondDir::parse),
            status: m.attribute("status").and_then(PrecondDir::parse),
            confirmed: m.attribute("confirmed").and_then(PrecondDir::parse),
        }
    }
    /// Append the populated attributes to a media line, skipping any the media
    /// already carries.
    fn push_to(&self, m: &mut Media) {
        for (attr, dir) in [
            ("createmedia", self.createmedia),
            ("status", self.status),
            ("confirmed", self.confirmed),
        ] {
            if let Some(d) = dir {
                if m.attribute(attr).is_some() {
                    continue;
                }
                m.attributes.push(Attribute::new(attr, Some(d.as_str())));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Media {
    pub kind: String,
    pub port: u16,
    pub protocol: String,
    pub formats: Vec<String>,
    pub connection: Option<Connection>,
    pub bandwidths: Vec<(String, String)>,
    pub attributes: Vec<Attribute>,
    pub other: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rtpmap<'a> {
    pub payload: u8,
    pub encoding: &'a str,
    pub clock_rate: u32,
    pub channels: Option<u8>,
}

impl Media {
    pub fn is_audio(&self) -> bool {
        self.kind.eq_ignore_ascii_case("audio")
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
            .and_then(|a| a.value.as_deref())
    }

    pub fn attribute_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.attributes
            .iter()
            .filter(move |a| a.name.eq_ignore_ascii_case(name))
            .filter_map(|a| a.value.as_deref())
    }

    pub fn rtpmap(&self, payload: u8) -> Option<Rtpmap<'_>> {
        let prefix = format!("{payload} ");
        self.attribute_values("rtpmap").find_map(|v| {
            let rest = v.strip_prefix(&prefix)?;
            let mut parts = rest.split('/');
            let encoding = parts.next()?;
            let clock_rate = parts.next()?.parse().ok()?;
            let channels = parts.next().and_then(|c| c.parse().ok());
            Some(Rtpmap {
                payload,
                encoding,
                clock_rate,
                channels,
            })
        })
    }

    /// Payload type whose rtpmap matches an encoding name and clock rate.
    pub fn payload_type(&self, encoding: &str, clock_rate: u32) -> Option<u8> {
        self.formats
            .iter()
            .filter_map(|f| f.parse::<u8>().ok())
            .find(|p| {
                self.rtpmap(*p)
                    .map(|r| {
                        r.encoding.eq_ignore_ascii_case(encoding) && r.clock_rate == clock_rate
                    })
                    .unwrap_or(false)
            })
    }

    pub fn fmtp(&self, payload: u8) -> Option<&str> {
        let prefix = format!("{payload} ");
        self.attribute_values("fmtp")
            .find_map(|v| v.strip_prefix(&prefix))
    }

    /// RFC 3312 media preconditions carried on this `m=` line, if any.
    pub fn precondition(&self) -> Option<Precondition> {
        let has = ["createmedia", "status", "confirmed"]
            .iter()
            .any(|a| self.attribute(a).is_some());
        if has {
            Some(Precondition::from_media(self))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    pub origin: Origin,
    pub session_name: String,
    pub timing: (String, String),
    pub connection: Option<Connection>,
    pub bandwidths: Vec<(String, String)>,
    pub attributes: Vec<Attribute>,
    pub media: Vec<Media>,
    pub other: Vec<String>,
}

impl Sdp {
    pub fn parse(input: &str) -> Result<Self, SdpError> {
        let mut version = None;
        let mut origin = None;
        let mut session_name = None;
        let mut timing = None;
        let mut connection = None;
        let mut bandwidths = Vec::new();
        let mut attributes = Vec::new();
        let mut media: Vec<Media> = Vec::new();
        let mut other = Vec::new();

        for (lineno, raw) in input.lines().enumerate() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if line.len() < 2 || line.as_bytes()[1] != b'=' {
                return Err(SdpError::Invalid {
                    line: lineno + 1,
                    detail: format!("not key=value: {line:?}"),
                });
            }
            let key = line.as_bytes()[0] as char;
            let value = &line[2..];
            match key {
                'v' => version = Some(value.to_string()),
                'o' => origin = Some(parse_origin(value, lineno + 1)?),
                's' => session_name = Some(value.to_string()),
                't' => {
                    let mut p = value.split_whitespace();
                    let start = p.next().unwrap_or("0").to_string();
                    let stop = p.next().unwrap_or("0").to_string();
                    timing = Some((start, stop));
                }
                'c' => {
                    let c = parse_connection(value, lineno + 1)?;
                    match media.last_mut() {
                        Some(m) => m.connection = Some(c),
                        None => connection = Some(c),
                    }
                }
                'b' => {
                    let (kind, bw) = value.split_once(':').ok_or_else(|| SdpError::Invalid {
                        line: lineno + 1,
                        detail: "bandwidth needs type:value".into(),
                    })?;
                    if let Some(m) = media.last_mut() {
                        m.bandwidths.push((kind.to_string(), bw.to_string()));
                    } else {
                        bandwidths.push((kind.to_string(), bw.to_string()));
                    }
                }
                'a' => {
                    let attr = parse_attribute(value);
                    if let Some(m) = media.last_mut() {
                        m.attributes.push(attr);
                    } else {
                        attributes.push(attr);
                    }
                }
                'm' => media.push(parse_media(value, lineno + 1)?),
                _ => {
                    if let Some(m) = media.last_mut() {
                        m.other.push(line.to_string());
                    } else {
                        other.push(line.to_string());
                    }
                }
            }
        }

        if version.as_deref() != Some("0") {
            return Err(SdpError::Missing("v=0"));
        }
        Ok(Self {
            origin: origin.ok_or(SdpError::Missing("o="))?,
            session_name: session_name.ok_or(SdpError::Missing("s="))?,
            timing: timing.ok_or(SdpError::Missing("t="))?,
            connection,
            bandwidths,
            attributes,
            media,
            other,
        })
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("v=0\r\n");
        out.push_str(&format!(
            "o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.net_type,
            self.origin.addr_type,
            self.origin.address
        ));
        out.push_str(&format!("s={}\r\n", self.session_name));
        out.push_str(&format!("t={} {}\r\n", self.timing.0, self.timing.1));
        if let Some(c) = &self.connection {
            out.push_str(&format!(
                "c={} {} {}\r\n",
                c.net_type, c.addr_type, c.address
            ));
        }
        for (k, v) in &self.bandwidths {
            out.push_str(&format!("b={k}:{v}\r\n"));
        }
        for a in &self.attributes {
            out.push_str(&format_attr(a));
            out.push_str("\r\n");
        }
        for line in &self.other {
            out.push_str(line);
            out.push_str("\r\n");
        }
        for m in &self.media {
            out.push_str(&format!(
                "m={} {} {} {}\r\n",
                m.kind,
                m.port,
                m.protocol,
                m.formats.join(" ")
            ));
            if let Some(c) = &m.connection {
                out.push_str(&format!(
                    "c={} {} {}\r\n",
                    c.net_type, c.addr_type, c.address
                ));
            }
            for (k, v) in &m.bandwidths {
                out.push_str(&format!("b={k}:{v}\r\n"));
            }
            for a in &m.attributes {
                out.push_str(&format_attr(a));
                out.push_str("\r\n");
            }
            for line in &m.other {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
        out
    }

    pub fn audio(&self) -> Option<&Media> {
        self.media.iter().find(|m| m.is_audio())
    }

    pub fn audio_mut(&mut self) -> Option<&mut Media> {
        self.media.iter_mut().find(|m| m.is_audio())
    }

    /// Build a lab MTSI offer carrying AMR-WB (payload 116) and optionally
    /// telephone-event. This is negotiation data only; no AMR-WB code exists in
    /// this tree.
    pub fn amr_wb_offer(modes: &[u8], telephone_event: bool, address: &str) -> Self {
        let mut media = Media {
            kind: "audio".into(),
            port: 49170,
            protocol: "RTP/AVP".into(),
            formats: if telephone_event {
                vec!["116".into(), "101".into()]
            } else {
                vec!["116".into()]
            },
            connection: Some(Connection::ip4(address)),
            bandwidths: Vec::new(),
            attributes: vec![
                Attribute::new("rtpmap", Some("116 AMR-WB/16000/1")),
                Attribute::new(
                    "fmtp",
                    Some(format!(
                        "116 octet-align=1;mode-set={};mode-change-capability=2;max-red=0",
                        modes
                            .iter()
                            .map(|m| m.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    )),
                ),
                Attribute::new("rtpmap", Some("101 telephone-event/16000")),
                Attribute::new("fmtp", Some("101 0-15")),
                Attribute::new("ptime", Some("20")),
                Attribute::new("maxptime", Some("240")),
                Attribute::new("sendrecv", None::<String>),
            ],
            other: Vec::new(),
        };
        if !telephone_event {
            media.attributes.retain(|a| {
                !a.value
                    .as_deref()
                    .map(|v| v.starts_with("101 "))
                    .unwrap_or(false)
            });
        }
        Self {
            origin: Origin {
                username: "-".into(),
                session_id: "0".into(),
                session_version: "0".into(),
                net_type: "IN".into(),
                addr_type: "IP4".into(),
                address: address.into(),
            },
            session_name: "-".into(),
            timing: ("0".into(), "0".into()),
            connection: Some(Connection::ip4(address)),
            bandwidths: Vec::new(),
            attributes: Vec::new(),
            media: vec![media],
            other: Vec::new(),
        }
    }

    /// Answer an AMR-WB offer with the offered payload and mode-set.
    pub fn answer_amr_wb(offer: &Sdp, local_address: &str) -> Result<Sdp, SdpError> {
        let media = offer.audio().ok_or(SdpError::Missing("audio m="))?;
        // RFC 3312: carry the offer's media preconditions into the answer.
        let precond = media.precondition();
        let payload = media
            .payload_type("AMR-WB", 16_000)
            .ok_or(SdpError::Missing("AMR-WB payload"))?;
        let rtpmap = media
            .rtpmap(payload)
            .ok_or(SdpError::Missing("AMR-WB rtpmap"))?;
        let fmtp = media.fmtp(payload).unwrap_or("octet-align=1");
        let mut attributes = vec![
            Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}/{}",
                    payload,
                    rtpmap.encoding,
                    rtpmap.clock_rate,
                    rtpmap.channels.unwrap_or(1)
                )),
            ),
            Attribute::new("fmtp", Some(format!("{payload} {fmtp}"))),
            Attribute::new("ptime", Some("20")),
            // RFC 3264 §6.1: the answer mirrors the offered direction, so a
            // remote hold (sendonly) is answered recvonly.
            Attribute::new(
                Direction::answer_to(media.direction()).as_str(),
                None::<String>,
            ),
        ];
        // Echo telephone-event if offered; it is harmless and expected by MTSI.
        if let Some(evt) = media.payload_type("telephone-event", 16_000) {
            if let Some(r) = media.rtpmap(evt) {
                attributes.push(Attribute::new(
                    "rtpmap",
                    Some(format!(
                        "{} {}/{}/{}",
                        evt,
                        r.encoding,
                        r.clock_rate,
                        r.channels.unwrap_or(1)
                    )),
                ));
                if let Some(f) = media.fmtp(evt) {
                    attributes.push(Attribute::new("fmtp", Some(format!("{evt} {f}"))));
                }
            }
        }
        let mut formats = vec![payload.to_string()];
        if let Some(evt) = media.payload_type("telephone-event", 16_000) {
            formats.push(evt.to_string());
        }
        Ok(Sdp {
            origin: Origin {
                username: "-".into(),
                session_id: "0".into(),
                session_version: "1".into(),
                net_type: "IN".into(),
                addr_type: "IP4".into(),
                address: local_address.into(),
            },
            session_name: "-".into(),
            timing: ("0".into(), "0".into()),
            connection: Some(Connection::ip4(local_address)),
            bandwidths: Vec::new(),
            attributes: Vec::new(),
            media: vec![{
                let mut answer_media = Media {
                    kind: "audio".into(),
                    port: 49_172,
                    protocol: "RTP/AVP".into(),
                    formats,
                    connection: Some(Connection::ip4(local_address)),
                    bandwidths: Vec::new(),
                    attributes,
                    other: Vec::new(),
                };
                if let Some(p) = precond {
                    p.push_to(&mut answer_media);
                }
                answer_media
            }],
            other: Vec::new(),
        })
    }

    /// Add RFC 3312 media preconditions (`sendrecv`) to every media line.
    ///
    /// The UE sends this in the early INVITE; once the local bearers are up it
    /// flips `status` to `sendrecv` and, after the peer acknowledges, sets
    /// `confirmed`. This is negotiation state only — no bearers are touched.
    pub fn add_preconditions(&mut self) {
        let p = Precondition {
            createmedia: Some(PrecondDir::SendRecv),
            status: Some(PrecondDir::SendRecv),
            confirmed: Some(PrecondDir::SendRecv),
        };
        for m in &mut self.media {
            p.push_to(m);
        }
    }

    /// Mark the media preconditions confirmed (`a=confirmed:sendrecv`) after the
    /// peer has acknowledged its resources. Returns the number of lines updated.
    pub fn confirm_preconditions(&mut self) -> usize {
        let mut n = 0;
        for m in &mut self.media {
            if m.attribute("confirmed").is_some() {
                m.attributes
                    .retain(|a| !a.name.eq_ignore_ascii_case("confirmed"));
                m.attributes.push(Attribute::new(
                    "confirmed",
                    Some(PrecondDir::SendRecv.as_str()),
                ));
                n += 1;
            }
        }
        n
    }
}

fn parse_origin(v: &str, line: usize) -> Result<Origin, SdpError> {
    let p: Vec<&str> = v.split_whitespace().collect();
    if p.len() != 6 {
        return Err(SdpError::Invalid {
            line,
            detail: "o= needs 6 fields".into(),
        });
    }
    Ok(Origin {
        username: p[0].into(),
        session_id: p[1].into(),
        session_version: p[2].into(),
        net_type: p[3].into(),
        addr_type: p[4].into(),
        address: p[5].into(),
    })
}

fn parse_connection(v: &str, line: usize) -> Result<Connection, SdpError> {
    let p: Vec<&str> = v.split_whitespace().collect();
    if p.len() != 3 {
        return Err(SdpError::Invalid {
            line,
            detail: "c= needs 3 fields".into(),
        });
    }
    Ok(Connection {
        net_type: p[0].into(),
        addr_type: p[1].into(),
        address: p[2].into(),
    })
}

fn parse_media(v: &str, line: usize) -> Result<Media, SdpError> {
    let p: Vec<&str> = v.split_whitespace().collect();
    if p.len() < 4 {
        return Err(SdpError::Invalid {
            line,
            detail: "m= needs media, port, protocol and at least one format".into(),
        });
    }
    let port = p[1]
        .split('/')
        .next()
        .unwrap_or(p[1])
        .parse()
        .map_err(|_| SdpError::Invalid {
            line,
            detail: format!("bad media port {:?}", p[1]),
        })?;
    Ok(Media {
        kind: p[0].into(),
        port,
        protocol: p[2].into(),
        formats: p[3..].iter().map(|s| s.to_string()).collect(),
        connection: None,
        bandwidths: Vec::new(),
        attributes: Vec::new(),
        other: Vec::new(),
    })
}

fn parse_attribute(v: &str) -> Attribute {
    match v.split_once(':') {
        Some((name, value)) => Attribute::new(name, Some(value)),
        None => Attribute::new(v, None::<String>),
    }
}

fn format_attr(a: &Attribute) -> String {
    match &a.value {
        Some(v) => format!("a={}:{v}", a.name),
        None => format!("a={}", a.name),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdpError {
    Missing(&'static str),
    Invalid { line: usize, detail: String },
}

impl fmt::Display for SdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdpError::Missing(field) => write!(f, "missing SDP {field}"),
            SdpError::Invalid { line, detail } => write!(f, "SDP line {line}: {detail}"),
        }
    }
}

impl std::error::Error for SdpError {}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &str = "v=0\r\n\
o=- 0 0 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 116 101\r\n\
a=rtpmap:116 AMR-WB/16000/1\r\n\
a=fmtp:116 octet-align=1;mode-set=0,1,2,3,4,5,6,7;mode-change-capability=2;max-red=0\r\n\
a=rtpmap:101 telephone-event/16000\r\n\
a=fmtp:101 0-15\r\n\
a=ptime:20\r\n\
a=sendrecv\r\n";

    #[test]
    fn parses_amr_wb_offer() {
        let s = Sdp::parse(OFFER).unwrap();
        let m = s.audio().unwrap();
        assert_eq!(m.port, 49170);
        assert_eq!(m.formats, vec!["116", "101"]);
        let r = m.rtpmap(116).unwrap();
        assert_eq!(r.encoding, "AMR-WB");
        assert_eq!(r.clock_rate, 16_000);
        assert_eq!(m.payload_type("AMR-WB", 16_000), Some(116));
        assert!(m.fmtp(116).unwrap().contains("octet-align=1"));
        assert!(m.fmtp(116).unwrap().contains("mode-set=0,1,2,3,4,5,6,7"));
    }

    #[test]
    fn round_trips_text() {
        let s = Sdp::parse(OFFER).unwrap();
        let text = s.to_text();
        let again = Sdp::parse(&text).unwrap();
        assert_eq!(again, s);
    }

    #[test]
    fn builds_offer_and_answer() {
        let offer = Sdp::amr_wb_offer(&[0, 1, 2, 3, 4, 5, 6, 7], true, "192.0.2.10");
        assert_eq!(
            offer.audio().unwrap().payload_type("AMR-WB", 16_000),
            Some(116)
        );
        let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
        let m = answer.audio().unwrap();
        assert_eq!(m.port, 49_172);
        assert_eq!(m.payload_type("AMR-WB", 16_000), Some(116));
        assert!(m.attribute("sendrecv").is_none());
        assert!(m.attributes.iter().any(|a| a.name == "sendrecv"));
    }

    #[test]
    fn rejects_missing_version() {
        let e = Sdp::parse("o=- 0 0 IN IP4 1.2.3.4\r\ns=-\r\nt=0 0\r\n").unwrap_err();
        assert_eq!(e, SdpError::Missing("v=0"));
    }

    const PRECOND_OFFER: &str = "v=0\r\n\
o=- 0 0 IN IP4 192.0.2.10\r\n\
s=-\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 116\r\n\
a=rtpmap:116 AMR-WB/16000/1\r\n\
a=createmedia:sendrecv\r\n\
a=status:send\r\n\
a=confirmed:sendrecv\r\n";

    #[test]
    fn parses_rfc3312_preconditions() {
        let s = Sdp::parse(PRECOND_OFFER).unwrap();
        let p = s.audio().unwrap().precondition().expect("preconditions");
        assert_eq!(p.createmedia, Some(PrecondDir::SendRecv));
        assert_eq!(p.status, Some(PrecondDir::Send));
        assert_eq!(p.confirmed, Some(PrecondDir::SendRecv));
        // Not yet met: local status is only `send`, not `sendrecv`.
        assert!(!p.met());
    }

    #[test]
    fn preconditions_are_met_when_status_sendrecv() {
        let mut s = Sdp::parse(PRECOND_OFFER).unwrap();
        let m = s.audio_mut().unwrap();
        m.attributes
            .retain(|a| !a.name.eq_ignore_ascii_case("status"));
        m.attributes
            .push(Attribute::new("status", Some("sendrecv")));
        assert!(s.audio().unwrap().precondition().unwrap().met());
    }

    #[test]
    fn answer_echoes_preconditions() {
        let offer = Sdp::parse(PRECOND_OFFER).unwrap();
        let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
        let p = answer
            .audio()
            .unwrap()
            .precondition()
            .expect("answer precond");
        assert_eq!(p.createmedia, Some(PrecondDir::SendRecv));
        assert_eq!(p.confirmed, Some(PrecondDir::SendRecv));
    }

    #[test]
    fn build_offer_preconditions_round_trip() {
        let mut offer = Sdp::amr_wb_offer(&[0, 1, 2, 3], false, "192.0.2.10");
        offer.add_preconditions();
        let text = offer.to_text();
        let mut parsed = Sdp::parse(&text).unwrap();
        let p = parsed.audio().unwrap().precondition().unwrap();
        assert_eq!(p.createmedia, Some(PrecondDir::SendRecv));
        assert_eq!(p.status, Some(PrecondDir::SendRecv));
        assert!(p.met());
        // Confirming flips `a=confirmed` and keeps it present.
        assert_eq!(parsed.confirm_preconditions(), 1);
        assert_eq!(
            parsed.audio().unwrap().attribute("confirmed"),
            Some("sendrecv")
        );
    }
}
