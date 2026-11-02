//! IKEv2 message and payload codec (RFC 7296).
//!
//! Wi-Fi calling reaches IMS through an ePDG over IKEv2 with EAP-AKA'
//! authentication. This module is the wire format: the 28-octet header, the
//! payload chain, and typed codecs for the payloads an ePDG exchange uses.
//!
//! ```text
//! header: initiator SPI(8) responder SPI(8)
//!         next payload(1) version(1=0x20) exchange(1) flags(1)
//!         message id(4) length(4)
//! payload: next(1) critical(1) length(2) body
//! ```
//!
//! The module is pure: no sockets, no crypto policy, no state machine. The
//! crypto (DH, SK encryption/integrity) is a later layer; what is here is
//! exactly what an implementer gets wrong first — the framing.

#![forbid(unsafe_code)]

/// Octets in an IKEv2 header.
pub const HEADER_LEN: usize = 28;
/// The only major/minor version in use: 2.0.
pub const VERSION_2_0: u8 = 0x20;

/// IKEv2 exchange types (RFC 7296 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
    IkeSessionResume = 38,
}

impl ExchangeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            34 => ExchangeType::IkeSaInit,
            35 => ExchangeType::IkeAuth,
            36 => ExchangeType::CreateChildSa,
            37 => ExchangeType::Informational,
            38 => ExchangeType::IkeSessionResume,
            _ => return None,
        })
    }
}

/// Payload types (RFC 7296 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    None = 0,
    Sa = 33,
    Ke = 34,
    Idi = 35,
    Idr = 36,
    Cert = 37,
    CertReq = 38,
    Auth = 39,
    Nonce = 40,
    Notify = 41,
    Delete = 42,
    VendorId = 43,
    Tsi = 44,
    Tsr = 45,
    Encrypted = 46,
    Config = 47,
    Eap = 48,
}

impl PayloadType {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => PayloadType::None,
            33 => PayloadType::Sa,
            34 => PayloadType::Ke,
            35 => PayloadType::Idi,
            36 => PayloadType::Idr,
            37 => PayloadType::Cert,
            38 => PayloadType::CertReq,
            39 => PayloadType::Auth,
            40 => PayloadType::Nonce,
            41 => PayloadType::Notify,
            42 => PayloadType::Delete,
            43 => PayloadType::VendorId,
            44 => PayloadType::Tsi,
            45 => PayloadType::Tsr,
            46 => PayloadType::Encrypted,
            47 => PayloadType::Config,
            48 => PayloadType::Eap,
            _ => return None,
        })
    }
}

/// The fixed IKEv2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    /// First payload type in the chain (`None` when there are no payloads).
    pub next_payload: PayloadType,
    pub exchange: ExchangeType,
    /// Initiator (`0x08`) / response (`0x20`) flags.
    pub flags: u8,
    pub message_id: u32,
}

/// Flag bit: the message is a response.
pub const FLAG_RESPONSE: u8 = 0x20;
/// Flag bit: the sender is the original initiator.
pub const FLAG_INITIATOR: u8 = 0x08;

impl Header {
    pub fn encode(&self, total_length: usize) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..8].copy_from_slice(&self.initiator_spi);
        out[8..16].copy_from_slice(&self.responder_spi);
        out[16] = self.next_payload as u8;
        out[17] = VERSION_2_0;
        out[18] = self.exchange as u8;
        out[19] = self.flags;
        out[20..24].copy_from_slice(&self.message_id.to_be_bytes());
        out[24..28].copy_from_slice(&(total_length as u32).to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), IkeError> {
        if bytes.len() < HEADER_LEN {
            return Err(IkeError::TooShort(bytes.len()));
        }
        let version = bytes[17];
        if version != VERSION_2_0 {
            return Err(IkeError::UnsupportedVersion(version));
        }
        let mut initiator_spi = [0u8; 8];
        initiator_spi.copy_from_slice(&bytes[..8]);
        let mut responder_spi = [0u8; 8];
        responder_spi.copy_from_slice(&bytes[8..16]);
        let next_payload =
            PayloadType::from_u8(bytes[16]).ok_or(IkeError::UnknownPayload(bytes[16]))?;
        let exchange =
            ExchangeType::from_u8(bytes[18]).ok_or(IkeError::UnknownExchange(bytes[18]))?;
        let message_id = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        let length = u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize;
        if length < HEADER_LEN || length > bytes.len() {
            return Err(IkeError::BadLength {
                declared: length,
                available: bytes.len(),
            });
        }
        Ok((
            Self {
                initiator_spi,
                responder_spi,
                next_payload,
                exchange,
                flags: bytes[19],
                message_id,
            },
            length,
        ))
    }
}

/// Errors from the IKEv2 codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IkeError {
    TooShort(usize),
    BadLength { declared: usize, available: usize },
    UnsupportedVersion(u8),
    UnknownPayload(u8),
    UnknownExchange(u8),
    Malformed(&'static str),
}

impl core::fmt::Display for IkeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IkeError::TooShort(n) => write!(f, "IKEv2 message too short: {n} bytes"),
            IkeError::BadLength {
                declared,
                available,
            } => write!(f, "IKEv2 length {declared} does not fit {available} bytes"),
            IkeError::UnsupportedVersion(v) => write!(f, "IKEv2 version {v:02x} unsupported"),
            IkeError::UnknownPayload(t) => write!(f, "unknown IKEv2 payload type {t}"),
            IkeError::UnknownExchange(t) => write!(f, "unknown IKEv2 exchange type {t}"),
            IkeError::Malformed(what) => write!(f, "malformed IKEv2 payload: {what}"),
        }
    }
}

impl std::error::Error for IkeError {}

/// One payload in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub kind: PayloadType,
    /// The critical bit: reject the message if the type is not understood.
    pub critical: bool,
    pub body: Vec<u8>,
}

/// Encode a payload chain, linking each `Next Payload` field.
pub fn encode_payloads(payloads: &[Payload]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, payload) in payloads.iter().enumerate() {
        let next = payloads
            .get(i + 1)
            .map(|p| p.kind as u8)
            .unwrap_or(PayloadType::None as u8);
        let len = 4 + payload.body.len();
        out.push(next);
        out.push(if payload.critical { 0x80 } else { 0x00 });
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&payload.body);
    }
    out
}

/// Decode a payload chain starting at `first`.
pub fn decode_payloads(bytes: &[u8], mut next: PayloadType) -> Result<Vec<Payload>, IkeError> {
    let mut out = Vec::new();
    let mut at = 0;
    while next != PayloadType::None {
        if at + 4 > bytes.len() {
            return Err(IkeError::Malformed("payload header truncated"));
        }
        let following =
            PayloadType::from_u8(bytes[at]).ok_or(IkeError::UnknownPayload(bytes[at]))?;
        let critical = bytes[at + 1] & 0x80 != 0;
        let len = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) as usize;
        if len < 4 {
            return Err(IkeError::Malformed("payload length below its header"));
        }
        let end = at
            .checked_add(len)
            .ok_or(IkeError::Malformed("payload length overflow"))?;
        let body = bytes
            .get(at + 4..end)
            .ok_or(IkeError::Malformed("payload body truncated"))?;
        out.push(Payload {
            kind: next,
            critical,
            body: body.to_vec(),
        });
        at = end;
        next = following;
        if out.len() > 64 {
            return Err(IkeError::Malformed("payload chain too long"));
        }
    }
    if at != bytes.len() {
        return Err(IkeError::Malformed(
            "trailing bytes after the payload chain",
        ));
    }
    Ok(out)
}

/// A complete IKEv2 message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub payloads: Vec<Payload>,
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        let body = encode_payloads(&self.payloads);
        let mut header = self.header;
        header.next_payload = self
            .payloads
            .first()
            .map(|p| p.kind)
            .unwrap_or(PayloadType::None);
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&header.encode(HEADER_LEN + body.len()));
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IkeError> {
        let (header, length) = Header::decode(bytes)?;
        let payloads = decode_payloads(&bytes[HEADER_LEN..length], header.next_payload)?;
        Ok(Self { header, payloads })
    }

    /// The first payload of `kind`.
    pub fn find(&self, kind: PayloadType) -> Option<&Payload> {
        self.payloads.iter().find(|p| p.kind == kind)
    }
}

// --- SA -------------------------------------------------------------------

/// IPsec protocol id for ESP (RFC 7296 §3.3).
pub const PROTO_ESP: u8 = 3;
/// IPsec protocol id for AH.
pub const PROTO_AH: u8 = 2;
/// Transform type: encryption algorithm.
pub const TRANSFORM_ENCR: u8 = 1;
/// Transform type: pseudorandom function.
pub const TRANSFORM_PRF: u8 = 2;
/// Transform type: integrity algorithm.
pub const TRANSFORM_INTEG: u8 = 3;
/// Transform type: Diffie-Hellman group.
pub const TRANSFORM_DH: u8 = 4;
/// Extended sequence numbers.
pub const TRANSFORM_ESN: u8 = 5;

/// One transform in a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: u8,
    pub id: u16,
    /// Raw attributes (each 4 octets: AF/TLV + type/length).
    pub attributes: Vec<u8>,
}

/// One proposal in an SA payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

/// An SA payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sa {
    pub proposals: Vec<Proposal>,
}

impl Sa {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let count = self.proposals.len();
        for (i, proposal) in self.proposals.iter().enumerate() {
            let mut transforms = Vec::new();
            let tcount = proposal.transforms.len();
            for (j, t) in proposal.transforms.iter().enumerate() {
                let last = j + 1 == tcount;
                let len = 8 + t.attributes.len();
                transforms.push(if last { 3u8 } else { 0u8 });
                transforms.push(0);
                transforms.extend_from_slice(&(len as u16).to_be_bytes());
                transforms.push(t.transform_type);
                transforms.push(0);
                transforms.extend_from_slice(&t.id.to_be_bytes());
                transforms.extend_from_slice(&t.attributes);
            }
            let last = i + 1 == count;
            let len = 8 + proposal.spi.len() + transforms.len();
            out.push(if last { 2u8 } else { 0u8 });
            out.push(0);
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.push(proposal.number);
            out.push(proposal.protocol_id);
            out.push(proposal.spi.len() as u8);
            out.push(proposal.transforms.len() as u8);
            out.extend_from_slice(&proposal.spi);
            out.extend_from_slice(&transforms);
        }
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        let mut proposals = Vec::new();
        let mut at = 0;
        loop {
            if at + 8 > body.len() {
                return Err(IkeError::Malformed("proposal header truncated"));
            }
            let last = body[at];
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            if len < 8 {
                return Err(IkeError::Malformed("proposal length below its header"));
            }
            let end = at
                .checked_add(len)
                .ok_or(IkeError::Malformed("proposal length overflow"))?;
            let block = body
                .get(at..end)
                .ok_or(IkeError::Malformed("proposal truncated"))?;
            let number = block[4];
            let protocol_id = block[5];
            let spi_size = block[6] as usize;
            let transform_count = block[7] as usize;
            let spi_end = 8 + spi_size;
            let spi = block
                .get(8..spi_end)
                .ok_or(IkeError::Malformed("proposal SPI truncated"))?
                .to_vec();
            let mut transforms = Vec::new();
            let mut t_at = spi_end;
            for _ in 0..transform_count {
                if t_at + 8 > block.len() {
                    return Err(IkeError::Malformed("transform header truncated"));
                }
                let t_len = u16::from_be_bytes([block[t_at + 2], block[t_at + 3]]) as usize;
                if t_len < 8 {
                    return Err(IkeError::Malformed("transform length below its header"));
                }
                let t_end = t_at + t_len;
                let t_block = block
                    .get(t_at..t_end)
                    .ok_or(IkeError::Malformed("transform truncated"))?;
                transforms.push(Transform {
                    transform_type: t_block[4],
                    id: u16::from_be_bytes([t_block[6], t_block[7]]),
                    attributes: t_block[8..].to_vec(),
                });
                t_at = t_end;
            }
            proposals.push(Proposal {
                number,
                protocol_id,
                spi,
                transforms,
            });
            at = end;
            if last == 2 || at >= body.len() {
                break;
            }
        }
        Ok(Self { proposals })
    }
}

// --- KE / Nonce / ID / AUTH / EAP / Notify / TS ---------------------------

/// A Key Exchange payload. `dh_group` is the transform id (e.g. 14 = MODP 2048).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ke {
    pub dh_group: u16,
    pub key_data: Vec<u8>,
}

impl Ke {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.key_data.len());
        out.extend_from_slice(&self.dh_group.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.key_data);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("KE payload too short"));
        }
        Ok(Self {
            dh_group: u16::from_be_bytes([body[0], body[1]]),
            key_data: body[4..].to_vec(),
        })
    }
}

/// Identification payload types (RFC 7296 §3.5).
pub const ID_IPV4_ADDR: u8 = 1;
pub const ID_FQDN: u8 = 2;
pub const ID_RFC822_ADDR: u8 = 3;
pub const ID_IPV6_ADDR: u8 = 5;
pub const ID_KEY_ID: u8 = 11;

/// An Identification payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id {
    pub id_type: u8,
    pub data: Vec<u8>,
}

impl Id {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.id_type);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("ID payload too short"));
        }
        Ok(Self {
            id_type: body[0],
            data: body[4..].to_vec(),
        })
    }
}

/// Authentication methods (RFC 7296 §3.8).
pub const AUTH_RSA_DIGITAL_SIGNATURE: u8 = 1;
pub const AUTH_SHARED_KEY_MIC: u8 = 2;
pub const AUTH_NULL: u8 = 8;

/// An Authentication payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub method: u8,
    pub data: Vec<u8>,
}

impl Auth {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.method);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("AUTH payload too short"));
        }
        Ok(Self {
            method: body[0],
            data: body[4..].to_vec(),
        })
    }
}

/// A Notify payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol_id: u8,
    pub notify_type: u16,
    pub spi: Vec<u8>,
    pub data: Vec<u8>,
}

impl Notify {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.spi.len() + self.data.len());
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        out.extend_from_slice(&self.notify_type.to_be_bytes());
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("notify payload too short"));
        }
        let spi_size = body[1] as usize;
        let end = 4 + spi_size;
        if body.len() < end {
            return Err(IkeError::Malformed("notify SPI truncated"));
        }
        Ok(Self {
            protocol_id: body[0],
            notify_type: u16::from_be_bytes([body[2], body[3]]),
            spi: body[4..end].to_vec(),
            data: body[end..].to_vec(),
        })
    }
}

/// A traffic selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    pub ts_type: u8,
    pub ip_protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_address: Vec<u8>,
    pub end_address: Vec<u8>,
}

/// A Traffic Selector payload (TSi or TSr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelectors {
    pub selectors: Vec<Selector>,
}

impl TrafficSelectors {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.selectors.len() as u8);
        out.extend_from_slice(&[0, 0, 0]);
        for s in &self.selectors {
            let len = 8 + s.start_address.len() + s.end_address.len();
            out.push(s.ts_type);
            out.push(s.ip_protocol);
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.extend_from_slice(&s.start_port.to_be_bytes());
            out.extend_from_slice(&s.end_port.to_be_bytes());
            out.extend_from_slice(&s.start_address);
            out.extend_from_slice(&s.end_address);
        }
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("TS payload too short"));
        }
        let count = body[0] as usize;
        let mut selectors = Vec::with_capacity(count);
        let mut at = 4;
        for _ in 0..count {
            if at + 8 > body.len() {
                return Err(IkeError::Malformed("TS header truncated"));
            }
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            if len < 8 {
                return Err(IkeError::Malformed("TS length below its header"));
            }
            let end = at + len;
            let block = body
                .get(at..end)
                .ok_or(IkeError::Malformed("TS truncated"))?;
            let rest = &block[8..];
            let half = rest.len() / 2;
            selectors.push(Selector {
                ts_type: block[0],
                ip_protocol: block[1],
                start_port: u16::from_be_bytes([block[4], block[5]]),
                end_port: u16::from_be_bytes([block[6], block[7]]),
                start_address: rest[..half].to_vec(),
                end_address: rest[half..].to_vec(),
            });
            at = end;
        }
        Ok(Self { selectors })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(exchange: ExchangeType) -> Header {
        Header {
            initiator_spi: [0x11; 8],
            responder_spi: [0; 8],
            next_payload: PayloadType::None,
            exchange,
            flags: FLAG_INITIATOR,
            message_id: 0,
        }
    }

    #[test]
    fn header_round_trips_with_the_exact_wire_shape() {
        let h = header(ExchangeType::IkeSaInit);
        let bytes = h.encode(HEADER_LEN);
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..8], &[0x11; 8]);
        assert_eq!(bytes[16], 0); // NONE
        assert_eq!(bytes[17], 0x20); // version 2.0
        assert_eq!(bytes[18], 34); // IKE_SA_INIT
        assert_eq!(bytes[19], FLAG_INITIATOR);
        assert_eq!(&bytes[24..28], &28u32.to_be_bytes());
        let (decoded, len) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(len, 28);
    }

    #[test]
    fn message_links_the_payload_chain() {
        let msg = Message {
            header: Header {
                next_payload: PayloadType::Sa,
                ..header(ExchangeType::IkeSaInit)
            },
            payloads: vec![
                Payload {
                    kind: PayloadType::Sa,
                    critical: false,
                    body: Sa {
                        proposals: vec![Proposal {
                            number: 1,
                            protocol_id: PROTO_ESP,
                            spi: vec![],
                            transforms: vec![
                                Transform {
                                    transform_type: TRANSFORM_ENCR,
                                    id: 12,
                                    attributes: vec![],
                                },
                                Transform {
                                    transform_type: TRANSFORM_PRF,
                                    id: 5,
                                    attributes: vec![],
                                },
                            ],
                        }],
                    }
                    .encode(),
                },
                Payload {
                    kind: PayloadType::Nonce,
                    critical: false,
                    body: vec![0xAB; 32],
                },
            ],
        };
        let bytes = msg.encode();
        // First payload byte is the *next* payload type (NONCE = 40).
        assert_eq!(bytes[16], PayloadType::Sa as u8);
        assert_eq!(bytes[28], PayloadType::Nonce as u8);
        let decoded = Message::decode(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.find(PayloadType::Sa).is_some());
        assert!(decoded.find(PayloadType::Ke).is_none());
    }

    #[test]
    fn sa_payload_round_trips() {
        let sa = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol_id: PROTO_ESP,
                spi: vec![0xDE, 0xAD, 0xBE, 0xEF],
                transforms: vec![
                    Transform {
                        transform_type: TRANSFORM_ENCR,
                        id: 12,
                        attributes: vec![0x80, 0x0E, 0x00, 0x80],
                    },
                    Transform {
                        transform_type: TRANSFORM_DH,
                        id: 14,
                        attributes: vec![],
                    },
                ],
            }],
        };
        let bytes = sa.encode();
        let decoded = Sa::decode(&bytes).unwrap();
        assert_eq!(decoded, sa);
    }

    #[test]
    fn ke_id_auth_notify_ts_round_trip() {
        let ke = Ke {
            dh_group: 14,
            key_data: vec![0x42; 256],
        };
        assert_eq!(Ke::decode(&ke.encode()).unwrap(), ke);

        let id = Id {
            id_type: ID_RFC822_ADDR,
            data: b"user@example".to_vec(),
        };
        assert_eq!(Id::decode(&id.encode()).unwrap(), id);

        let auth = Auth {
            method: AUTH_SHARED_KEY_MIC,
            data: vec![0x99; 32],
        };
        assert_eq!(Auth::decode(&auth.encode()).unwrap(), auth);

        let notify = Notify {
            protocol_id: 0,
            notify_type: 16414, // NO_ADDITIONAL_AUTH
            spi: vec![],
            data: vec![],
        };
        assert_eq!(Notify::decode(&notify.encode()).unwrap(), notify);

        let ts = TrafficSelectors {
            selectors: vec![Selector {
                ts_type: 7, // TS_IPV4_ADDR_RANGE
                ip_protocol: 0,
                start_port: 0,
                end_port: 0xffff,
                start_address: vec![0, 0, 0, 0],
                end_address: vec![255, 255, 255, 255],
            }],
        };
        assert_eq!(TrafficSelectors::decode(&ts.encode()).unwrap(), ts);
    }

    #[test]
    fn malformed_messages_are_rejected() {
        assert_eq!(Header::decode(&[0u8; 4]), Err(IkeError::TooShort(4)));

        let mut bytes = header(ExchangeType::IkeAuth).encode(HEADER_LEN);
        bytes[17] = 0x10; // IKEv1
        assert!(matches!(
            Header::decode(&bytes),
            Err(IkeError::UnsupportedVersion(0x10))
        ));

        let mut bytes = header(ExchangeType::IkeAuth).encode(HEADER_LEN);
        bytes[24..28].copy_from_slice(&999u32.to_be_bytes());
        assert!(matches!(
            Header::decode(&bytes),
            Err(IkeError::BadLength { .. })
        ));

        // A payload whose declared length overruns the buffer.
        let mut chain = vec![0u8, 0, 0, 16, 1, 2];
        assert!(decode_payloads(&chain, PayloadType::Nonce).is_err());
        chain[3] = 6;
        assert!(decode_payloads(&chain, PayloadType::Nonce).is_ok());
    }
}
