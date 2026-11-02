//! EAP-AKA' peer exchange (RFC 4187 §10, RFC 5448).
//!
//! The ePDG sends `EAP-Request/AKA'-Challenge`; the peer verifies the server's
//! `AT_MAC`, answers with `AT_RES` (the USIM's RES) and its own `AT_MAC`, and
//! the IKEv2 layer then ties that EAP result to the tunnel (RFC 7296 §2.16).
//!
//! This module implements the EAP packet framing and the AKA' challenge/
//! response step. It does not run IKEv2 and it does not talk to a card: the
//! caller supplies the `RES` the USIM produced.

#![forbid(unsafe_code)]

use aka::eap_aka_prime::{
    at_mac, attribute, parse_attributes, EapAkaPrimeKeys, AT_KDF_INPUT, AT_MAC_LEN,
};

/// EAP codes (RFC 3748 §4).
pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;

/// EAP method type for EAP-AKA' (RFC 5448).
pub const EAP_TYPE_AKA_PRIME: u8 = 50;
/// EAP method type for EAP-AKA.
pub const EAP_TYPE_AKA: u8 = 23;

/// EAP-AKA' subtypes (RFC 4187 §10, RFC 5448).
pub const SUBTYPE_CHALLENGE: u8 = 1;
pub const SUBTYPE_AUTHENTICATION_REJECT: u8 = 2;
pub const SUBTYPE_SYNCHRONIZATION_FAILURE: u8 = 4;
pub const SUBTYPE_IDENTITY: u8 = 5;
pub const SUBTYPE_NOTIFICATION: u8 = 12;
pub const SUBTYPE_REAUTHENTICATION: u8 = 13;
pub const SUBTYPE_CLIENT_ERROR: u8 = 14;

/// AT_RES (RFC 4187 §10.6).
pub const AT_RES: u8 = 3;
/// AT_MAC (RFC 4187 §10.15).
pub const AT_MAC: u8 = 11;
/// AT_NOTIFICATION.
pub const AT_NOTIFICATION: u8 = 12;

/// Errors from the EAP exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EapPeerError {
    /// The packet was not a well-formed EAP Request.
    BadPacket(&'static str),
    /// The method was not EAP-AKA'.
    WrongMethod(u8),
    /// An unexpected subtype arrived.
    UnexpectedSubtype(u8),
    /// The server's AT_MAC did not verify.
    BadServerMac,
    /// The challenge carried no AT_MAC.
    MissingMac,
    /// The access-network name in AT_KDF_INPUT differs from the derived one.
    NetworkNameMismatch,
    /// Attribute framing was invalid.
    Attribute(&'static str),
}

impl core::fmt::Display for EapPeerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EapPeerError::BadPacket(s) => write!(f, "bad EAP packet: {s}"),
            EapPeerError::WrongMethod(t) => write!(f, "unexpected EAP method {t}"),
            EapPeerError::UnexpectedSubtype(t) => write!(f, "unexpected EAP-AKA' subtype {t}"),
            EapPeerError::BadServerMac => f.write_str("server AT_MAC did not verify"),
            EapPeerError::MissingMac => f.write_str("challenge carried no AT_MAC"),
            EapPeerError::NetworkNameMismatch => {
                f.write_str("AT_KDF_INPUT access-network name differs from the derived one")
            }
            EapPeerError::Attribute(s) => write!(f, "bad EAP attribute: {s}"),
        }
    }
}

impl std::error::Error for EapPeerError {}

/// A parsed EAP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    /// Method type (Request/Response only).
    pub method: Option<u8>,
    /// Subtype (AKA/AKA' only).
    pub subtype: Option<u8>,
    /// Attributes after the subtype.
    pub attributes: Vec<u8>,
}

impl EapPacket {
    /// Parse an EAP packet, validating the length field.
    pub fn parse(bytes: &[u8]) -> Result<Self, EapPeerError> {
        if bytes.len() < 4 {
            return Err(EapPeerError::BadPacket("shorter than the header"));
        }
        let code = bytes[0];
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if length < 4 || length > bytes.len() {
            return Err(EapPeerError::BadPacket("length is outside the buffer"));
        }
        let body = &bytes[4..length];
        if !matches!(code, EAP_REQUEST | EAP_RESPONSE) {
            return Ok(Self {
                code,
                identifier,
                method: None,
                subtype: None,
                attributes: body.to_vec(),
            });
        }
        let (method, rest) = body
            .split_first()
            .ok_or(EapPeerError::BadPacket("missing method type"))?;
        let (subtype, attributes) = if *method == EAP_TYPE_AKA_PRIME || *method == EAP_TYPE_AKA {
            let (subtype, rest) = rest
                .split_first()
                .ok_or(EapPeerError::BadPacket("missing AKA subtype"))?;
            (Some(*subtype), rest.to_vec())
        } else {
            (None, rest.to_vec())
        };
        Ok(Self {
            code,
            identifier,
            method: Some(*method),
            subtype,
            attributes,
        })
    }

    /// Build an EAP Response with a method type and subtype.
    pub fn response(identifier: u8, method: u8, subtype: Option<u8>, attributes: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + 1 + attributes.len());
        body.push(method);
        if let Some(s) = subtype {
            body.push(s);
        }
        body.extend_from_slice(attributes);
        let total = 4 + body.len();
        let mut out = Vec::with_capacity(total);
        out.push(EAP_RESPONSE);
        out.push(identifier);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

/// The peer side of one EAP-AKA' challenge.
pub struct AkaPrimePeer {
    /// The access-network name used to derive CK'/IK'.
    network_name: String,
    keys: EapAkaPrimeKeys,
    /// RES from the USIM AUTHENTICATE.
    res: Vec<u8>,
}

impl AkaPrimePeer {
    /// Build the peer from the derived keys, the USIM RES and the network name.
    pub fn new(network_name: impl Into<String>, keys: EapAkaPrimeKeys, res: Vec<u8>) -> Self {
        Self {
            network_name: network_name.into(),
            keys,
            res,
        }
    }

    /// Process an `EAP-Request/AKA'-Challenge` and return the EAP Response.
    ///
    /// Verifies the server `AT_MAC` and the `AT_KDF_INPUT` network name, then
    /// answers with `AT_RES` and its own `AT_MAC`.
    pub fn on_request(&mut self, packet: &[u8]) -> Result<Vec<u8>, EapPeerError> {
        let request = EapPacket::parse(packet)?;
        if request.code != EAP_REQUEST {
            return Err(EapPeerError::BadPacket("not an EAP Request"));
        }
        match request.method {
            Some(EAP_TYPE_AKA_PRIME) => {}
            Some(other) => return Err(EapPeerError::WrongMethod(other)),
            None => return Err(EapPeerError::BadPacket("missing method")),
        }
        match request.subtype {
            Some(SUBTYPE_CHALLENGE) => self.answer_challenge(packet, &request),
            Some(SUBTYPE_NOTIFICATION) => {
                Err(EapPeerError::UnexpectedSubtype(SUBTYPE_NOTIFICATION))
            }
            Some(subtype) => Err(EapPeerError::UnexpectedSubtype(subtype)),
            None => Err(EapPeerError::BadPacket("missing subtype")),
        }
    }

    /// The EAP-AKA' key set, including the MSK used for IKEv2 AUTH.
    pub fn keys(&self) -> &EapAkaPrimeKeys {
        &self.keys
    }

    fn answer_challenge(
        &mut self,
        raw: &[u8],
        request: &EapPacket,
    ) -> Result<Vec<u8>, EapPeerError> {
        // Verify the server's AT_MAC over the whole request packet with the MAC
        // value zeroed. The value starts after the 4-octet EAP header, the
        // method octet, the subtype octet and the attribute header.
        let mac_offset =
            attribute_value_offset(&request.attributes, AT_MAC).ok_or(EapPeerError::MissingMac)?;
        let packet_mac_offset = 4 + 2 + mac_offset;
        let expected = at_mac(&self.keys.k_aut, raw, packet_mac_offset)
            .map_err(|_| EapPeerError::BadPacket("MAC offset"))?;
        let received = &request.attributes[mac_offset..mac_offset + AT_MAC_LEN];
        if !constant_time_eq(received, &expected) {
            return Err(EapPeerError::BadServerMac);
        }

        // AT_KDF_INPUT must name the network we derived CK'/IK' from, or the
        // keys are not bound to the same access network.
        if let Some((_, value)) = parse_attributes(&request.attributes)
            .map_err(|_| EapPeerError::Attribute("unparseable attributes"))?
            .into_iter()
            .find(|(kind, _)| *kind == 0x80 | AT_KDF_INPUT)
        {
            let name = parse_kdf_input(&value)?;
            if name != self.network_name {
                return Err(EapPeerError::NetworkNameMismatch);
            }
        }

        // AT_RES: 16-bit length in bits, then the RES octets, then AT_MAC.
        let mut res_value = Vec::with_capacity(2 + self.res.len());
        res_value.extend_from_slice(&((self.res.len() * 8) as u16).to_be_bytes());
        res_value.extend_from_slice(&self.res);
        let mut attributes = attribute(0x80 | AT_RES, &res_value);
        // Placeholder MAC, patched after the packet is assembled.
        let mac_offset_in_attrs = attributes.len() + 2;
        attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));

        let mut response = EapPacket::response(
            request.identifier,
            EAP_TYPE_AKA_PRIME,
            Some(SUBTYPE_CHALLENGE),
            &attributes,
        );
        // AT_MAC covers the whole EAP packet with the MAC value zeroed.
        let packet_mac_offset = 4 + 2 + mac_offset_in_attrs;
        let mac = at_mac(&self.keys.k_aut, &response, packet_mac_offset)
            .map_err(|_| EapPeerError::BadPacket("MAC offset"))?;
        response[packet_mac_offset..packet_mac_offset + AT_MAC_LEN].copy_from_slice(&mac);
        Ok(response)
    }
}

/// Find the byte offset of an attribute's value within an attribute list.
pub fn attribute_value_offset(attributes: &[u8], kind: u8) -> Option<usize> {
    let mut at = 0;
    while at + 2 <= attributes.len() {
        let wire = attributes[at];
        let units = attributes[at + 1] as usize;
        if units == 0 {
            return None;
        }
        let len = units * 4;
        if wire == 0x80 | kind {
            return Some(at + 2);
        }
        at = at.checked_add(len)?;
    }
    None
}

fn parse_kdf_input(value: &[u8]) -> Result<String, EapPeerError> {
    if value.len() < 2 {
        return Err(EapPeerError::Attribute("AT_KDF_INPUT too short"));
    }
    let len = u16::from_be_bytes([value[0], value[1]]) as usize;
    let name = value
        .get(2..2 + len)
        .ok_or(EapPeerError::Attribute("AT_KDF_INPUT name truncated"))?;
    String::from_utf8(name.to_vec()).map_err(|_| EapPeerError::Attribute("name is not UTF-8"))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aka::eap_aka_prime::{ck_ik_prime, derive_keys, kdf_input_attribute};

    const NETWORK: &str = "WLAN";
    const IDENTITY: &str = "user@example";
    const RES: [u8; 8] = [0xA5; 8];

    fn keys() -> EapAkaPrimeKeys {
        let (ck, ik) = ck_ik_prime(&[0x11; 16], &[0x22; 16], NETWORK).unwrap();
        derive_keys(&ck, &ik, NETWORK, IDENTITY, &[0x80, 0x00]).unwrap()
    }

    /// Build the server's EAP-Request/AKA'-Challenge with a correct AT_MAC.
    fn server_challenge(keys: &EapAkaPrimeKeys, network: &str) -> Vec<u8> {
        let mut attributes = kdf_input_attribute(network).unwrap();
        attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));
        let mut packet =
            EapPacket::response(7, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &attributes);
        // Turn the code into a Request and patch the MAC.
        packet[0] = EAP_REQUEST;
        let offset = 4 + 2 + attribute_value_offset(&attributes, AT_MAC).unwrap();
        let mac = at_mac(&keys.k_aut, &packet, offset).unwrap();
        packet[offset..offset + AT_MAC_LEN].copy_from_slice(&mac);
        packet
    }

    #[test]
    fn eap_packet_round_trips() {
        let bytes = EapPacket::response(9, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &[1, 2, 3]);
        assert_eq!(&bytes[..4], &[EAP_RESPONSE, 9, 0, 9]);
        let parsed = EapPacket::parse(&bytes).unwrap();
        assert_eq!(parsed.code, EAP_RESPONSE);
        assert_eq!(parsed.identifier, 9);
        assert_eq!(parsed.method, Some(EAP_TYPE_AKA_PRIME));
        assert_eq!(parsed.subtype, Some(SUBTYPE_CHALLENGE));
        assert_eq!(parsed.attributes, vec![1, 2, 3]);
    }

    #[test]
    fn peer_verifies_the_server_mac_and_answers_with_res() {
        let keys = keys();
        let challenge = server_challenge(&keys, NETWORK);
        let mut peer = AkaPrimePeer::new(NETWORK, keys.clone(), RES.to_vec());
        let response = peer.on_request(&challenge).unwrap();

        let parsed = EapPacket::parse(&response).unwrap();
        assert_eq!(parsed.code, EAP_RESPONSE);
        assert_eq!(parsed.identifier, 7);
        assert_eq!(parsed.method, Some(EAP_TYPE_AKA_PRIME));
        assert_eq!(parsed.subtype, Some(SUBTYPE_CHALLENGE));

        // AT_RES carries (bits, RES).
        let offset = attribute_value_offset(&parsed.attributes, AT_RES).unwrap();
        let bits = u16::from_be_bytes([parsed.attributes[offset], parsed.attributes[offset + 1]]);
        assert_eq!(bits, 64);
        assert_eq!(&parsed.attributes[offset + 2..offset + 10], &RES[..]);

        // Our AT_MAC verifies against the same key.
        let mac_offset = attribute_value_offset(&parsed.attributes, AT_MAC).unwrap();
        let packet_mac = 4 + 2 + mac_offset;
        let mut zeroed = response.clone();
        zeroed[packet_mac..packet_mac + AT_MAC_LEN].fill(0);
        let expected = at_mac(&keys.k_aut, &zeroed, packet_mac).unwrap();
        assert_eq!(
            &response[packet_mac..packet_mac + AT_MAC_LEN],
            &expected[..]
        );
    }

    #[test]
    fn a_tampered_server_mac_is_rejected() {
        let keys = keys();
        let mut challenge = server_challenge(&keys, NETWORK);
        let last = challenge.len() - 1;
        challenge[last] ^= 0x01;
        let mut peer = AkaPrimePeer::new(NETWORK, keys, RES.to_vec());
        assert_eq!(peer.on_request(&challenge), Err(EapPeerError::BadServerMac));
    }

    #[test]
    fn a_different_network_name_is_rejected() {
        let keys = keys();
        // The server names a different access network than we derived from.
        let challenge = server_challenge(&keys, "OTHER");
        let mut peer = AkaPrimePeer::new(NETWORK, keys, RES.to_vec());
        assert_eq!(
            peer.on_request(&challenge),
            Err(EapPeerError::NetworkNameMismatch)
        );
    }

    #[test]
    fn non_aka_prime_requests_are_rejected() {
        let bytes = EapPacket::response(1, EAP_TYPE_AKA, Some(SUBTYPE_CHALLENGE), &[]);
        let mut request = bytes.clone();
        request[0] = EAP_REQUEST;
        let mut peer = AkaPrimePeer::new(NETWORK, keys(), RES.to_vec());
        assert_eq!(
            peer.on_request(&request),
            Err(EapPeerError::WrongMethod(EAP_TYPE_AKA))
        );
    }

    #[test]
    fn malformed_packets_are_rejected() {
        assert!(EapPacket::parse(&[1, 2]).is_err());
        assert!(EapPacket::parse(&[1, 2, 0, 99]).is_err());
        let mut peer = AkaPrimePeer::new(NETWORK, keys(), RES.to_vec());
        assert!(peer.on_request(&[1, 2, 0, 4]).is_err());
    }
}
