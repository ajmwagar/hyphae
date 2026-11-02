//! IKEv2 Configuration payloads (RFC 7296 §3.15).
//!
//! S2b is how a Wi-Fi-calling UE learns its IMS address: the ePDG answers the
//! `CP(CFG_REQUEST)` in IKE_AUTH's final message with a `CP(CFG_REPLY)` carrying
//! `INTERNAL_IP4_ADDRESS` and friends. Without it the tunnel is up but there is
//! no address to send SIP from.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   CFG Type    |                    RESERVED                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|        Attribute Type       |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ~                             Value                             ~
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Note the difference from *transform* attributes: these always carry an
//! explicit 16-bit type and a 16-bit length, never the AF/TLV form, and the
//! value is zero-padded to a 4-octet boundary (the length excludes the padding).

#![forbid(unsafe_code)]

use crate::ikev2::IkeError;

/// CFG_REQUEST — the initiator asks (RFC 7296 §3.15.1).
pub const CFG_REQUEST: u8 = 1;
/// CFG_REPLY — the responder answers.
pub const CFG_REPLY: u8 = 2;
/// CFG_SET — push configuration to the peer.
pub const CFG_SET: u8 = 3;
/// CFG_ACK — acknowledge a CFG_SET.
pub const CFG_ACK: u8 = 4;

/// INTERNAL_IP4_ADDRESS: the address the peer should use inside the tunnel.
pub const INTERNAL_IP4_ADDRESS: u16 = 1;
/// INTERNAL_IP4_NETMASK.
pub const INTERNAL_IP4_NETMASK: u16 = 2;
/// INTERNAL_IP4_DNS.
pub const INTERNAL_IP4_DNS: u16 = 3;
/// INTERNAL_IP4_NBNS.
pub const INTERNAL_IP4_NBNS: u16 = 4;
/// INTERNAL_ADDRESS_EXPIRY, in seconds.
pub const INTERNAL_ADDRESS_EXPIRY: u16 = 5;
/// INTERNAL_IP4_DHCP.
pub const INTERNAL_IP4_DHCP: u16 = 6;
/// APPLICATION_VERSION, a UTF-8 string.
pub const APPLICATION_VERSION: u16 = 7;
/// INTERNAL_IP6_ADDRESS: address plus prefix length.
pub const INTERNAL_IP6_ADDRESS: u16 = 8;
/// INTERNAL_IP6_DNS.
pub const INTERNAL_IP6_DNS: u16 = 10;
/// INTERNAL_IP6_DHCP.
pub const INTERNAL_IP6_DHCP: u16 = 12;
/// INTERNAL_IP4_SUBNET.
pub const INTERNAL_IP4_SUBNET: u16 = 13;
/// SUPPORTED_ATTRIBUTES.
pub const SUPPORTED_ATTRIBUTES: u16 = 14;
/// INTERNAL_IP6_SUBNET.
pub const INTERNAL_IP6_SUBNET: u16 = 15;

/// One configuration attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttribute {
    /// The attribute type (see the `INTERNAL_*` constants).
    pub kind: u16,
    /// The value; empty in a request.
    pub value: Vec<u8>,
}

impl ConfigAttribute {
    /// A request entry: a type with no value.
    pub fn request(kind: u16) -> Self {
        Self {
            kind,
            value: Vec::new(),
        }
    }

    /// An attribute carrying a value.
    pub fn new(kind: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    /// The value as an IPv4 address, if it is an `INTERNAL_IP4_*` attribute of
    /// the right length.
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        match self.value.len() {
            4 => Some([self.value[0], self.value[1], self.value[2], self.value[3]]),
            _ => None,
        }
    }

    /// The value as a UTF-8 string, if it is printable.
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.value).ok()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
        // Pad the value to a 4-octet boundary; the length excludes the padding.
        let pad = (4 - (self.value.len() % 4)) % 4;
        out.resize(out.len() + pad, 0);
    }
}

/// A Configuration payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPayload {
    /// One of `CFG_REQUEST` / `CFG_REPLY` / `CFG_SET` / `CFG_ACK`.
    pub kind: u8,
    pub attributes: Vec<ConfigAttribute>,
}

impl ConfigPayload {
    /// A CFG_REQUEST asking for each type in `kinds`.
    pub fn request(kinds: &[u16]) -> Self {
        Self {
            kind: CFG_REQUEST,
            attributes: kinds
                .iter()
                .copied()
                .map(ConfigAttribute::request)
                .collect(),
        }
    }

    /// The S2b request: an IMS address and the DNS servers to resolve the P-CSCF.
    pub fn s2b_request() -> Self {
        Self::request(&[INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS])
    }

    /// A CFG_REPLY carrying `attributes`.
    pub fn reply(attributes: Vec<ConfigAttribute>) -> Self {
        Self {
            kind: CFG_REPLY,
            attributes,
        }
    }

    /// The first attribute of `kind`.
    pub fn get(&self, kind: u16) -> Option<&ConfigAttribute> {
        self.attributes.iter().find(|a| a.kind == kind)
    }

    /// Every attribute of `kind` (DNS servers repeat).
    pub fn get_all(&self, kind: u16) -> impl Iterator<Item = &ConfigAttribute> {
        self.attributes.iter().filter(move |a| a.kind == kind)
    }

    /// The IMS address from a reply, if the ePDG assigned one.
    pub fn internal_ip4_address(&self) -> Option<[u8; 4]> {
        self.get(INTERNAL_IP4_ADDRESS)?.ipv4()
    }

    /// The DNS servers from a reply.
    pub fn internal_ip4_dns(&self) -> Vec<[u8; 4]> {
        self.get_all(INTERNAL_IP4_DNS)
            .filter_map(ConfigAttribute::ipv4)
            .collect()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.attributes.len() * 4);
        out.push(self.kind);
        out.extend_from_slice(&[0, 0, 0]);
        for a in &self.attributes {
            a.encode_into(&mut out);
        }
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Malformed("CP payload too short"));
        }
        let kind = body[0];
        let mut attributes = Vec::new();
        let mut at = 4;
        while at < body.len() {
            if at + 4 > body.len() {
                return Err(IkeError::Malformed("CP attribute header truncated"));
            }
            let attribute_kind = u16::from_be_bytes([body[at], body[at + 1]]) & 0x7fff;
            let len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            let value_at = at + 4;
            let value_end = value_at
                .checked_add(len)
                .ok_or(IkeError::Malformed("CP attribute length overflow"))?;
            let value = body
                .get(value_at..value_end)
                .ok_or(IkeError::Malformed("CP attribute truncated"))?;
            attributes.push(ConfigAttribute {
                kind: attribute_kind,
                value: value.to_vec(),
            });
            // Skip the value plus its 4-octet padding.
            at = value_end + ((4 - (len % 4)) % 4);
        }
        Ok(Self { kind, attributes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_asks_for_types_without_values() {
        let cp = ConfigPayload::s2b_request();
        assert_eq!(cp.kind, CFG_REQUEST);
        assert_eq!(cp.attributes.len(), 2);
        assert_eq!(cp.attributes[0].kind, INTERNAL_IP4_ADDRESS);
        assert!(cp.attributes[0].value.is_empty());
        assert_eq!(cp.encode(), vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0]);
    }

    #[test]
    fn a_reply_round_trips() {
        let cp = ConfigPayload::reply(vec![
            ConfigAttribute::new(INTERNAL_IP4_ADDRESS, [10, 1, 2, 3]),
            ConfigAttribute::new(INTERNAL_IP4_DNS, [10, 1, 2, 4]),
            ConfigAttribute::new(INTERNAL_IP4_DNS, [10, 1, 2, 5]),
        ]);
        let bytes = cp.encode();
        let decoded = ConfigPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, cp);
        assert_eq!(decoded.kind, CFG_REPLY);
        assert_eq!(decoded.internal_ip4_address(), Some([10, 1, 2, 3]));
        assert_eq!(
            decoded.internal_ip4_dns(),
            vec![[10, 1, 2, 4], [10, 1, 2, 5]]
        );
    }

    #[test]
    fn an_odd_length_value_is_padded_to_four_octets() {
        // APPLICATION_VERSION is a string, so its length is not a multiple of 4.
        let cp = ConfigPayload::reply(vec![ConfigAttribute::new(
            APPLICATION_VERSION,
            b"hyphae".to_vec(),
        )]);
        let bytes = cp.encode();
        // 4 header + 4 attribute header + 6 value + 2 padding.
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[8..14], b"hyphae");
        assert_eq!(&bytes[14..], &[0, 0]);
        let decoded = ConfigPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.attributes[0].text(), Some("hyphae"));
    }

    #[test]
    fn a_truncated_attribute_is_rejected() {
        // Claims 8 octets of value but only carries 2.
        let bytes = vec![2, 0, 0, 0, 0, 1, 0, 8, 1, 2];
        assert!(ConfigPayload::decode(&bytes).is_err());
    }

    #[test]
    fn a_reply_without_an_address_yields_none() {
        let cp = ConfigPayload::reply(vec![ConfigAttribute::new(INTERNAL_IP4_DNS, [10, 0, 0, 1])]);
        assert_eq!(cp.internal_ip4_address(), None);
        assert_eq!(cp.internal_ip4_dns(), vec![[10, 0, 0, 1]]);
    }
}
