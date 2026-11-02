//! The child SA created by IKE_AUTH — the S2b bearer (RFC 7296 §2.17, §3.3).
//!
//! [`crate::ike_auth`] finishes with raw `KEYMAT` octets. This module turns
//! those octets into something a kernel can be programmed with: two directions
//! with their SPIs, an encryption algorithm, an integrity algorithm, and the
//! traffic selectors the exchange agreed on.
//!
//! Two rules govern the split, and both are easy to get backwards:
//!
//! 1. Keys are taken from the KEYMAT **in the order the transforms appear in
//!    the proposal**, and the **initiator→responder** direction comes first
//!    (RFC 7296 §2.17).
//! 2. The SA payload in the final IKE_AUTH response carries the *responder's*
//!    SPI — the one we must stamp on packets we send. Our own SPI, the one the
//!    responder stamps on packets it sends us, was chosen when we built `SAi2`.

#![forbid(unsafe_code)]

use crate::ikev2::{
    IkeError, Message, PayloadType, Proposal, Sa, Selector, TrafficSelectors, PROTO_ESP,
    TRANSFORM_ENCR, TRANSFORM_INTEG,
};

/// ENCR_AES_CBC (RFC 7296 §3.3.2). The key length comes from `KEY_LENGTH`.
pub const ENCR_AES_CBC: u16 = 12;
/// ENCR_NULL.
pub const ENCR_NULL: u16 = 11;
/// AUTH_HMAC_SHA2_256_128 (RFC 4868): a 256-bit key, a 128-bit ICV.
pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
/// Transform attribute type `KEY_LENGTH`, in bits.
pub const ATTR_KEY_LENGTH: u16 = 14;

/// Errors while building a child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildError {
    Ike(IkeError),
    /// The responder answered with something this tree does not implement.
    Unsupported(&'static str),
    /// No ESP proposal in the responder's SA payload.
    NoEspProposal,
    /// The response carried no traffic selectors.
    NoTrafficSelectors,
    /// The KEYMAT was shorter than the negotiated transforms need.
    ShortKeymat {
        need: usize,
        got: usize,
    },
}

impl core::fmt::Display for ChildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChildError::Ike(e) => write!(f, "IKE error: {e}"),
            ChildError::Unsupported(what) => write!(f, "unsupported child SA {what}"),
            ChildError::NoEspProposal => f.write_str("no ESP proposal in the child SA"),
            ChildError::NoTrafficSelectors => f.write_str("no traffic selectors in the response"),
            ChildError::ShortKeymat { need, got } => {
                write!(f, "child KEYMAT is {got} octets, need {need}")
            }
        }
    }
}

impl std::error::Error for ChildError {}

impl From<IkeError> for ChildError {
    fn from(e: IkeError) -> Self {
        ChildError::Ike(e)
    }
}

/// The encryption algorithm of one direction of the child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildEncryption {
    /// AES-CBC with a 128/192/256-bit key.
    AesCbc { key: Vec<u8> },
}

impl ChildEncryption {
    /// The key this direction uses.
    pub fn key(&self) -> &[u8] {
        match self {
            ChildEncryption::AesCbc { key } => key,
        }
    }

    /// The `ip xfrm` algorithm name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            ChildEncryption::AesCbc { .. } => "cbc(aes)",
        }
    }
}

/// The integrity algorithm of one direction of the child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildIntegrity {
    /// HMAC-SHA-256 truncated to 128 bits.
    HmacSha256_128 { key: Vec<u8> },
}

impl ChildIntegrity {
    /// The key this direction uses.
    pub fn key(&self) -> &[u8] {
        match self {
            ChildIntegrity::HmacSha256_128 { key } => key,
        }
    }

    /// The `ip xfrm` algorithm name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            ChildIntegrity::HmacSha256_128 { .. } => "hmac(sha256)",
        }
    }

    /// The ICV length in octets.
    pub fn icv_len(&self) -> usize {
        match self {
            ChildIntegrity::HmacSha256_128 { .. } => 16,
        }
    }
}

/// One direction of the child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildDirection {
    /// The SPI stamped on packets in this direction.
    pub spi: u32,
    pub encryption: ChildEncryption,
    pub integrity: ChildIntegrity,
}

/// A negotiated child SA: the S2b bearer between the UE and the ePDG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildSa {
    /// UE → ePDG; carries the responder's SPI.
    pub outbound: ChildDirection,
    /// ePDG → UE; carries the SPI we chose in `SAi2`.
    pub inbound: ChildDirection,
    /// The initiator's traffic selectors (what we asked to send).
    pub tsi: Vec<Selector>,
    /// The responder's traffic selectors (what it narrowed to).
    pub tsr: Vec<Selector>,
}

impl ChildSa {
    /// Build the child SA from the final IKE_AUTH response.
    ///
    /// `local_spi` is the SPI placed in `SAi2`; `keymat` is the octet string
    /// from [`crate::auth::child_keymat`].
    pub fn from_response(
        response: &Message,
        local_spi: u32,
        keymat: &[u8],
    ) -> Result<Self, ChildError> {
        let sa = response
            .find(PayloadType::Sa)
            .ok_or(ChildError::NoEspProposal)?;
        let sa = Sa::decode(&sa.body)?;
        let proposal = sa
            .proposals
            .iter()
            .find(|p| p.protocol_id == PROTO_ESP)
            .ok_or(ChildError::NoEspProposal)?;

        let tsi = response
            .find(PayloadType::Tsi)
            .ok_or(ChildError::NoTrafficSelectors)?;
        let tsr = response
            .find(PayloadType::Tsr)
            .ok_or(ChildError::NoTrafficSelectors)?;
        let tsi = TrafficSelectors::decode(&tsi.body)?.selectors;
        let tsr = TrafficSelectors::decode(&tsr.body)?.selectors;

        Self::from_proposal(proposal, local_spi, keymat, tsi, tsr)
    }

    /// Build the child SA from a proposal and both traffic-selector lists.
    pub fn from_proposal(
        proposal: &Proposal,
        local_spi: u32,
        keymat: &[u8],
        tsi: Vec<Selector>,
        tsr: Vec<Selector>,
    ) -> Result<Self, ChildError> {
        if proposal.protocol_id != PROTO_ESP {
            return Err(ChildError::Unsupported("protocol is not ESP"));
        }
        if proposal.spi.len() != 4 {
            return Err(ChildError::Unsupported("ESP SPI is not 4 octets"));
        }
        let remote_spi = u32::from_be_bytes([
            proposal.spi[0],
            proposal.spi[1],
            proposal.spi[2],
            proposal.spi[3],
        ]);

        // Two directions, initiator→responder first, each consuming the keys in
        // the order the transforms are listed (RFC 7296 §2.17).
        let mut at = 0;
        let mut direction = |spi: u32| -> Result<ChildDirection, ChildError> {
            let mut encryption = None;
            let mut integrity = None;
            for t in &proposal.transforms {
                match t.transform_type {
                    TRANSFORM_ENCR => {
                        if encryption.is_some() {
                            return Err(ChildError::Unsupported("two encryption transforms"));
                        }
                        let len = encryption_key_len(t.id, &t.attributes)?;
                        let key = take(keymat, &mut at, len)?.to_vec();
                        encryption = Some(ChildEncryption::AesCbc { key });
                    }
                    TRANSFORM_INTEG => {
                        if integrity.is_some() {
                            return Err(ChildError::Unsupported("two integrity transforms"));
                        }
                        let len = integrity_key_len(t.id)?;
                        let key = take(keymat, &mut at, len)?.to_vec();
                        integrity = Some(ChildIntegrity::HmacSha256_128 { key });
                    }
                    // Other transform types carry no key material of their own.
                    _ => {}
                }
            }
            Ok(ChildDirection {
                spi,
                encryption: encryption.ok_or(ChildError::Unsupported("no ENCR transform"))?,
                integrity: integrity.ok_or(ChildError::Unsupported("no INTEG transform"))?,
            })
        };

        let outbound = direction(remote_spi)?;
        let inbound = direction(local_spi)?;

        Ok(Self {
            outbound,
            inbound,
            tsi,
            tsr,
        })
    }

    /// The total key material the proposal consumes, in octets.
    pub fn keymat_len(proposal: &Proposal) -> Result<usize, ChildError> {
        let mut total = 0;
        for _ in 0..2 {
            for t in &proposal.transforms {
                total += match t.transform_type {
                    TRANSFORM_ENCR => encryption_key_len(t.id, &t.attributes)?,
                    TRANSFORM_INTEG => integrity_key_len(t.id)?,
                    _ => 0,
                };
            }
        }
        Ok(total)
    }
}

fn take<'a>(keymat: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8], ChildError> {
    let end = *at + len;
    keymat.get(*at..end).ok_or(ChildError::ShortKeymat {
        need: end,
        got: keymat.len(),
    })?;
    let slice = &keymat[*at..end];
    *at = end;
    Ok(slice)
}

/// The key length in octets for an ENCR transform.
fn encryption_key_len(id: u16, attributes: &[u8]) -> Result<usize, ChildError> {
    match id {
        ENCR_AES_CBC => {
            // KEY_LENGTH is in bits (RFC 7296 §3.3.2); absent means AES-128.
            let bits = attribute(attributes, ATTR_KEY_LENGTH).unwrap_or(128);
            let bytes = (bits / 8) as usize;
            // AES only defines 128, 192 and 256-bit keys (FIPS 197 §5).
            if !matches!(bytes, 16 | 24 | 32) {
                return Err(ChildError::Unsupported("AES key length"));
            }
            Ok(bytes)
        }
        ENCR_NULL => Err(ChildError::Unsupported("ENCR_NULL for S2b")),
        _ => Err(ChildError::Unsupported("encryption algorithm")),
    }
}

/// The key length in octets for an INTEG transform.
fn integrity_key_len(id: u16) -> Result<usize, ChildError> {
    match id {
        // AUTH_HMAC_SHA2_256_128 uses a 256-bit key (RFC 4868 §2.2).
        AUTH_HMAC_SHA2_256_128 => Ok(32),
        _ => Err(ChildError::Unsupported("integrity algorithm")),
    }
}

/// Read a transform attribute, handling both the TV and TLV forms
/// (RFC 7296 §3.3): `AF=1` means a 15-bit type and a 2-octet value inline.
fn attribute(attributes: &[u8], wanted: u16) -> Option<u16> {
    let mut at = 0;
    while at + 4 <= attributes.len() {
        let first = attributes[at];
        let af = first & 0x80 != 0;
        let kind = u16::from_be_bytes([first & 0x7f, attributes[at + 1]]);
        if af {
            if kind == wanted {
                return Some(u16::from_be_bytes([attributes[at + 2], attributes[at + 3]]));
            }
            at += 4;
        } else {
            let len = u16::from_be_bytes([attributes[at + 2], attributes[at + 3]]) as usize;
            let value_at = at + 4;
            let value_end = value_at.checked_add(len)?;
            if kind == wanted && len == 2 {
                return Some(u16::from_be_bytes([
                    *attributes.get(value_at)?,
                    *attributes.get(value_at + 1)?,
                ]));
            }
            if value_end > attributes.len() {
                return None;
            }
            at = value_end + ((4 - (len % 4)) % 4);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::{Proposal, Transform};

    fn proposal(encr: u16, integ: u16, attributes: Vec<u8>) -> Proposal {
        Proposal {
            number: 1,
            protocol_id: PROTO_ESP,
            spi: vec![0xAB, 0xCD, 0xEF, 0x01],
            transforms: vec![
                Transform {
                    transform_type: TRANSFORM_ENCR,
                    id: encr,
                    attributes,
                },
                Transform {
                    transform_type: TRANSFORM_INTEG,
                    id: integ,
                    attributes: vec![],
                },
            ],
        }
    }

    fn keymat(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    #[test]
    fn keys_split_initiator_to_responder_first() {
        // AES-CBC-128 (16) + HMAC-SHA-256 (32) per direction = 96 octets.
        let p = proposal(
            ENCR_AES_CBC,
            AUTH_HMAC_SHA2_256_128,
            vec![0x80, 0x0E, 0x00, 0x80],
        );
        assert_eq!(ChildSa::keymat_len(&p).unwrap(), 96);
        let km = keymat(96);
        let sa = ChildSa::from_proposal(&p, 0x11223344, &km, vec![], vec![]).unwrap();

        // Outbound is the responder's SPI, inbound is ours.
        assert_eq!(sa.outbound.spi, 0xABCDEF01);
        assert_eq!(sa.inbound.spi, 0x11223344);
        // Outbound takes the first 16 octets as the AES key, then 32 as the HMAC key.
        assert_eq!(sa.outbound.encryption.key(), &km[0..16]);
        assert_eq!(sa.outbound.integrity.key(), &km[16..48]);
        // Inbound takes the next 48.
        assert_eq!(sa.inbound.encryption.key(), &km[48..64]);
        assert_eq!(sa.inbound.integrity.key(), &km[64..96]);
    }

    #[test]
    fn aes_256_uses_the_key_length_attribute() {
        let p = proposal(
            ENCR_AES_CBC,
            AUTH_HMAC_SHA2_256_128,
            vec![0x80, 0x0E, 0x01, 0x00],
        );
        assert_eq!(ChildSa::keymat_len(&p).unwrap(), 128);
        let km = keymat(128);
        let sa = ChildSa::from_proposal(&p, 1, &km, vec![], vec![]).unwrap();
        assert_eq!(sa.outbound.encryption.key().len(), 32);
    }

    #[test]
    fn aes_128_is_the_default_without_a_key_length() {
        let p = proposal(ENCR_AES_CBC, AUTH_HMAC_SHA2_256_128, vec![]);
        assert_eq!(ChildSa::keymat_len(&p).unwrap(), 96);
    }

    #[test]
    fn a_tlv_key_length_attribute_is_also_accepted() {
        // AF=0 (TLV): type 14, length 2, value 256, then 2 octets of padding.
        let p = proposal(
            ENCR_AES_CBC,
            AUTH_HMAC_SHA2_256_128,
            vec![0x00, 0x0E, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00],
        );
        assert_eq!(ChildSa::keymat_len(&p).unwrap(), 128);
    }

    #[test]
    fn short_keymat_is_rejected() {
        let p = proposal(ENCR_AES_CBC, AUTH_HMAC_SHA2_256_128, vec![]);
        assert_eq!(
            ChildSa::from_proposal(&p, 1, &keymat(95), vec![], vec![]),
            Err(ChildError::ShortKeymat { need: 96, got: 95 })
        );
    }

    #[test]
    fn an_unsupported_encryption_algorithm_is_rejected() {
        let p = proposal(ENCR_NULL, AUTH_HMAC_SHA2_256_128, vec![]);
        assert_eq!(
            ChildSa::from_proposal(&p, 1, &keymat(96), vec![], vec![]),
            Err(ChildError::Unsupported("ENCR_NULL for S2b"))
        );
    }

    #[test]
    fn an_unsupported_integrity_algorithm_is_rejected() {
        // AUTH_HMAC_MD5_96 is not what S2b negotiates here.
        let p = proposal(ENCR_AES_CBC, 1, vec![]);
        assert_eq!(
            ChildSa::from_proposal(&p, 1, &keymat(96), vec![], vec![]),
            Err(ChildError::Unsupported("integrity algorithm"))
        );
    }

    #[test]
    fn a_non_esp_proposal_is_rejected() {
        let mut p = proposal(ENCR_AES_CBC, AUTH_HMAC_SHA2_256_128, vec![]);
        p.protocol_id = 51; // AH
        assert_eq!(
            ChildSa::from_proposal(&p, 1, &keymat(96), vec![], vec![]),
            Err(ChildError::Unsupported("protocol is not ESP"))
        );
    }

    #[test]
    fn xfrm_names_match_the_negotiated_algorithms() {
        let p = proposal(ENCR_AES_CBC, AUTH_HMAC_SHA2_256_128, vec![]);
        let sa = ChildSa::from_proposal(&p, 1, &keymat(96), vec![], vec![]).unwrap();
        assert_eq!(sa.outbound.encryption.xfrm_name(), "cbc(aes)");
        assert_eq!(sa.outbound.integrity.xfrm_name(), "hmac(sha256)");
        assert_eq!(sa.outbound.integrity.icv_len(), 16);
    }
}
