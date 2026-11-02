//! IKE_SA_INIT initiator (RFC 7296 §2.1, §3.3–3.4).
//!
//! The initiator sends `SAi1, KEi, Ni`; the responder answers with
//! `SAr1, KEr, Nr[, CERTREQ]`. Both sides then compute `g^ir` and run the key
//! schedule. This module is the initiator half only — enough to make the first
//! two messages of an ePDG exchange correct.
//!
//! ```text
//! I --> R : SAi1, KEi, Ni
//! I <-- R : SAr1, KEr, Nr
//!           SKEYSEED = prf(Ni | Nr, g^ir)
//! ```

#![forbid(unsafe_code)]

use crate::dh::{DhError, DhKeyPair};
use crate::ikev2::{
    ExchangeType, Header, IkeError, Ke, Message, Payload, PayloadType, Proposal, Sa, Transform,
    FLAG_RESPONSE, PROTO_ESP, TRANSFORM_DH, TRANSFORM_ENCR, TRANSFORM_INTEG, TRANSFORM_PRF,
};
use crate::keys::{derive_keys, skeyseed, IkeKeySizes, IkeKeys};

/// Errors from the SA_INIT handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaError {
    Dh(DhError),
    Ike(IkeError),
    /// The response carried no SA proposal.
    MissingSa,
    /// The response's KE group differs from the one we proposed.
    GroupMismatch {
        ours: u16,
        theirs: u16,
    },
    /// The response carried no nonce.
    MissingNonce,
    /// The responder answered with a non-response flag.
    NotAResponse,
}

impl core::fmt::Display for SaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SaError::Dh(e) => write!(f, "DH error: {e}"),
            SaError::Ike(e) => write!(f, "IKE error: {e}"),
            SaError::MissingSa => f.write_str("IKE_SA_INIT response carried no SA"),
            SaError::GroupMismatch { ours, theirs } => {
                write!(
                    f,
                    "DH group mismatch: we proposed {ours}, responder chose {theirs}"
                )
            }
            SaError::MissingNonce => f.write_str("IKE_SA_INIT response carried no nonce"),
            SaError::NotAResponse => f.write_str("IKE_SA_INIT reply is not marked as a response"),
        }
    }
}

impl std::error::Error for SaError {}

impl From<DhError> for SaError {
    fn from(e: DhError) -> Self {
        SaError::Dh(e)
    }
}

impl From<IkeError> for SaError {
    fn from(e: IkeError) -> Self {
        SaError::Ike(e)
    }
}

/// The IKE_SA_INIT initiator state.
#[derive(Debug, Clone)]
pub struct SaInitInitiator {
    header: Header,
    keypair: DhKeyPair,
    nonce_i: Vec<u8>,
    responder_spi: Option<[u8; 8]>,
}

impl SaInitInitiator {
    /// Build the initiator from a caller-supplied SPI, DH exponent and nonce.
    pub fn new(
        initiator_spi: [u8; 8],
        private_exponent: &[u8],
        nonce_i: Vec<u8>,
        dh_group: u16,
    ) -> Result<Self, SaError> {
        Ok(Self {
            header: Header {
                initiator_spi,
                responder_spi: [0; 8],
                next_payload: PayloadType::Sa,
                exchange: ExchangeType::IkeSaInit,
                flags: crate::ikev2::FLAG_INITIATOR,
                message_id: 0,
            },
            keypair: DhKeyPair::from_private(dh_group, private_exponent)?,
            nonce_i,
            responder_spi: None,
        })
    }

    /// The `SAi1, KEi, Ni` message.
    pub fn first_message(&self) -> Message {
        let sa = Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol_id: PROTO_ESP,
                spi: vec![],
                transforms: vec![
                    Transform {
                        transform_type: TRANSFORM_ENCR,
                        id: 12, // ENCR_AES_CBC
                        attributes: vec![],
                    },
                    Transform {
                        transform_type: TRANSFORM_PRF,
                        id: 5, // PRF_HMAC_SHA2_256
                        attributes: vec![],
                    },
                    Transform {
                        transform_type: TRANSFORM_INTEG,
                        id: 12, // AUTH_HMAC_SHA2_256_128
                        attributes: vec![],
                    },
                    Transform {
                        transform_type: TRANSFORM_DH,
                        id: self.keypair.group(),
                        attributes: vec![],
                    },
                ],
            }],
        };
        Message {
            header: self.header,
            payloads: vec![
                Payload {
                    kind: PayloadType::Sa,
                    critical: false,
                    body: sa.encode(),
                },
                Payload {
                    kind: PayloadType::Ke,
                    critical: false,
                    body: Ke {
                        dh_group: self.keypair.group(),
                        key_data: self.keypair.public_bytes(),
                    }
                    .encode(),
                },
                Payload {
                    kind: PayloadType::Nonce,
                    critical: false,
                    body: self.nonce_i.clone(),
                },
            ],
        }
    }

    /// Consume the responder's `SAr1, KEr, Nr` and derive the IKE SA keys.
    pub fn on_response(
        &mut self,
        message: &Message,
        sizes: IkeKeySizes,
    ) -> Result<IkeKeys, SaError> {
        if message.header.flags & FLAG_RESPONSE == 0 {
            return Err(SaError::NotAResponse);
        }
        let sa = message.find(PayloadType::Sa).ok_or(SaError::MissingSa)?;
        Sa::decode(&sa.body)?;
        let ke = message
            .find(PayloadType::Ke)
            .ok_or(SaError::Ike(IkeError::Malformed("missing KE")))?;
        let ke = Ke::decode(&ke.body)?;
        if ke.dh_group != self.keypair.group() {
            return Err(SaError::GroupMismatch {
                ours: self.keypair.group(),
                theirs: ke.dh_group,
            });
        }
        let nonce_r = message
            .find(PayloadType::Nonce)
            .ok_or(SaError::MissingNonce)?
            .body
            .clone();
        let shared = self.keypair.agree(&ke.key_data)?;
        let seed = skeyseed(&self.nonce_i, &nonce_r, &shared);
        self.responder_spi = Some(message.header.responder_spi);
        Ok(derive_keys(&seed, &self.nonce_i, &nonce_r, sizes))
    }

    pub fn nonce_i(&self) -> &[u8] {
        &self.nonce_i
    }

    pub fn initiator_spi(&self) -> [u8; 8] {
        self.header.initiator_spi
    }

    pub fn responder_spi(&self) -> Option<[u8; 8]> {
        self.responder_spi
    }
}

/// Build a responder's `SAr1, KEr, Nr` — used by the tests and by a lab peer.
pub fn sa_init_response(
    request: &Message,
    responder_spi: [u8; 8],
    private_exponent: &[u8],
    nonce_r: Vec<u8>,
    dh_group: u16,
) -> Result<Message, SaError> {
    let _ = request;
    let keypair = DhKeyPair::from_private(dh_group, private_exponent)?;
    let header = Header {
        initiator_spi: request.header.initiator_spi,
        responder_spi,
        next_payload: PayloadType::Sa,
        exchange: ExchangeType::IkeSaInit,
        flags: FLAG_RESPONSE,
        message_id: 0,
    };
    Ok(Message {
        header,
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
                                transform_type: TRANSFORM_DH,
                                id: dh_group,
                                attributes: vec![],
                            },
                        ],
                    }],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Ke,
                critical: false,
                body: Ke {
                    dh_group,
                    key_data: keypair.public_bytes(),
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Nonce,
                critical: false,
                body: nonce_r,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::DhKeyPair;
    use crate::ikev2::FLAG_INITIATOR;

    #[test]
    fn sa_init_produces_the_expected_first_message() {
        let initiator = SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let msg = initiator.first_message();
        assert_eq!(msg.header.exchange, ExchangeType::IkeSaInit);
        assert_eq!(msg.header.flags, FLAG_INITIATOR);
        assert_eq!(msg.header.next_payload, PayloadType::Sa);
        assert_eq!(msg.payloads[0].kind, PayloadType::Sa);
        assert_eq!(msg.payloads[1].kind, PayloadType::Ke);
        assert_eq!(msg.payloads[2].kind, PayloadType::Nonce);
        // It is a well-formed IKEv2 message on the wire.
        let bytes = msg.encode();
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
        assert_eq!(&bytes[..8], &[0x11; 8]);
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let initiator = SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let request = initiator.first_message();

        let response =
            sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 14).unwrap();

        // Initiator path.
        let mut initiator = initiator;
        let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
        let i_keys = initiator.on_response(&response, sizes).unwrap();
        assert_eq!(initiator.responder_spi(), Some([0x44; 8]));

        // Responder path: the same shared secret and nonces.
        let responder = DhKeyPair::from_private(14, &[0x55; 32]).unwrap();
        let initiator_ke = Ke::decode(&request.find(PayloadType::Ke).unwrap().body).unwrap();
        let shared = responder.agree(&initiator_ke.key_data).unwrap();
        let seed = skeyseed(&[0x33; 32], &[0x66; 32], &shared);
        let r_keys = derive_keys(&seed, &[0x33; 32], &[0x66; 32], sizes);
        assert_eq!(i_keys, r_keys);
    }

    #[test]
    fn a_group_mismatch_is_rejected() {
        let mut initiator =
            SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let request = initiator.first_message();
        // Responder picks a different group.
        let response =
            sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 15).unwrap();
        assert_eq!(
            initiator.on_response(&response, IkeKeySizes::aes_cbc_128_sha256_128()),
            Err(SaError::GroupMismatch {
                ours: 14,
                theirs: 15
            })
        );
    }

    #[test]
    fn a_non_response_is_rejected() {
        let mut initiator =
            SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let request = initiator.first_message();
        let mut response =
            sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 14).unwrap();
        response.header.flags = FLAG_INITIATOR; // not a response
        assert_eq!(
            initiator.on_response(&response, IkeKeySizes::aes_cbc_128_sha256_128()),
            Err(SaError::NotAResponse)
        );
    }

    #[test]
    fn a_missing_nonce_is_rejected() {
        let mut initiator =
            SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let request = initiator.first_message();
        let mut response =
            sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 14).unwrap();
        response.payloads.retain(|p| p.kind != PayloadType::Nonce);
        assert_eq!(
            initiator.on_response(&response, IkeKeySizes::aes_cbc_128_sha256_128()),
            Err(SaError::MissingNonce)
        );
    }

    #[test]
    fn messages_round_trip_through_the_codec() {
        let initiator = SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
        let request = initiator.first_message();
        let response =
            sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 14).unwrap();
        let bytes = response.encode();
        assert_eq!(Message::decode(&bytes).unwrap(), response);
        assert_eq!(bytes.len() % 4, 0, "IKEv2 messages are 4-octet aligned");
    }
}
