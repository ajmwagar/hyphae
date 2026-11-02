//! IKE_AUTH with EAP-AKA' (RFC 5998 EAP-only authentication, RFC 7296 §2.2).
//!
//! The exchange this drives:
//!
//! ```text
//! I -> R : SK{ IDi, SAi2, TSi, TSr, N(EAP_ONLY_AUTHENTICATION) }
//! I <- R : SK{ IDr, EAP(Request/AKA'-Challenge) }
//! I -> R : SK{ EAP(Response/AKA'-Challenge) }
//! I <- R : SK{ EAP(Success) }
//! I -> R : SK{ AUTH }                       AUTH = prf(MSK, ...)
//! I <- R : SK{ AUTH, SAr2, TSi, TSr }
//! ```
//!
//! The state machine owns the message counter, the identity and the child-SA
//! SPI. The caller supplies a fresh IV per message, because this crate has no
//! RNG.

#![forbid(unsafe_code)]

use crate::auth::{
    auth_payload, child_keymat, constant_time_eq, signed_octets_initiator, signed_octets_responder,
};
use crate::child::{ChildError, ChildSa};
use crate::cp::ConfigPayload;
use crate::eap::{AkaPrimePeer, EapPacket, EAP_SUCCESS};
use crate::ikev2::{
    ExchangeType, Header, Id, IkeError, Message, Notify, Payload, PayloadType, Proposal, Sa,
    Selector, TrafficSelectors, Transform, FLAG_INITIATOR, FLAG_RESPONSE, ID_RFC822_ADDR,
    PROTO_ESP, TRANSFORM_ENCR, TRANSFORM_INTEG,
};
use crate::keys::IkeKeys;
use crate::sk::{Sk, SkError, BLOCK_LEN};

/// Notify type: the initiator only supports EAP authentication (RFC 5998 §3).
pub const N_EAP_ONLY_AUTHENTICATION: u16 = 16417;
/// Notify type: no additional authentication is needed (RFC 7296 §3.10).
pub const N_NO_ADDITIONAL_AUTH: u16 = 16414;

/// Errors from the IKE_AUTH exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Sk(SkError),
    Ike(IkeError),
    /// The responder asked for something this exchange does not handle.
    Unexpected(&'static str),
    /// The responder's AUTH payload did not verify.
    BadResponderAuth,
    /// EAP failed or was rejected.
    EapFailed,
    /// The child SA could not be built from the responder's answer.
    Child(ChildError),
    /// The EAP peer rejected the exchange.
    Eap(String),
    /// A message arrived out of order.
    OutOfOrder(&'static str),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::Sk(e) => write!(f, "SK error: {e}"),
            AuthError::Ike(e) => write!(f, "IKE error: {e}"),
            AuthError::Unexpected(what) => write!(f, "unexpected IKE_AUTH content: {what}"),
            AuthError::BadResponderAuth => f.write_str("responder AUTH did not verify"),
            AuthError::EapFailed => f.write_str("EAP authentication failed"),
            AuthError::Child(e) => write!(f, "child SA: {e}"),
            AuthError::Eap(what) => write!(f, "EAP error: {what}"),
            AuthError::OutOfOrder(what) => write!(f, "IKE_AUTH out of order: {what}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<SkError> for AuthError {
    fn from(e: SkError) -> Self {
        AuthError::Sk(e)
    }
}

impl From<IkeError> for AuthError {
    fn from(e: IkeError) -> Self {
        AuthError::Ike(e)
    }
}

impl From<ChildError> for AuthError {
    fn from(e: ChildError) -> Self {
        AuthError::Child(e)
    }
}

impl From<crate::eap::EapPeerError> for AuthError {
    fn from(e: crate::eap::EapPeerError) -> Self {
        AuthError::Eap(e.to_string())
    }
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStep {
    /// Send this sealed message and wait for the reply.
    Send(Vec<u8>),
    /// The tunnel is authenticated. The child SA carries the SPIs, algorithms
    /// and traffic selectors a kernel needs; `config` is the ePDG's CFG_REPLY
    /// with the IMS address, when the responder sent one.
    Established {
        child: ChildSa,
        config: Option<ConfigPayload>,
        child_keys: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    AwaitingChallenge,
    AwaitingSuccess,
    AwaitingFinalAuth,
    Done,
}

/// The initiator side of an EAP-only IKE_AUTH exchange.
pub struct IkeAuthInitiator {
    keys: IkeKeys,
    initiator_spi: [u8; 8],
    responder_spi: [u8; 8],
    nonce_i: Vec<u8>,
    nonce_r: Vec<u8>,
    real_message1: Vec<u8>,
    real_message2: Vec<u8>,
    identity: Vec<u8>,
    child_spi: [u8; 4],
    message_id: u32,
    phase: Phase,
    msk: Option<Vec<u8>>,
    id_r_body: Option<Vec<u8>>,
}

impl IkeAuthInitiator {
    /// Build the state machine after a successful IKE_SA_INIT.
    ///
    /// `real_message1` / `real_message2` are the SA_INIT messages as sent, and
    /// `identity` is the NAI placed in `IDi`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        keys: IkeKeys,
        initiator_spi: [u8; 8],
        responder_spi: [u8; 8],
        nonce_i: Vec<u8>,
        nonce_r: Vec<u8>,
        real_message1: Vec<u8>,
        real_message2: Vec<u8>,
        identity: &str,
        child_spi: [u8; 4],
    ) -> Self {
        Self {
            keys,
            initiator_spi,
            responder_spi,
            nonce_i,
            nonce_r,
            real_message1,
            real_message2,
            identity: identity.as_bytes().to_vec(),
            child_spi,
            message_id: 1,
            phase: Phase::AwaitingChallenge,
            msk: None,
            id_r_body: None,
        }
    }

    /// The first IKE_AUTH request: `SK{ IDi, SAi2, TSi, TSr, N(EAP_ONLY) }`.
    pub fn first_request(&self, iv: &[u8; BLOCK_LEN]) -> Result<Vec<u8>, AuthError> {
        let payloads = vec![
            Payload {
                kind: PayloadType::Idi,
                critical: false,
                body: Id {
                    id_type: ID_RFC822_ADDR,
                    data: self.identity.clone(),
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Config,
                critical: false,
                body: ConfigPayload::s2b_request().encode(),
            },
            Payload {
                kind: PayloadType::Sa,
                critical: false,
                body: self.child_sa_proposal().encode(),
            },
            Payload {
                kind: PayloadType::Tsi,
                critical: false,
                body: any_ipv4().encode(),
            },
            Payload {
                kind: PayloadType::Tsr,
                critical: false,
                body: any_ipv4().encode(),
            },
            Payload {
                kind: PayloadType::Notify,
                critical: false,
                body: Notify {
                    protocol_id: 0,
                    notify_type: N_EAP_ONLY_AUTHENTICATION,
                    spi: Vec::new(),
                    data: Vec::new(),
                }
                .encode(),
            },
        ];
        self.seal(payloads, iv)
    }

    /// Consume one IKE_AUTH response.
    pub fn on_response(
        &mut self,
        bytes: &[u8],
        iv: &[u8; BLOCK_LEN],
        peer: &mut AkaPrimePeer,
    ) -> Result<AuthStep, AuthError> {
        let message = self.sk_in()?.open(bytes)?;
        if message.header.flags & FLAG_RESPONSE == 0 {
            return Err(AuthError::Unexpected("reply is not a response"));
        }
        if message.header.message_id != self.message_id {
            return Err(AuthError::OutOfOrder("message id mismatch"));
        }

        // Remember the responder identity for its AUTH computation.
        if let Some(idr) = message.find(PayloadType::Idr) {
            self.id_r_body = Some(idr.body.clone());
        }

        // An EAP payload drives the authentication.
        if let Some(eap) = message.find(PayloadType::Eap) {
            let parsed = EapPacket::parse(&eap.body)?;
            if parsed.code == EAP_SUCCESS {
                self.msk = Some(peer.keys().msk.to_vec());
                self.phase = Phase::AwaitingFinalAuth;
                // Every request starts a new exchange, so the counter moves
                // before the message is sealed, not after (RFC 7296 §2.2).
                self.message_id += 1;
                let auth = self.initiator_auth()?;
                let sealed = self.seal(
                    vec![Payload {
                        kind: PayloadType::Auth,
                        critical: false,
                        body: auth,
                    }],
                    iv,
                )?;
                return Ok(AuthStep::Send(sealed));
            }
            // Otherwise it is an EAP request: answer it.
            let response = peer.on_request(&eap.body)?;
            self.message_id += 1;
            let sealed = self.seal(
                vec![Payload {
                    kind: PayloadType::Eap,
                    critical: false,
                    body: response,
                }],
                iv,
            )?;
            self.phase = Phase::AwaitingSuccess;
            return Ok(AuthStep::Send(sealed));
        }

        // The final responder message carries AUTH.
        if let Some(auth) = message.find(PayloadType::Auth) {
            if self.phase != Phase::AwaitingFinalAuth {
                return Err(AuthError::OutOfOrder("AUTH before EAP success"));
            }
            self.verify_responder_auth(&auth.body)?;
            // 64 octets is enough for AES-256-CBC plus HMAC-SHA-256 in both
            // directions; the child SA only consumes what it needs.
            let child_keys = child_keymat(&self.keys.sk_d, &self.nonce_i, &self.nonce_r, 128);
            let child =
                ChildSa::from_response(&message, u32::from_be_bytes(self.child_spi), &child_keys)?;
            let config = message
                .find(PayloadType::Config)
                .map(|p| ConfigPayload::decode(&p.body))
                .transpose()?;
            self.phase = Phase::Done;
            return Ok(AuthStep::Established {
                child,
                config,
                child_keys,
            });
        }

        Err(AuthError::Unexpected("neither EAP nor AUTH"))
    }

    /// Open an inbound message without advancing the exchange.
    ///
    /// A caller needs this to inspect a challenge (a USIM has to see RAND
    /// before it can produce RES), which is why it is separate from
    /// [`Self::on_response`].
    pub fn peek(&self, bytes: &[u8]) -> Result<Message, AuthError> {
        Ok(self.sk_in()?.open(bytes)?)
    }

    /// Whether the exchange has completed.
    pub fn is_established(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Outbound keys: the initiator encrypts with SK_ei and signs with SK_ai.
    fn sk_out(&self) -> Result<Sk, AuthError> {
        Ok(Sk::aes_cbc_128_sha256_128(
            &self.keys.sk_ei,
            &self.keys.sk_ai,
        )?)
    }

    /// Inbound keys: responder traffic uses SK_er and SK_ar.
    fn sk_in(&self) -> Result<Sk, AuthError> {
        Ok(Sk::aes_cbc_128_sha256_128(
            &self.keys.sk_er,
            &self.keys.sk_ar,
        )?)
    }

    fn seal(&self, payloads: Vec<Payload>, iv: &[u8; BLOCK_LEN]) -> Result<Vec<u8>, AuthError> {
        let header = Header {
            initiator_spi: self.initiator_spi,
            responder_spi: self.responder_spi,
            next_payload: PayloadType::Encrypted,
            exchange: ExchangeType::IkeAuth,
            flags: FLAG_INITIATOR,
            message_id: self.message_id,
        };
        Ok(self.sk_out()?.seal(header, &payloads, iv))
    }

    fn initiator_auth(&self) -> Result<Vec<u8>, AuthError> {
        let msk = self.msk.as_ref().ok_or(AuthError::OutOfOrder("no MSK"))?;
        let signed = signed_octets_initiator(
            &self.real_message1,
            &self.nonce_r,
            &self.keys.sk_pi,
            &self.idi_body(),
        );
        Ok(auth_payload(msk, &signed))
    }

    fn verify_responder_auth(&self, received: &[u8]) -> Result<(), AuthError> {
        let msk = self.msk.as_ref().ok_or(AuthError::OutOfOrder("no MSK"))?;
        let idr = self
            .id_r_body
            .as_ref()
            .ok_or(AuthError::Unexpected("no IDr before AUTH"))?;
        let signed =
            signed_octets_responder(&self.real_message2, &self.nonce_i, &self.keys.sk_pr, idr);
        let expected = auth_payload(msk, &signed);
        if constant_time_eq(received, &expected) {
            Ok(())
        } else {
            Err(AuthError::BadResponderAuth)
        }
    }

    fn idi_body(&self) -> Vec<u8> {
        Id {
            id_type: ID_RFC822_ADDR,
            data: self.identity.clone(),
        }
        .encode()
    }

    fn child_sa_proposal(&self) -> Sa {
        Sa {
            proposals: vec![Proposal {
                number: 1,
                protocol_id: PROTO_ESP,
                spi: self.child_spi.to_vec(),
                transforms: vec![
                    Transform {
                        transform_type: TRANSFORM_ENCR,
                        id: 12,
                        attributes: vec![],
                    },
                    Transform {
                        transform_type: TRANSFORM_INTEG,
                        id: 12,
                        attributes: vec![],
                    },
                ],
            }],
        }
    }
}

fn any_ipv4() -> TrafficSelectors {
    TrafficSelectors {
        selectors: vec![Selector {
            ts_type: 7, // TS_IPV4_ADDR_RANGE
            ip_protocol: 0,
            start_port: 0,
            end_port: 0xffff,
            start_address: vec![0, 0, 0, 0],
            end_address: vec![255, 255, 255, 255],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eap::{
        AkaPrimePeer, EapPacket, AT_MAC, EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS,
        EAP_TYPE_AKA_PRIME, SUBTYPE_CHALLENGE,
    };
    use crate::ikev2::{Payload, PayloadType, Transform, TRANSFORM_ENCR, TRANSFORM_INTEG};
    use crate::keys::{derive_keys, skeyseed, IkeKeySizes};
    use aka::eap_aka_prime::{
        at_mac, attribute, ck_ik_prime, derive_keys as eap_keys, kdf_input_attribute, AT_MAC_LEN,
    };

    const NETWORK: &str = "WLAN";
    const IDENTITY: &str = "user@example";
    const RES: [u8; 8] = [0xA5; 8];

    struct Fixture {
        auth: IkeAuthInitiator,
        peer: AkaPrimePeer,
        keys: IkeKeys,
        eap: aka::eap_aka_prime::EapAkaPrimeKeys,
        iv: [u8; BLOCK_LEN],
    }

    fn fixture() -> Fixture {
        let (ck, ik) = ck_ik_prime(&[0x11; 16], &[0x22; 16], NETWORK).unwrap();
        let eap = eap_keys(&ck, &ik, NETWORK, IDENTITY, &[0x80, 0x00]).unwrap();
        let seed = skeyseed(&[0x33; 32], &[0x66; 32], &[0x77; 256]);
        let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
        let keys = derive_keys(&seed, &[0x33; 32], &[0x66; 32], sizes);
        let auth = IkeAuthInitiator::new(
            keys.clone(),
            [0x01; 8],
            [0x02; 8],
            vec![0x33; 32],
            vec![0x66; 32],
            b"real-message-1".to_vec(),
            b"real-message-2".to_vec(),
            IDENTITY,
            [0xDE, 0xAD, 0xBE, 0xEF],
        );
        let peer = AkaPrimePeer::new(NETWORK, eap.clone(), RES.to_vec());
        Fixture {
            auth,
            peer,
            keys,
            eap,
            iv: [0x55; BLOCK_LEN],
        }
    }

    /// Seal a responder message with the responder-direction SK keys.
    fn responder_message(
        keys: &IkeKeys,
        message_id: u32,
        payloads: Vec<Payload>,
        iv: &[u8; BLOCK_LEN],
    ) -> Vec<u8> {
        let sk = Sk::aes_cbc_128_sha256_128(&keys.sk_er, &keys.sk_ar).unwrap();
        let header = Header {
            initiator_spi: [0x01; 8],
            responder_spi: [0x02; 8],
            next_payload: PayloadType::Encrypted,
            exchange: ExchangeType::IkeAuth,
            flags: FLAG_RESPONSE,
            message_id,
        };
        sk.seal(header, &payloads, iv)
    }

    fn eap_challenge(eap: &aka::eap_aka_prime::EapAkaPrimeKeys) -> Vec<u8> {
        let mut attributes = kdf_input_attribute(NETWORK).unwrap();
        attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));
        let mut packet =
            EapPacket::response(7, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &attributes);
        packet[0] = EAP_REQUEST;
        let offset = 4 + 2 + crate::eap::attribute_value_offset(&attributes, AT_MAC).unwrap();
        let mac = at_mac(&eap.k_aut, &packet, offset).unwrap();
        packet[offset..offset + AT_MAC_LEN].copy_from_slice(&mac);
        packet
    }

    #[test]
    fn first_request_is_an_encrypted_ike_auth() {
        let f = fixture();
        let bytes = f.auth.first_request(&f.iv).unwrap();
        let (header, _) = Header::decode(&bytes).unwrap();
        assert_eq!(header.exchange, ExchangeType::IkeAuth);
        assert_eq!(header.message_id, 1);
        assert_eq!(header.next_payload, PayloadType::Encrypted);
        assert_eq!(header.flags, FLAG_INITIATOR);
        // The identity is not on the wire in clear.
        assert!(!bytes.windows(4).any(|w| w == b"user"));
        let opened = f.auth.sk_out().unwrap().open(&bytes).unwrap();
        assert_eq!(opened.payloads[0].kind, PayloadType::Idi);
        assert!(opened.payloads.iter().any(|p| p.kind == PayloadType::Sa));
        assert!(opened.payloads.iter().any(|p| p.kind == PayloadType::Tsi));
    }

    #[test]
    fn the_full_eap_flow_establishes_and_derives_child_keys() {
        let mut f = fixture();
        let keys = f.keys.clone();
        let _ = f.auth.first_request(&f.iv).unwrap();

        // 1. Responder sends the AKA' challenge.
        let challenge = eap_challenge(&f.eap);
        let msg = responder_message(
            &keys,
            1,
            vec![Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: challenge,
            }],
            &f.iv,
        );
        let step = f.auth.on_response(&msg, &f.iv, &mut f.peer).unwrap();
        let AuthStep::Send(response) = step else {
            panic!("expected an EAP response, got {step:?}");
        };
        // The response is a new request, so it carries the next message id.
        assert_eq!(
            Header::decode(&response).unwrap().0.message_id,
            2,
            "the EAP response must advance the message id"
        );
        let opened = f.auth.sk_out().unwrap().open(&response).unwrap();
        let eap = EapPacket::parse(&opened.payloads[0].body).unwrap();
        assert_eq!(eap.code, EAP_RESPONSE);
        assert_eq!(eap.method, Some(EAP_TYPE_AKA_PRIME));

        // 2. Responder sends EAP Success.
        let msg = responder_message(
            &keys,
            2,
            vec![Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: vec![EAP_SUCCESS, 7, 0, 4],
            }],
            &f.iv,
        );
        let step = f.auth.on_response(&msg, &f.iv, &mut f.peer).unwrap();
        let AuthStep::Send(final_auth) = step else {
            panic!("expected AUTH, got {step:?}");
        };
        assert_eq!(
            Header::decode(&final_auth).unwrap().0.message_id,
            3,
            "AUTH is the third request"
        );
        let opened = f.auth.sk_out().unwrap().open(&final_auth).unwrap();
        assert_eq!(opened.payloads[0].kind, PayloadType::Auth);
        let our_auth = opened.payloads[0].body.clone();

        // 3. Responder sends its AUTH plus a child SA; we verify and finish.
        let idr_body = Id {
            id_type: ID_RFC822_ADDR,
            data: b"epdg.example".to_vec(),
        }
        .encode();
        let signed =
            signed_octets_responder(b"real-message-2", &[0x33; 32], &keys.sk_pr, &idr_body);
        let msk = f.peer.keys().msk;
        let responder_auth = auth_payload(&msk, &signed);
        // Sanity: our AUTH and the responder's are over different octets.
        assert_ne!(our_auth, responder_auth);
        let msg = responder_message(
            &keys,
            3,
            vec![
                Payload {
                    kind: PayloadType::Idr,
                    critical: false,
                    body: idr_body,
                },
                Payload {
                    kind: PayloadType::Auth,
                    critical: false,
                    body: responder_auth,
                },
                Payload {
                    kind: PayloadType::Sa,
                    critical: false,
                    body: Sa {
                        proposals: vec![Proposal {
                            number: 1,
                            protocol_id: PROTO_ESP,
                            spi: vec![0x01, 0x02, 0x03, 0x04],
                            transforms: vec![
                                Transform {
                                    transform_type: TRANSFORM_ENCR,
                                    id: 12,
                                    attributes: vec![0x80, 0x0E, 0x00, 0x80],
                                },
                                Transform {
                                    transform_type: TRANSFORM_INTEG,
                                    id: 12,
                                    attributes: vec![],
                                },
                            ],
                        }],
                    }
                    .encode(),
                },
                Payload {
                    kind: PayloadType::Tsi,
                    critical: false,
                    body: any_ipv4().encode(),
                },
                Payload {
                    kind: PayloadType::Tsr,
                    critical: false,
                    body: any_ipv4().encode(),
                },
                Payload {
                    kind: PayloadType::Config,
                    critical: false,
                    body: crate::cp::ConfigPayload::reply(vec![crate::cp::ConfigAttribute::new(
                        crate::cp::INTERNAL_IP4_ADDRESS,
                        [10, 1, 2, 3],
                    )])
                    .encode(),
                },
            ],
            &f.iv,
        );
        let step = f.auth.on_response(&msg, &f.iv, &mut f.peer).unwrap();
        let AuthStep::Established {
            child,
            config,
            child_keys,
        } = step
        else {
            panic!("expected Established, got {step:?}");
        };
        assert_eq!(child_keys.len(), 128);
        assert_eq!(
            child_keys,
            child_keymat(&keys.sk_d, &[0x33; 32], &[0x66; 32], 128)
        );
        // Our SPI came from SAi2, the responder's from SAr2.
        assert_eq!(child.inbound.spi, 0xDEADBEEF);
        assert_eq!(child.outbound.spi, 0x01020304);
        assert_eq!(child.outbound.encryption.key(), &child_keys[0..16]);
        assert_eq!(child.outbound.integrity.key(), &child_keys[16..48]);
        let config = config.expect("the ePDG assigned an address");
        assert_eq!(config.internal_ip4_address(), Some([10, 1, 2, 3]));
        assert!(f.auth.is_established());
    }

    #[test]
    fn a_forged_responder_auth_is_rejected() {
        let mut f = fixture();
        let keys = f.keys.clone();
        let _ = f.auth.first_request(&f.iv).unwrap();
        let challenge = eap_challenge(&f.eap);
        let msg = responder_message(
            &keys,
            1,
            vec![Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: challenge,
            }],
            &f.iv,
        );
        let _ = f.auth.on_response(&msg, &f.iv, &mut f.peer).unwrap();
        let msg = responder_message(
            &keys,
            2,
            vec![Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: vec![EAP_SUCCESS, 7, 0, 4],
            }],
            &f.iv,
        );
        let _ = f.auth.on_response(&msg, &f.iv, &mut f.peer).unwrap();

        let idr_body = Id {
            id_type: ID_RFC822_ADDR,
            data: b"epdg.example".to_vec(),
        }
        .encode();
        let msg = responder_message(
            &keys,
            3,
            vec![
                Payload {
                    kind: PayloadType::Idr,
                    critical: false,
                    body: idr_body,
                },
                Payload {
                    kind: PayloadType::Auth,
                    critical: false,
                    body: vec![0x00; 32],
                },
            ],
            &f.iv,
        );
        assert_eq!(
            f.auth.on_response(&msg, &f.iv, &mut f.peer),
            Err(AuthError::BadResponderAuth)
        );
    }
}
