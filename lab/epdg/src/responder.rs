//! A stand-in ePDG: the responder half of the Wi-Fi calling exchange.
//!
//! This exists so the IKEv2/EAP-AKA' client can be exercised over a real socket
//! without an operator network. It is a *lab* peer, not a product: it holds the
//! subscriber key in memory (a real ePDG gets RES/CK/IK from the HSS), it uses a
//! fixed sequence number, and it makes no attempt at rekeying or liveness.
//!
//! It is deliberately the independent half of the exchange: it derives
//! `CK'`/`IK'`, the EAP keys and the IKE key schedule from `K`/`OPc` and the
//! RAND it chooses, so a client that agrees with it has agreed on the whole
//! chain rather than on a shared fixture.

#![forbid(unsafe_code)]

use aka::eap_aka_prime::{
    at_mac, attribute, derive_keys as eap_keys, kdf_input_attribute, parse_attributes, AT_MAC_LEN,
};
use aka::{Amf, Milenage, Rand, Sqn};
use epdg::auth::{auth_payload, child_keymat, constant_time_eq, signed_octets_responder};
use epdg::child::{ChildSa, AUTH_HMAC_SHA2_256_128, ENCR_AES_CBC};
use epdg::cp::{ConfigAttribute, ConfigPayload, INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS};
use epdg::dh::DhKeyPair;
use epdg::eap::{
    EapPacket, AT_MAC, AT_RES, EAP_FAILURE, EAP_REQUEST, EAP_SUCCESS, EAP_TYPE_AKA_PRIME,
    SUBTYPE_CHALLENGE,
};
use epdg::ikev2::{
    ExchangeType, Header, Id, Message, Payload, PayloadType, Proposal, Sa, Selector,
    TrafficSelectors, Transform, FLAG_RESPONSE, ID_RFC822_ADDR, PROTO_ESP, TRANSFORM_ENCR,
    TRANSFORM_INTEG,
};
use epdg::keys::{derive_keys, skeyseed, IkeKeySizes, IkeKeys};
use epdg::sa::sa_init_response;
use epdg::sk::{Sk, SkError, BLOCK_LEN};

/// EAP-AKA' attribute: the random challenge (RFC 4187 §10.7).
pub const AT_RAND: u8 = 1;
/// EAP-AKA' attribute: the network authentication token (RFC 4187 §10.8).
pub const AT_AUTN: u8 = 2;

/// What the responder wants the caller to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Send these bytes back to the peer.
    Send(Vec<u8>),
    /// The exchange completed. `bytes` is the final sealed IKE_AUTH response;
    /// the rest is what the client should have derived from it.
    Established {
        /// The final IKE_AUTH response, ready to send.
        bytes: Vec<u8>,
        /// The child SA the client will install.
        child: ChildSa,
        /// The IMS address handed out in `CFG_REPLY`.
        ims_address: [u8; 4],
    },
}

/// Errors from the stand-in responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponderError {
    Sk(SkError),
    /// A message arrived that does not fit the current step.
    OutOfOrder(&'static str),
    /// The client's AT_RES did not match, or its AT_MAC did not verify.
    BadResponse,
    /// The client's AUTH payload did not verify.
    BadAuth,
    /// The exchange requested something this stand-in does not do.
    Unsupported(&'static str),
    /// A message could not be parsed.
    Decode(String),
}

impl core::fmt::Display for ResponderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResponderError::Sk(e) => write!(f, "SK error: {e}"),
            ResponderError::OutOfOrder(what) => write!(f, "out of order: {what}"),
            ResponderError::BadResponse => f.write_str("EAP-AKA' response did not verify"),
            ResponderError::BadAuth => f.write_str("client AUTH did not verify"),
            ResponderError::Unsupported(what) => write!(f, "unsupported: {what}"),
            ResponderError::Decode(what) => write!(f, "decode error: {what}"),
        }
    }
}

impl std::error::Error for ResponderError {}

impl From<SkError> for ResponderError {
    fn from(e: SkError) -> Self {
        ResponderError::Sk(e)
    }
}

fn decode_error<E: core::fmt::Display>(e: E) -> ResponderError {
    ResponderError::Decode(e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    AwaitingAuth,
    AwaitingEapResponse,
    AwaitingFinalAuth,
    Done,
}

/// The responder side of the exchange.
pub struct StandInEpdg {
    network: String,
    milenage: Milenage,
    group: u16,
    private_exponent: Vec<u8>,
    responder_spi: [u8; 8],
    nonce_r: Vec<u8>,
    child_spi: [u8; 4],
    ims_address: [u8; 4],
    dns: [u8; 4],
    /// Cleared once the RAND is chosen; the lab uses a fixed one so a run is
    /// reproducible.
    rand: Rand,

    // Filled in as the exchange progresses.
    real_message1: Option<Vec<u8>>,
    real_message2: Option<Vec<u8>>,
    nonce_i: Option<Vec<u8>>,
    identity: Option<Vec<u8>>,
    initiator_spi_value: [u8; 8],
    client_child_spi: [u8; 4],
    ike: Option<IkeKeys>,
    eap: Option<aka::eap_aka_prime::EapAkaPrimeKeys>,
    expected_res: Option<Vec<u8>>,
    step: Step,
}

impl StandInEpdg {
    /// Build a responder for `network` holding subscriber key `k`/`opc`.
    ///
    /// Every parameter is a lab constant: DH group, exponent, SPIs, nonces, the
    /// child SPI, and the address and DNS to hand out.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: impl Into<String>,
        k: [u8; 16],
        opc: [u8; 16],
        group: u16,
        private_exponent: Vec<u8>,
        responder_spi: [u8; 8],
        nonce_r: Vec<u8>,
        child_spi: [u8; 4],
        ims_address: [u8; 4],
        dns: [u8; 4],
    ) -> Self {
        Self {
            network: network.into(),
            milenage: Milenage::new_with_opc(k, opc),
            group,
            private_exponent,
            responder_spi,
            nonce_r,
            child_spi,
            ims_address,
            dns,
            rand: [0x5a; 16],
            real_message1: None,
            real_message2: None,
            nonce_i: None,
            identity: None,
            initiator_spi_value: [0; 8],
            client_child_spi: [0; 4],
            ike: None,
            eap: None,
            expected_res: None,
            step: Step::AwaitingAuth,
        }
    }

    /// Use a specific RAND instead of the fixed lab default.
    pub fn with_rand(mut self, rand: Rand) -> Self {
        self.rand = rand;
        self
    }

    /// Handle IKE_SA_INIT and answer with SAr1/KEr/Nr.
    pub fn on_sa_init(&mut self, request: &[u8]) -> Result<Vec<u8>, ResponderError> {
        let request = Message::decode(request).map_err(decode_error)?;
        self.initiator_spi_value = request.header.initiator_spi;
        self.real_message1 = Some(request.encode());

        let response = sa_init_response(
            &request,
            self.responder_spi,
            &self.private_exponent,
            self.nonce_r.clone(),
            self.group,
        )
        .map_err(|e| ResponderError::Decode(e.to_string()))?;

        // Derive the same schedule the initiator will derive.
        let ke = request
            .find(PayloadType::Ke)
            .ok_or(ResponderError::OutOfOrder("no KE in SA_INIT"))
            .and_then(|p| {
                epdg::ikev2::Ke::decode(&p.body).map_err(|e| ResponderError::Decode(e.to_string()))
            })?;
        let keypair = DhKeyPair::from_private(self.group, &self.private_exponent)
            .map_err(|e| ResponderError::Decode(e.to_string()))?;
        let shared = keypair
            .agree(&ke.key_data)
            .map_err(|e| ResponderError::Decode(e.to_string()))?;

        let nonce_i = request
            .find(PayloadType::Nonce)
            .ok_or(ResponderError::OutOfOrder("no nonce in SA_INIT"))?
            .body
            .clone();
        let seed = skeyseed(&nonce_i, &self.nonce_r, &shared);
        let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
        self.ike = Some(derive_keys(&seed, &nonce_i, &self.nonce_r, sizes));
        self.nonce_i = Some(nonce_i);

        let bytes = response.encode();
        self.real_message2 = Some(bytes.clone());
        Ok(bytes)
    }

    fn sk_out(&self) -> Result<Sk, ResponderError> {
        let keys = self
            .ike
            .as_ref()
            .ok_or(ResponderError::OutOfOrder("SA_INIT first"))?;
        Ok(Sk::aes_cbc_128_sha256_128(&keys.sk_er, &keys.sk_ar)?)
    }

    fn sk_in(&self) -> Result<Sk, ResponderError> {
        let keys = self
            .ike
            .as_ref()
            .ok_or(ResponderError::OutOfOrder("SA_INIT first"))?;
        // The initiator seals with SK_ei/SK_ai; the responder opens with them.
        Ok(Sk::aes_cbc_128_sha256_128(&keys.sk_ei, &keys.sk_ai)?)
    }

    fn seal(&self, message_id: u32, payloads: Vec<Payload>, iv: &[u8; BLOCK_LEN]) -> Vec<u8> {
        let header = Header {
            initiator_spi: self.initiator_spi(),
            responder_spi: self.responder_spi,
            next_payload: PayloadType::Encrypted,
            exchange: ExchangeType::IkeAuth,
            flags: FLAG_RESPONSE,
            message_id,
        };
        self.sk_out()
            .expect("SK keys exist after SA_INIT")
            .seal(header, &payloads, iv)
    }

    fn initiator_spi(&self) -> [u8; 8] {
        // Recorded from the SA_INIT request header.
        self.initiator_spi_value
    }

    /// Handle one IKE_AUTH message.
    pub fn on_ike_auth(
        &mut self,
        bytes: &[u8],
        iv: &[u8; BLOCK_LEN],
    ) -> Result<Reply, ResponderError> {
        let message = self.sk_in()?.open(bytes)?;
        if message.header.flags & FLAG_RESPONSE != 0 {
            return Err(ResponderError::OutOfOrder("request flagged as a response"));
        }
        match self.step {
            Step::AwaitingAuth => self.on_first_auth(message, iv),
            Step::AwaitingEapResponse => self.on_eap_response(message, iv),
            Step::AwaitingFinalAuth => self.on_final_auth(message),
            Step::Done => Err(ResponderError::OutOfOrder("exchange already finished")),
        }
    }

    /// The first IKE_AUTH: IDi, CP(CFG_REQUEST), SAi2, TSi, TSr, N(EAP_ONLY).
    fn on_first_auth(
        &mut self,
        message: Message,
        iv: &[u8; BLOCK_LEN],
    ) -> Result<Reply, ResponderError> {
        let idi = message
            .find(PayloadType::Idi)
            .ok_or(ResponderError::OutOfOrder("no IDi"))?;
        let id = Id::decode(&idi.body).map_err(decode_error)?;
        self.identity = Some(id.data.clone());

        // SAi2 carries the child SPI the client expects us to use when sending.
        let sai2 = message
            .find(PayloadType::Sa)
            .ok_or(ResponderError::OutOfOrder("no SAi2"))?;
        let sai2 = Sa::decode(&sai2.body).map_err(decode_error)?;
        let spi = sai2
            .proposals
            .first()
            .map(|p| p.spi.clone())
            .ok_or(ResponderError::OutOfOrder("empty SAi2"))?;
        if spi.len() != 4 {
            return Err(ResponderError::OutOfOrder("child SPI is not 4 octets"));
        }
        self.client_child_spi.copy_from_slice(&spi);

        // Run the AKA algorithm for this subscriber and build the challenge.
        let sqn: Sqn = [0, 0, 0, 0, 0, 1];
        let mut amf: Amf = [0x80, 0x00]; // separation bit set: EAP-AKA'
        let outputs = self.milenage.compute(&self.rand, &sqn, &amf);
        amf[0] |= 0x80;

        // AUTN = SQN ⊕ AK | AMF | MAC-A (TS 33.102 §6.3.3).
        let mut sqn_xor_ak = [0u8; 6];
        for i in 0..6 {
            sqn_xor_ak[i] = sqn[i] ^ outputs.ak[i];
        }
        let mut autn = [0u8; 16];
        autn[..6].copy_from_slice(&sqn_xor_ak);
        autn[6..8].copy_from_slice(&amf);
        autn[8..].copy_from_slice(&outputs.mac_a);

        // The EAP-AKA' key set is derived from CK' / IK'.
        let (ck, ik) = aka::eap_aka_prime::ck_ik_prime(&outputs.ck, &outputs.ik, &self.network)
            .map_err(decode_error)?;
        let identity_text = String::from_utf8_lossy(&id.data).to_string();
        let keys = eap_keys(&ck, &ik, &self.network, &identity_text, &amf).map_err(decode_error)?;
        self.expected_res = Some(outputs.res.to_vec());
        self.eap = Some(keys);

        // AT_RAND | AT_AUTN | AT_KDF_INPUT | AT_KDF | AT_BIDDING | AT_MAC
        let mut attributes = attribute(AT_RAND, &self.rand);
        attributes.extend_from_slice(&attribute(AT_AUTN, &autn));
        attributes.extend_from_slice(&kdf_input_attribute(&self.network).map_err(decode_error)?);
        attributes.extend_from_slice(&aka::eap_aka_prime::kdf_attribute(1));
        attributes.extend_from_slice(&aka::eap_aka_prime::bidding_attribute(true));
        attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));

        let mut packet =
            EapPacket::response(1, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &attributes);
        packet[0] = EAP_REQUEST;
        let k_aut = self.expect_eap()?.k_aut;
        let mac_at = 4
            + 2
            + epdg::eap::attribute_value_offset(&attributes, AT_MAC)
                .ok_or(ResponderError::OutOfOrder("no AT_MAC slot"))?;
        let mac = at_mac(&k_aut, &packet, mac_at).map_err(decode_error)?;
        packet[mac_at..mac_at + AT_MAC_LEN].copy_from_slice(&mac);

        self.step = Step::AwaitingEapResponse;
        let idr = Id {
            id_type: ID_RFC822_ADDR,
            data: b"epdg.lab.hyphae".to_vec(),
        }
        .encode();
        Ok(Reply::Send(self.seal(
            message.header.message_id,
            vec![
                Payload {
                    kind: PayloadType::Idr,
                    critical: false,
                    body: idr,
                },
                Payload {
                    kind: PayloadType::Eap,
                    critical: false,
                    body: packet,
                },
            ],
            iv,
        )))
    }

    /// The client's EAP-Response/AKA'-Challenge.
    fn on_eap_response(
        &mut self,
        message: Message,
        iv: &[u8; BLOCK_LEN],
    ) -> Result<Reply, ResponderError> {
        let eap = message
            .find(PayloadType::Eap)
            .ok_or(ResponderError::OutOfOrder("no EAP payload"))?;
        let packet = EapPacket::parse(&eap.body).map_err(decode_error)?;
        if packet.code != 2 {
            return Err(ResponderError::BadResponse);
        }

        let parsed = parse_attributes(&packet.attributes).map_err(decode_error)?;
        // AT_RES may carry the "M" bit (0x80) on the type octet.
        let res = parsed
            .iter()
            .find(|(kind, _)| (kind & 0x7f) == AT_RES)
            .map(|(_, value)| value.clone())
            .ok_or(ResponderError::BadResponse)?;

        // AT_RES is a bit length followed by that many octets (RFC 4187 §10.9).
        let expected = self
            .expected_res
            .clone()
            .ok_or(ResponderError::OutOfOrder("no challenge sent"))?;
        let bit_len = (expected.len() as u16) * 8;
        let mut wire = bit_len.to_be_bytes().to_vec();
        wire.extend_from_slice(&expected);
        // The parsed value carries its padding; compare the meaningful prefix.
        let received = res.get(..wire.len()).unwrap_or(&res);
        if !constant_time_eq(received, &wire) {
            self.step = Step::Done;
            let failure = vec![EAP_FAILURE, 2, 0, 4];
            return Ok(Reply::Send(self.seal(
                message.header.message_id,
                vec![Payload {
                    kind: PayloadType::Eap,
                    critical: false,
                    body: failure,
                }],
                iv,
            )));
        }

        self.step = Step::AwaitingFinalAuth;
        Ok(Reply::Send(self.seal(
            message.header.message_id,
            vec![Payload {
                kind: PayloadType::Eap,
                critical: false,
                body: vec![EAP_SUCCESS, 2, 0, 4],
            }],
            iv,
        )))
    }

    /// The client's AUTH, computed over the EAP MSK.
    fn on_final_auth(&mut self, message: Message) -> Result<Reply, ResponderError> {
        let auth = message
            .find(PayloadType::Auth)
            .ok_or(ResponderError::OutOfOrder("expected AUTH"))?;

        let msk = self.expect_eap()?.msk;
        let identity = self
            .identity
            .clone()
            .ok_or(ResponderError::OutOfOrder("no IDi"))?;
        let idi_body = Id {
            id_type: ID_RFC822_ADDR,
            data: identity,
        }
        .encode();
        let real_message1 = self
            .real_message1
            .clone()
            .ok_or(ResponderError::OutOfOrder("no SA_INIT request"))?;
        let keys = self
            .ike
            .as_ref()
            .ok_or(ResponderError::OutOfOrder("SA_INIT first"))?;
        let signed = epdg::auth::signed_octets_initiator(
            &real_message1,
            &self.nonce_r,
            &keys.sk_pi,
            &idi_body,
        );
        if !constant_time_eq(&auth.body, &auth_payload(&msk, &signed)) {
            self.step = Step::Done;
            return Err(ResponderError::BadAuth);
        }

        // The child SA we are announcing: our SPI is what the client must use
        // when it sends to us.
        let proposal = Proposal {
            number: 1,
            protocol_id: PROTO_ESP,
            spi: self.child_spi.to_vec(),
            transforms: vec![
                Transform {
                    transform_type: TRANSFORM_ENCR,
                    id: ENCR_AES_CBC,
                    attributes: vec![0x80, 0x0E, 0x00, 0x80],
                },
                Transform {
                    transform_type: TRANSFORM_INTEG,
                    id: AUTH_HMAC_SHA2_256_128,
                    attributes: vec![],
                },
            ],
        };

        // Our own AUTH over the MSK.
        let idr_body = Id {
            id_type: ID_RFC822_ADDR,
            data: b"epdg.lab.hyphae".to_vec(),
        }
        .encode();
        let real_message2 = self
            .real_message2
            .clone()
            .ok_or(ResponderError::OutOfOrder("no SA_INIT response"))?;
        let nonce_i = self
            .nonce_i
            .clone()
            .ok_or(ResponderError::OutOfOrder("no nonce_i"))?;
        let signed = signed_octets_responder(&real_message2, &nonce_i, &keys.sk_pr, &idr_body);
        let our_auth = auth_payload(&msk, &signed);

        let config = ConfigPayload::reply(vec![
            ConfigAttribute::new(INTERNAL_IP4_ADDRESS, self.ims_address),
            ConfigAttribute::new(INTERNAL_IP4_DNS, self.dns),
        ]);

        let payloads = vec![
            Payload {
                kind: PayloadType::Idr,
                critical: false,
                body: idr_body,
            },
            Payload {
                kind: PayloadType::Auth,
                critical: false,
                body: our_auth,
            },
            Payload {
                kind: PayloadType::Sa,
                critical: false,
                body: Sa {
                    proposals: vec![proposal],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Tsi,
                critical: false,
                body: selector(self.ims_address, [255, 255, 255, 0]).encode(),
            },
            Payload {
                kind: PayloadType::Tsr,
                critical: false,
                body: selector([10, 32, 0, 7], [10, 32, 0, 7]).encode(),
            },
            Payload {
                kind: PayloadType::Config,
                critical: false,
                body: config.encode(),
            },
        ];
        let bytes = self.seal(message.header.message_id, payloads, &[0x11; BLOCK_LEN]);

        // Sanity: what the client should end up with.
        let child_keys = child_keymat(&keys.sk_d, &nonce_i, &self.nonce_r, 128);
        let child = ChildSa::from_proposal(
            &Proposal {
                number: 1,
                protocol_id: PROTO_ESP,
                spi: self.child_spi.to_vec(),
                transforms: vec![
                    Transform {
                        transform_type: TRANSFORM_ENCR,
                        id: ENCR_AES_CBC,
                        attributes: vec![0x80, 0x0E, 0x00, 0x80],
                    },
                    Transform {
                        transform_type: TRANSFORM_INTEG,
                        id: AUTH_HMAC_SHA2_256_128,
                        attributes: vec![],
                    },
                ],
            },
            u32::from_be_bytes(self.client_child_spi),
            &child_keys,
            vec![],
            vec![],
        )
        .map_err(|e| ResponderError::Decode(e.to_string()))?;

        self.step = Step::Done;
        Ok(Reply::Established {
            bytes,
            child,
            ims_address: self.ims_address,
        })
    }

    fn expect_eap(&self) -> Result<aka::eap_aka_prime::EapAkaPrimeKeys, ResponderError> {
        self.eap
            .clone()
            .ok_or(ResponderError::OutOfOrder("no EAP keys yet"))
    }
}

fn selector(start: [u8; 4], end: [u8; 4]) -> TrafficSelectors {
    TrafficSelectors {
        selectors: vec![Selector {
            ts_type: 7, // TS_IPV4_ADDR_RANGE
            ip_protocol: 0,
            start_port: 0,
            end_port: 0xffff,
            start_address: start.to_vec(),
            end_address: end.to_vec(),
        }],
    }
}
