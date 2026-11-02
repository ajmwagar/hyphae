//! The UE half: a socket-driven IKEv2/EAP-AKA' client.
//!
//! This is the driver the protocol crates deliberately do not contain — no
//! socket lives in `epdg`, so someone has to own the network. It is also the
//! closest thing the tree has to a real Wi-Fi calling client: it holds
//! `K`/`OPc` and runs Milenage *as the USIM would*, so the RAND the network
//! picks is what drives the key schedule.

#![forbid(unsafe_code)]

use aka::eap_aka_prime::{ck_ik_prime, derive_keys as eap_keys, parse_attributes};
use aka::{verify_autn, Milenage, Rand};
use epdg::eap::{AkaPrimePeer, EapPacket, EAP_REQUEST};
use epdg::ike_auth::{AuthError, AuthStep, IkeAuthInitiator};
use epdg::ikev2::{Message, PayloadType};
use epdg::keys::IkeKeySizes;
use epdg::natt::{Endpoint, NatVerdict};
use epdg::sa::{SaError, SaInitInitiator};
use epdg::sk::BLOCK_LEN;
use epdg::ChildSa;
use usim::{AkaOutput, Usim};

use crate::responder::AT_RAND;

/// Errors from the client driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Sa(SaError),
    Auth(AuthError),
    /// The network's AUTN did not verify — a real USIM would send a
    /// synchronization failure here instead of a response.
    AutnRejected,
    /// A message arrived that the client did not expect at this point.
    Unexpected(&'static str),
    /// A message could not be decoded.
    Decode(String),
    /// The exchange finished without the parameters a client needs.
    Incomplete,
    /// The USIM rejected the challenge or the channel failed.
    Usim(usim::UsimError),
    /// The USIM asked for SQN resynchronisation; a real UE sends AUTS.
    SyncFailure([u8; 14]),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Sa(e) => write!(f, "IKE_SA_INIT error: {e}"),
            ClientError::Auth(e) => write!(f, "IKE_AUTH error: {e}"),
            ClientError::AutnRejected => f.write_str("AUTN MAC did not verify"),
            ClientError::Unexpected(what) => write!(f, "unexpected message: {what}"),
            ClientError::Decode(what) => write!(f, "decode error: {what}"),
            ClientError::Incomplete => f.write_str("exchange finished without a child SA"),
            ClientError::Usim(e) => write!(f, "USIM: {e}"),
            ClientError::SyncFailure(_) => f.write_str("USIM requested SQN resynchronisation"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<SaError> for ClientError {
    fn from(e: SaError) -> Self {
        ClientError::Sa(e)
    }
}

impl From<AuthError> for ClientError {
    fn from(e: AuthError) -> Self {
        ClientError::Auth(e)
    }
}

/// What a completed exchange produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Established {
    /// The child SA to hand to `transport::ipsec`.
    pub child: ChildSa,
    /// The IMS address the ePDG assigned.
    pub ims_address: Option<[u8; 4]>,
    /// The DNS servers the ePDG assigned.
    pub dns: Vec<[u8; 4]>,
    /// The raw child KEYMAT, in case the caller wants the octets.
    pub child_keys: Vec<u8>,
}

/// Where the AKA vectors come from: in-process Milenage for the lab, or a
/// real USIM/PC/SC card.
enum Credential {
    Milenage(Milenage),
    Usim(Box<dyn Usim>),
}

/// A UE driving IKE_SA_INIT and IKE_AUTH (EAP-only, RFC 5998).
pub struct UeClient {
    network: String,
    identity: String,
    credential: Credential,
    sa: SaInitInitiator,
    auth: Option<IkeAuthInitiator>,
    peer: Option<AkaPrimePeer>,
    child_spi: [u8; 4],
    iv: [u8; BLOCK_LEN],
    message_id: u32,
    /// Kept only so the lab can re-derive the shared secret for diagnostics.
    private_exponent: Vec<u8>,
    group: u16,
}

impl UeClient {
    /// Build a client. `private_exponent` and `nonce_i` come from the caller
    /// because this crate has no RNG.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: impl Into<String>,
        identity: impl Into<String>,
        k: [u8; 16],
        opc: [u8; 16],
        initiator_spi: [u8; 8],
        private_exponent: &[u8],
        nonce_i: Vec<u8>,
        group: u16,
        child_spi: [u8; 4],
    ) -> Result<Self, ClientError> {
        Ok(Self {
            network: network.into(),
            identity: identity.into(),
            credential: Credential::Milenage(Milenage::new_with_opc(k, opc)),
            sa: SaInitInitiator::new(initiator_spi, private_exponent, nonce_i, group)?,
            auth: None,
            peer: None,
            child_spi,
            iv: [0x33; BLOCK_LEN],
            message_id: 1,
            private_exponent: private_exponent.to_vec(),
            group,
        })
    }

    /// Build a client backed by a real USIM/card boundary instead of an
    /// in-process Milenage. The card owns K/OP and the SQN window.
    #[allow(clippy::too_many_arguments)]
    pub fn with_usim(
        network: impl Into<String>,
        identity: impl Into<String>,
        usim: Box<dyn Usim>,
        initiator_spi: [u8; 8],
        private_exponent: &[u8],
        nonce_i: Vec<u8>,
        group: u16,
        child_spi: [u8; 4],
    ) -> Result<Self, ClientError> {
        Ok(Self {
            network: network.into(),
            identity: identity.into(),
            credential: Credential::Usim(usim),
            sa: SaInitInitiator::new(initiator_spi, private_exponent, nonce_i, group)?,
            auth: None,
            peer: None,
            child_spi,
            iv: [0x33; BLOCK_LEN],
            message_id: 1,
            private_exponent: private_exponent.to_vec(),
            group,
        })
    }

    /// Enable NAT detection with these endpoints (RFC 7296 §2.23).
    ///
    /// Must be called before [`Self::sa_init_request`]: the notifies go in the
    /// first message.
    pub fn set_endpoints(&mut self, local: Endpoint, peer: Endpoint) {
        self.sa = std::mem::replace(
            &mut self.sa,
            SaInitInitiator::new([0; 8], &[1; 32], vec![0; 32], 14).unwrap(),
        )
        .with_endpoints(local, peer);
    }

    /// What NAT detection concluded, once the responder has answered.
    pub fn nat_verdict(&self) -> Option<NatVerdict> {
        self.sa.nat_verdict()
    }

    /// Whether the rest of the exchange must be UDP-encapsulated on port 4500.
    pub fn needs_encapsulation(&self) -> bool {
        self.sa
            .nat_verdict()
            .map(|v| v.needs_encapsulation())
            .unwrap_or(false)
    }

    /// The IKE_SA_INIT request.
    pub fn sa_init_request(&self) -> Vec<u8> {
        self.sa.first_message().encode()
    }

    /// Consume the IKE_SA_INIT response and build the first IKE_AUTH.
    pub fn on_sa_init_response(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
        let message = Message::decode(bytes).map_err(|e| ClientError::Decode(e.to_string()))?;
        if std::env::var("EPDG_LAB_DEBUG").is_ok() {
            eprintln!(
                "debug: raw_response={}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            let nonce = message
                .find(PayloadType::Nonce)
                .map(|p| p.body.clone())
                .unwrap_or_default();
            eprintln!(
                "debug: sa_init response payloads={:?} nonce_r_len={} nonce_i_len={}",
                message.payloads.iter().map(|p| p.kind).collect::<Vec<_>>(),
                nonce.len(),
                self.nonce_i().len()
            );
            // Dump everything needed to check the DH agreement independently.
            if let Some(ke) = message.find(PayloadType::Ke) {
                let ke = epdg::ikev2::Ke::decode(&ke.body).unwrap();
                let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                let ours =
                    epdg::dh::DhKeyPair::from_private(self.group, &self.private_exponent).unwrap();
                eprintln!("debug: ke_group={}", ke.dh_group);
                eprintln!("debug: ke_y={}", hex(&ke.key_data));
                eprintln!("debug: priv_x={}", hex(&self.private_exponent));
                eprintln!("debug: our_public={}", hex(&ours.public_bytes()));
                eprintln!("debug: shared={}", hex(&ours.agree(&ke.key_data).unwrap()));
                eprintln!("debug: nonce_i_hex={}", hex(&self.nonce_i()));
                eprintln!("debug: nonce_r_hex={}", hex(&nonce));
                // What our own key schedule produces, for comparison with an
                // independent computation of the same inputs.
                let shared = ours.agree(&ke.key_data).unwrap();
                let seed = epdg::keys::skeyseed(&self.nonce_i(), &nonce, &shared);
                eprintln!("debug: our_skeyseed={}", hex(&seed));
                let keys = epdg::keys::derive_keys(
                    &seed,
                    &self.nonce_i(),
                    &nonce,
                    self.sa.initiator_spi(),
                    self.sa.responder_spi().unwrap_or([0; 8]),
                    epdg::keys::IkeKeySizes::aes_cbc_128_sha256_128(),
                );
                eprintln!("debug: our_sk_d={}", hex(&keys.sk_d));
                eprintln!("debug: our_sk_ai={}", hex(&keys.sk_ai));
                eprintln!("debug: our_sk_ar={}", hex(&keys.sk_ar));
                eprintln!("debug: our_sk_ei={}", hex(&keys.sk_ei));
                eprintln!("debug: our_sk_er={}", hex(&keys.sk_er));
            }
        }
        // `on_response` needs the Message, and the raw bytes for SignedOctets.
        let keys = self
            .sa
            .on_response(&message, IkeKeySizes::aes_cbc_128_sha256_128())?;
        if std::env::var("EPDG_LAB_DEBUG").is_ok() {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            eprintln!("debug: real_sk_d={}", hex(&keys.sk_d));
            eprintln!("debug: real_sk_ai={}", hex(&keys.sk_ai));
            eprintln!("debug: real_sk_ei={}", hex(&keys.sk_ei));
            eprintln!("debug: spi_i={}", hex(&self.sa.initiator_spi()));
            eprintln!(
                "debug: spi_r={}",
                hex(&self.sa.responder_spi().unwrap_or([0; 8]))
            );
        }

        let first = self.sa.first_message().encode();
        let auth = IkeAuthInitiator::new(
            keys,
            self.sa.initiator_spi(),
            self.sa.responder_spi().ok_or(ClientError::Incomplete)?,
            self.nonce_i(),
            message
                .find(PayloadType::Nonce)
                .ok_or(ClientError::Unexpected("no nonce in SA_INIT"))?
                .body
                .clone(),
            first,
            bytes.to_vec(),
            &self.identity,
            self.child_spi,
        );
        let request = auth.first_request(&self.iv)?;
        if std::env::var("EPDG_LAB_DEBUG").is_ok() {
            eprintln!(
                "debug: auth_msg={}",
                request
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }
        self.auth = Some(auth);
        self.message_id += 1;
        Ok(request)
    }

    fn nonce_i(&self) -> Vec<u8> {
        self.sa.nonce_i().to_vec()
    }

    /// Consume one IKE_AUTH message.
    ///
    /// Returns the bytes to send next, or `None` when the exchange is done.
    pub fn on_ike_auth(
        &mut self,
        bytes: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<Established>), ClientError> {
        // The first EAP request carries the RAND; that is where a USIM starts.
        if self.peer.is_none() {
            if let Some(peer) = self.try_build_peer(bytes)? {
                self.peer = Some(peer);
            }
        }
        let peer = self
            .peer
            .as_mut()
            .ok_or(ClientError::Unexpected("no EAP challenge and no keys yet"))?;
        let auth = self
            .auth
            .as_mut()
            .ok_or(ClientError::Unexpected("IKE_AUTH before SA_INIT completed"))?;

        match auth.on_response(bytes, &self.iv, peer)? {
            AuthStep::Send(next) => {
                self.message_id += 1;
                Ok((Some(next), None))
            }
            AuthStep::Established {
                child,
                config,
                child_keys,
            } => {
                let (ims_address, dns) = match config {
                    Some(cfg) => (cfg.internal_ip4_address(), cfg.internal_ip4_dns()),
                    None => (None, Vec::new()),
                };
                Ok((
                    None,
                    Some(Established {
                        child,
                        ims_address,
                        dns,
                        child_keys,
                    }),
                ))
            }
        }
    }

    /// If this message is the AKA' challenge, run Milenage and derive the EAP
    /// key set — what a USIM plus the ISIM would do in a real handset.
    fn try_build_peer(&mut self, bytes: &[u8]) -> Result<Option<AkaPrimePeer>, ClientError> {
        let Some(auth) = self.auth.as_ref() else {
            return Ok(None);
        };
        let Ok(message) = auth.peek(bytes) else {
            return Ok(None);
        };
        let Some(eap) = message.find(PayloadType::Eap) else {
            return Ok(None);
        };
        let Ok(packet) = EapPacket::parse(&eap.body) else {
            return Ok(None);
        };
        if packet.code != EAP_REQUEST || packet.method != Some(epdg::eap::EAP_TYPE_AKA_PRIME) {
            return Ok(None);
        }
        let Ok(attributes) = parse_attributes(&packet.attributes) else {
            return Ok(None);
        };
        let get = |kind: u8| {
            attributes
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, v)| v.clone())
        };
        // AT_RAND is 16 octets; the parsed value carries its padding, so take
        // the leading octets rather than converting the whole slice.
        let rand_raw = get(AT_RAND).ok_or(ClientError::Unexpected("challenge without AT_RAND"))?;
        let mut rand: Rand = [0u8; 16];
        rand.copy_from_slice(
            rand_raw
                .get(..16)
                .ok_or(ClientError::Unexpected("AT_RAND is not 16 octets"))?,
        );
        let autn_raw = get(crate::responder::AT_AUTN)
            .ok_or(ClientError::Unexpected("challenge without AT_AUTN"))?;
        let mut autn = [0u8; 16];
        autn.copy_from_slice(
            autn_raw
                .get(..16)
                .ok_or(ClientError::Unexpected("AT_AUTN is not 16 octets"))?,
        );

        let amf = [autn[6], autn[7]];
        let (res, ck, ik) = match &mut self.credential {
            Credential::Milenage(milenage) => {
                // A software USIM checks AUTN before answering (TS 33.102 §6.3.3).
                let check = verify_autn(milenage, &rand, &autn);
                if !check.mac_valid {
                    return Err(ClientError::AutnRejected);
                }
                let outputs = milenage.compute(&rand, &check.sqn, &amf);
                (outputs.res.to_vec(), outputs.ck, outputs.ik)
            }
            Credential::Usim(usim) => match usim.authenticate(&rand, &autn) {
                Ok(AkaOutput::Success { res, ck, ik }) => (res, ck, ik),
                Ok(AkaOutput::SyncFailure { auts }) => {
                    return Err(ClientError::SyncFailure(auts));
                }
                Err(e) => return Err(ClientError::Usim(e)),
            },
        };
        let (ck, ik) = ck_ik_prime(&ck, &ik, &self.network)
            .map_err(|_| ClientError::Unexpected("CK'/IK' derivation failed"))?;
        let keys = eap_keys(&ck, &ik, &self.network, &self.identity, &amf)
            .map_err(|_| ClientError::Unexpected("EAP key derivation failed"))?;

        Ok(Some(AkaPrimePeer::new(self.network.clone(), keys, res)))
    }
}
