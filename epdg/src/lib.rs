//! Wi-Fi calling (ePDG) protocol core.
//!
//! VoLTE peers with the IMS network through the carrier's ePDG when the UE is on
//! Wi-Fi. That path is IKEv2 to the ePDG with EAP-AKA' authentication, then a
//! child SA carrying SIP to the P-CSCF.
//!
//! This crate is the protocol core:
//!
//! * [`ikev2`] — the IKEv2 header, payload chain and the typed payloads an ePDG
//!   exchange uses (SA, KE, Nonce, ID, AUTH, EAP, Notify, traffic selectors).
//! * [`eap`] — the EAP packet framing and the EAP-AKA' peer challenge/response,
//!   using the key hierarchy from `aka::eap_aka_prime`.
//!
//! * [`ike_auth`] — the EAP-only IKE_AUTH exchange (RFC 5998).
//! * [`child`] — the child SA the exchange negotiates: the S2b bearer's SPIs,
//!   algorithms, keys and traffic selectors.
//! * [`cp`] — the Configuration payload that hands the UE its IMS address.
//!
//! What is **not** here: sockets (the caller supplies every byte), random
//! number generation, and the data plane. Programming the tunnel into a kernel
//! lives in `transport::ipsec`; driving the exchange lives in `lab/epdg`.
//!
//! ## Unsafe policy
//!
//! Pure Rust: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

pub mod auth;
pub mod child;
pub mod cp;
pub mod dh;
pub mod eap;
pub mod ike_auth;
pub mod ikev2;
pub mod keys;
pub mod sa;
pub mod sk;

pub use auth::{
    auth_payload, child_keymat, key_pad, signed_octets_initiator, signed_octets_responder,
};
pub use child::{ChildDirection, ChildEncryption, ChildError, ChildIntegrity, ChildSa};
pub use cp::{ConfigAttribute, ConfigPayload};
pub use eap::{AkaPrimePeer, EapPacket, EapPeerError};
pub use ike_auth::{AuthError, AuthStep, IkeAuthInitiator};
pub use ikev2::{ExchangeType, Header, IkeError, Message, Payload, PayloadType};
pub use keys::{derive_keys, prf_plus, skeyseed, IkeKeySizes, IkeKeys};
pub use sa::{sa_init_response, SaError, SaInitInitiator};
pub use sk::{Sk, SkError};
