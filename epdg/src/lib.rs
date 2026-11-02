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
//! What is **not** here yet: Diffie-Hellman, the SK encryption/integrity layer,
//! the IKE_SA_INIT/SA_AUTH state machine, and the S2b bearer. Those are the next
//! slices; this crate deliberately stops at "messages are well-formed and the
//! challenge verifies".
//!
//! ## Unsafe policy
//!
//! Pure Rust: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

pub mod auth;
pub mod dh;
pub mod eap;
pub mod ike_auth;
pub mod ikev2;
pub mod keys;
pub mod sa;
pub mod sk;

pub use eap::{AkaPrimePeer, EapPacket, EapPeerError};
pub use ike_auth::{AuthError, AuthStep, IkeAuthInitiator};
pub use ikev2::{ExchangeType, Header, IkeError, Message, Payload, PayloadType};
pub use keys::{derive_keys, prf_plus, skeyseed, IkeKeySizes, IkeKeys};
pub use sa::{sa_init_response, SaError, SaInitInitiator};
pub use sk::{Sk, SkError};
