//! IMS/VoLTE control plane, derived from 3GPP and IETF specifications.
//!
//! This crate contains **no media codec implementation and no I/O**. It owns:
//! * the IMS profile (identities, P-CSCF, Service-Route, Security-Client),
//! * REGISTER transaction construction and challenge handling (AKA digest),
//! * SDP offer/answer for the MTSI audio stream,
//! * in-dialog request construction (PRACK/UPDATE/BYE).
//!
//! It talks to the network through `transport::Transport` and to media through
//! `codec::Codec`; neither is a dependency here, which keeps the state machine
//! testable with plain values.

#![forbid(unsafe_code)]

pub mod auth;
pub mod dialog;
pub mod profile;
pub mod register;
pub mod sdp;

pub use dialog::{Dialog, DialogState};
pub use profile::{ImsProfile, SecurityClient};
pub use register::{Challenge, Registration, RegistrationEvent, RegistrationState};
pub use sdp::{Connection, Media, Origin, Sdp};
