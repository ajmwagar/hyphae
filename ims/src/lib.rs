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
pub mod call;
pub mod dialog;
pub mod emergency;
pub mod profile;
pub mod register;
pub mod sdp;
pub mod sms;
pub mod supplementary;
pub mod uas;

pub use call::{Call, CallEvent, CallState};
pub use dialog::{Dialog, DialogState};
pub use emergency::{EmergencyIdentity, EmergencyRequest, Geolocation, SosService};
pub use profile::{ImsProfile, SecurityClient};
pub use register::{Challenge, Registration, RegistrationEvent, RegistrationState};
pub use sdp::Direction;
pub use sdp::{Connection, Media, Origin, PrecondDir, Precondition, Sdp};
pub use sms::{IncomingSms, RpData, SmsDeliver, SmsSender, SmsSubmit};
pub use supplementary::{accept_waiting, decline_waiting, is_call_waiting, CallWaitingActions};
pub use uas::{IncomingCall, UasError, UasEvent, UasState};
