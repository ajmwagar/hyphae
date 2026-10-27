//! Minimal, typed SIP (RFC 3261) building blocks.
//!
//! This crate deliberately contains **no I/O and no async runtime**. It parses
//! and serialises messages, and models the client/server transaction state used
//! by the `ims` crate. Transport lives behind the `transport` crate's trait.
//!
//! References:
//! * RFC 3261 §7 (messages), §8 (general user agent behaviour), §17 (transactions)
//! * RFC 3265/6665 (SUBSCRIBE/NOTIFY), RFC 3311 (UPDATE), RFC 3262 (100rel)

#![forbid(unsafe_code)]

mod headers;
mod message;
mod transaction;
mod uri;

pub use headers::{
    parse_challenge, split_params, AuthChallenge, CSeq, Header, Headers, NameAddr, Via,
};
pub use message::{Message, Method, Request, Response, Version};
pub use transaction::{
    key_from_message, ClientEvent, ClientTransaction, ClientTransactionState, ServerEvent,
    ServerTransaction, ServerTransactionState, Timer, TransactionKey,
};
pub use uri::SipUri;

/// Errors produced by parsing or serialising SIP syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A required start line / header is missing.
    Missing(&'static str),
    /// A field had an unexpected or malformed value.
    Invalid { field: &'static str, detail: String },
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Missing(field) => write!(f, "missing {field}"),
            ParseError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn invalid(field: &'static str, detail: impl Into<String>) -> ParseError {
    ParseError::Invalid {
        field,
        detail: detail.into(),
    }
}
