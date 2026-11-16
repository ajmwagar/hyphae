//! One error type for the crate.
//!
//! The variants are deliberately small and flat: every layer of the bring-up
//! (QRTR socket, QMI codec, WDS sequence, rtnetlink) reports the same type, so
//! the bearer state machine and the CLI never have to translate. Variants are
//! `Clone + Eq` so a test can assert on the exact error a scripted modem
//! produced.

use std::fmt;

use crate::qmi::Op;

/// The QMI protocol error field of a failed response.
///
/// A QMI response carries `result u16 | error u16` in TLV 0x02. When `result`
/// is not zero the `error` field is one of these codes. Values and names come
/// from the public QMI protocol error enumeration (the same table libqmi ships
/// as `QmiProtocolError`); only the codes this crate can plausibly surface are
/// named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError {
    /// The `error` field of the response's result TLV.
    pub code: u16,
}

impl ProtocolError {
    /// `INTERNAL` (3): the modem failed for its own reasons.
    pub const INTERNAL: Self = Self { code: 3 };
    /// `OUT_OF_CALL` (15): no data call is up for this client.
    pub const OUT_OF_CALL: Self = Self { code: 15 };
    /// `INVALID_OPERATION` (70): the request is not valid in the modem's
    /// current state — for WDS `Start Network` this is what a missing
    /// `Bind Mux Data Port` on the same client looks like.
    pub const INVALID_OPERATION: Self = Self { code: 70 };

    /// The protocol name of the code, when it is one this crate knows.
    pub const fn name(&self) -> Option<&'static str> {
        match self.code {
            0 => Some("NONE"),
            1 => Some("MALFORMED_MESSAGE"),
            2 => Some("NO_MEMORY"),
            3 => Some("INTERNAL"),
            4 => Some("ABORTED"),
            7 => Some("INVALID_CLIENT_ID"),
            9 => Some("INVALID_HANDLE"),
            10 => Some("INVALID_PROFILE"),
            13 => Some("NO_NETWORK_FOUND"),
            14 => Some("CALL_FAILED"),
            15 => Some("OUT_OF_CALL"),
            16 => Some("NOT_PROVISIONED"),
            17 => Some("MISSING_ARGUMENT"),
            22 => Some("INVALID_TRANSACTION_ID"),
            23 => Some("DEVICE_IN_USE"),
            24 => Some("NETWORK_UNSUPPORTED"),
            26 => Some("NO_EFFECT"),
            34 => Some("AUTHENTICATION_FAILED"),
            70 => Some("INVALID_OPERATION"),
            90 => Some("INCOMPATIBLE_STATE"),
            94 => Some("NOT_SUPPORTED"),
            _ => None,
        }
    }

    /// True for `INVALID_OPERATION`, the code that means "the modem's state
    /// does not allow this": on `WDS Start Network` it is the signature of a
    /// `Bind Mux Data Port` that never reached this client.
    pub const fn is_invalid_operation(&self) -> bool {
        self.code == 70
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({})", self.code),
            None => write!(f, "QMI error {}", self.code),
        }
    }
}

/// Everything that can go wrong between this crate and a live bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A syscall or socket operation failed. `op` names the call.
    Io {
        /// The operation, e.g. `"sendto"`.
        op: &'static str,
        /// The `errno` text.
        message: String,
    },
    /// A frame was structurally invalid: short header, length mismatch,
    /// truncated TLV.
    Malformed {
        /// What failed to parse.
        what: &'static str,
    },
    /// The QRTR name service never reported the service.
    ServiceNotFound {
        /// The QRTR service id that was looked up.
        service: u16,
    },
    /// A request went unanswered until the deadline.
    Timeout {
        /// The message that got no answer.
        op: Op,
    },
    /// The modem answered `result = 1` (failure).
    Modem {
        /// The message that was rejected.
        op: Op,
        /// The protocol error the modem reported.
        error: ProtocolError,
    },
    /// A response lacked a TLV the exchange cannot proceed without.
    MissingTlv {
        /// The message that was too short.
        op: Op,
        /// The TLV type that was missing.
        tlv: u8,
    },
    /// The kernel refused an rtnetlink request.
    Netlink {
        /// The request, e.g. `"RTM_NEWADDR"`.
        op: &'static str,
        /// The negative `NLMSG_ERROR` code, as a positive `errno`.
        errno: i32,
    },
    /// A bearer step ran before `open_port` created the QMI clients.
    NoClient,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { op, message } => write!(f, "{op} failed: {message}"),
            Error::Malformed { what } => write!(f, "malformed frame: {what}"),
            Error::ServiceNotFound { service } => {
                write!(f, "QRTR name service has no entry for service {service}")
            }
            Error::Timeout { op } => write!(f, "no response to {op} before the timeout"),
            Error::Modem { op, error } => write!(f, "modem rejected {op}: {error}"),
            Error::MissingTlv { op, tlv } => {
                write!(f, "{op} response is missing TLV 0x{tlv:02x}")
            }
            Error::Netlink { op, errno } => {
                let source = std::io::Error::from_raw_os_error(*errno);
                write!(f, "{op} refused by the kernel: {source} ({errno})")
            }
            Error::NoClient => write!(
                f,
                "no QMI client: the bearer must open the data port before this step"
            ),
        }
    }
}

impl std::error::Error for Error {}
