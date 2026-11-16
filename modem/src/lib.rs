//! # hyphae-modem — QMI over QRTR modem bring-up
//!
//! This crate owns one job: take a modem that exposes QMI over QRTR, open its
//! BAM DMUX data port, bring an LTE bearer up on it, configure the network
//! interface, and keep that bearer alive — in Rust, with no `libqmi`, no GLib
//! and no C library.
//!
//! It replaces a validated Python/libqmi prototype. The prototype's shape is
//! the specification here, including the two things that made it necessary:
//!
//! * the BAM DMUX port has to be opened first, or the modem never starts the
//!   power-control handshake; and
//! * `WDS Bind Mux Data Port` only applies to the client that sent it, and on
//!   QRTR a client is the socket, so the bind and `WDS Start Network` must share
//!   one long-lived client. `qmicli` allows one action per invocation, which is
//!   why a shell script could not do this.
//!
//! ```text
//!   Unbound ──open_port──▶ PortOpen ──bind──▶ Bound ──start + settings──▶ Connected
//!      ▲                                                                     │
//!      │                          loss, reset, or a rejected step            │
//!      └───────────────── backoff ◀──────────────────────────────────────── Lost
//! ```
//!
//! ## Modules
//!
//! Pure code first, hardware at the edges:
//!
//! | module | what it owns |
//! |---|---|
//! | [`qrtr`] | QRTR addresses, the name-service control packet, the lookup, and the `AF_QIPCRTR` socket |
//! | [`qmi`] | the 7-byte QMI frame, TLVs, transaction correlation, protocol errors |
//! | [`dpm`] | DPM `Open Port` on service 47 (the BAM DMUX handshake) |
//! | [`wds`] | WDS bind/start/stop/get-current-settings on service 1, and [`wds::BearerConfig`] |
//! | [`bearer`] | the state machine: order, teardown, retry with backoff |
//! | [`netlink`] | rtnetlink encoders plus the interface configuration |
//!
//! The codec modules ([`qrtr`]'s packet type, [`qmi`], [`dpm`], [`wds`]) and the
//! state machine ([`bearer`]) are pure and tested on any host. [`netlink`]'s
//! encoders and parsers are pure too. Only the sockets need Linux.
//!
//! ## Feature gate
//!
//! Everything that touches hardware is behind `modem-qmi`, which is **off by
//! default**:
//!
//! * default build: no `libc`, no sockets, no `unsafe` — the IMS and lab builds
//!   keep exactly the dependency graph they had;
//! * `--features modem-qmi` adds `libc` and compiles the `AF_QIPCRTR` socket
//!   and `netlink::Interface`. Those modules are `target_os = "linux"` only; on
//!   another host the codecs and the state machine still build and test.
//!
//! ```text
//!   cargo test -p hyphae-modem                                        # codecs + state machine
//!   cargo check -p hyphae-modem --features modem-qmi --target aarch64-unknown-linux-gnu
//! ```
//!
//! ## Unsafe policy
//!
//! `#![deny(unsafe_code)]` covers the crate. `AF_QIPCRTR` and `NETLINK_ROUTE`
//! have no `std` wrapper, so two modules carry a narrowly scoped
//! `#[allow(unsafe_code)]`:
//!
//! * [`qrtr`]'s socket: `socket`, `bind`, `getsockname`, `sendto`, `recvfrom`,
//!   `poll`;
//! * [`netlink`]'s socket: `socket`, `bind`, `send`, `recv`, `poll`,
//!   `if_nametoindex`.
//!
//! Every block is a single syscall with locally built arguments, and each one
//! has a `// SAFETY:` line. `forbid(unsafe_code)` is not possible without giving
//! up the syscalls; `deny` plus two named modules is the strongest policy this
//! crate can actually satisfy.
//!
//! ## What is verified, and what is not
//!
//! The QRTR control exchange and one `WDS Get Current Settings` error were
//! captured from the target and are byte-exact in the tests. The happy-path
//! settings vector is built from the public WDS service definition (the
//! capture needs a live call to be owned by the requesting client). Nothing in
//! this crate has been run against hardware yet — `modem/README.md` says
//! exactly which vector came from where and gives the command to run on the
//! phone.

#![deny(unsafe_code)]

pub mod bearer;
pub mod dpm;
mod error;
pub mod netlink;
pub mod qmi;
pub mod qrtr;
#[cfg(test)]
mod test_support;
pub mod wds;

pub use error::{Error, ProtocolError};
