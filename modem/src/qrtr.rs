//! QRTR: the Qualcomm inter-processor transport that carries QMI.
//!
//! QRTR is a datagram bus between the application processor and the modem.
//! Addresses are `(node, port)` pairs, and a service is found by asking the
//! name service on the control port:
//!
//! ```text
//!   host -> (local node, 0xfffffffe)   NEW_LOOKUP, service = 1 (WDS)
//!   ns   -> host                       NEW_SERVER, { service, instance, node, port }
//!   ns   -> host                       NEW_SERVER, all zero fields = end of list
//!   host -> (node, port)               QMI frames for that service
//! ```
//!
//! A control packet is the 20-byte `struct qrtr_ctrl_pkt` from `linux/qrtr.h`:
//! a `__le32` command followed by four `__le32` fields. The command numbering
//! is libqrtr's (`include/libqrtr.h`), which is what userspace — and therefore
//! this device's name service — speaks; libqrtr carries its own copy of the
//! values rather than trusting an installed kernel header. The captured
//! `NEW_LOOKUP = 10` exchange in the tests is answered by the target, which is
//! the check that matters.
//!
//! Two address encodings deserve care:
//!
//! * the `sockaddr_qrtr` passed to `bind`/`sendto` carries `__u32` node and
//!   port in **host** byte order (it is a kernel struct, not a wire format);
//! * the control packet's fields are explicitly `__le32` on the wire.
//!
//! Binding is the one place where kernels differ. `bind` with node 0 ("any")
//! is rejected with `EINVAL` by the target's kernel (7.3 on msm8937), while
//! libqrtr binds node 1 explicitly; `Socket::connect` therefore tries node 0
//! first and retries node 1 on `EINVAL`, then reports the address the kernel
//! actually assigned. `getsockname` is the source of truth for the local node,
//! and the name-service lookup is sent to *that* node.

/// `AF_QIPCRTR`. Family 42, as in `linux/qrtr.h` and libqrtr's fallback
/// definition.
pub const AF_QIPCRTR: i32 = 42;

/// The control port: the name service answers here.
pub const PORT_CTRL: u32 = 0xffff_fffe;

/// A QRTR address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    /// Node id: 0 is the modem on the target, 1 is the application processor.
    pub node: u32,
    /// Port id: one per service instance, plus the control port.
    pub port: u32,
}

impl Addr {
    /// An address.
    pub const fn new(node: u32, port: u32) -> Self {
        Self { node, port }
    }

    /// The control port on `node`.
    pub const fn control(node: u32) -> Self {
        Self {
            node,
            port: PORT_CTRL,
        }
    }
}

impl core::fmt::Display for Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.node, self.port)
    }
}

/// A QRTR control command.
///
/// The numbering is libqrtr's; see the module docs for why it is not taken
/// from a kernel header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CtrlCmd {
    /// A data packet marker, not a command userspace sends.
    Data = 1,
    /// A service announcing itself.
    Hello = 2,
    /// A service going away.
    Bye = 3,
    /// A name-service reply: one matching server.
    NewServer = 4,
    /// A server was removed.
    DelServer = 5,
    /// A client went away.
    DelClient = 6,
    /// Resume transmission for a client.
    ResumeTx = 7,
    /// Exit.
    Exit = 8,
    /// Ping.
    Ping = 9,
    /// Ask the name service for servers.
    NewLookup = 10,
    /// Stop receiving lookup replies.
    DelLookup = 11,
}

impl CtrlCmd {
    /// The wire value.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// Decode a wire value, if it is a command this crate names.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        Some(match raw {
            1 => CtrlCmd::Data,
            2 => CtrlCmd::Hello,
            3 => CtrlCmd::Bye,
            4 => CtrlCmd::NewServer,
            5 => CtrlCmd::DelServer,
            6 => CtrlCmd::DelClient,
            7 => CtrlCmd::ResumeTx,
            8 => CtrlCmd::Exit,
            9 => CtrlCmd::Ping,
            10 => CtrlCmd::NewLookup,
            11 => CtrlCmd::DelLookup,
            _ => return None,
        })
    }
}

/// What a name-service datagram means for a pending lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupReply {
    /// A matching server: use this address.
    Found(Addr),
    /// The all-zero terminator: the list is complete.
    End,
    /// Someone else's reply, or not a reply at all.
    Other,
}

/// The 20-byte `struct qrtr_ctrl_pkt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrlPacket {
    /// One of [`CtrlCmd`].
    pub cmd: u32,
    /// Service id, when the packet is about a server.
    pub service: u32,
    /// `instance << 8 | version` in replies, zero in a wildcard request.
    pub instance: u32,
    /// The node the server is on.
    pub node: u32,
    /// The port the server listens on.
    pub port: u32,
}

impl CtrlPacket {
    /// Encoded size: five little-endian `u32`s.
    pub const LEN: usize = 20;

    /// A `NEW_LOOKUP` request for one service.
    ///
    /// The request is sent with a zero instance, which the name service reads
    /// as "any version, any instance".
    pub fn lookup(service: u16) -> Self {
        Self {
            cmd: CtrlCmd::NewLookup.raw(),
            service: u32::from(service),
            instance: 0,
            node: 0,
            port: 0,
        }
    }

    /// Encode for the wire.
    pub fn encode(self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[0..4].copy_from_slice(&self.cmd.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.service.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.instance.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.node.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.port.to_le_bytes());
        bytes
    }

    /// Decode a control datagram. The control packet is fixed size; trailing
    /// bytes are ignored, as libqrtr does.
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() < Self::LEN {
            return Err(crate::Error::Malformed {
                what: "QRTR control packet shorter than 20 bytes",
            });
        }
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Ok(Self {
            cmd: word(0),
            service: word(4),
            instance: word(8),
            node: word(12),
            port: word(16),
        })
    }

    /// The all-zero `NEW_SERVER` that terminates a lookup listing.
    pub fn is_lookup_end(&self) -> bool {
        self.cmd == CtrlCmd::NewServer.raw()
            && self.service == 0
            && self.instance == 0
            && self.node == 0
            && self.port == 0
    }

    /// What this packet means for a lookup of `service`.
    pub fn classify(&self, service: u16) -> LookupReply {
        if self.cmd != CtrlCmd::NewServer.raw() {
            return LookupReply::Other;
        }
        if self.is_lookup_end() {
            return LookupReply::End;
        }
        if self.service == u32::from(service) {
            LookupReply::Found(Addr::new(self.node, self.port))
        } else {
            LookupReply::Other
        }
    }
}

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
#[allow(unsafe_code)]
mod sys {
    //! The AF_QIPCRTR socket. This is one of the crate's two `unsafe` surfaces
    //! (the other is `crate::netlink`); see `lib.rs` for the policy. Every
    //! block below is a single syscall whose arguments are built locally.

    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use super::{Addr, CtrlPacket, LookupReply, AF_QIPCRTR};
    use crate::Error;

    /// Length of `struct sockaddr_qrtr`: `u16 family`, 2 bytes of padding,
    /// `u32 node`, `u32 port`.
    const SOCKADDR_LEN: usize = 12;

    fn io_error(op: &'static str, error: io::Error) -> Error {
        Error::Io {
            op,
            message: error.to_string(),
        }
    }

    /// `struct sockaddr_qrtr` as bytes. The node and port are host order: this
    /// is a kernel struct, not a wire header.
    fn sockaddr(addr: Addr) -> [u8; SOCKADDR_LEN] {
        let mut raw = [0u8; SOCKADDR_LEN];
        raw[0..2].copy_from_slice(&(AF_QIPCRTR as u16).to_ne_bytes());
        raw[4..8].copy_from_slice(&addr.node.to_ne_bytes());
        raw[8..12].copy_from_slice(&addr.port.to_ne_bytes());
        raw
    }

    fn parse_sockaddr(raw: &[u8; SOCKADDR_LEN]) -> Result<Addr, Error> {
        let family = u16::from_ne_bytes([raw[0], raw[1]]);
        if family != AF_QIPCRTR as u16 {
            return Err(Error::Malformed {
                what: "QRTR address has the wrong family",
            });
        }
        Ok(Addr::new(
            u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]),
            u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]),
        ))
    }

    fn bind_raw(fd: &OwnedFd, addr: Addr) -> io::Result<()> {
        let raw = sockaddr(addr);
        // SAFETY: `fd` is an open socket, `raw` is a live 12-byte
        // `sockaddr_qrtr`, and the length matches.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                raw.as_ptr().cast(),
                raw.len() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn name(fd: &OwnedFd) -> io::Result<Addr> {
        let mut raw = [0u8; SOCKADDR_LEN];
        let mut len = raw.len() as libc::socklen_t;
        // SAFETY: `raw`/`len` describe a writable 12-byte address buffer.
        let rc = unsafe { libc::getsockname(fd.as_raw_fd(), raw.as_mut_ptr().cast(), &mut len) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != SOCKADDR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "getsockname returned a short QRTR address",
            ));
        }
        parse_sockaddr(&raw).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// A bound `AF_QIPCRTR` datagram socket.
    ///
    /// One socket is one QMI client as far as the modem is concerned: the
    /// modem keys a client on the QRTR port it receives messages from, which
    /// is why the bearer keeps this socket alive for as long as the call
    /// (see `crate::bearer`).
    #[derive(Debug)]
    pub struct Socket {
        fd: OwnedFd,
        local: Addr,
    }

    impl Socket {
        /// Open a socket and let the kernel pick the port.
        ///
        /// Node 0 asks the kernel for any local node, which the target's
        /// kernel rejects; node 1 is the application processor on the target
        /// and is what libqrtr binds. The first failure is only retried for
        /// `EINVAL`, so a real configuration error still surfaces.
        pub fn connect() -> Result<Self, Error> {
            // SAFETY: a plain socket(2) call with a constant family and type.
            let raw = unsafe { libc::socket(AF_QIPCRTR, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if raw < 0 {
                return Err(io_error("socket(AF_QIPCRTR)", io::Error::last_os_error()));
            }
            // SAFETY: `raw` is a fresh descriptor this function owns.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            match bind_raw(&fd, Addr::new(0, 0)) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                    bind_raw(&fd, Addr::new(1, 0)).map_err(|error| io_error("bind", error))?;
                }
                Err(error) => return Err(io_error("bind", error)),
            }

            let local = name(&fd).map_err(|error| io_error("getsockname", error))?;
            Ok(Self { fd, local })
        }

        /// The address the kernel assigned: the local node and port.
        pub fn local(&self) -> Addr {
            self.local
        }

        /// Send one datagram to `dst`.
        pub fn send_to(&self, dst: Addr, payload: &[u8]) -> Result<(), Error> {
            let raw = sockaddr(dst);
            // SAFETY: `fd` is open, `payload` is a live slice and `raw` a live
            // address of the length passed.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    payload.as_ptr().cast(),
                    payload.len(),
                    0,
                    raw.as_ptr().cast(),
                    raw.len() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(io_error("sendto", io::Error::last_os_error()));
            }
            if sent as usize != payload.len() {
                return Err(Error::Io {
                    op: "sendto",
                    message: format!("datagram truncated: sent {sent} of {} bytes", payload.len()),
                });
            }
            Ok(())
        }

        /// Receive one datagram, waiting at most `timeout`.
        ///
        /// `Ok(None)` means the wait expired with nothing to read.
        pub fn recv_from(
            &self,
            buf: &mut [u8],
            timeout: Duration,
        ) -> Result<Option<(Addr, usize)>, Error> {
            let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            let mut pollfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: `pollfd` is one initialised entry, `millis` a timeout.
                let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
                if ready == 0 {
                    return Ok(None);
                }
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_error("poll", error));
                }
                break;
            }

            let mut raw = [0u8; SOCKADDR_LEN];
            let mut len = raw.len() as libc::socklen_t;
            // SAFETY: `buf` and `raw` are writable, `len` describes `raw`.
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    raw.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if received < 0 {
                return Err(io_error("recvfrom", io::Error::last_os_error()));
            }
            if len as usize != SOCKADDR_LEN {
                return Err(Error::Malformed {
                    what: "recvfrom returned a short QRTR address",
                });
            }
            Ok(Some((parse_sockaddr(&raw)?, received as usize)))
        }

        /// Ask the name service for `service` and return the first server.
        ///
        /// The lookup is sent to the local node's control port, which is what
        /// `qrtr-lookup` and libqrtr-glib do; the kernel forwards it to the
        /// remote nodes. Replies for other services and non-replies are
        /// skipped; the all-zero terminator means the service is absent.
        pub fn lookup(&self, service: u16, timeout: Duration) -> Result<Addr, Error> {
            let request = CtrlPacket::lookup(service).encode();
            self.send_to(Addr::control(self.local.node), &request)?;

            let deadline = Instant::now() + timeout;
            let mut buf = [0u8; 256];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::ServiceNotFound { service });
                }
                let Some((_, len)) = self.recv_from(&mut buf, remaining)? else {
                    return Err(Error::ServiceNotFound { service });
                };
                match CtrlPacket::decode(&buf[..len])?.classify(service) {
                    LookupReply::Found(addr) => return Ok(addr),
                    LookupReply::End => return Err(Error::ServiceNotFound { service }),
                    LookupReply::Other => continue,
                }
            }
        }
    }
}

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
pub use sys::Socket;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_request_matches_the_captured_bytes() {
        // Sent to (local node, 0xfffffffe) on the target; the name service
        // answered it (see README for the captured reply).
        let request = CtrlPacket::lookup(1).encode();
        let mut expected = [0u8; CtrlPacket::LEN];
        expected[0] = 0x0a; // NEW_LOOKUP
        expected[4] = 0x01; // service: WDS
        assert_eq!(request, expected);
        // A wildcard lookup (service 0) is what `qrtr-lookup` sends.
        assert_eq!(CtrlPacket::lookup(0).encode()[4..8], [0, 0, 0, 0]);
    }

    #[test]
    fn decodes_the_captured_name_service_replies() {
        // Both captured from the target's name service, in this order.
        let cases: [(&str, [u8; CtrlPacket::LEN], u16, u32, u32); 2] = [
            (
                "Data Port Mapper",
                [
                    0x04, 0x00, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
                ],
                47,
                0,
                37,
            ),
            (
                "Wireless Data Service",
                [
                    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x27, 0x00, 0x00, 0x00,
                ],
                1,
                0,
                39,
            ),
        ];
        for (name, bytes, service, node, port) in cases {
            let packet = CtrlPacket::decode(&bytes).expect(name);
            assert_eq!(packet.cmd, CtrlCmd::NewServer.raw());
            assert_eq!(packet.service, u32::from(service));
            assert_eq!(
                packet.classify(service),
                LookupReply::Found(Addr::new(node, port))
            );
            // A reply for another service is not a match.
            assert_eq!(packet.classify(service + 1), LookupReply::Other);
        }
    }

    #[test]
    fn the_all_zero_reply_ends_the_listing() {
        let end = [
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let packet = CtrlPacket::decode(&end).unwrap();
        assert!(packet.is_lookup_end());
        assert_eq!(packet.classify(1), LookupReply::End);
    }

    #[test]
    fn non_server_packets_are_ignored() {
        let ping = CtrlPacket {
            cmd: CtrlCmd::Ping.raw(),
            ..CtrlPacket::lookup(1)
        }
        .encode();
        assert_eq!(
            CtrlPacket::decode(&ping).unwrap().classify(1),
            LookupReply::Other
        );
    }

    #[test]
    fn short_control_packets_are_rejected() {
        assert!(CtrlPacket::decode(&[0u8; 19]).is_err());
        // Trailing bytes are tolerated: the packet is fixed size.
        let mut bytes = [0u8; CtrlPacket::LEN + 4];
        bytes[..CtrlPacket::LEN].copy_from_slice(&CtrlPacket::lookup(1).encode());
        assert!(CtrlPacket::decode(&bytes).is_ok());
    }

    #[test]
    fn control_commands_round_trip() {
        for raw in 1..=11u32 {
            let cmd = CtrlCmd::from_raw(raw).expect("named command");
            assert_eq!(cmd.raw(), raw);
        }
        assert_eq!(CtrlCmd::from_raw(0), None);
        assert_eq!(CtrlCmd::from_raw(12), None);
    }

    #[test]
    fn addresses_display_as_node_port() {
        assert_eq!(Addr::new(0, 39).to_string(), "0:39");
        assert_eq!(Addr::control(1), Addr::new(1, PORT_CTRL));
    }
}
