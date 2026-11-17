//! rtnetlink: bring the interface up, move the bearer's address onto it, and
//! route the default through its gateway.
//!
//! ## Why this is hand-rolled
//!
//! Five message shapes are needed (`RTM_NEWLINK`, `RTM_NEWADDR`, `RTM_DELADDR`,
//! `RTM_GETADDR`, `RTM_NEWROUTE`/`RTM_DELROUTE`) over one socket family. A
//! netlink crate would add a dependency, a type system and an async runtime
//! decision for a few hundred lines of fixed-layout encoder, and the encoder is
//! exactly the part a test can check byte for byte. The same reasoning as
//! `crate::qrtr`: one dependency (`libc`) for the syscalls, no C library.
//!
//! ## What `configure` does, and why
//!
//! ```text
//!   RTM_NEWLINK   IFF_UP                       a down interface drops the route
//!   RTM_GETADDR   dump IPv4 addresses          find what a previous run left
//!   RTM_DELADDR   for each of them             flush, so a retry cannot stack
//!   RTM_NEWADDR   address/32                    a /32 host route: the modem
//!                                               owns the subnet, not us
//!   RTM_NEWROUTE  default via gateway, onlink,
//!                 metric 50                    the gateway is not in any
//!                                               subnet we have, so the route
//!                                               must be `onlink`
//! ```
//!
//! `RTNH_F_ONLINK` travels in `rtmsg.rtm_flags` for a single-nexthop route (the
//! kernel copies it into the fib config), which is what `ip route ... onlink`
//! sets. The metric (50) puts the bearer above a DHCP lease route while it is
//! up; the prototype used the same value.
//!
//! Teardown deletes the default route and flushes the addresses. Deleting
//! something that is already gone (`ESRCH`) is not an error here: a bearer that
//! was never applied, or that another process already tore down, is not a
//! failure to report.

use std::net::Ipv4Addr;

use crate::Error;

/// `RTM_NEWLINK`.
pub const RTM_NEWLINK: u16 = 16;
/// `RTM_NEWADDR`.
pub const RTM_NEWADDR: u16 = 20;
/// `RTM_DELADDR`.
pub const RTM_DELADDR: u16 = 21;
/// `RTM_GETADDR`.
pub const RTM_GETADDR: u16 = 22;
/// `RTM_NEWROUTE`.
pub const RTM_NEWROUTE: u16 = 24;
/// `RTM_DELROUTE`.
pub const RTM_DELROUTE: u16 = 25;

/// `NLM_F_REQUEST`.
pub const NLM_F_REQUEST: u16 = 0x0001;
/// `NLM_F_ACK`.
pub const NLM_F_ACK: u16 = 0x0004;
/// `NLM_F_REPLACE`.
pub const NLM_F_REPLACE: u16 = 0x0100;
/// `NLM_F_EXCL`.
pub const NLM_F_EXCL: u16 = 0x0200;
/// `NLM_F_CREATE`.
pub const NLM_F_CREATE: u16 = 0x0400;
/// `NLM_F_ROOT | NLM_F_MATCH`.
pub const NLM_F_DUMP: u16 = 0x0300;

/// `NLMSG_ERROR`: the acknowledgement (or the refusal) of a request.
pub const NLMSG_ERROR: u16 = 2;
/// `NLMSG_DONE`: the end of a dump.
pub const NLMSG_DONE: u16 = 3;
/// `struct nlmsghdr`.
pub const NLMSG_HEADER_LEN: usize = 16;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;

const AF_INET: u8 = 2;
const AF_UNSPEC: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTNH_F_ONLINK: u32 = 0x0004;
const IFF_UP: u32 = 0x0001;

/// The bearer address is a host route: the modem hands out one address and
/// owns everything behind the gateway.
pub const HOST_PREFIX: u8 = 32;

/// Route metric: below a DHCP default so the bearer wins while it is up.
pub const DEFAULT_METRIC: u32 = 50;

/// One decoded netlink message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    /// `RTM_*` or `NLMSG_*`.
    pub kind: u16,
    /// `NLM_F_*` flags.
    pub flags: u16,
    /// Sequence number the request carried.
    pub seq: u32,
    /// The message body, after the header.
    pub payload: &'a [u8],
}

/// Iterate the messages of one netlink datagram.
pub fn messages(datagram: &[u8]) -> Messages<'_> {
    Messages {
        datagram,
        offset: 0,
    }
}

/// An iterator over the messages in a netlink datagram.
pub struct Messages<'a> {
    datagram: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Messages<'a> {
    type Item = Result<Message<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.datagram.len() {
            return None;
        }
        let rest = &self.datagram[self.offset..];
        if rest.len() < NLMSG_HEADER_LEN {
            return Some(Err(Error::Malformed {
                what: "netlink message shorter than its header",
            }));
        }
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len < NLMSG_HEADER_LEN || self.offset + len > self.datagram.len() {
            return Some(Err(Error::Malformed {
                what: "netlink message length overruns the datagram",
            }));
        }
        let kind = u16::from_ne_bytes([rest[4], rest[5]]);
        let flags = u16::from_ne_bytes([rest[6], rest[7]]);
        let seq = u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]);
        let payload = &rest[NLMSG_HEADER_LEN..len];
        self.offset += (len + 3) & !3;
        Some(Ok(Message {
            kind,
            flags,
            seq,
            payload,
        }))
    }
}

/// One IPv4 address found on the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressEntry {
    /// The local address.
    pub address: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
    /// Address scope (`RT_SCOPE_*`).
    pub scope: u8,
}

/// Read an `RTM_NEWADDR` body for `ifindex`, if it is an IPv4 address on it.
///
/// `IFA_LOCAL` wins over `IFA_ADDRESS`: on a point-to-point link they differ,
/// and the local one is what `ip addr flush` names.
pub fn parse_address_reply(payload: &[u8], ifindex: u32) -> Option<AddressEntry> {
    if payload.len() < 8 {
        return None;
    }
    let family = payload[0];
    let prefix = payload[1];
    let scope = payload[3];
    let index = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if family != AF_INET || index != ifindex {
        return None;
    }

    let mut address: Option<&[u8]> = None;
    let mut local: Option<&[u8]> = None;
    let mut at = 8;
    while at + 4 <= payload.len() {
        let len = usize::from(u16::from_ne_bytes([payload[at], payload[at + 1]]));
        let kind = u16::from_ne_bytes([payload[at + 2], payload[at + 3]]);
        if len < 4 || at + len > payload.len() {
            break;
        }
        let value = &payload[at + 4..at + len];
        match kind {
            IFA_LOCAL => local = Some(value),
            IFA_ADDRESS => address = Some(value),
            _ => {}
        }
        at += (len + 3) & !3;
    }

    let octets = local.or(address)?;
    let octets: [u8; 4] = octets.try_into().ok()?;
    Some(AddressEntry {
        address: Ipv4Addr::from(octets),
        prefix,
        scope,
    })
}

/// The `error` field of an `NLMSG_ERROR` message: `0` is an acknowledgement,
/// a negative value is `-errno`.
pub fn ack_result(message: &Message<'_>) -> Option<i32> {
    if message.kind != NLMSG_ERROR || message.payload.len() < 4 {
        return None;
    }
    Some(i32::from_ne_bytes([
        message.payload[0],
        message.payload[1],
        message.payload[2],
        message.payload[3],
    ]))
}

fn header(kind: u16, flags: u16, seq: u32, payload_len: usize) -> Vec<u8> {
    let total = NLMSG_HEADER_LEN + payload_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    // The kernel fills the pid of a request in.
    out.extend_from_slice(&0u32.to_ne_bytes());
    out
}

/// Append a route/address attribute, padded to 4 bytes.
fn push_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(&[0u8; 4][..(4 - len % 4) % 4]);
}

fn ifaddrmsg(family: u8, prefix: u8, scope: u8, index: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.push(family);
    payload.push(prefix);
    payload.push(0); // flags
    payload.push(scope);
    payload.extend_from_slice(&index.to_ne_bytes());
    payload
}

/// `RTM_NEWLINK`: set `IFF_UP` on the interface.
pub fn link_up(seq: u32, ifindex: u32) -> Vec<u8> {
    // struct ifinfomsg: family, pad, type, index, flags, change
    let mut payload = Vec::with_capacity(16);
    payload.push(AF_UNSPEC);
    payload.push(0);
    payload.extend_from_slice(&0u16.to_ne_bytes()); // type
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    payload.extend_from_slice(&IFF_UP.to_ne_bytes());
    payload.extend_from_slice(&IFF_UP.to_ne_bytes());
    let mut out = header(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq, payload.len());
    out.extend_from_slice(&payload);
    out
}

/// `RTM_GETADDR`: dump every IPv4 address on every interface.
pub fn dump_addresses(seq: u32) -> Vec<u8> {
    let payload = ifaddrmsg(AF_INET, 0, 0, 0);
    let mut out = header(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq, payload.len());
    out.extend_from_slice(&payload);
    out
}

/// `RTM_NEWADDR`: add `address` as a host route on the interface.
///
/// `IFA_LOCAL` only, which is what `ip addr add <addr>/32` sends: the kernel
/// fills `IFA_ADDRESS` from it. Sending both would be read as a peer address
/// on a point-to-point interface, and this interface is not one.
pub fn add_address(seq: u32, ifindex: u32, address: Ipv4Addr) -> Vec<u8> {
    let mut payload = ifaddrmsg(AF_INET, HOST_PREFIX, RT_SCOPE_UNIVERSE, ifindex);
    push_attr(&mut payload, IFA_LOCAL, &address.octets());
    let mut out = header(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        payload.len(),
    );
    out.extend_from_slice(&payload);
    out
}

/// `RTM_DELADDR`: remove one of the addresses a dump reported.
pub fn del_address(seq: u32, ifindex: u32, entry: &AddressEntry) -> Vec<u8> {
    let mut payload = ifaddrmsg(AF_INET, entry.prefix, entry.scope, ifindex);
    push_attr(&mut payload, IFA_LOCAL, &entry.address.octets());
    let mut out = header(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, seq, payload.len());
    out.extend_from_slice(&payload);
    out
}

/// The `rtmsg` body shared by the two route requests.
fn rtmsg(dst_len: u8, protocol: u8, flags: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(12);
    payload.push(AF_INET);
    payload.push(dst_len);
    payload.push(0); // src_len
    payload.push(0); // tos
    payload.push(RT_TABLE_MAIN);
    payload.push(protocol);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.push(RTN_UNICAST);
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload
}

/// `RTM_NEWROUTE`: the default route through `gateway`, `onlink`, metric 50.
pub fn add_default_route(seq: u32, ifindex: u32, gateway: Ipv4Addr) -> Vec<u8> {
    let mut payload = rtmsg(0, RTPROT_BOOT, RTNH_F_ONLINK);
    push_attr(&mut payload, RTA_GATEWAY, &gateway.octets());
    push_attr(&mut payload, RTA_OIF, &ifindex.to_ne_bytes());
    push_attr(&mut payload, RTA_PRIORITY, &DEFAULT_METRIC.to_ne_bytes());
    let mut out = header(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
        payload.len(),
    );
    out.extend_from_slice(&payload);
    out
}

/// `RTM_DELROUTE`: remove the default route this crate installed.
///
/// The match is "default prefix through `ifindex` with our metric", so a
/// default route another process installed with a different metric is left
/// alone.
pub fn del_default_route(seq: u32, ifindex: u32) -> Vec<u8> {
    let mut payload = rtmsg(0, RTPROT_BOOT, 0);
    push_attr(&mut payload, RTA_OIF, &ifindex.to_ne_bytes());
    push_attr(&mut payload, RTA_PRIORITY, &DEFAULT_METRIC.to_ne_bytes());
    let mut out = header(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq, payload.len());
    out.extend_from_slice(&payload);
    out
}

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
#[allow(unsafe_code)]
mod sys {
    //! The netlink socket and the [`crate::bearer::NetworkConfig`]
    //! implementation. This is one of the crate's two `unsafe` surfaces (the
    //! other is `crate::qrtr`); see `lib.rs` for the policy. Every block below
    //! is a single syscall whose arguments are built locally.

    use std::cell::Cell;
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        ack_result, add_address, add_default_route, del_address, del_default_route, dump_addresses,
        link_up, messages, parse_address_reply, AddressEntry, NLMSG_DONE, NLMSG_ERROR, RTM_NEWADDR,
    };
    use crate::bearer::NetworkConfig;
    use crate::wds::BearerConfig;
    use crate::Error;

    /// `struct sockaddr_nl`: family, pad, pid, groups.
    const SOCKADDR_NL_LEN: usize = 12;

    fn io_error(op: &'static str, error: io::Error) -> Error {
        Error::Io {
            op,
            message: error.to_string(),
        }
    }

    /// An interface as the kernel sees it.
    ///
    /// Requires `CAP_NET_ADMIN` to change anything; reads (the address dump)
    /// work as an ordinary user.
    #[derive(Debug)]
    pub struct Interface {
        fd: OwnedFd,
        /// The interface name, kept because the index cannot be resolved yet:
        /// see `ifindex`.
        name: CString,
        /// `0` until the name resolves. A `Cell` because `configure` takes
        /// `&self` -- the bearer config is applied through a shared reference.
        ifindex: Cell<u32>,
        seq: Cell<u32>,
        timeout: Duration,
    }

    impl Interface {
        /// Open a netlink socket. The name is resolved later, on purpose.
        ///
        /// The interface does not exist until the modem opens its BAM DMUX
        /// channel, which happens just *after* `WDS Start Network` returns --
        /// and that call has not been made when the bearer is built. Waiting
        /// here is a deadlock: the tool sat for a minute looking for an
        /// interface that only the call it had not started yet would create,
        /// and the call was never started.
        pub fn new(name: &str) -> Result<Self, Error> {
            let c_name = CString::new(name).map_err(|_| Error::Malformed {
                what: "interface name contains a NUL byte",
            })?;


            // SAFETY: a plain socket(2) call with constant arguments.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            };
            if raw < 0 {
                return Err(io_error("socket(AF_NETLINK)", io::Error::last_os_error()));
            }
            // SAFETY: `raw` is a fresh descriptor this function owns.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            // Bind with pid 0: the kernel assigns one, which is what routes
            // the acknowledgement back to this socket.
            let mut local = [0u8; SOCKADDR_NL_LEN];
            local[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
            // SAFETY: `local` is a live 12-byte `sockaddr_nl`.
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    local.as_ptr().cast(),
                    local.len() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io_error("bind(AF_NETLINK)", io::Error::last_os_error()));
            }

            Ok(Self {
                fd,
                name: c_name,
                ifindex: Cell::new(0),
                seq: Cell::new(0),
                timeout: Duration::from_secs(5),
            })
        }

        /// The kernel's index for the interface, or 0 before it exists.
        pub fn ifindex(&self) -> u32 {
            self.ifindex.get()
        }

        /// The interface index, waiting for the interface to appear.
        ///
        /// The kernel workqueue that creates `wwan0` runs just after the modem
        /// accepts the data call, so the first `configure` is what has to be
        /// patient. The bound is generous because the failure mode is silent:
        /// an unresolved index leaves a live call with no interface, and the
        /// only symptom is a bearer that never carries traffic.
        fn resolve_ifindex(&self) -> Result<u32, Error> {
            const WAIT: Duration = Duration::from_secs(60);
            const STEP: Duration = Duration::from_millis(100);

            let cached = self.ifindex.get();
            if cached != 0 {
                return Ok(cached);
            }

            let start = Instant::now();
            let deadline = start + WAIT;
            let mut announced = false;
            loop {
                // SAFETY: `self.name` is NUL-terminated and outlives the call.
                let index = unsafe { libc::if_nametoindex(self.name.as_ptr()) };
                if index != 0 {
                    self.ifindex.set(index);
                    return Ok(index);
                }
                if Instant::now() >= deadline {
                    return Err(io_error("if_nametoindex", io::Error::last_os_error()));
                }
                if !announced && start.elapsed() >= Duration::from_secs(1) {
                    eprintln!(
                        "hyphae-modem: waiting for {} (the modem creates it when it opens its data channel)",
                        self.name.to_string_lossy()
                    );
                    announced = true;
                }
                thread::sleep(STEP);
            }
        }

        fn next_seq(&self) -> u32 {
            let seq = self.seq.get().wrapping_add(1);
            self.seq.set(seq);
            seq
        }

        fn send(&self, request: &[u8]) -> Result<(), Error> {
            // SAFETY: `request` is a live buffer and `fd` is open.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    request.as_ptr().cast(),
                    request.len(),
                    0,
                )
            };
            if sent < 0 {
                return Err(io_error("netlink send", io::Error::last_os_error()));
            }
            if sent as usize != request.len() {
                return Err(Error::Io {
                    op: "netlink send",
                    message: format!("short write: {sent} of {} bytes", request.len()),
                });
            }
            Ok(())
        }

        fn recv(&self, buf: &mut [u8], timeout: Duration) -> Result<Option<usize>, Error> {
            let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
            let mut pollfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: one initialised `pollfd`, a timeout in milliseconds.
                let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
                if ready == 0 {
                    return Ok(None);
                }
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_error("netlink poll", error));
                }
                break;
            }

            // SAFETY: `buf` is writable.
            let received =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if received < 0 {
                return Err(io_error("netlink recv", io::Error::last_os_error()));
            }
            Ok(Some(received as usize))
        }

        /// Send one request and wait for its acknowledgement.
        fn request(&self, op: &'static str, request: Vec<u8>, seq: u32) -> Result<(), Error> {
            self.send(&request)?;
            let deadline = Instant::now() + self.timeout;
            let mut buf = [0u8; 4096];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::Io {
                        op,
                        message: "timed out waiting for the acknowledgement".to_string(),
                    });
                }
                let Some(len) = self.recv(&mut buf, remaining)? else {
                    continue;
                };
                for reply in messages(&buf[..len]) {
                    let reply = reply?;
                    if reply.seq != seq {
                        continue;
                    }
                    match ack_result(&reply) {
                        Some(0) => return Ok(()),
                        Some(errno) if errno < 0 => {
                            return Err(Error::Netlink { op, errno: -errno })
                        }
                        _ => continue,
                    }
                }
            }
        }

        /// Like [`Self::request`], but `allowed` errnos are treated as success.
        fn request_allowing(
            &self,
            op: &'static str,
            request: Vec<u8>,
            seq: u32,
            allowed: &[i32],
        ) -> Result<(), Error> {
            match self.request(op, request, seq) {
                Err(Error::Netlink { errno, .. }) if allowed.contains(&errno) => Ok(()),
                other => other,
            }
        }

        /// Every IPv4 address currently on this interface.
        fn addresses(&self) -> Result<Vec<AddressEntry>, Error> {
            let ifindex = self.resolve_ifindex()?;
            let seq = self.next_seq();
            self.send(&dump_addresses(seq))?;

            let deadline = Instant::now() + self.timeout;
            let mut buf = [0u8; 8192];
            let mut entries = Vec::new();
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::Io {
                        op: "RTM_GETADDR",
                        message: "timed out waiting for the dump to finish".to_string(),
                    });
                }
                let Some(len) = self.recv(&mut buf, remaining)? else {
                    continue;
                };
                for reply in messages(&buf[..len]) {
                    let reply = reply?;
                    if reply.kind == NLMSG_DONE {
                        return Ok(entries);
                    }
                    if reply.kind == NLMSG_ERROR {
                        if let Some(errno) = ack_result(&reply) {
                            if errno != 0 {
                                return Err(Error::Netlink {
                                    op: "RTM_GETADDR",
                                    errno: -errno,
                                });
                            }
                        }
                        continue;
                    }
                    if reply.kind != RTM_NEWADDR {
                        continue;
                    }
                    if let Some(entry) = parse_address_reply(reply.payload, ifindex) {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    impl NetworkConfig for Interface {
        fn configure(&self, config: &BearerConfig) -> Result<(), Error> {
            let ifindex = self.resolve_ifindex()?;
            let seq = self.next_seq();
            self.request("RTM_NEWLINK", link_up(seq, ifindex), seq)?;

            // Flush first, so a retry cannot stack addresses on top of a
            // previous partial attempt.
            for entry in self.addresses()? {
                let seq = self.next_seq();
                self.request_allowing(
                    "RTM_DELADDR",
                    del_address(seq, ifindex, &entry),
                    seq,
                    &[libc::ESRCH],
                )?;
            }

            let seq = self.next_seq();
            self.request(
                "RTM_NEWADDR",
                add_address(seq, ifindex, config.address),
                seq,
            )?;

            let seq = self.next_seq();
            self.request(
                "RTM_NEWROUTE",
                add_default_route(seq, ifindex, config.gateway),
                seq,
            )?;
            Ok(())
        }

        fn clear(&self) -> Result<(), Error> {
            let ifindex = self.resolve_ifindex()?;
            for entry in self.addresses()? {
                let seq = self.next_seq();
                self.request_allowing(
                    "RTM_DELADDR",
                    del_address(seq, ifindex, &entry),
                    seq,
                    &[libc::ESRCH],
                )?;
            }
            let seq = self.next_seq();
            self.request_allowing(
                "RTM_DELROUTE",
                del_default_route(seq, ifindex),
                seq,
                &[libc::ESRCH],
            )?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::Interface;

        #[test]
        fn an_unknown_interface_is_rejected_when_it_is_used() {
            // `new` only opens the socket: the interface the modem has not
            // created yet must be accepted here, or the bearer can never start
            // the call that creates it. Resolution is what has to fail.
            let interface = Interface::new("hyphae-no-such0").expect("socket");
            assert_eq!(interface.ifindex(), 0, "not resolved yet");
        }
    }
}

#[cfg(all(feature = "modem-qmi", target_os = "linux"))]
pub use sys::Interface;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{hex, unhex};

    const IFINDEX: u32 = 7;

    #[test]
    fn link_up_request_is_byte_exact() {
        let request = link_up(1, IFINDEX);
        let expected = unhex(concat!(
            "20000000", // nlmsg_len 32
            "1000",     // RTM_NEWLINK
            "0500",     // REQUEST|ACK
            "01000000", // seq
            "00000000", // pid, filled in by the kernel
            "00",       // ifi_family AF_UNSPEC
            "00",       // pad
            "0000",     // ifi_type
            "07000000", // ifi_index
            "01000000", // ifi_flags IFF_UP
            "01000000", // ifi_change IFF_UP
        ));
        assert_eq!(hex(&request), hex(&expected));
    }

    #[test]
    fn add_address_request_is_byte_exact() {
        let request = add_address(2, IFINDEX, Ipv4Addr::new(192, 0, 0, 2));
        let expected = unhex(concat!(
            "20000000",          // nlmsg_len 32
            "1400",              // RTM_NEWADDR
            "0506",              // REQUEST|ACK|CREATE|EXCL
            "02000000",          // seq
            "00000000",          // pid
            "02",                // AF_INET
            "20",                // /32
            "00",                // flags
            "00",                // scope universe
            "07000000",          // ifa_index
            "08000200 c0000002", // IFA_LOCAL 192.0.0.2
        ));
        assert_eq!(hex(&request), hex(&expected));
    }

    #[test]
    fn default_route_request_is_byte_exact() {
        let request = add_default_route(3, IFINDEX, Ipv4Addr::new(192, 0, 0, 1));
        let expected = unhex(concat!(
            "34000000", // nlmsg_len 52
            "1800",     // RTM_NEWROUTE
            "0505",     // REQUEST|ACK|CREATE|REPLACE
            "03000000", // seq
            "00000000", // pid
            "02",
            "00",
            "00",
            "00",                // AF_INET, prefix 0, src_len 0, tos 0
            "fe",                // table main
            "03",                // protocol boot
            "00",                // scope universe
            "01",                // type unicast
            "04000000",          // flags RTNH_F_ONLINK
            "08000500 c0000001", // RTA_GATEWAY 192.0.0.1
            "08000400 07000000", // RTA_OIF
            "08000600 32000000", // RTA_PRIORITY 50
        ));
        assert_eq!(hex(&request), hex(&expected));
    }

    #[test]
    fn dump_request_is_byte_exact() {
        let request = dump_addresses(4);
        let expected = unhex(concat!(
            "18000000", // nlmsg_len 24
            "1600",     // RTM_GETADDR
            "0103",     // REQUEST|DUMP
            "04000000", // seq
            "00000000", // pid
            "02", "00", "00", "00",       // AF_INET, all prefixes, all scopes
            "00000000", // any interface
        ));
        assert_eq!(hex(&request), hex(&expected));
    }

    #[test]
    fn every_request_length_is_aligned_and_self_describing() {
        let requests = [
            link_up(1, IFINDEX),
            dump_addresses(2),
            add_address(3, IFINDEX, Ipv4Addr::new(192, 0, 0, 2)),
            del_address(
                4,
                IFINDEX,
                &AddressEntry {
                    address: Ipv4Addr::new(192, 0, 0, 2),
                    prefix: 32,
                    scope: 0,
                },
            ),
            add_default_route(5, IFINDEX, Ipv4Addr::new(192, 0, 0, 1)),
            del_default_route(6, IFINDEX),
        ];
        for request in requests {
            assert_eq!(request.len() % 4, 0);
            let declared = u32::from_ne_bytes([request[0], request[1], request[2], request[3]]);
            assert_eq!(declared as usize, request.len());
        }
    }

    /// A real `RTM_GETADDR` dump, captured from the target (kernel 7.3,
    /// msm8937): lo, usb0 and wlan0, then the `NLMSG_DONE` terminator. The
    /// kernel writes `IFA_LABEL`, `IFA_FLAGS` and `IFA_CACHEINFO` attributes
    /// too, so the parser's attribute walk is exercised against real bytes.
    const CAPTURED_DUMP: &str = concat!(
        "4c000000140002000100000035030000020880fe01000000080001007f000001080002007f000001",
        "070003006c6f0000080008008000000014000600ffffffffffffffff7501000075010000",
        "58000000140002000100000035030000021e80000200000008000100c0a84d0208000200c0a84d02",
        "08000400c0a84d03090003007573623000000000080008008000000014000600ffffffffffffffff",
        "2e0100002e010000",
        "58000000140002000100000035030000021800000300000008000100c0a80a6508000200c0a80a65",
        "08000400c0a80aff0a000300776c616e3000000008000800000200001400060098260100c8500100",
        "b5070000b5070000",
        "1400000003000200010000003503000000000000",
    );

    #[test]
    fn parses_the_captured_address_dump_and_filters_by_interface() {
        let datagram = unhex(CAPTURED_DUMP);
        let replies: Vec<Message<'_>> = messages(&datagram)
            .collect::<Result<Vec<_>, _>>()
            .expect("the captured dump parses");
        assert_eq!(replies.len(), 4, "three addresses and the terminator");
        assert_eq!(replies[3].kind, NLMSG_DONE);

        let addresses = |ifindex: u32| -> Vec<AddressEntry> {
            replies
                .iter()
                .filter_map(|reply| parse_address_reply(reply.payload, ifindex))
                .collect()
        };
        assert_eq!(
            addresses(1),
            vec![AddressEntry {
                address: Ipv4Addr::new(127, 0, 0, 1),
                prefix: 8,
                scope: 254, // RT_SCOPE_HOST on loopback
            }]
        );
        assert_eq!(
            addresses(2),
            vec![AddressEntry {
                address: Ipv4Addr::new(192, 168, 77, 2),
                prefix: 30,
                scope: 0,
            }]
        );
        assert_eq!(
            addresses(3),
            vec![AddressEntry {
                address: Ipv4Addr::new(192, 168, 10, 101),
                prefix: 24,
                scope: 0,
            }]
        );
        // An interface with no IPv4 address contributes nothing.
        assert!(addresses(9).is_empty());
        // The terminator is not an address.
        assert!(parse_address_reply(replies[3].payload, 1).is_none());
    }

    #[test]
    fn local_wins_over_address_on_a_point_to_point_link() {
        let datagram = unhex(concat!(
            "28000000",
            "1400",
            "0000",
            "01000000",
            "00000000",
            "02",
            "20",
            "00",
            "00",
            "07000000",
            "08000100 0a000001", // IFA_ADDRESS (peer)
            "08000200 c0000002", // IFA_LOCAL (us)
        ));
        let message = messages(&datagram).next().unwrap().unwrap();
        assert_eq!(
            parse_address_reply(message.payload, IFINDEX)
                .unwrap()
                .address,
            Ipv4Addr::new(192, 0, 0, 2)
        );
    }

    #[test]
    fn acknowledgements_carry_zero_and_refusals_a_negative_errno() {
        // `struct nlmsgerr`: error i32 + the 16-byte header of the request.
        let ack = unhex(concat!(
            "24000000", "0200", "0000", "01000000", "00000000", // header, 36 bytes
            "00000000", // error 0 = ack
            "14000000", "1400", "0506", "01000000", "00000000",
        ));
        let message = messages(&ack).next().unwrap().unwrap();
        assert_eq!(ack_result(&message), Some(0));

        let refused = unhex(concat!(
            "24000000", "0200", "0000", "01000000", "00000000", "eaffffff", // -22, EINVAL
            "14000000", "1400", "0506", "01000000", "00000000",
        ));
        let message = messages(&refused).next().unwrap().unwrap();
        assert_eq!(ack_result(&message), Some(-22));

        let data =
            unhex("20000000 1400 0000 01000000 00000000 02 20 00 00 07000000 08000200 c0000002");
        let message = messages(&data).next().unwrap().unwrap();
        assert_eq!(ack_result(&message), None);
    }

    #[test]
    fn a_truncated_datagram_is_an_error_not_a_silent_stop() {
        let short = unhex("08000000 1400");
        assert!(messages(&short).next().unwrap().is_err());
        let overrun = unhex("ff000000 1400 0000 01000000 00000000");
        assert!(messages(&overrun).next().unwrap().is_err());
    }
}
