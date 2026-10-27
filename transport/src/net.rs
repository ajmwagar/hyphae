//! `std::net` UDP and TCP transports.
//!
//! Both backends are synchronous and std-only. UDP is datagram-oriented: one
//! SIP message per datagram. TCP is a byte stream and therefore needs framing:
//! a message ends at CRLFCRLF plus the number of bytes named by
//! `Content-Length` (RFC 3261 §7.5, §18.2). No TLS is implemented yet.

use crate::{Transport, TransportError};
use sip::Message;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// Largest SIP message (headers plus body) accepted from a stream peer.
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// A UDP SIP endpoint. It can be connected to one peer or learn the peer from
/// the first received datagram (useful for a lab server).
pub struct UdpTransport {
    socket: UdpSocket,
    local: String,
    peer: Option<SocketAddr>,
}

impl UdpTransport {
    /// Bind without a peer. `send` fails until `connect` or an inbound datagram
    /// teaches the transport the peer address.
    pub fn bind(local: impl ToSocketAddrs) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(local).map_err(io_err)?;
        let local = socket.local_addr().map_err(io_err)?.to_string();
        Ok(Self {
            socket,
            local,
            peer: None,
        })
    }

    /// Bind locally and connect to the remote SIP endpoint.
    pub fn connect(
        local: impl ToSocketAddrs,
        peer: impl ToSocketAddrs,
    ) -> Result<Self, TransportError> {
        let peer = resolve_one(peer)?;
        let mut transport = Self::bind(local)?;
        transport.socket.connect(peer).map_err(io_err)?;
        transport.peer = Some(peer);
        Ok(transport)
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    pub fn set_peer(&mut self, peer: SocketAddr) {
        let _ = self.socket.connect(peer);
        self.peer = Some(peer);
    }
}

impl Transport for UdpTransport {
    fn local_addr(&self) -> &str {
        &self.local
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        let bytes = message.to_bytes();
        let connected = self.socket.peer_addr().is_ok();
        let sent = match (connected, self.peer) {
            (true, _) => self.socket.send(&bytes),
            (false, Some(peer)) => self.socket.send_to(&bytes, peer),
            (false, None) => Err(std::io::Error::new(
                ErrorKind::NotConnected,
                "UDP transport has no peer yet",
            )),
        }
        .map_err(io_err)?;
        if sent != bytes.len() {
            return Err(TransportError::Rejected(format!(
                "UDP sent {sent} of {} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError> {
        self.socket
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))
            .map_err(io_err)?;
        let mut buf = vec![0u8; 65_535];
        // `peer` may have been learned from an inbound datagram without
        // connecting the socket, so use the socket's actual state here.
        let connected = self.socket.peer_addr().is_ok();
        let (n, from) = if connected {
            match self.socket.recv(&mut buf) {
                Ok(n) => (n, self.peer),
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) => return Err(io_err(e)),
            }
        } else {
            match self.socket.recv_from(&mut buf) {
                Ok((n, from)) => (n, Some(from)),
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) => return Err(io_err(e)),
            }
        };
        if let (Some(peer), Some(from)) = (self.peer, from) {
            if peer != from {
                // Connected UDP normally filters this, but keep the check for
                // platforms that deliver stray datagrams.
                return Ok(None);
            }
        }
        if self.peer.is_none() {
            self.peer = from;
        }
        let text =
            std::str::from_utf8(&buf[..n]).map_err(|e| TransportError::Codec(e.to_string()))?;
        Message::parse(text)
            .map(Some)
            .map_err(|e| TransportError::Codec(e.to_string()))
    }
}

/// A TCP SIP stream with RFC 3261 message framing.
pub struct TcpTransport {
    stream: TcpStream,
    local: String,
    peer: String,
    read_buf: Vec<u8>,
    eof: bool,
}

impl TcpTransport {
    /// Connect to a remote endpoint. DNS may yield several addresses; the first
    /// one that accepts within `timeout` wins.
    pub fn connect(peer: impl ToSocketAddrs, timeout: Duration) -> Result<Self, TransportError> {
        let mut last = None;
        for addr in peer.to_socket_addrs().map_err(io_err)? {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => return Self::from_stream(stream).map_err(io_err),
                Err(e) => last = Some(e),
            }
        }
        Err(io_err(last.unwrap_or_else(|| {
            std::io::Error::new(ErrorKind::AddrNotAvailable, "no TCP address resolved")
        })))
    }

    /// Accept one connection from a bound listener and wrap it.
    pub fn accept(listener: &TcpListener) -> Result<Self, TransportError> {
        let (stream, _peer) = listener.accept().map_err(io_err)?;
        Self::from_stream(stream).map_err(io_err)
    }

    /// Wrap an already-connected stream. Useful for tests and platform adapters.
    pub fn from_stream(stream: TcpStream) -> Result<Self, std::io::Error> {
        let local = stream.local_addr()?.to_string();
        let peer = stream.peer_addr()?.to_string();
        Ok(Self {
            stream,
            local,
            peer,
            read_buf: Vec::new(),
            eof: false,
        })
    }

    pub fn peer_addr(&self) -> &str {
        &self.peer
    }

    /// Read at most one message without waiting; returns `None` if the buffer
    /// does not yet hold a complete frame.
    pub fn try_recv_buffered(&mut self) -> Result<Option<Message>, TransportError> {
        match take_message(&mut self.read_buf)? {
            Some(bytes) => parse_frame(&bytes).map(Some),
            None => Ok(None),
        }
    }
}

impl Transport for TcpTransport {
    fn local_addr(&self) -> &str {
        &self.local
    }

    fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        let bytes = message.to_bytes();
        self.stream.write_all(&bytes).map_err(|e| {
            if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) {
                TransportError::Closed
            } else {
                io_err(e)
            }
        })?;
        self.stream.flush().map_err(io_err)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Message>, TransportError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(bytes) = take_message(&mut self.read_buf)? {
                return parse_frame(&bytes).map(Some);
            }
            if self.eof {
                return if self.read_buf.is_empty() {
                    Err(TransportError::Closed)
                } else {
                    Err(TransportError::Codec(
                        "peer closed with a partial SIP message".into(),
                    ))
                };
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(io_err)?;
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    self.read_buf.extend_from_slice(&chunk[..n]);
                    // A header without its terminator can already be too big.
                    check_buffer_size(&self.read_buf)?;
                }
                Err(e) if is_timeout(&e) => return Ok(None),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if matches!(e.kind(), ErrorKind::ConnectionReset) => {
                    self.eof = true;
                }
                Err(e) => return Err(io_err(e)),
            }
        }
    }
}

/// Extract one complete SIP frame from `buf`, leaving any following bytes.
///
/// Returns `Ok(None)` for a partial frame. Oversized frames are rejected before
/// allocating or parsing them (64 KiB cap).
fn take_message(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, TransportError> {
    let (head_end, sep_len) = match find_head_end(buf) {
        Some(v) => v,
        None => {
            check_buffer_size(buf)?;
            return Ok(None);
        }
    };
    let head = &buf[..head_end];
    let body_len = content_length(head)?;
    let total = head_end + sep_len + body_len;
    if total > MAX_MESSAGE_SIZE {
        return Err(TransportError::Rejected(format!(
            "SIP message of {total} bytes exceeds {MAX_MESSAGE_SIZE}"
        )));
    }
    if buf.len() < total {
        return Ok(None);
    }
    let bytes = buf[..total].to_vec();
    buf.drain(..total);
    Ok(Some(bytes))
}

fn find_head_end(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((i, 4));
    }
    // Be tolerant of bare-LF test peers, but never of a missing terminator.
    buf.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2))
}

fn content_length(head: &[u8]) -> Result<usize, TransportError> {
    let text = std::str::from_utf8(head)
        .map_err(|e| TransportError::Codec(format!("non-UTF-8 SIP headers: {e}")))?;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length")
            || name.trim().eq_ignore_ascii_case("l")
        {
            return value.trim().parse::<usize>().map_err(|_| {
                TransportError::Codec(format!("invalid Content-Length {:?}", value.trim()))
            });
        }
    }
    Ok(0)
}

fn check_buffer_size(buf: &[u8]) -> Result<(), TransportError> {
    if buf.len() > MAX_MESSAGE_SIZE {
        return Err(TransportError::Rejected(format!(
            "SIP stream buffer exceeds {MAX_MESSAGE_SIZE} bytes without a complete message"
        )));
    }
    Ok(())
}

fn parse_frame(bytes: &[u8]) -> Result<Message, TransportError> {
    let text = std::str::from_utf8(bytes).map_err(|e| TransportError::Codec(e.to_string()))?;
    Message::parse(text).map_err(|e| TransportError::Codec(e.to_string()))
}

fn resolve_one(peer: impl ToSocketAddrs) -> Result<SocketAddr, TransportError> {
    peer.to_socket_addrs()
        .map_err(io_err)?
        .next()
        .ok_or_else(|| TransportError::Rejected("no address resolved".into()))
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

fn io_err(e: std::io::Error) -> TransportError {
    if matches!(
        e.kind(),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    ) {
        TransportError::Closed
    } else {
        TransportError::Rejected(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip::{Header, Headers, Method, Request};
    use std::net::{TcpListener, UdpSocket};
    use std::thread;

    fn response(status: u16, body: &[u8]) -> Message {
        let mut headers = Headers::new();
        headers.push(Header::new("Call-ID", "frame-test"));
        headers.push(Header::new("CSeq", "1 REGISTER"));
        headers.push(Header::new("Content-Length", body.len().to_string()));
        Message::Response(sip::Response {
            status,
            reason: "test".into(),
            headers,
            body: body.to_vec(),
        })
    }

    fn register() -> Message {
        let mut headers = Headers::new();
        headers.push(Header::new("Via", "SIP/2.0/UDP 192.0.2.10:5060"));
        headers.push(Header::new("Call-ID", "udp-test"));
        headers.push(Header::new("CSeq", "1 REGISTER"));
        headers.push(Header::new("Content-Length", "0"));
        Message::Request(Request {
            method: Method::Register,
            uri: "sip:ims.mnc001.mcc001.3gppnetwork.org".into(),
            headers,
            body: Vec::new(),
        })
    }

    #[test]
    fn framing_waits_for_partial_body() {
        let full = response(200, b"hello").to_bytes();
        let split = full.len() - 2;
        let mut buf = full[..split].to_vec();
        assert_eq!(take_message(&mut buf).unwrap(), None);
        buf.extend_from_slice(&full[split..]);
        let frame = take_message(&mut buf).unwrap().unwrap();
        assert_eq!(frame, full);
        assert!(buf.is_empty());
    }

    #[test]
    fn framing_extracts_two_messages_from_one_read() {
        let a = response(200, b"a").to_bytes();
        let b = response(401, b"challenge").to_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        assert_eq!(take_message(&mut buf).unwrap().unwrap(), a);
        assert_eq!(take_message(&mut buf).unwrap().unwrap(), b);
        assert!(buf.is_empty());
    }

    #[test]
    fn framing_rejects_oversize_content_length() {
        let mut buf = b"SIP/2.0 200 OK\r\nContent-Length: 65535\r\n\r\n".to_vec();
        buf.extend_from_slice(&[b'x'; 100]);
        let err = take_message(&mut buf).unwrap_err();
        assert!(matches!(err, TransportError::Rejected(_)));
    }

    #[test]
    fn framing_rejects_endless_header() {
        let mut buf = vec![b'x'; MAX_MESSAGE_SIZE + 1];
        let err = take_message(&mut buf).unwrap_err();
        assert!(matches!(err, TransportError::Rejected(_)));
    }

    #[test]
    fn tcp_reads_message_split_across_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = response(200, b"sdp-body").to_bytes();
        let (left, right) = (bytes.len() / 2, bytes.len());
        thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(&bytes[..left]).unwrap();
            stream.flush().unwrap();
            thread::sleep(Duration::from_millis(20));
            stream.write_all(&bytes[left..right]).unwrap();
            stream.flush().unwrap();
        });
        let stream = listener.accept().unwrap().0;
        let mut tcp = TcpTransport::from_stream(stream).unwrap();
        let got = tcp.recv(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(got, response(200, b"sdp-body"));
    }

    #[test]
    fn tcp_reports_graceful_close_after_message() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = response(200, b"").to_bytes();
        thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(&bytes).unwrap();
        });
        let stream = listener.accept().unwrap().0;
        let mut tcp = TcpTransport::from_stream(stream).unwrap();
        assert_eq!(
            tcp.recv(Duration::from_secs(1)).unwrap().unwrap(),
            response(200, b"")
        );
        assert_eq!(
            tcp.recv(Duration::from_secs(1)),
            Err(TransportError::Closed)
        );
    }

    #[test]
    fn udp_round_trip_and_peer_learning() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        drop(server_socket);
        let mut server = UdpTransport::bind(server_addr).unwrap();
        let mut client = UdpTransport::connect("127.0.0.1:0", server_addr).unwrap();
        client.send(&register()).unwrap();
        let got = server.recv(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(got, register());
        assert!(server.peer_addr().is_some());
        server.send(&response(200, b"")).unwrap();
        assert_eq!(
            client.recv(Duration::from_secs(1)).unwrap().unwrap(),
            response(200, b"")
        );
    }

    #[test]
    fn udp_recv_times_out_without_error() {
        let mut endpoint = UdpTransport::bind("127.0.0.1:0").unwrap();
        assert_eq!(endpoint.recv(Duration::from_millis(5)).unwrap(), None);
    }
}
