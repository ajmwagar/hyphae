//! `epdg-lab` — drive the Wi-Fi calling exchange over UDP.
//!
//! ```sh
//! epdg-lab                       # client and stand-in ePDG on loopback
//! epdg-lab --listen 0.0.0.0:500  # stand-in ePDG only
//! epdg-lab --connect 10.0.0.1:500
//! ```
//!
//! This is lab tooling: it prints what it negotiated and exits. It never dials
//! a real operator network on its own.

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use epdg::ikev2::{ExchangeType, Header};
use epdg::natt::{decapsulate, encapsulate, Endpoint};
use epdg::sk::BLOCK_LEN;
use epdg_lab::{Reply, StandInEpdg, UeClient, TEST_IDENTITY, TEST_K, TEST_NETWORK, TEST_OPC};

const GROUP: u16 = 14;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Wrap a socket address as raw octets for the NAT-detection digest.
fn to_endpoint(addr: SocketAddr) -> Endpoint {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => Endpoint::new(v4.octets(), addr.port()),
        std::net::IpAddr::V6(v6) => Endpoint::new(v6.octets(), addr.port()),
    }
}

fn iv_for(message_id: u32) -> [u8; BLOCK_LEN] {
    [message_id as u8; BLOCK_LEN]
}

fn responder() -> StandInEpdg {
    StandInEpdg::new(
        TEST_NETWORK,
        TEST_K,
        TEST_OPC,
        GROUP,
        vec![0x55; 32],
        [0x44; 8],
        vec![0x66; 32],
        [0x00, 0x00, 0x10, 0x00],
        [10, 32, 0, 7],
        [10, 32, 0, 1],
    )
}

fn client() -> UeClient {
    UeClient::new(
        TEST_NETWORK,
        TEST_IDENTITY,
        TEST_K,
        TEST_OPC,
        [0x11; 8],
        &[0x22; 32],
        vec![0x33; 32],
        GROUP,
        [0x00, 0x00, 0x10, 0x01],
    )
    .expect("client parameters are valid")
}

#[cfg(feature = "pcsc")]
fn client_with_pcsc(reader: Option<&str>) -> UeClient {
    let channel = usim_pcsc::PcscChannel::open(reader).unwrap_or_else(|e| {
        eprintln!("hyphae-epdg: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "hyphae-epdg: USIM reader {:?}; the stand-in ePDG uses TS 35.208 test set 1",
        channel.reader()
    );
    UeClient::with_usim(
        TEST_NETWORK,
        TEST_IDENTITY,
        Box::new(usim::UsimCard::new(channel)),
        [0x11; 8],
        &[0x22; 32],
        vec![0x33; 32],
        GROUP,
        [0x00, 0x00, 0x10, 0x01],
    )
    .expect("client parameters are valid")
}

#[cfg(not(feature = "pcsc"))]
fn client_with_pcsc(_reader: Option<&str>) -> UeClient {
    eprintln!("hyphae-epdg: PC/SC support not built; rebuild with --features pcsc");
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Optional `--pcsc [READER]` applies to the UE side; it is removed before
    // the listen/connect parsing so the existing CLI shape stays intact.
    let mut pcsc: Option<Option<String>> = None;
    if let Some(pos) = args.iter().position(|a| a == "--pcsc") {
        let reader = args
            .get(pos + 1)
            .filter(|value| !value.starts_with("--"))
            .cloned();
        args.remove(pos);
        if reader.is_some() {
            args.remove(pos);
        }
        pcsc = Some(reader);
    }
    match args.first().map(String::as_str) {
        Some("--listen") => {
            let addr = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "127.0.0.1:500".into());
            serve(&addr);
        }
        Some("--connect") => {
            let addr = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "127.0.0.1:500".into());
            let addr: SocketAddr = addr.parse().unwrap_or_else(|e| {
                eprintln!("hyphae-epdg: bad address {addr:?}: {e}");
                std::process::exit(2);
            });
            // `--force-nat-t` exercises the encapsulated path even when the
            // path has no NAT, so the 4500 framing can be tested on its own.
            let force = args.iter().any(|a| a == "--force-nat-t");
            run_client(addr, pcsc.clone(), force);
        }
        Some(other) => {
            eprintln!("hyphae-epdg: unknown argument {other:?}");
            eprintln!("usage: epdg-lab [--listen ADDR | --connect ADDR]");
            std::process::exit(2);
        }
        None => loopback(pcsc),
    }
}

/// Start a responder on `addr` and drive a client at it.
fn loopback(pcsc: Option<Option<String>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
    socket
        .set_read_timeout(Some(TIMEOUT))
        .expect("read timeout");
    let addr = socket.local_addr().expect("local addr");

    let server = thread::spawn(move || serve_socket(socket));
    run_client(addr, pcsc, false);
    server.join().expect("responder thread");
}

fn serve(addr: &str) {
    let socket = UdpSocket::bind(addr).unwrap_or_else(|e| {
        eprintln!("hyphae-epdg: cannot bind {addr}: {e}");
        std::process::exit(1);
    });
    println!("hyphae-epdg: listening on {}", socket.local_addr().unwrap());

    // NAT-T: when IKE starts on 500, the encapsulated path is 4500 (RFC 3948).
    let natted = socket
        .local_addr()
        .ok()
        .filter(|a| a.port() == 500)
        .and_then(|a| UdpSocket::bind((a.ip(), 4500)).ok());
    if let Some(natted) = &natted {
        println!(
            "hyphae-epdg: NAT-T listening on {}",
            natted.local_addr().unwrap()
        );
    }
    serve_socket_with(socket, natted);
}

fn serve_socket(socket: UdpSocket) {
    serve_socket_with(socket, None)
}

/// The responder loop: one datagram in, one out, until the exchange completes.
///
/// `natted` is the port-4500 socket when one was bound; datagrams there carry
/// the 4-octet non-ESP marker (RFC 3948 §2.2).
fn serve_socket_with(socket: UdpSocket, natted: Option<UdpSocket>) {
    // Poll both ports with a short timeout: once the client switches to 4500,
    // blocking on 500 would sit out the whole exchange.
    const POLL: Duration = Duration::from_millis(100);
    socket.set_read_timeout(Some(POLL)).expect("read timeout");
    if let Some(natted) = &natted {
        natted.set_read_timeout(Some(POLL)).expect("read timeout");
    }
    let mut responder = responder();
    let mut buf = [0u8; 4096];
    let mut idle = 0u32;
    let idle_limit = (TIMEOUT.as_millis() / POLL.as_millis()) as u32;
    loop {
        let received = match socket.recv_from(&mut buf) {
            Ok(v) => (v, false),
            Err(_) => match &natted {
                Some(natted) => match natted.recv_from(&mut buf) {
                    Ok(v) => (v, true),
                    Err(_) => {
                        idle += 1;
                        if idle >= idle_limit {
                            return; // idle: this is a lab responder, not a daemon
                        }
                        continue;
                    }
                },
                None => return,
            },
        };
        idle = 0;
        let ((len, from), encapsulated) = received;
        let request = if encapsulated {
            match decapsulate(&buf[..len]) {
                Some(inner) => inner.to_vec(),
                None => continue, // keepalive or ESP, not IKE
            }
        } else {
            buf[..len].to_vec()
        };
        let reply_socket = if encapsulated {
            natted.as_ref().unwrap()
        } else {
            &socket
        };
        let wrap = |bytes: Vec<u8>| {
            if encapsulated {
                encapsulate(&bytes)
            } else {
                bytes
            }
        };
        let header = match Header::decode(&request) {
            Ok((header, _)) => header,
            Err(_) => continue,
        };
        let reply = if header.exchange == ExchangeType::IkeSaInit {
            responder.on_sa_init(&request).map(Reply::Send)
        } else {
            responder.on_ike_auth(&request, &iv_for(header.message_id))
        };
        match reply {
            Ok(Reply::Send(bytes)) => {
                if reply_socket.send_to(&wrap(bytes), from).is_err() {
                    return;
                }
            }
            Ok(Reply::Established {
                bytes,
                child,
                ims_address,
            }) => {
                let _ = reply_socket.send_to(&wrap(bytes), from);
                println!(
                    "hyphae-epdg: established; UE IMS address {}.{}.{}.{}, out spi {:#x}, in spi {:#x}",
                    ims_address[0],
                    ims_address[1],
                    ims_address[2],
                    ims_address[3],
                    child.outbound.spi,
                    child.inbound.spi
                );
                return;
            }
            Err(e) => {
                eprintln!("hyphae-epdg: {e}");
                return;
            }
        }
    }
}

fn run_client(addr: SocketAddr, pcsc: Option<Option<String>>, force_nat_t: bool) {
    // Bind wide and connect first: only after `connect` does `local_addr`
    // report the address the kernel actually chose, which is what NAT
    // detection has to hash.
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind client");
    socket
        .set_read_timeout(Some(TIMEOUT))
        .expect("read timeout");
    socket.connect(addr).expect("connect");
    let local = socket.local_addr().expect("local addr");
    let mut client = match pcsc {
        Some(reader) => client_with_pcsc(reader.as_deref()),
        None => client(),
    };
    client.set_endpoints(to_endpoint(local), to_endpoint(addr));
    let mut buf = [0u8; 4096];

    socket
        .send(&client.sa_init_request())
        .expect("send SA_INIT");
    let len = socket.recv(&mut buf).expect("recv SA_INIT response");
    let first_auth = client
        .on_sa_init_response(&buf[..len])
        .expect("SA_INIT response");

    // NAT-T (RFC 3948): if detection found a NAT, the rest of the exchange
    // moves to port 4500 and every datagram gains the non-ESP marker.
    let verdict = client.nat_verdict();
    let mut encapsulated = false;
    if let Some(verdict) = verdict {
        println!(
            "hyphae-epdg: NAT detection: peer_behind_nat={} we_are_behind_nat={}",
            verdict.peer_behind_nat, verdict.we_are_behind_nat
        );
        if verdict.needs_encapsulation() || force_nat_t {
            let mut nat_addr = addr;
            nat_addr.set_port(4500);
            socket.connect(nat_addr).expect("connect to 4500");
            encapsulated = true;
            println!("hyphae-epdg: switching to UDP-encapsulated IKE on port 4500");
        }
    }
    let frame = |bytes: Vec<u8>| {
        if encapsulated {
            encapsulate(&bytes)
        } else {
            bytes
        }
    };

    let mut outbound = Some(first_auth);
    let mut established = None;
    while let Some(request) = outbound.take() {
        socket.send(&frame(request)).expect("send IKE_AUTH");
        let len = socket.recv(&mut buf).expect("recv IKE_AUTH response");
        let reply = if encapsulated {
            match decapsulate(&buf[..len]) {
                Some(inner) => inner.to_vec(),
                None => panic!("expected a non-ESP marker on port 4500"),
            }
        } else {
            buf[..len].to_vec()
        };
        let (next, done) = client.on_ike_auth(&reply).expect("IKE_AUTH response");
        outbound = next;
        if done.is_some() {
            established = done;
        }
    }

    let established = established.expect("the exchange completed");
    let address = established
        .ims_address
        .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
        .unwrap_or_else(|| "none".into());
    println!("hyphae-epdg: authenticated; IMS address {address}");
    println!(
        "hyphae-epdg: child SA out spi {:#x} ({}) in spi {:#x} ({})",
        established.child.outbound.spi,
        established.child.outbound.encryption.xfrm_name(),
        established.child.inbound.spi,
        established.child.inbound.integrity.xfrm_name()
    );
    if !established.dns.is_empty() {
        let dns: Vec<String> = established
            .dns
            .iter()
            .map(|d| format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]))
            .collect();
        println!("hyphae-epdg: DNS {}", dns.join(", "));
    }
}
