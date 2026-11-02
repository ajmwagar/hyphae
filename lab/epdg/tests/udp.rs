//! The exchange over real UDP sockets on loopback.
//!
//! The in-process test proves the state machines agree. This one proves the
//! bytes survive a socket: datagram boundaries, the sealed payload, and the
//! message-id progression, against a responder that derives its keys
//! independently.

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use epdg::sk::BLOCK_LEN;
use epdg_lab::{Reply, StandInEpdg, UeClient, TEST_IDENTITY, TEST_K, TEST_NETWORK, TEST_OPC};

const GROUP: u16 = 14;

/// A per-message IV. This crate has no RNG by design; a real client must use a
/// fresh unpredictable IV, and reusing one under the same key is a break.
fn iv_for(message_id: u32) -> [u8; BLOCK_LEN] {
    [message_id as u8; BLOCK_LEN]
}

#[test]
fn the_ike_exchange_completes_over_udp() {
    let responder_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    responder_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let responder_addr = responder_socket.local_addr().unwrap();

    let server = thread::spawn(move || {
        let mut responder = StandInEpdg::new(
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
        );
        let mut buf = [0u8; 4096];

        loop {
            let (len, from) = responder_socket.recv_from(&mut buf).unwrap();
            let request = &buf[..len];

            // Only the header is readable on an encrypted message, so routing
            // must not depend on the payload chain.
            let header = epdg::ikev2::Header::decode(request).unwrap().0;
            match header.exchange {
                epdg::ikev2::ExchangeType::IkeSaInit => {
                    let response = responder.on_sa_init(request).unwrap();
                    responder_socket.send_to(&response, from).unwrap();
                }
                _ => {
                    let iv = iv_for(header.message_id);
                    match responder.on_ike_auth(request, &iv).unwrap() {
                        Reply::Send(bytes) => {
                            responder_socket.send_to(&bytes, from).unwrap();
                        }
                        Reply::Established { bytes, .. } => {
                            responder_socket.send_to(&bytes, from).unwrap();
                            return;
                        }
                    }
                }
            }
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.connect(responder_addr).unwrap();

    let mut client = UeClient::new(
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
    .unwrap();

    let mut buf = [0u8; 4096];

    // IKE_SA_INIT
    socket.send(&client.sa_init_request()).unwrap();
    let len = socket.recv(&mut buf).unwrap();
    let first_auth = client.on_sa_init_response(&buf[..len]).unwrap();

    // IKE_AUTH: challenge, then AUTH, then the responder's final message.
    let mut outbound = Some(first_auth);
    let mut established = None;
    while let Some(request) = outbound.take() {
        socket.send(&request).unwrap();
        let len = socket.recv(&mut buf).unwrap();
        let (next, done) = client.on_ike_auth(&buf[..len]).unwrap();
        outbound = next;
        if let Some(done) = done {
            established = Some(done);
        }
    }

    let established = established.expect("the exchange completed");
    assert_eq!(established.ims_address, Some([10, 32, 0, 7]));
    assert_eq!(established.dns, vec![[10, 32, 0, 1]]);
    assert_eq!(established.child.outbound.spi, 0x1000);
    assert_eq!(established.child.inbound.spi, 0x1001);
    assert_eq!(established.child.outbound.encryption.key().len(), 16);
    assert_eq!(established.child.outbound.integrity.key().len(), 32);

    server.join().unwrap();
}

/// The same exchange, but with every IKE_AUTH datagram encapsulated on the
/// NAT-T port with the 4-octet non-ESP marker (RFC 3948 §2.2).
///
/// Two sockets stand in for ports 500 and 4500; the point is the framing and
/// the responder accepting IKE from either, not the port numbers.
#[test]
fn the_ike_exchange_completes_with_udp_encapsulation() {
    use epdg::natt::{decapsulate, encapsulate};

    let plain = UdpSocket::bind("127.0.0.1:0").unwrap();
    let natted = UdpSocket::bind("127.0.0.1:0").unwrap();
    for socket in [&plain, &natted] {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    let plain_addr = plain.local_addr().unwrap();
    let natted_addr = natted.local_addr().unwrap();

    let server = thread::spawn(move || {
        let mut responder = StandInEpdg::new(
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
        );
        let mut buf = [0u8; 4096];
        let mut idle = 0u32;
        loop {
            // Try the plain port, then the NAT-T port.
            let (len, from, encapsulated) = match plain.recv_from(&mut buf) {
                Ok((len, from)) => (len, from, false),
                Err(_) => match natted.recv_from(&mut buf) {
                    Ok((len, from)) => (len, from, true),
                    Err(_) => {
                        idle += 1;
                        if idle >= 50 {
                            return; // ~5 s of silence
                        }
                        continue;
                    }
                },
            };
            idle = 0;
            let request = if encapsulated {
                decapsulate(&buf[..len]).expect("marker").to_vec()
            } else {
                buf[..len].to_vec()
            };
            let header = epdg::ikev2::Header::decode(&request).unwrap().0;
            let reply = if header.exchange == epdg::ikev2::ExchangeType::IkeSaInit {
                responder.on_sa_init(&request).map(Reply::Send)
            } else {
                responder.on_ike_auth(&request, &iv_for(header.message_id))
            };
            let socket = if encapsulated { &natted } else { &plain };
            let send = |bytes: Vec<u8>| {
                let bytes = if encapsulated {
                    encapsulate(&bytes)
                } else {
                    bytes
                };
                socket.send_to(&bytes, from).unwrap();
            };
            match reply {
                Ok(Reply::Send(bytes)) => send(bytes),
                Ok(Reply::Established { bytes, .. }) => {
                    send(bytes);
                    return;
                }
                Err(_) => return,
            }
        }
    });

    let client_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut client = UeClient::new(
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
    .unwrap();

    let mut buf = [0u8; 4096];
    client_socket
        .send_to(&client.sa_init_request(), plain_addr)
        .unwrap();
    let (len, _) = client_socket.recv_from(&mut buf).unwrap();
    let first_auth = client.on_sa_init_response(&buf[..len]).unwrap();

    let mut outbound = Some(first_auth);
    let mut established = None;
    while let Some(request) = outbound.take() {
        client_socket
            .send_to(&encapsulate(&request), natted_addr)
            .unwrap();
        // Patient receive: the responder polls two sockets, so a datagram can
        // arrive after the first short timeout.
        let mut waited = Duration::ZERO;
        let len = loop {
            match client_socket.recv_from(&mut buf) {
                Ok((len, _)) => break len,
                Err(_) if waited < Duration::from_secs(10) => {
                    waited += Duration::from_millis(200);
                }
                Err(e) => panic!("no reply on the NAT-T port: {e}"),
            }
        };
        let reply = decapsulate(&buf[..len]).expect("marker on the NAT-T port");
        let (next, done) = client.on_ike_auth(reply).unwrap();
        outbound = next;
        if done.is_some() {
            established = done;
        }
    }

    let established = established.expect("the exchange completed");
    assert_eq!(established.ims_address, Some([10, 32, 0, 7]));
    server.join().unwrap();
}
