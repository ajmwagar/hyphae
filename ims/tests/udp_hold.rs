//! End-to-end over real UDP: hold and resume via re-INVITE, with the UAS
//! renegotiating the session description each time.

use ims::{Call, CallEvent, Direction, ImsProfile, IncomingCall, UasEvent};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use transport::net::UdpTransport;
use transport::Transport;

const CALLEE: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";

fn profile() -> ImsProfile {
    ImsProfile::lab_default()
}

fn parse(buf: &[u8], n: usize) -> sip::Message {
    sip::Message::parse_bytes(&buf[..n]).unwrap()
}

#[test]
fn udp_hold_and_resume_renegotiate_the_session() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];

        // Establish: INVITE -> 180 -> (PRACK) -> 200 -> ACK
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let sip::Message::Request(invite) = parse(&buf, n) else {
            panic!("expected INVITE");
        };
        let mut uas = IncomingCall::from_invite(&invite, profile()).unwrap();
        server
            .send_to(&sip::Message::Response(uas.ringing()).to_bytes(), peer)
            .unwrap();
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        if let sip::Message::Request(prack) = parse(&buf, n) {
            if let UasEvent::Respond(r) = uas.on_request(&prack).unwrap() {
                server
                    .send_to(&sip::Message::Response(r).to_bytes(), peer)
                    .unwrap();
            }
        }
        let ok = uas.accept().unwrap();
        server
            .send_to(&sip::Message::Response(ok).to_bytes(), peer)
            .unwrap();
        let (n, _peer) = server.recv_from(&mut buf).unwrap();
        if let sip::Message::Request(ack) = parse(&buf, n) {
            let _ = uas.on_request(&ack);
        }

        // Hold then resume: each re-INVITE is answered with a mirrored SDP.
        for expected in ["a=recvonly", "a=sendrecv"] {
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let sip::Message::Request(reinvite) = parse(&buf, n) else {
                panic!("expected re-INVITE");
            };
            assert_eq!(reinvite.method, sip::Method::Invite);
            let response = match uas.on_request(&reinvite).unwrap() {
                UasEvent::Respond(r) => r,
                other => panic!("unexpected {other:?}"),
            };
            let body = String::from_utf8_lossy(&response.body).to_string();
            assert!(
                body.contains(expected),
                "answer should contain {expected}: {body}"
            );
            server
                .send_to(&sip::Message::Response(response).to_bytes(), peer)
                .unwrap();
            // ACK for the re-INVITE.
            let (n, _peer) = server.recv_from(&mut buf).unwrap();
            if let sip::Message::Request(ack) = parse(&buf, n) {
                let _ = uas.on_request(&ack);
            }
        }

        // BYE.
        let (n, _peer) = server.recv_from(&mut buf).unwrap();
        if let sip::Message::Request(bye) = parse(&buf, n) {
            assert_eq!(uas.on_request(&bye).unwrap(), UasEvent::Terminated);
        }
    });

    let mut caller = UdpTransport::connect("127.0.0.1:0", addr).unwrap();
    let local = caller.local_addr().to_string();
    let (host, port) = local.rsplit_once(':').unwrap();
    let mut p = profile();
    p.contact_host = host.to_string();
    p.contact_port = port.parse().unwrap();

    let mut call = Call::new(p, CALLEE);
    let CallEvent::Send(invite) = call.invite() else {
        panic!("invite")
    };
    caller.send(&sip::Message::Request(invite)).unwrap();

    let timeout = Duration::from_secs(2);
    // Drive to Established.
    let mut established = false;
    for _ in 0..8 {
        let Some(msg) = caller.recv(timeout).unwrap() else {
            break;
        };
        let sip::Message::Response(response) = msg else {
            continue;
        };
        match call.on_response(&response) {
            CallEvent::Send(prack) => {
                caller.send(&sip::Message::Request(prack)).unwrap();
            }
            CallEvent::Established { ack } => {
                caller.send(&sip::Message::Request(ack)).unwrap();
                established = true;
                break;
            }
            CallEvent::Failed(s) => panic!("call failed {s}"),
            _ => {}
        }
    }
    assert!(established, "call never established");

    // Hold.
    let hold = call.hold().expect("hold");
    caller.send(&sip::Message::Request(hold)).unwrap();
    let response = caller.recv(timeout).unwrap().expect("no 200 to hold");
    let sip::Message::Response(response) = response else {
        panic!("expected response")
    };
    match call.on_response(&response) {
        CallEvent::Renegotiated { ack } => caller.send(&sip::Message::Request(ack)).unwrap(),
        other => panic!("unexpected {other:?}"),
    }
    // The stored SDP is the peer's answer: it mirrors our sendonly offer, so
    // the callee's answer is recvonly (it only receives while we are on hold).
    assert_eq!(
        call.answer().map(ims::Sdp::direction),
        Some(Direction::RecvOnly)
    );

    // Resume.
    let resume = call.resume().expect("resume");
    caller.send(&sip::Message::Request(resume)).unwrap();
    let response = caller.recv(timeout).unwrap().expect("no 200 to resume");
    let sip::Message::Response(response) = response else {
        panic!("expected response")
    };
    match call.on_response(&response) {
        CallEvent::Renegotiated { ack } => caller.send(&sip::Message::Request(ack)).unwrap(),
        other => panic!("unexpected {other:?}"),
    }

    let bye = call.bye().expect("bye");
    caller.send(&sip::Message::Request(bye)).unwrap();
    server_thread.join().unwrap();
}
