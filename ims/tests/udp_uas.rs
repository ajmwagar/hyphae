//! End-to-end: a real UDP INVITE answered by the UAS and driven to
//! `Established` by the caller state machine.
//!
//! Caller: `ims::Call` (INVITE -> 180 -> PRACK -> 200 -> ACK).
//! Callee: `ims::IncomingCall` (trying/ringing/accept, PRACK 200).
//!
//! This proves the two halves of the call path interoperate over the wire
//! codec, not just in-memory.

use ims::{Call, CallEvent, ImsProfile, IncomingCall, UasEvent};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use transport::net::UdpTransport;
use transport::Transport;

const CALLEE: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";

fn profile() -> ImsProfile {
    ImsProfile::lab_default()
}

#[test]
fn udp_incoming_call_reaches_established() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];

        // 1. INVITE arrives; build the callee dialog and ring.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let msg = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(invite) = msg else {
            panic!("expected INVITE");
        };
        let mut uas = IncomingCall::from_invite(&invite, profile()).unwrap();

        let trying = uas.trying();
        server
            .send_to(&sip::Message::Response(trying).to_bytes(), peer)
            .unwrap();
        let ringing = uas.ringing();
        server
            .send_to(&sip::Message::Response(ringing).to_bytes(), peer)
            .unwrap();

        // 2. Caller answers the reliable 180 with a PRACK.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let msg = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(prack) = msg else {
            panic!("expected PRACK");
        };
        match uas.on_request(&prack).unwrap() {
            UasEvent::Respond(r) => {
                assert_eq!(r.status, 200);
                server
                    .send_to(&sip::Message::Response(r).to_bytes(), peer)
                    .unwrap();
            }
            other => panic!("unexpected {other:?}"),
        }

        // 3. Accept: 200 OK with the SDP answer.
        let ok = uas.accept().unwrap();
        server
            .send_to(&sip::Message::Response(ok).to_bytes(), peer)
            .unwrap();

        // 4. ACK confirms the dialog.
        let (n, _peer) = server.recv_from(&mut buf).unwrap();
        let msg = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(ack) = msg else {
            panic!("expected ACK");
        };
        assert_eq!(
            uas.on_request(&ack).unwrap(),
            UasEvent::Established,
            "ACK did not confirm the callee dialog"
        );

        // 5. The caller sends BYE; the callee acknowledges and terminates.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let msg = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(bye) = msg else {
            panic!("expected BYE");
        };
        assert_eq!(uas.on_request(&bye).unwrap(), UasEvent::Terminated);
        server
            .send_to(&sip::Message::Response(uas_dummy_200()).to_bytes(), peer)
            .unwrap();
    });

    // --- caller ---
    let mut caller = UdpTransport::connect("127.0.0.1:0", server_addr).unwrap();
    let local = caller.local_addr().to_string();
    let (host, port) = local.rsplit_once(':').unwrap();
    let mut caller_profile = profile();
    caller_profile.contact_host = host.to_string();
    caller_profile.contact_port = port.parse().unwrap();

    let mut call = Call::new(caller_profile, CALLEE);
    let CallEvent::Send(invite) = call.invite() else {
        panic!("invite did not produce a request");
    };
    caller.send(&sip::Message::Request(invite)).unwrap();

    let timeout = Duration::from_secs(2);
    let mut acked = false;
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
                acked = true;
                break;
            }
            CallEvent::Failed(status) => panic!("call failed with {status}"),
            CallEvent::Provisional | CallEvent::Renegotiated { .. } | CallEvent::Forked { .. } => {}
        }
    }
    assert!(acked, "caller never reached Established");
    assert!(call.is_established());

    // Release the dialog.
    let bye = call.bye().expect("BYE for an established call");
    caller.send(&sip::Message::Request(bye)).unwrap();
    let _ = caller.recv(timeout).unwrap();

    server_thread.join().unwrap();
}

/// A minimal 200 OK used only to acknowledge BYE in this test.
fn uas_dummy_200() -> sip::Response {
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("Content-Length", "0"));
    sip::Response {
        status: 200,
        reason: "OK".into(),
        headers,
        body: Vec::new(),
    }
}
