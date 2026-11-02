//! End-to-end over real UDP: outgoing CANCEL completes with 487, and an
//! incoming MESSAGE is acknowledged with an RP-ACK in the 200 OK.

use ims::sms::{delivery_response, receive_message, rp_ack, RpData, SmsDeliver};
use ims::{Call, CallEvent, CallState, ImsProfile, IncomingCall, UasEvent};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use transport::net::UdpTransport;
use transport::Transport;

fn profile() -> ImsProfile {
    ImsProfile::lab_default()
}

#[test]
fn udp_cancel_reaches_487() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        // INVITE -> ring.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let sip::Message::Request(invite) = sip::Message::parse_bytes(&buf[..n]).unwrap() else {
            panic!("expected INVITE");
        };
        let mut uas = IncomingCall::from_invite(&invite, profile()).unwrap();
        let ringing = uas.ringing();
        server
            .send_to(&sip::Message::Response(ringing).to_bytes(), peer)
            .unwrap();

        // CANCEL -> 200 to CANCEL, then 487 to INVITE.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let sip::Message::Request(cancel) = sip::Message::parse_bytes(&buf[..n]).unwrap() else {
            panic!("expected CANCEL");
        };
        assert_eq!(cancel.method, sip::Method::Cancel);
        match uas.on_request(&cancel).unwrap() {
            UasEvent::Cancelled { responses } => {
                for r in responses {
                    server
                        .send_to(&sip::Message::Response(r).to_bytes(), peer)
                        .unwrap();
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    });

    let mut client = UdpTransport::connect("127.0.0.1:0", addr).unwrap();
    let local = client.local_addr().to_string();
    let (host, port) = local.rsplit_once(':').unwrap();
    let mut p = profile();
    p.contact_host = host.to_string();
    p.contact_port = port.parse().unwrap();

    let mut call = Call::new(p, "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org");
    let CallEvent::Send(invite) = call.invite() else {
        panic!("invite expected")
    };
    client.send(&sip::Message::Request(invite)).unwrap();

    let timeout = Duration::from_secs(2);
    // Consume the 180, then cancel.
    let Some(msg) = client.recv(timeout).unwrap() else {
        panic!("no 180")
    };
    let sip::Message::Response(progress) = msg else {
        panic!("expected a response")
    };
    assert_eq!(progress.status, 180);
    let _ = call.on_response(&progress);

    let cancel = call.cancel().expect("CANCEL after 180");
    client.send(&sip::Message::Request(cancel)).unwrap();
    assert_eq!(call.state(), CallState::Cancelling);

    let mut failed = None;
    for _ in 0..6 {
        let Some(msg) = client.recv(timeout).unwrap() else {
            break;
        };
        let sip::Message::Response(response) = msg else {
            continue;
        };
        if let CallEvent::Failed(status) = call.on_response(&response) {
            failed = Some(status);
            break;
        }
    }
    assert_eq!(failed, Some(487), "CANCEL did not end with 487");
    assert_eq!(call.state(), CallState::Terminated);
    server_thread.join().unwrap();
}

#[test]
fn udp_mt_sms_is_acknowledged_with_rp_ack() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();

    // Network side: build RP-DATA / SMS-DELIVER and send it as a MESSAGE.
    let tpdu = SmsDeliver {
        originator: "15551234567".into(),
        pid: 0,
        dcs: 0,
        scts: [0x42, 0x10, 0x51, 0x32, 0x41, 0x00, 0x00],
        text: "meet me at 9".into(),
    }
    .encode();
    let rp = RpData {
        message_reference: 42,
        originator: "15551234567".into(),
        destination: "001010000000001".into(),
        tpdu,
    };
    let body = rp.encode();

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let sip::Message::Request(message) = sip::Message::parse_bytes(&buf[..n]).unwrap() else {
            panic!("expected MESSAGE");
        };
        assert_eq!(message.method, sip::Method::Message);
        let incoming = receive_message(&message).expect("MT SMS should decode");
        assert_eq!(incoming.originator, "15551234567");
        assert_eq!(incoming.text, "meet me at 9");

        let response = delivery_response(&message, &profile()).expect("200 OK + RP-ACK");
        server
            .send_to(&sip::Message::Response(response).to_bytes(), peer)
            .unwrap();
    });

    // UE side: bind a socket and send the MESSAGE with the RP-DATA body.
    let ue = UdpTransport::connect("127.0.0.1:0", addr).unwrap();
    let ue_addr = ue.local_addr().to_string();
    let (host, port) = ue_addr.rsplit_once(':').unwrap();
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "Via",
        format!("SIP/2.0/UDP {host}:{port};branch=z9hG4bK-mt-ue-1;rport"),
    ));
    headers.push(sip::Header::new("Max-Forwards", "70"));
    headers.push(sip::Header::new("From", "<sip:ip-sm-gw@ims>;tag=gw-1"));
    headers.push(sip::Header::new(
        "To",
        "<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>",
    ));
    headers.push(sip::Header::new("Call-ID", "mt-sms-udp-1"));
    headers.push(sip::Header::new("CSeq", "1 MESSAGE"));
    headers.push(sip::Header::new("Content-Type", "application/vnd.3gpp.sms"));
    headers.push(sip::Header::new("Content-Length", body.len().to_string()));
    let message = sip::Request {
        method: sip::Method::Message,
        uri: "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org".into(),
        headers,
        body,
    };

    let mut client = ue;
    client.send(&sip::Message::Request(message)).unwrap();
    let response = client
        .recv(Duration::from_secs(2))
        .unwrap()
        .expect("no 200");
    let sip::Message::Response(response) = response else {
        panic!("expected a response")
    };
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-type"),
        Some("application/vnd.3gpp.sms")
    );
    assert_eq!(response.body, rp_ack(42));

    server_thread.join().unwrap();
}
