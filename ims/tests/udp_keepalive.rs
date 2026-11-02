//! End-to-end over real UDP: an OPTIONS keepalive ping and its 200 OK.

use ims::{Keepalive, KeepaliveStatus};
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};
use transport::net::UdpTransport;
use transport::Transport;

#[test]
fn udp_options_ping_is_answered_and_marks_the_path_alive() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();

    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let sip::Message::Request(ping) = sip::Message::parse_bytes(&buf[..n]).unwrap() else {
            panic!("expected OPTIONS");
        };
        assert_eq!(ping.method, sip::Method::Options);
        // Echo the dialog headers back in a 200 with an Allow list.
        let mut headers = sip::Headers::new();
        for via in ping.headers.get_all("via") {
            headers.push(sip::Header::new("Via", via));
        }
        headers.push(sip::Header::new("From", ping.headers.get("from").unwrap()));
        headers.push(sip::Header::new(
            "To",
            format!("{};tag=pcscf", ping.headers.get("to").unwrap()),
        ));
        headers.push(sip::Header::new(
            "Call-ID",
            ping.headers.get("call-id").unwrap(),
        ));
        headers.push(sip::Header::new("CSeq", ping.headers.get("cseq").unwrap()));
        headers.push(sip::Header::new(
            "Allow",
            "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,INFO,MESSAGE,OPTIONS",
        ));
        headers.push(sip::Header::new("Content-Length", "0"));
        let ok = sip::Message::Response(sip::Response {
            status: 200,
            reason: "OK".into(),
            headers,
            body: Vec::new(),
        });
        server.send_to(&ok.to_bytes(), peer).unwrap();
    });

    let mut client = UdpTransport::connect("127.0.0.1:0", addr).unwrap();
    let local = client.local_addr().to_string();
    let (host, port) = local.rsplit_once(':').unwrap();
    let mut profile = ims::ImsProfile::lab_default();
    profile.contact_host = host.to_string();
    profile.contact_port = port.parse().unwrap();

    let mut ka = Keepalive::new(profile).with_interval(Duration::from_secs(10));
    let now = Instant::now();
    assert!(ka.due(now));
    let ping = ka.ping("sip:pcscf.ims.example", now);
    client.send(&sip::Message::Request(ping)).unwrap();

    let response = client
        .recv(Duration::from_secs(2))
        .unwrap()
        .expect("no 200");
    let sip::Message::Response(response) = response else {
        panic!("expected a response");
    };
    assert_eq!(response.status, 200);
    assert_eq!(ka.on_response(&response), KeepaliveStatus::Alive);
    assert_eq!(ka.failures(), 0);

    server_thread.join().unwrap();
}
