//! The emergency IMS flow, driven end to end over loopback.
//!
//! The UE side is `ims::emergency`; the network side is [`StandInEcscf`]. What
//! this proves is that the messages the UE builds are the messages the core is
//! supposed to receive, and that the sequences connect: register, invite, and —
//! when the registration is refused — the unauthenticated fallback.
//!
//! It proves nothing about PSAP routing, media, or a real carrier. Both ends run
//! in this process, on `127.0.0.1`.

#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::time::Duration;

use emergency_lab::{Policy, StandInEcscf};
use ims::emergency::{
    emergency_fallback, EmergencyFallback, EmergencyIdentity, EmergencyRegistration,
    EmergencyRequest, Geolocation, SosService,
};
use sip::{Message, Response};

const HOME: &str = "ims.mnc001.mcc001.3gppnetwork.org";
const UE_HOST: &str = "127.0.0.1";
const UE_PORT: u16 = 5060;

/// A UE-side socket pointed at the stand-in.
struct Ue {
    socket: UdpSocket,
    ecscf: std::net::SocketAddr,
}

impl Ue {
    fn new(ecscf: std::net::SocketAddr) -> Self {
        let socket = UdpSocket::bind((UE_HOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        Self { socket, ecscf }
    }

    fn send(&self, request: &sip::Request) -> Response {
        let bytes = sip::Message::Request(request.clone()).to_bytes();
        self.socket.send_to(&bytes, self.ecscf).unwrap();
        let mut buf = [0u8; 65535];
        let (len, _) = self.socket.recv_from(&mut buf).unwrap();
        match Message::parse_bytes(&buf[..len]).unwrap() {
            Message::Response(response) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }
}

/// Spawn a stand-in that answers until `count` requests have been handled.
fn spawn_ecscf(
    policy: Policy,
    count: usize,
) -> (std::net::SocketAddr, std::thread::JoinHandle<StandInEcscf>) {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let mut ecscf = StandInEcscf::new(policy, format!("sip:ecscf@127.0.0.1:{}", addr.port()));
        let mut buf = [0u8; 65535];
        for _ in 0..count {
            let (len, from) = socket.recv_from(&mut buf).unwrap();
            let request = match Message::parse_bytes(&buf[..len]).unwrap() {
                Message::Request(request) => request,
                Message::Response(_) => continue,
            };
            let response = match request.method {
                sip::Method::Register => ecscf.on_register(&request),
                sip::Method::Invite => ecscf.on_invite(&request),
                sip::Method::Publish => ecscf.on_publish(&request),
                _ => sip::Response {
                    status: 405,
                    reason: "Method Not Allowed".into(),
                    headers: sip::Headers::new(),
                    body: Vec::new(),
                },
            };
            socket
                .send_to(&Message::Response(response).to_bytes(), from)
                .unwrap();
        }
        ecscf
    });
    (addr, handle)
}

fn temporary_identity() -> EmergencyIdentity {
    EmergencyIdentity::temporary_from_imsi("001010000000001", HOME)
}

#[test]
fn an_emergency_registration_then_call_reaches_the_core() {
    let (addr, server) = spawn_ecscf(Policy::Accept, 2);
    let ue = Ue::new(addr);

    // 1. Emergency registration: Contact carries `;sos` (§5.1.6.2 a).
    let register = EmergencyRegistration::new(temporary_identity(), UE_HOST, UE_PORT, 600)
        .with_pani("IEEE-802.11; i-wlan-node-id=001122334455")
        .register(&format!("sip:{HOME}"), UE_HOST, UE_PORT);
    let response = ue.send(&register);
    assert_eq!(
        response.status, 200,
        "the stand-in accepts an emergency registration"
    );

    // 2. Emergency call inside that registration (§5.1.6.8.3): the URN is the
    //    Request-URI and To carries it too, location and offer travel together,
    //    and no `esnet` namespace is sent.
    let invite = EmergencyRequest::new(SosService::Sos, temporary_identity(), UE_HOST, UE_PORT)
        .with_geolocation(Geolocation::new(51.5, -0.12).unwrap().with_radius(50.0))
        .with_offer_sdp("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\nm=audio 40000 RTP/AVP 98\r\n")
        .with_pani("IEEE-802.11; i-wlan-node-id=001122334455")
        .with_current_location_discovery()
        .invite()
        .unwrap();
    let response = ue.send(&invite);
    assert_eq!(response.status, 200);

    let ecscf = server.join().unwrap();
    assert_eq!(ecscf.observations.len(), 2);

    let register = &ecscf.observations[0];
    assert_eq!(register.method, "REGISTER");
    assert!(register.contact_sos, "the sos URI parameter is the marker");
    assert!(register.from.contains("001010000000001"));
    assert_eq!(
        register.pani.as_deref(),
        Some("IEEE-802.11; i-wlan-node-id=001122334455")
    );

    let invite = &ecscf.observations[1];
    assert_eq!(invite.method, "INVITE");
    assert_eq!(invite.uri, "urn:service:sos");
    assert_eq!(invite.priority.as_deref(), Some("emergency"));
    // §4.7: the trust domain strips this if a UE sends it, so it must be absent.
    assert_eq!(invite.resource_priority, None);
    // RFC 6442: the location is a body part named by cid, and it did not
    // displace the media offer.
    assert!(invite.geolocation.as_deref().unwrap().starts_with("<cid:"));
    assert_eq!(invite.geolocation_routing.as_deref(), Some("yes"));
    assert!(invite.multipart);
    assert!(invite.has_pidf);
    assert!(invite.has_sdp);
    assert_eq!(
        invite.recv_info.as_deref(),
        Some("g.3gpp.current-location-discovery")
    );
}

#[test]
fn a_refused_emergency_registration_falls_back_to_an_anonymous_call() {
    // The network will not do emergency registration for this UE.
    let (addr, server) = spawn_ecscf(Policy::RejectAnonymous, 2);
    let ue = Ue::new(addr);

    let register = EmergencyRegistration::new(temporary_identity(), UE_HOST, UE_PORT, 600)
        .register(&format!("sip:{HOME}"), UE_HOST, UE_PORT);
    let response = ue.send(&register);
    assert_eq!(response.status, 403);

    // TS 24.229 §5.1.6.2: 403 with this body means "call without registering".
    assert_eq!(
        emergency_fallback(&response),
        Some(EmergencyFallback::AnonymousEmergencyCall)
    );

    // §5.1.6.8.2: From is "Anonymous", with an instance id on the Contact.
    let invite = EmergencyRequest::new(SosService::Sos, temporary_identity(), UE_HOST, UE_PORT)
        .anonymous("6f9c2b1e-0000-4000-8000-000000000001")
        .with_offer_sdp("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\nm=audio 40000 RTP/AVP 98\r\n")
        .invite()
        .unwrap();
    let response = ue.send(&invite);
    assert_eq!(response.status, 200);

    let ecscf = server.join().unwrap();
    let invite = &ecscf.observations[1];
    assert_eq!(invite.method, "INVITE");
    assert_eq!(invite.uri, "urn:service:sos");
    assert!(invite
        .from
        .starts_with("\"Anonymous\" <sip:anonymous@anonymous.invalid>"));
    assert_eq!(invite.preferred_identity, None);
}

#[test]
fn a_registration_without_the_sos_parameter_is_not_an_emergency_registration() {
    let (addr, server) = spawn_ecscf(Policy::Accept, 1);
    let ue = Ue::new(addr);

    // A plain REGISTER with no `sos` parameter: the stand-in refuses it, which
    // is the guard that keeps the emergency path from accepting ordinary ones.
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "Via",
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1",
    ));
    headers.push(sip::Header::new(
        "From",
        "<sip:001010000000001@ims.example>;tag=a",
    ));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims.example>"));
    headers.push(sip::Header::new("Call-ID", "c"));
    headers.push(sip::Header::new("CSeq", "1 REGISTER"));
    headers.push(sip::Header::new(
        "Contact",
        "<sip:001010000000001@127.0.0.1:5060>",
    ));
    headers.push(sip::Header::new("Content-Length", "0"));
    let request = sip::Request {
        method: sip::Method::Register,
        uri: format!("sip:{HOME}"),
        headers,
        body: Vec::new(),
    };
    let response = ue.send(&request);
    assert_eq!(response.status, 400);
    let ecscf = server.join().unwrap();
    assert!(!ecscf.observations[0].contact_sos);
}
