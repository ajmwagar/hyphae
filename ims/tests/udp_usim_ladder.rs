//! End-to-end: a real UDP REGISTER ladder where the client derives RES from the
//! USIM boundary, and a stand-in P-CSCF verifies the AKAv1-MD5 digest.
//!
//! This is the same ladder `lab/pris` runs, but entirely in Rust so it is part
//! of `cargo test` and needs no external process.
//!
//! Path under test:
//!
//! ```text
//!   ims::Registration --UDP--> stand-in P-CSCF
//!          |                        |
//!          | 401 + base64(RAND||AUTN) nonce
//!          v
//!   usim::SoftwareUsim (TS 31.102 AUTHENTICATE) -> RES/CK/IK
//!          |
//!          v
//!   digest REGISTER -> 200 OK (Service-Route)
//! ```

use ims::auth::{digest_response, DigestInput};
use ims::{ImsProfile, Registration, RegistrationEvent};
use std::net::UdpSocket;
use std::thread;
use std::time::Duration;
use transport::net::UdpTransport;
use transport::Transport;
use usim::{AkaOutput, Usim};

const K_HEX: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
const OP_HEX: &str = "cdc202d5123e20f62b6d676ac72cb318";
const SQN: [u8; 6] = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
const AMF: [u8; 2] = [0xb9, 0xb9];
const RAND: [u8; 16] = [
    0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
];

/// Standard base64 with padding (RFC 4648 §4).
fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Build the AUTN a network would send for SQN/AMF, using the card's Milenage.
fn autn_for(m: &aka::Milenage) -> [u8; 16] {
    let ak = m.f2345(&RAND).3;
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = SQN[i] ^ ak[i];
    }
    autn[6..8].copy_from_slice(&AMF);
    autn[8..].copy_from_slice(&m.compute(&RAND, &SQN, &AMF).mac_a);
    autn
}

#[test]
fn udp_register_with_usim_derived_res() {
    let k = aka::parse_hex16(K_HEX).unwrap();
    let op = aka::parse_hex16(OP_HEX).unwrap();
    let milenage = aka::Milenage::new(k, op);
    let autn = autn_for(&milenage);
    // The lab challenge carries base64(RAND || AUTN) as the nonce.
    let mut nonce_bytes = [0u8; 32];
    nonce_bytes[..16].copy_from_slice(&RAND);
    nonce_bytes[16..].copy_from_slice(&autn);
    let nonce = base64(&nonce_bytes);

    // The expected RES for this RAND/SQN is the TS 35.208 test-set-1 output.
    let expected_res = milenage.compute(&RAND, &SQN, &AMF).res;

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server.local_addr().unwrap();

    let nonce_for_server = nonce.clone();
    let expected_res_for_server = expected_res;
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];

        // 1. Initial REGISTER (no Authorization) -> 401 with the AKA nonce.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let first = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(req) = first else {
            panic!("expected a request");
        };
        assert!(
            req.headers.get("authorization").is_none(),
            "initial REGISTER must be unchallenged"
        );
        let mut headers = sip::Headers::new();
        headers.push(sip::Header::new(
            "Call-ID",
            req.headers.get("call-id").unwrap(),
        ));
        headers.push(sip::Header::new("CSeq", req.headers.get("cseq").unwrap()));
        headers.push(sip::Header::new(
            "WWW-Authenticate",
            format!(
                "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"{nonce_for_server}\", algorithm=AKAv1-MD5, qop=\"auth\""
            ),
        ));
        headers.push(sip::Header::new("Content-Length", "0"));
        let challenge = sip::Message::Response(sip::Response {
            status: 401,
            reason: "Unauthorized".into(),
            headers,
            body: Vec::new(),
        });
        server.send_to(&challenge.to_bytes(), peer).unwrap();

        // 2. Challenged REGISTER -> verify the digest, then 200 OK.
        let (n, peer) = server.recv_from(&mut buf).unwrap();
        let second = sip::Message::parse_bytes(&buf[..n]).unwrap();
        let sip::Message::Request(req) = second else {
            panic!("expected a request");
        };
        let auth = req
            .headers
            .get("authorization")
            .expect("Authorization missing");
        let creds = sip::parse_challenge(auth).expect("Authorization is not Digest");
        let got = creds.param("response").expect("no response param");
        let cnonce = creds.param("cnonce").expect("no cnonce");
        let nc = creds.param("nc").unwrap_or("00000001");
        let realm = creds.param("realm").unwrap();
        let got_nonce = creds.param("nonce").unwrap();
        let uri = creds.param("uri").unwrap();
        let qop = creds.param("qop");
        let expected = digest_response(&DigestInput {
            impi: "001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
            realm,
            res: &expected_res_for_server,
            method: "REGISTER",
            digest_uri: uri,
            nonce: got_nonce,
            nc,
            cnonce,
            qop,
        });
        assert_eq!(got, expected, "the client's AKA digest did not verify");

        let mut headers = sip::Headers::new();
        headers.push(sip::Header::new(
            "Call-ID",
            req.headers.get("call-id").unwrap(),
        ));
        headers.push(sip::Header::new("CSeq", req.headers.get("cseq").unwrap()));
        headers.push(sip::Header::new(
            "Service-Route",
            "<sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>",
        ));
        headers.push(sip::Header::new(
            "P-Associated-URI",
            "<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>",
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

    // --- client ---
    let mut profile = ImsProfile::lab_default();
    profile.p_cscf = vec![server_addr.to_string()];
    let mut client = UdpTransport::connect("127.0.0.1:0", server_addr).unwrap();
    let local = client.local_addr().to_string();
    let (host, port) = local.rsplit_once(':').unwrap();
    profile.contact_host = host.to_string();
    profile.contact_port = port.parse().unwrap();

    let mut reg = Registration::new(profile.clone());
    let timeout = Duration::from_secs(2);

    let initial = reg.register_request();
    client.send(&sip::Message::Request(initial)).unwrap();
    let response = client.recv(timeout).unwrap().expect("no 401");
    let sip::Message::Response(response) = response else {
        panic!("expected a response");
    };
    let RegistrationEvent::Challenge(challenge) = reg.on_response(&response) else {
        panic!("401 was not recognised as an AKA challenge");
    };

    // Derive RES through the USIM boundary, not from a hard-coded constant.
    let (rand, autn) = Registration::rand_autn_from_response(&response)
        .expect("challenge nonce is not base64(RAND||AUTN)");
    let mut card = usim::SoftwareUsim::new(k, op, SQN);
    let res = match card
        .authenticate(&rand, &autn)
        .expect("USIM rejected the challenge")
    {
        AkaOutput::Success { res, .. } => res,
        other => panic!("unexpected USIM output: {other:?}"),
    };
    assert_eq!(res, expected_res.to_vec());

    let auth = reg.authorize(&challenge, &res, "0a4f113b");
    client.send(&sip::Message::Request(auth)).unwrap();
    let response = client.recv(timeout).unwrap().expect("no 200 OK");
    let sip::Message::Response(response) = response else {
        panic!("expected a response");
    };
    assert!(
        matches!(reg.on_response(&response), RegistrationEvent::Registered),
        "client did not reach Registered"
    );

    server_thread.join().unwrap();
}
