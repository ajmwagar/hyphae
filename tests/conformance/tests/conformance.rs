//! Spec-derived conformance tests. These run against the mock transport and
//! plain values only: no network, no modem, no codec C dependency.

use conformance::{sdp, sip};
use ims::{Dialog, ImsProfile, Registration, RegistrationEvent, RegistrationState, Sdp};
use sip::{Headers, Message, Method, Response};
use std::time::Duration;
use transport::{MockTransport, Transport};

const RES: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];

fn response(status: u16, headers: &[(&str, &str)]) -> Response {
    let mut h = Headers::new();
    for (n, v) in headers {
        h.push(sip::Header::new(*n, *v));
    }
    Response {
        status,
        reason: "test".into(),
        headers: h,
        body: Vec::new(),
    }
}

// --- Registration ---------------------------------------------------------

#[test]
fn reg_001_initial_register_has_security_client() {
    let Message::Request(req) = sip("register_initial.sip") else {
        panic!("REGISTER expected")
    };
    assert_eq!(req.method, Method::Register);
    assert_eq!(req.uri, "sip:ims.mnc001.mcc001.3gppnetwork.org");
    let sc = req.headers.get("security-client").expect("Security-Client");
    assert!(sc.contains("algorithm=hmac-md5-96"));
    assert!(sc.contains("spi-c=10000"));
    assert!(req
        .headers
        .get("contact")
        .unwrap()
        .contains("expires=600000"));
    assert!(req.headers.get("contact").unwrap().contains("icsi.mmtel"));
    assert_eq!(req.headers.get("supported"), Some("path,100rel"));
    assert_eq!(req.headers.get("expires"), Some("600000"));
    assert_eq!(
        req.headers.get("user-agent"),
        Some("fungos-ims/0.1 (Linux)")
    );
    assert_eq!(req.headers.cseq().unwrap().method, Method::Register);
}

#[test]
fn reg_002_register_round_trips_wire_format() {
    let original = sip("register_initial.sip");
    let text = original.to_text();
    assert!(text.contains("\r\nContent-Length: 0\r\n\r\n"));
    assert_eq!(Message::parse(&text).unwrap(), original);
}

#[test]
fn reg_003_401_challenge_handling() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let Message::Response(resp) = sip("challenge_401.sip") else {
        panic!("response expected")
    };
    let RegistrationEvent::Challenge(challenge) = reg.on_response(&resp) else {
        panic!("challenge expected")
    };
    assert_eq!(challenge.status, 401);
    assert!(!challenge.proxy);
    assert_eq!(challenge.challenge.param("algorithm"), Some("AKAv1-MD5"));
    assert_eq!(challenge.challenge.param("qop"), Some("auth"));
    assert!(matches!(reg.state(), RegistrationState::Challenged(_)));
}

#[test]
fn reg_004_authorized_register_has_digest() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let Message::Response(resp) = sip("challenge_401.sip") else {
        panic!("response expected")
    };
    let RegistrationEvent::Challenge(challenge) = reg.on_response(&resp) else {
        panic!("challenge expected")
    };
    let auth = reg.authorize(&challenge, &RES, "0a4f113b");
    let value = auth.headers.get("authorization").expect("Authorization");
    assert!(value.starts_with("Digest username=\"001010000000001@"));
    assert!(value.contains("realm=\"ims.mnc001.mcc001.3gppnetwork.org\""));
    assert!(value.contains("algorithm=AKAv1-MD5"));
    assert!(value.contains("qop=auth"));
    assert!(value.contains("nc=00000001"));
    assert!(value.contains("response=\""));
    // Security-Server from the challenge is echoed as Security-Verify.
    assert!(auth.headers.get("security-verify").is_some());
}

#[test]
fn reg_005_407_proxy_challenge_handling() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let Message::Response(resp) = sip("challenge_407.sip") else {
        panic!("response expected")
    };
    let RegistrationEvent::Challenge(challenge) = reg.on_response(&resp) else {
        panic!("challenge expected")
    };
    assert!(challenge.proxy);
    let auth = reg.authorize(&challenge, &RES, "cnonce");
    assert!(auth.headers.get("proxy-authorization").is_some());
    assert!(auth.headers.get("authorization").is_none());
}

#[test]
fn reg_006_200_sets_service_route() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let Message::Response(resp) = sip("register_200.sip") else {
        panic!("response expected")
    };
    assert_eq!(reg.on_response(&resp), RegistrationEvent::Registered);
    assert_eq!(reg.state(), &RegistrationState::Registered);
    assert_eq!(
        reg.profile().service_route,
        vec!["sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr"]
    );
}

#[test]
fn reg_007_deregister_sets_expires_zero() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    assert_eq!(
        reg.on_response(&response(200, &[])),
        RegistrationEvent::Registered
    );
    let req = reg.deregister_request();
    assert_eq!(req.headers.get("expires"), Some("0"));
    assert!(req.headers.get("contact").unwrap().contains("expires=0"));
}

#[test]
fn reg_008_mock_transport_delivers_register() {
    let (mut a, mut b) = MockTransport::pair();
    let msg = sip("register_initial.sip");
    a.send(&msg).unwrap();
    let got = b.recv(Duration::from_millis(100)).unwrap().unwrap();
    assert_eq!(got, msg);
}

// --- AKA ------------------------------------------------------------------

#[test]
fn aka_001_ts35208_test_set_1() {
    let k = aka::parse_hex16("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
    let op = aka::parse_hex16("cdc202d5123e20f62b6d676ac72cb318").unwrap();
    let rand = aka::parse_hex16("23553cbe9637a89d218ae64dae47bf35").unwrap();
    let sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    let amf = [0xb9, 0xb9];
    let out = aka::Milenage::new(k, op).compute(&rand, &sqn, &amf);
    assert_eq!(out.mac_a, [0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3]);
    assert_eq!(out.res, RES);
    assert_eq!(aka::ims_aka_response(&out.res), "A54211D5E3BA50BF");
}

#[test]
fn aka_002_autn_verification_and_resync_key() {
    let k = aka::parse_hex16("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
    let op = aka::parse_hex16("cdc202d5123e20f62b6d676ac72cb318").unwrap();
    let rand = aka::parse_hex16("23553cbe9637a89d218ae64dae47bf35").unwrap();
    let sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    let amf = [0xb9, 0xb9];
    let m = aka::Milenage::new(k, op);
    let out = m.compute(&rand, &sqn, &amf);
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ out.ak[i];
    }
    autn[6..8].copy_from_slice(&amf);
    autn[8..].copy_from_slice(&out.mac_a);
    let check = aka::verify_autn(&m, &rand, &autn);
    assert!(check.mac_valid);
    assert_eq!(check.sqn, sqn);
    assert_eq!(m.f5_star(&rand), [0x45, 0x1e, 0x8b, 0xec, 0xa4, 0x3b]);
}

// --- SDP / media ----------------------------------------------------------

#[test]
fn sdp_001_amr_wb_offer() {
    let offer = sdp("sdp_amr_wb_offer.sdp");
    let m = offer.audio().expect("audio m-line");
    assert_eq!(m.protocol, "RTP/AVP");
    assert_eq!(m.payload_type("AMR-WB", 16_000), Some(116));
    let fmtp = m.fmtp(116).unwrap();
    assert!(fmtp.contains("octet-align=1"));
    assert!(fmtp.contains("mode-set=0,1,2,3,4,5,6,7"));
    assert_eq!(m.attribute("ptime"), Some("20"));
    assert_eq!(m.port, 49170);
}

#[test]
fn sdp_002_offer_answer_selects_amr_wb() {
    let offer = sdp("sdp_amr_wb_offer.sdp");
    let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
    let m = answer.audio().unwrap();
    assert_eq!(m.payload_type("AMR-WB", 16_000), Some(116));
    assert!(m.fmtp(116).unwrap().contains("octet-align=1"));
    assert_eq!(m.port, 49172);
}

#[test]
fn rtp_001_rfc4867_octet_aligned_round_trip() {
    use codec_amr::rtp::{Frame, Payload};
    let p = Payload::new(
        8,
        vec![
            Frame::speech(8, vec![0xA5; 60], true).unwrap(),
            Frame::no_data(),
        ],
    );
    let bytes = p.to_bytes().unwrap();
    // CMR=8, F=1/FT=8/Q=1 => 0x80 0x44; last F=1/FT=15 => 0xF8.
    assert_eq!(&bytes[..2], &[0x80, 0xC4]);
    assert_eq!(*bytes.last().unwrap(), 0x78);
    let parsed = Payload::parse(&bytes).unwrap();
    assert_eq!(parsed, p);
    assert_eq!(parsed.speech_modes(), vec![8]);
}

// --- PRACK / dialog -------------------------------------------------------

#[test]
fn prack_001_100rel_and_rack() {
    let Message::Response(resp) = sip("183_rel1xx.sip") else {
        panic!("response expected")
    };
    assert_eq!(resp.status, 183);
    assert_eq!(resp.headers.get("require"), Some("100rel"));
    let rseq: u32 = resp.headers.get("rseq").unwrap().parse().unwrap();
    assert_eq!(rseq, 1);

    let mut dlg = Dialog::new(
        "golden-call-1@192.0.2.10",
        "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
        "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        "caller-tag",
        "callee-tag",
        "sip:001010000000001@192.0.2.10:5060",
    )
    .with_invite_cseq(1);
    let prack = dlg.prack(rseq);
    assert_eq!(prack.headers.get("rack"), Some("1 1 INVITE"));
    assert_eq!(prack.headers.cseq().unwrap().method, Method::Prack);

    let Message::Request(golden) = sip("prack.sip") else {
        panic!("PRACK expected")
    };
    assert_eq!(golden.headers.get("rack"), Some("1 1 INVITE"));
    assert_eq!(
        golden.headers.get("call-id"),
        Some("golden-call-1@192.0.2.10")
    );
}

#[test]
fn dialog_001_update_and_bye() {
    let Message::Request(update) = sip("update.sip") else {
        panic!("UPDATE expected")
    };
    assert_eq!(update.method, Method::Update);
    assert_eq!(update.headers.get("content-type"), Some("application/sdp"));
    let offer = Sdp::parse(std::str::from_utf8(&update.body).unwrap()).unwrap();
    assert_eq!(
        offer.audio().unwrap().payload_type("AMR-WB", 16_000),
        Some(116)
    );

    let Message::Request(bye) = sip("bye.sip") else {
        panic!("BYE expected")
    };
    assert_eq!(bye.method, Method::Bye);
    assert_eq!(bye.headers.cseq().unwrap().method, Method::Bye);
    assert_eq!(bye.headers.get("call-id"), Some("golden-call-1@192.0.2.10"));
    assert!(bye.headers.get("to").unwrap().contains("callee-tag"));

    let mut dlg = Dialog::new(
        "golden-call-1@192.0.2.10",
        "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org",
        "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
        "caller-tag",
        "callee-tag",
        "sip:001010000000001@192.0.2.10:5060",
    );
    dlg.confirm();
    let bye = dlg.bye();
    assert_eq!(bye.method, Method::Bye);
    assert_eq!(dlg.state, ims::DialogState::Terminated);
}

// --- Carrier / profiles ---------------------------------------------------

#[test]
fn carrier_001_lab_profile_loads() {
    let p = carrier::CarrierProfile::lab();
    assert_eq!(p.ims_apn, "ims");
    assert_eq!(p.p_cscf_discovery, carrier::PCscfDiscovery::Static);
    assert!(p.volte);
    assert_eq!(p.amr_wb_modes, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(p.ims_domain(), "ims.mnc001.mcc001.3gppnetwork.org");
    assert!(!p.evs);
}

// --- Transactions ---------------------------------------------------------

#[test]
fn tx_001_client_transaction_401_then_200() {
    use sip::{ClientEvent, ClientTransaction, Method, TransactionKey};
    let key = TransactionKey {
        branch: "z9hG4bK-golden-1".into(),
        method: Method::Register,
        sent_by: "192.0.2.10:5060".into(),
    };
    let mut tx = ClientTransaction::new(key, true);
    assert_eq!(tx.on_response(401), ClientEvent::Final(401));
    assert_eq!(tx.state, sip::ClientTransactionState::Completed);
}
