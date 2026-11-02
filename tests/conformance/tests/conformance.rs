//! Spec-derived conformance tests. These run against the mock transport and
//! plain values only: no network, no modem, no codec C dependency.

use conformance::{sdp, sip};
use ims::{
    Call, CallEvent, CallState, Dialog, ImsProfile, Registration, RegistrationEvent,
    RegistrationState, Sdp, SmsSender, SmsSubmit,
};
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
fn sec_001_security_server_echoed_as_security_verify() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let Message::Response(resp) = sip("challenge_401.sip") else {
        panic!("response expected")
    };
    let expected = resp
        .headers
        .get("security-server")
        .expect("fixture has Security-Server")
        .to_string();
    let RegistrationEvent::Challenge(challenge) = reg.on_response(&resp) else {
        panic!("challenge expected")
    };
    let auth = reg.authorize(&challenge, &RES, "0a4f113b");
    let verify: Vec<&str> = auth.headers.get_all("security-verify").collect();
    assert_eq!(verify, vec![expected.as_str()]);
    assert!(verify[0].contains("alg=hmac-md5-96"));
    assert!(verify[0].contains("spi-c=20000"));
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

// --- EVS-001: TS 26.445 appendix A Header-Full RTP payload ----------------

#[test]
fn evs_001_cmr_toc_byte_round_trips() {
    use evs::rtp::{Cmr, ModeSet, Payload};
    // CMR: H=1, T=2 (WB), D=7 (32 kbit/s) => 0xA7;
    // ToC: H=0, F=0, FT=7 => 0x07. The EVS Header-Full ToC has no Q/P bits,
    // so the round-trip is byte-exact.
    let p = Payload::new(
        Cmr::new(ModeSet::Wb, 7),
        vec![evs::rtp::Frame::speech(7, vec![0xA5; 80]).unwrap()],
    );
    let bytes = p.to_bytes().unwrap();
    assert_eq!(&bytes[..2], &[0xA7, 0x07]);
    assert_eq!(bytes.len(), 2 + 80);
    assert_eq!(Payload::parse(&bytes).unwrap(), p);
    // The CMR byte round-trips its T/D fields exactly.
    assert_eq!(Cmr::parse(bytes[0]).unwrap().to_byte(), 0xA7);
    // Table A.3: the T/D pair decodes to the right requested rate.
    assert_eq!(Cmr::new(ModeSet::Wb, 7).bitrate_kbps(), Some(32.0));
    assert_eq!(Cmr::new(ModeSet::Io, 8).bitrate_kbps(), Some(23.85));
    assert!(Cmr::no_request().is_no_request());
}

#[test]
fn evs_001_frame_table_classification() {
    use evs::rtp::{classify_ft, Cmr, FrameKind, Payload};
    // Every defined frame type classifies to its EVS kind.
    assert_eq!(classify_ft(0), FrameKind::PrimarySpeech { ft: 0 });
    assert_eq!(classify_ft(12), FrameKind::PrimarySid);
    assert_eq!(classify_ft(14), FrameKind::Lost);
    assert_eq!(classify_ft(15), FrameKind::NoData);
    assert_eq!(classify_ft(16), FrameKind::IoSpeech { mode: 0 });
    assert_eq!(classify_ft(25), FrameKind::IoSid);
    assert_eq!(classify_ft(30), FrameKind::Lost);
    assert_eq!(classify_ft(31), FrameKind::NoData);
    assert_eq!(classify_ft(13), FrameKind::Reserved { ft: 13 });

    // A mixed payload reports the right kinds end to end.
    let p = Payload::new(
        Cmr::no_request(),
        vec![
            evs::rtp::Frame::primary_sid(vec![0x11; 6]).unwrap(),
            evs::rtp::Frame::lost(true),
            evs::rtp::Frame::no_data(false),
        ],
    );
    let parsed = Payload::parse(&p.to_bytes().unwrap()).unwrap();
    assert_eq!(parsed.frames[0].kind(), FrameKind::PrimarySid);
    assert_eq!(parsed.frames[1].kind(), FrameKind::Lost);
    assert_eq!(parsed.frames[2].kind(), FrameKind::NoData);
    assert!(!parsed.has_speech());
}

#[test]
fn evs_001_primary_speech_frame_sizes() {
    use evs::rtp::{frame_size, Payload};
    // Primary speech octet size = kbps * 2.5 for a 20 ms frame.
    assert_eq!(frame_size(4), Some(33)); // 13.2 kbps
    assert_eq!(frame_size(10), Some(240)); // 96 kbps
    assert_eq!(frame_size(11), Some(320)); // 128 kbps (largest EVS frame)
                                           // AMR-WB IO frames carry the RFC 4867 octet-aligned sizes verbatim.
    assert_eq!(frame_size(16), Some(17));
    assert_eq!(frame_size(24), Some(60));
    // The largest frame serialises and round-trips exactly.
    let p = Payload::single_speech(11, vec![0xA5; 320]).unwrap();
    let bytes = p.to_bytes().unwrap();
    assert_eq!(bytes.len(), 2 + 320);
    assert_eq!(Payload::parse(&bytes).unwrap(), p);
}

#[test]
fn evs_001_multi_frame_round_trips() {
    use evs::rtp::{Cmr, Frame, ModeSet, Payload};
    // Primary speech FT=0 (7 bytes), then FT=4 (33 bytes), then AMR-WB IO
    // mode 0 (FT=16, 17 bytes) in one multi-frame payload.
    let p = Payload::new(
        Cmr::new(ModeSet::Io, 0),
        vec![
            Frame::speech(0, vec![0xA5; 7]).unwrap(),
            Frame::speech(4, vec![0xA5; 33]).unwrap(),
            Frame::speech(16, vec![0xA5; 17]).unwrap(),
        ],
    );
    let bytes = p.to_bytes().unwrap();
    assert_eq!(bytes[1], 0x40); // F=1, FT=0
    assert_eq!(bytes[9], 0x44); // F=1, FT=4
    assert_eq!(bytes[43], 0x10); // F=0, FT=16
    let parsed = Payload::parse(&bytes).unwrap();
    assert_eq!(parsed, p);
    assert_eq!(parsed.speech_frame_types(), vec![0, 4, 16]);
}

#[test]
fn evs_001_compact_format_is_rejected() {
    use evs::rtp::{Payload, PayloadFormat};
    // Header-Compact, storage and multi-channel are not implemented; they must
    // error rather than be inferred from a header-full buffer (mirroring how
    // codec-amr rejects RFC 4867 bandwidth-efficient mode).
    for format in [
        PayloadFormat::HeaderCompact,
        PayloadFormat::Storage,
        PayloadFormat::MultiChannel,
    ] {
        assert_eq!(
            Payload::parse_mode(&[0xA7, 0x07], format),
            Err(evs::EvsError::Unsupported)
        );
    }
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
fn carrier_002_amr_wb_modes_feed_sdp_offer() {
    let c = carrier::CarrierProfile::lab();
    let profile = ImsProfile::from_carrier(&c, "001010000000001");
    let offer = profile.amr_wb_offer("192.0.2.10", true);
    let m = offer.audio().expect("audio m-line");
    let fmtp = m.fmtp(116).unwrap();
    let expected = c
        .amr_wb_modes
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    assert!(fmtp.contains(&format!("mode-set={expected}")));
    assert!(fmtp.contains("octet-align=1"));
}

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
// --- Call establishment (INV-001) -----------------------------------------

fn mk_response(status: u16, cseq: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
    let mut h = Headers::new();
    h.push(sip::Header::new("CSeq", cseq.to_string()));
    for &(k, v) in extra {
        h.push(sip::Header::new(k, v));
    }
    Response {
        status,
        reason: "test".into(),
        headers: h,
        body: body.to_vec(),
    }
}

#[test]
fn inv_001_full_call_establishment() {
    let (mut client, mut server) = MockTransport::pair();
    let mut call = Call::new(
        ImsProfile::lab_default(),
        "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
    );
    let timeout = Duration::from_millis(200);

    // 1. INVITE with an AMR-WB offer goes onto the wire.
    let CallEvent::Send(invite) = call.invite() else {
        panic!("invite expected")
    };
    let invite_cseq = invite.headers.cseq().unwrap().seq;
    client.send(&Message::Request(invite)).unwrap();
    let Message::Request(got_invite) = server.recv(timeout).unwrap().unwrap() else {
        panic!("invite not delivered")
    };
    assert_eq!(got_invite.method, Method::Invite);
    let offer = Sdp::parse(core::str::from_utf8(&got_invite.body).unwrap()).unwrap();
    assert_eq!(
        offer.audio().unwrap().payload_type("AMR-WB", 16_000),
        Some(116)
    );

    // Server ladder: 100 Trying, reliable 183 (answer + RSeq), 200 to PRACK,
    // 200 to INVITE. Only the CSeq method distinguishes the two 2xx responses.
    let cseq_invite = format!("{invite_cseq} INVITE");
    let cseq_prack = format!("{} PRACK", invite_cseq + 1);
    let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
    let answer_bytes = answer.to_text().into_bytes();
    server
        .send(&Message::Response(mk_response(
            183,
            &cseq_invite,
            &[
                ("Require", "100rel"),
                ("RSeq", "1"),
                (
                    "To",
                    "<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag",
                ),
                ("Content-Type", "application/sdp"),
            ],
            &answer_bytes,
        )))
        .unwrap();
    server
        .send(&Message::Response(mk_response(200, &cseq_prack, &[], &[])))
        .unwrap();
    server
        .send(&Message::Response(mk_response(200, &cseq_invite, &[], &[])))
        .unwrap();

    // 100 Trying: no action.
    assert_eq!(
        call.on_response(&mk_response(100, &cseq_invite, &[], &[])),
        CallEvent::Provisional
    );
    assert_eq!(call.state(), CallState::Inviting);

    // Reliable 183: PRACK is owed, and the answer is captured.
    let prack = match call.on_response(&mk_response(
        183,
        &cseq_invite,
        &[
            ("Require", "100rel"),
            ("RSeq", "1"),
            (
                "To",
                "<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag",
            ),
            ("Content-Type", "application/sdp"),
        ],
        &answer_bytes,
    )) {
        CallEvent::Send(req) => req,
        other => panic!("expected PRACK, got {other:?}"),
    };
    assert_eq!(prack.method, Method::Prack);
    assert_eq!(prack.headers.get("rack"), Some("1 1 INVITE"));
    assert!(call.answer().is_some());
    client.send(&Message::Request(prack)).unwrap();
    let Message::Request(got_prack) = server.recv(timeout).unwrap().unwrap() else {
        panic!("prack not delivered")
    };
    assert_eq!(got_prack.method, Method::Prack);
    assert_eq!(got_prack.headers.get("rack"), Some("1 1 INVITE"));

    // 200 to PRACK advances the machine but does not establish the call.
    assert_eq!(
        call.on_response(&mk_response(200, &cseq_prack, &[], &[])),
        CallEvent::Provisional
    );
    assert_eq!(call.state(), CallState::AwaitingInviteFinal);

    // 200 to INVITE: the call is established and an ACK is owed.
    let CallEvent::Established { ack } =
        call.on_response(&mk_response(200, &cseq_invite, &[], &[]))
    else {
        panic!("expected the call to be established");
    };
    assert_eq!(ack.method, Method::Ack);
    assert_eq!(ack.headers.cseq().unwrap().seq, invite_cseq);
    // The negotiated answer is available after establishment.
    assert_eq!(
        call.answer()
            .unwrap()
            .audio()
            .unwrap()
            .payload_type("AMR-WB", 16_000),
        Some(116)
    );
    client.send(&Message::Request(ack)).unwrap();
    assert_eq!(call.state(), CallState::Established);
    let Message::Request(got_ack) = server.recv(timeout).unwrap().unwrap() else {
        panic!("ack not delivered")
    };
    assert_eq!(got_ack.method, Method::Ack);
    assert_eq!(got_ack.headers.cseq().unwrap().seq, invite_cseq);

    // The dialog can now be released with a BYE.
    let bye = call.bye().expect("bye on an established call");
    assert_eq!(bye.method, Method::Bye);
    assert_eq!(call.state(), CallState::Terminated);
}

#[test]
fn inv_001_busy_returns_failed_and_blocks_bye() {
    let mut call = Call::new(
        ImsProfile::lab_default(),
        "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
    );
    let _ = call.invite();
    let busy = mk_response(
        486,
        "1 INVITE",
        &[(
            "To",
            "<sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag",
        )],
        &[],
    );
    assert_eq!(call.on_response(&busy), CallEvent::Failed(486));
    assert_eq!(call.state(), CallState::Failed(486));
    assert!(call.bye().is_none());
}

// --- Registration refresh (REG-009) ---------------------------------------

#[test]
fn reg_009_refresh_before_expiry_and_re_register_on_network_change() {
    let mut reg = Registration::new(ImsProfile::lab_default());
    let _ = reg.register_request();
    let first = reg.cseq();
    // Refresh before expiry: same expiry, incremented CSeq.
    let refresh = reg.refresh_request();
    assert_eq!(refresh.headers.get("expires"), Some("600000"));
    assert_eq!(refresh.headers.cseq().unwrap().seq, first + 1);
    // Network change: the contact moves; re-REGISTER rebinds it.
    reg.set_contact("192.0.2.20", 5060);
    let re = reg.re_register();
    assert_eq!(re.headers.cseq().unwrap().seq, first + 2);
    assert!(re.headers.get("contact").unwrap().contains("192.0.2.20"));
    assert_eq!(re.headers.get("expires"), Some("600000"));
}

// --- SMS over IMS (SMS-001) -------------------------------------------------

#[test]
fn sms_001_sip_message_carries_rp_data() {
    let profile = ImsProfile::lab_default();
    let mut tx = SmsSender::new(&profile.public_identity, &profile.contact_host, 5060);
    let submit = SmsSubmit {
        service_center: "15551000000".into(),
        destination: "15552000000".into(),
        pid: 0,
        dcs: 0,
        text: "Hello over IMS".into(),
    };
    let request = tx.message(
        &profile,
        "sip:ip-sm-gw@ims.mnc001.mcc001.3gppnetwork.org",
        &submit,
    );
    assert_eq!(request.method, Method::Message);
    assert_eq!(
        request.headers.get("content-type"),
        Some("application/vnd.3gpp.sms")
    );
    // The GSM 03.40 PDU is the tail of the RP-DATA body and round-trips.
    let pdu = submit.encode();
    assert!(request.body.ends_with(&pdu));
    assert_eq!(ims::SmsSubmit::encode(&submit).len(), pdu.len());

    // The wire serialisation is binary-safe: Content-Type is a header and the
    // RP-DATA body (with its binary GSM PDU) is the trailing octets. The sip
    // parser is &str-based for text bodies (SDP), so we assert the raw bytes
    // rather than re-parsing the binary MESSAGE body.
    let wire = Message::Request(request).to_bytes();
    let sep = wire
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header/body separator");
    let head = std::str::from_utf8(&wire[..sep]).unwrap();
    assert!(head.contains("Content-Type: application/vnd.3gpp.sms"));
    assert!(wire.ends_with(&pdu));
}

// --- Preconditions (INV-002) ------------------------------------------------

#[test]
fn inv_002_preconditions_offered_and_answered() {
    // The callee offers with preconditions; the caller answers and confirms.
    let mut offer = Sdp::amr_wb_offer(&[0, 1, 2, 3, 4, 5, 6, 7], true, "192.0.2.10");
    offer.add_preconditions();
    let m = offer.audio().unwrap();
    let precond = m.precondition().expect("offer has preconditions");
    assert_eq!(precond.createmedia, Some(ims::PrecondDir::SendRecv));
    assert!(precond.met());

    let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
    let a = answer.audio().unwrap();
    let answered = a.precondition().expect("answer echoes preconditions");
    assert_eq!(answered.createmedia, Some(ims::PrecondDir::SendRecv));
    assert_eq!(answered.confirmed, Some(ims::PrecondDir::SendRecv));
    // The wire form carries the RFC 3312 attributes.
    assert!(answer.to_text().contains("a=createmedia:sendrecv"));
    assert!(answer.to_text().contains("a=confirmed:sendrecv"));
}

// --- MEDIA-001: RTP/RTCP framing, jitter buffer, PLC ----------------------

#[test]
fn media_001_rtp_amr_frame_round_trips_the_wire() {
    use codec_amr::rtp::Payload;
    use media::amr_rtp::{AmrRtp, MediaEncoder};
    use media::packet::RtpPacket;

    // Encode one AMR-WB speech frame into an RTP packet over the wire.
    let mut enc = MediaEncoder::new(AmrRtp::amr_wb(0x00ff_00ff));
    let payload = Payload::single_speech(8, vec![0xA5; 60], true).unwrap();
    let packet = enc.encode(&payload).unwrap();
    let wire = packet.encode().unwrap();

    // Parse it back exactly as a receiver would.
    let parsed = RtpPacket::decode(&wire).unwrap();
    assert_eq!(parsed.payload_type, media::AMR_WB_PAYLOAD_TYPE);
    assert_eq!(parsed.sequence, 1);
    assert_eq!(parsed.timestamp, 0);
    assert!(parsed.marker);
    assert_eq!(parsed.ssrc, 0x00ff_00ff);

    // The RTP payload is still a valid RFC 4867 octet-aligned AMR payload.
    let back = AmrRtp::amr_wb(0x00ff_00ff)
        .parse_payload(&parsed.payload)
        .unwrap();
    assert_eq!(back, payload);

    // The second frame advances the timestamp by one 20 ms tick (320 @16k).
    let next = enc.encode(&payload).unwrap();
    assert_eq!(next.sequence, 2);
    assert_eq!(next.timestamp, media::AMR_WB_FRAME_SAMPLES as u32);
}

#[test]
fn media_001_rtcp_sender_report_survives_the_wire() {
    use media::rtcp::{fraction_lost, ReportBlock, RtcpPacket, SenderReport};

    let block = ReportBlock {
        ssrc: 0x1122_3344,
        fraction_lost: fraction_lost(100, 90),
        cumulative_lost: -10,
        expected: 100,
        received: 90,
        jitter: 7,
        last_sender_report: 0xaa55_bb66,
        delay: 2000,
    };
    let sr = SenderReport {
        ssrc: 0xdead_beef,
        ntp_seconds: 0x0123_4567,
        ntp_fraction: 0x89ab_cdef,
        rtp_timestamp: 0x1122_3344,
        packet_count: 42,
        octet_count: 42 * 40,
        blocks: vec![block],
    };
    let bytes = sr.to_bytes();
    let (parsed, consumed) = RtcpPacket::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    let RtcpPacket::Sender(got) = parsed else {
        panic!("expected SR")
    };
    assert_eq!(got.packet_count, 42);
    assert_eq!(got.octet_count, 42 * 40);
    assert_eq!(got.blocks.len(), 1);
    assert_eq!(got.blocks[0].cumulative_lost, -10);
    assert_eq!(got.blocks[0].fraction_lost, fraction_lost(100, 90));
}

#[test]
fn media_001_jitter_buffer_reorders_and_flags_loss() {
    use media::jitter::{JitterBuffer, PushResult};
    use media::packet::RtpPacket;

    let mut jb = JitterBuffer::new(0);
    // Anchor is 1; arrivals come 3, 2, 5 (out of order) with a hole at 4.
    assert_eq!(jb.push(RtpPacket::new(97, 1, 0, 1)), PushResult::Accepted);
    assert_eq!(jb.push(RtpPacket::new(97, 3, 0, 1)), PushResult::Accepted);
    assert_eq!(jb.push(RtpPacket::new(97, 2, 0, 1)), PushResult::Accepted);
    assert_eq!(jb.push(RtpPacket::new(97, 5, 0, 1)), PushResult::Accepted);
    // In-order release: 1, 2, 3, then 5 with 4 declared lost.
    let mut seqs = Vec::new();
    for _ in 0..4 {
        if let Some(p) = jb.pop() {
            seqs.push(p.sequence);
        }
    }
    assert_eq!(seqs, vec![1, 2, 3, 5]);
    assert!(jb.take_losses().contains(&4));
}

#[test]
fn media_001_plc_conceals_a_lost_frame() {
    use media::plc::Plc;

    let mut plc = Plc::new(media::AMR_WB_FRAME_SAMPLES);
    let good = vec![100i16; media::AMR_WB_FRAME_SAMPLES];
    plc.note_good_frame(&good);
    let concealed = plc.conceal_frame();
    assert_eq!(concealed.len(), media::AMR_WB_FRAME_SAMPLES);
    // First concealed frame is faded to half the held amplitude.
    assert_eq!(concealed[0], 50);
    assert_eq!(plc.fade_frames(), 1);
}

// --- TRN-002: MTK CCCI vendor-channel shim --------------------------------

#[test]
fn trn_002_sip_survives_the_ccci_channel_boundary() {
    use std::time::Duration;
    use transport::ccci::{frame, parse_frame, CcciTransport, MockCcciChannel};

    // The private length framing round-trips a SIP payload unchanged.
    let framed = frame(b"sip-payload").unwrap();
    assert_eq!(&framed[..2], &[0x00, 0x0b]);
    assert_eq!(parse_frame(&framed).unwrap().0, b"sip-payload");

    // And a real SIP message survives the vendor-channel boundary intact.
    let (ca, cb) = MockCcciChannel::pair();
    let mut a = CcciTransport::new("0", ca);
    let mut b = CcciTransport::new("1", cb);
    assert_eq!(a.local_addr(), "ccci:0");
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("Via", "SIP/2.0/UDP x;branch=z9hG4bK-ccci"));
    headers.push(sip::Header::new("CSeq", "1 REGISTER"));
    headers.push(sip::Header::new("Content-Length", "0"));
    let sent = sip::Message::Request(sip::Request {
        method: sip::Method::Register,
        uri: "sip:ims.example".into(),
        headers,
        body: Vec::new(),
    });
    a.send(&sent).unwrap();
    assert_eq!(b.recv(Duration::from_millis(100)).unwrap().unwrap(), sent);
}

// --- TRN-003: MBIM transport ----------------------------------------------

#[test]
fn trn_003_mbim_frame_and_session_round_trip() {
    use std::time::Duration;
    use transport::mbim::{MbimFrame, MbimMessageType, MbimSession, MbimTransport};

    // The MBIM control frame keeps its 12-octet header shape on the wire.
    let frame = MbimFrame::new(MbimMessageType::Command, 0xABCD_1234, vec![0x01, 0x02]);
    let bytes = frame.to_bytes();
    assert_eq!(bytes.len(), 12 + 2);
    assert_eq!(&bytes[..4], &3u32.to_le_bytes()); // MessageType = COMMAND
    assert_eq!(MbimFrame::parse(&bytes).unwrap(), frame);

    // A session is activated on the IMS APN and hands back the modem address.
    let session = MbimSession::activate("ims");
    assert_eq!(session.apn, "ims");
    assert!(session.active);
    let (mut a, mut b) = MbimTransport::pair("ims", "ims");
    assert_eq!(a.local_addr(), session.address());

    // SIP rides the MBIM IMS PDN unchanged.
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("Via", "SIP/2.0/UDP x;branch=z9hG4bK-mbim"));
    headers.push(sip::Header::new("CSeq", "1 REGISTER"));
    headers.push(sip::Header::new("Content-Length", "0"));
    let sent = sip::Message::Request(sip::Request {
        method: sip::Method::Register,
        uri: "sip:ims.example".into(),
        headers,
        body: Vec::new(),
    });
    a.send(&sent).unwrap();
    assert_eq!(b.recv(Duration::from_millis(100)).unwrap().unwrap(), sent);
}

// --- E911-001: emergency session identity and routing ---------------------

#[test]
fn e911_001_emergency_invite_targets_the_service_urn() {
    use ims::emergency::{EmergencyIdentity, EmergencyRequest, SosService};

    // RFC 5031 service URNs for the sos subtree parse and are recognised.
    assert_eq!(
        SosService::parse("urn:service:sos").unwrap(),
        SosService::Sos
    );
    assert_eq!(
        SosService::parse("urn:service:sos.police").unwrap(),
        SosService::Police
    );
    assert!(SosService::is_emergency_urn("urn:service:sos.fire"));
    assert!(!SosService::is_emergency_urn("sip:911@example.net"));

    // An unregistered UE derives a temporary identity from the IMSI.
    let id = EmergencyIdentity::temporary_from_imsi(
        "001010000000001",
        "ims.mnc001.mcc001.3gppnetwork.org",
    );
    assert!(id.is_temporary());

    // TS 24.229 §5.1.6.3: Request-URI is the service URN and the request
    // carries Resource-Priority: esnet.0.
    let request = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
        .invite()
        .unwrap();
    assert_eq!(request.method, sip::Method::Invite);
    assert_eq!(request.uri, "urn:service:sos");
    assert_eq!(request.headers.get("resource-priority"), Some("esnet.0"));
    assert!(request
        .headers
        .get("to")
        .unwrap()
        .contains("urn:service:sos"));
}

#[test]
fn e911_001_geolocation_is_routed_as_pidf_lo() {
    use ims::emergency::{EmergencyIdentity, EmergencyRequest, Geolocation, SosService};

    // Out-of-range coordinates are rejected, not clamped.
    assert!(Geolocation::new(90.1, 0.0).is_err());
    assert!(Geolocation::new(0.0, -180.1).is_err());

    let id = EmergencyIdentity::registered("sip:001010000000001@ims.example").unwrap();
    let location = Geolocation::new(48.8584, 2.2945).unwrap().with_radius(50.0);
    let request = EmergencyRequest::new(SosService::Sos, id, "192.0.2.10", 5060)
        .with_geolocation(location)
        .invite()
        .unwrap();

    // RFC 6442: the location is eligible for routing.
    assert_eq!(request.headers.get("geolocation-routing"), Some("yes"));
    assert_eq!(
        request.headers.get("content-type"),
        Some("application/pidf+xml")
    );
    let body = String::from_utf8(request.body.clone()).unwrap();
    assert!(body.contains("<gml:pos>48.858400 2.294500</gml:pos>"));
    assert!(body.contains("urn:ogc:def:crs:EPSG::4326"));
    assert_eq!(
        request.headers.get("content-length"),
        Some(request.body.len().to_string().as_str())
    );
}

// --- USIM-001: TS 31.102 AUTHENTICATE over the card boundary --------------

#[test]
fn usim_001_authenticate_apdu_matches_ts_31_102() {
    use usim::{authenticate_command, sw, ApduChannel, CardResponse, Usim, UsimCard, UsimError};

    // Command layout: CLA=00 INS=88 P1=00 P2=01 Lc=22, data = 10 RAND 10 AUTN.
    let rand = [0x11u8; 16];
    let autn = [0x22u8; 16];
    let bytes = authenticate_command(&rand, &autn).to_bytes();
    assert_eq!(&bytes[..5], &[0x00, 0x88, 0x00, 0x01, 0x22]);
    assert_eq!(bytes[5], 0x10);
    assert_eq!(&bytes[6..22], &rand);
    assert_eq!(bytes[22], 0x10);
    assert_eq!(&bytes[23..39], &autn);
    assert_eq!(bytes[39], 0x00);

    // A card that returns a 98 62 status must surface as a status-word error.
    struct Reject;
    impl ApduChannel for Reject {
        fn transmit(&mut self, _c: &[u8]) -> Result<CardResponse, UsimError> {
            Ok(CardResponse::status(
                sw::AUTH_MAC_FAILURE.0,
                sw::AUTH_MAC_FAILURE.1,
            ))
        }
    }
    let mut card = UsimCard::new(Reject);
    assert_eq!(
        card.authenticate(&rand, &autn).unwrap_err(),
        UsimError::StatusWord {
            sw1: 0x98,
            sw2: 0x62
        }
    );
}

#[test]
fn usim_001_software_usim_returns_the_ts_35_208_vector() {
    use usim::{AkaOutput, LoopbackChannel, SoftwareUsim, Usim, UsimCard};

    // 3GPP TS 35.208 test set 1 (public vector).
    let k = aka::parse_hex16("465b5ce8b199b49faa5f0a2ee238a6bc").unwrap();
    let op = aka::parse_hex16("cdc202d5123e20f62b6d676ac72cb318").unwrap();
    let rand = aka::parse_hex16("23553cbe9637a89d218ae64dae47bf35").unwrap();
    let sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    let amf = [0xb9, 0xb9];

    // Build the AUTN the network would send: (SQN xor AK) || AMF || MAC-A.
    let m = aka::Milenage::new(k, op);
    let ak = m.f2345(&rand).3;
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ ak[i];
    }
    autn[6..8].copy_from_slice(&amf);
    autn[8..].copy_from_slice(&m.compute(&rand, &sqn, &amf).mac_a);

    // The full path: ME builds the APDU, the channel carries it, the card
    // (Milenage) answers, and the ME decodes RES/CK/IK.
    let mut card = UsimCard::new(LoopbackChannel::new(SoftwareUsim::new(k, op, sqn)));
    match card.authenticate(&rand, &autn).unwrap() {
        AkaOutput::Success { res, ck, ik } => {
            assert_eq!(res, vec![0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf]);
            assert_eq!(ck[0], 0xb4);
            assert_eq!(ik[0], 0xf7);
            // RFC 3310: the IMS digest response is RES as uppercase hex.
            assert_eq!(aka::ims_aka_response(&res), "A54211D5E3BA50BF");
        }
        other => panic!("unexpected {other:?}"),
    }
    // The command seen on the wire was the spec APDU.
    assert_eq!(card.channel().seen.len(), 1);
    assert_eq!(
        &card.channel().seen[0][..5],
        &[0x00, 0x88, 0x00, 0x01, 0x22]
    );
}

// --- UAS-001: incoming call (INVITE / 180 / 200 / ACK / BYE) --------------

#[test]
fn uas_001_incoming_call_rings_answers_and_tears_down() {
    use ims::{ImsProfile, IncomingCall, UasEvent, UasState};

    // An INVITE from the caller with an AMR-WB offer.
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 49170 RTP/AVP 116 117\r\na=rtpmap:116 AMR-WB/16000/1\r\na=fmtp:116 mode-set=0,1,2,3,4,5,6,7;octet-align=1\r\na=rtpmap:117 telephone-event/16000\r\na=ptime:20\r\n";
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "Via",
        "SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-uas-1;rport",
    ));
    headers.push(sip::Header::new(
        "From",
        "<sip:001010000000002@ims.example>;tag=caller-tag",
    ));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims.example>"));
    headers.push(sip::Header::new("Call-ID", "uas-call-1"));
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    headers.push(sip::Header::new("Supported", "100rel"));
    headers.push(sip::Header::new("Content-Type", "application/sdp"));
    let invite = sip::Request {
        method: sip::Method::Invite,
        uri: "sip:001010000000001@ims.example".into(),
        headers,
        body: offer.as_bytes().to_vec(),
    };

    let mut call = IncomingCall::from_invite(&invite, ImsProfile::lab_default()).unwrap();
    assert_eq!(call.state(), UasState::Offered);

    // 180 Ringing is a reliable provisional: Require: 100rel + RSeq, and the
    // To header carries our local tag (RFC 3262 §3, RFC 3261 §12.1.1).
    let ringing = call.ringing();
    assert_eq!(ringing.status, 180);
    assert_eq!(ringing.headers.get("require"), Some("100rel"));
    assert!(ringing.headers.get("rseq").is_some());
    assert!(ringing.headers.get("to").unwrap().contains("tag="));
    assert_eq!(ringing.headers.get("call-id"), Some("uas-call-1"));

    // 200 OK carries the SDP answer and a Contact for the dialog.
    let ok = call.accept().unwrap();
    assert_eq!(ok.status, 200);
    assert_eq!(ok.headers.get("content-type"), Some("application/sdp"));
    assert!(ok.headers.get("contact").is_some());
    let answer = String::from_utf8(ok.body.clone()).unwrap();
    assert!(answer.contains("m=audio"));
    assert!(answer.contains("AMR-WB"));
    assert_eq!(call.state(), UasState::Accepted);

    // ACK confirms the dialog; BYE tears it down.
    let ack = sip::Request {
        method: sip::Method::Ack,
        uri: invite.uri.clone(),
        headers: {
            let mut h = sip::Headers::new();
            h.push(sip::Header::new("CSeq", "1 ACK"));
            h
        },
        body: Vec::new(),
    };
    assert_eq!(call.on_request(&ack).unwrap(), UasEvent::Established);
    assert_eq!(call.state(), UasState::Confirmed);

    let bye = sip::Request {
        method: sip::Method::Bye,
        uri: invite.uri.clone(),
        headers: {
            let mut h = sip::Headers::new();
            h.push(sip::Header::new("CSeq", "2 BYE"));
            h
        },
        body: Vec::new(),
    };
    assert_eq!(call.on_request(&bye).unwrap(), UasEvent::Terminated);
    assert_eq!(call.state(), UasState::Terminated);
}

#[test]
fn uas_001_cancel_answers_200_and_487() {
    use ims::{ImsProfile, IncomingCall, UasEvent};

    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("From", "<sip:a@example>;tag=t1"));
    headers.push(sip::Header::new("To", "<sip:b@example>"));
    headers.push(sip::Header::new("Call-ID", "cancel-call"));
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let invite = sip::Request {
        method: sip::Method::Invite,
        uri: "sip:b@example".into(),
        headers,
        body: Vec::new(),
    };
    let mut call = IncomingCall::from_invite(&invite, ImsProfile::lab_default()).unwrap();
    let _ = call.ringing();

    // RFC 3261 §9.2: CANCEL is answered 200, and the INVITE gets 487.
    let cancel = sip::Request {
        method: sip::Method::Cancel,
        uri: invite.uri.clone(),
        headers: {
            let mut h = sip::Headers::new();
            h.push(sip::Header::new("CSeq", "1 CANCEL"));
            h
        },
        body: Vec::new(),
    };
    match call.on_request(&cancel).unwrap() {
        UasEvent::Cancelled { responses } => {
            assert_eq!(responses[0].status, 200);
            assert_eq!(responses[1].status, 487);
        }
        other => panic!("unexpected {other:?}"),
    }
}

// --- INV-003: outgoing CANCEL ---------------------------------------------

#[test]
fn inv_003_cancel_reuses_the_invite_transaction() {
    use ims::{Call, CallEvent, CallState, ImsProfile};

    let mut call = Call::new(ImsProfile::lab_default(), "sip:b@ims.example");
    let CallEvent::Send(invite) = call.invite() else {
        panic!("invite expected")
    };
    let invite_branch = invite.headers.via().unwrap().branch().unwrap().to_string();

    // RFC 3261 §9.1: the CANCEL matches the INVITE's branch and CSeq number;
    // only the method differs, and it carries no body or Contact.
    let cancel = call.cancel().expect("CANCEL before a final response");
    assert_eq!(cancel.method, sip::Method::Cancel);
    assert_eq!(
        cancel.headers.via().unwrap().branch().unwrap(),
        invite_branch
    );
    assert_eq!(cancel.headers.get("cseq"), Some("1 CANCEL"));
    assert_eq!(cancel.headers.get("call-id"), invite.headers.get("call-id"));
    assert!(cancel.body.is_empty());
    assert_eq!(call.state(), CallState::Cancelling);

    // 200 to CANCEL is a no-op; 487 to INVITE ends the attempt.
    let mut ok_headers = sip::Headers::new();
    ok_headers.push(sip::Header::new("CSeq", "1 CANCEL"));
    let cancel_ok = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers: ok_headers,
        body: Vec::new(),
    };
    assert_eq!(call.on_response(&cancel_ok), CallEvent::Provisional);

    let mut terminated_headers = sip::Headers::new();
    terminated_headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let terminated = sip::Response {
        status: 487,
        reason: "Request Terminated".into(),
        headers: terminated_headers,
        body: Vec::new(),
    };
    assert_eq!(call.on_response(&terminated), CallEvent::Failed(487));
    assert_eq!(call.state(), CallState::Terminated);
}

// --- SMS-002: mobile-terminated SMS ---------------------------------------

#[test]
fn sms_002_mt_deliver_is_decoded_and_acknowledged() {
    use ims::sms::{delivery_response, receive_message, rp_ack, RpData, SmsDeliver};
    use ims::ImsProfile;

    // Network -> MS: RP-DATA wrapping an SMS-DELIVER TPDU (TS 24.011, GSM 03.40).
    let tpdu = SmsDeliver {
        originator: "15551234567".into(),
        pid: 0,
        dcs: 0,
        scts: [0x42, 0x10, 0x51, 0x32, 0x41, 0x00, 0x00],
        text: "meet me at 9".into(),
    }
    .encode();
    assert_eq!(tpdu[0] & 0x03, 0x00, "TP-MTI must be SMS-DELIVER");

    let rp = RpData {
        message_reference: 42,
        originator: "15551234567".into(),
        destination: "001010000000001".into(),
        tpdu,
    };
    let body = rp.encode();
    assert_eq!(body[0], 0x01, "RP-MTI network->MS must be 0x01");

    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "Via",
        "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-mt-1;rport",
    ));
    headers.push(sip::Header::new("From", "<sip:ip-sm-gw@ims>;tag=gw-1"));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims>"));
    headers.push(sip::Header::new("Call-ID", "mt-sms-1"));
    headers.push(sip::Header::new("CSeq", "1 MESSAGE"));
    let message = sip::Request {
        method: sip::Method::Message,
        uri: "sip:001010000000001@ims".into(),
        headers,
        body,
    };

    // The UE decodes originator + text and ACKs with RP-ACK in the 200 OK.
    let incoming = receive_message(&message).expect("MT SMS should decode");
    assert_eq!(incoming.originator, "15551234567");
    assert_eq!(incoming.text, "meet me at 9");
    assert_eq!(incoming.message_reference, 42);

    let response = delivery_response(&message, &ImsProfile::lab_default()).expect("200 OK");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-type"),
        Some("application/vnd.3gpp.sms")
    );
    assert_eq!(response.body, rp_ack(42));
    assert_eq!(response.body, vec![0x02, 42, 0x00]);
}

// --- UAS-002: received re-INVITE / UPDATE renegotiation -------------------

fn uas_dialog() -> ims::IncomingCall {
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "From",
        "<sip:001010000000002@ims.example>;tag=caller-tag",
    ));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims.example>"));
    headers.push(sip::Header::new("Call-ID", "reneg-1"));
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    headers.push(sip::Header::new("Content-Type", "application/sdp"));
    let offer = ims::Sdp::amr_wb_offer(&[0, 1, 2, 3], true, "192.0.2.20");
    let invite = sip::Request {
        method: sip::Method::Invite,
        uri: "sip:001010000000001@ims.example".into(),
        headers,
        body: offer.to_text().into_bytes(),
    };
    let mut call = ims::IncomingCall::from_invite(&invite, ims::ImsProfile::lab_default()).unwrap();
    call.ringing();
    let _ = call.accept().unwrap();
    let mut ack_headers = sip::Headers::new();
    ack_headers.push(sip::Header::new("CSeq", "1 ACK"));
    let ack = sip::Request {
        method: sip::Method::Ack,
        uri: invite.uri.clone(),
        headers: ack_headers,
        body: Vec::new(),
    };
    let _ = call.on_request(&ack).unwrap();
    call
}

#[test]
fn uas_002_reinvite_and_update_renegotiate_hold() {
    use ims::{Sdp, UasEvent};

    let mut call = uas_dialog();

    // Remote hold arrives as an offer with a=sendonly; the answer mirrors it.
    let mut hold = Sdp::amr_wb_offer(&[0, 1, 2, 3], true, "192.0.2.20");
    hold.set_direction(ims::Direction::SendOnly);

    for method in [sip::Method::Invite, sip::Method::Update] {
        let mut headers = sip::Headers::new();
        headers.push(sip::Header::new("CSeq", format!("5 {method}")));
        headers.push(sip::Header::new("Content-Type", "application/sdp"));
        let request = sip::Request {
            method,
            uri: "sip:001010000000001@ims.example".into(),
            headers,
            body: hold.to_text().into_bytes(),
        };
        match call.on_request(&request).unwrap() {
            UasEvent::Respond(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.headers.get("content-type"), Some("application/sdp"));
                let body = String::from_utf8(r.body.clone()).unwrap();
                // RFC 3264 §6.1: sendonly offer -> recvonly answer.
                assert!(body.contains("a=recvonly"), "{body}");
                assert!(!body.contains("a=sendonly"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        call.answer().map(ims::Sdp::direction),
        Some(ims::Direction::RecvOnly)
    );
    // ACK for the re-INVITE keeps the dialog confirmed.
    let mut ack_headers = sip::Headers::new();
    ack_headers.push(sip::Header::new("CSeq", "5 ACK"));
    let ack = sip::Request {
        method: sip::Method::Ack,
        uri: "sip:001010000000001@ims.example".into(),
        headers: ack_headers,
        body: Vec::new(),
    };
    assert_eq!(call.on_request(&ack).unwrap(), UasEvent::Established);
    assert_eq!(call.state(), ims::UasState::Confirmed);
}

// --- SUP-001 / SUP-002: hold-resume and call waiting ----------------------

#[test]
fn sup_001_hold_and_resume_reinvite_directions() {
    use ims::{Call, CallEvent, Direction, ImsProfile};

    let mut call = Call::new(ImsProfile::lab_default(), "sip:b@ims.example");
    let _ = call.invite();
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let ok = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers,
        body: Vec::new(),
    };
    assert!(matches!(
        call.on_response(&ok),
        CallEvent::Established { .. }
    ));

    // Hold: a re-INVITE with a=sendonly.
    let hold = call.hold().expect("hold");
    assert!(String::from_utf8_lossy(&hold.body).contains("a=sendonly"));
    assert_eq!(
        call.answer().map(ims::Sdp::direction),
        Some(Direction::SendOnly)
    );

    // Resume: a=sendrecv.
    let resume = call.resume().expect("resume");
    let body = String::from_utf8_lossy(&resume.body).to_string();
    assert!(body.contains("a=sendrecv"));
    assert!(!body.contains("a=sendonly"));
}

#[test]
fn sup_002_call_waiting_holds_the_active_call_and_answers() {
    use ims::{Call, CallEvent, ImsProfile};

    let mut active = Call::new(ImsProfile::lab_default(), "sip:b@ims.example");
    let _ = active.invite();
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let ok = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers,
        body: Vec::new(),
    };
    assert!(matches!(
        active.on_response(&ok),
        CallEvent::Established { .. }
    ));
    assert!(ims::is_call_waiting(Some(&active)));

    // A second INVITE arrives while the first is established.
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new(
        "From",
        "<sip:001010000000003@ims.example>;tag=waiting",
    ));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims.example>"));
    headers.push(sip::Header::new("Call-ID", "waiting-call"));
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let offer = ims::Sdp::amr_wb_offer(&[0, 1, 2], true, "192.0.2.30");
    headers.push(sip::Header::new("Content-Type", "application/sdp"));
    let invite = sip::Request {
        method: sip::Method::Invite,
        uri: "sip:001010000000001@ims.example".into(),
        headers,
        body: offer.to_text().into_bytes(),
    };
    let mut incoming = ims::IncomingCall::from_invite(&invite, ImsProfile::lab_default()).unwrap();

    let actions = ims::accept_waiting(&mut active, &mut incoming).expect("accept waiting");
    // The active call is held and the new one is answered.
    assert!(String::from_utf8_lossy(&actions.hold.body).contains("a=sendonly"));
    assert_eq!(actions.answer.status, 200);
}

#[test]
fn sup_002_declining_a_waiting_call_is_486() {
    let mut headers = sip::Headers::new();
    headers.push(sip::Header::new("From", "<sip:c@ims>;tag=w"));
    headers.push(sip::Header::new("To", "<sip:001010000000001@ims>"));
    headers.push(sip::Header::new("Call-ID", "decline-1"));
    headers.push(sip::Header::new("CSeq", "1 INVITE"));
    let invite = sip::Request {
        method: sip::Method::Invite,
        uri: "sip:001010000000001@ims".into(),
        headers,
        body: Vec::new(),
    };
    let mut incoming =
        ims::IncomingCall::from_invite(&invite, ims::ImsProfile::lab_default()).unwrap();
    let response = ims::decline_waiting(&mut incoming);
    assert_eq!(response.status, 486);
    assert_eq!(response.reason, "Busy Here");
}

// --- REG-011..013: registration edge cases --------------------------------

#[test]
fn reg_011_multiple_contacts_third_party_and_pcscf_failover() {
    use ims::{ImsProfile, Registration};

    // Multiple bindings for one IMPU in a single REGISTER (RFC 3261 §10.2).
    let mut reg = Registration::new(ImsProfile::lab_default());
    reg.add_contact("sip:001010000000001@192.0.2.77:5060", Some(300));
    let request = reg.register_request();
    let contacts: Vec<&str> = request.headers.get_all("contact").collect();
    assert_eq!(contacts.len(), 2);
    assert!(contacts[1].contains("expires=300"));

    // Third-party registration: To is the address-of-record being registered.
    let mut reg = Registration::new(ImsProfile::lab_default());
    reg.as_third_party("sip:001010000000042@ims.example");
    let request = reg.register_request();
    assert_eq!(
        request.headers.get("to"),
        Some("<sip:001010000000042@ims.example>")
    );
    assert!(request
        .headers
        .get("from")
        .unwrap()
        .contains("001010000000001@"));

    // P-CSCF failover walks the candidate list once, then stops.
    let mut profile = ImsProfile::lab_default();
    profile.p_cscf = vec!["pcscf1:5060".into(), "pcscf2:5060".into()];
    let mut reg = Registration::new(profile);
    assert_eq!(reg.current_p_cscf(), Some("pcscf1:5060"));
    assert_eq!(reg.next_p_cscf().as_deref(), Some("pcscf2:5060"));
    assert_eq!(reg.next_p_cscf(), None);
}

// --- KEEP-001: OPTIONS keepalive ------------------------------------------

#[test]
fn keep_001_options_ping_and_failure_accounting() {
    use ims::{Keepalive, KeepaliveStatus};
    use std::time::{Duration, Instant};

    let mut ka = Keepalive::new(ims::ImsProfile::lab_default())
        .with_interval(Duration::from_secs(10))
        .with_max_failures(2);
    let t0 = Instant::now();

    // The first ping is due immediately and is a well-formed OPTIONS.
    assert!(ka.due(t0));
    let ping = ka.ping("sip:pcscf.ims.example", t0);
    assert_eq!(ping.method, sip::Method::Options);
    assert_eq!(ping.headers.get("cseq"), Some("1 OPTIONS"));
    assert!(ping
        .headers
        .get("via")
        .unwrap()
        .contains("branch=z9hG4bK-fungos-ka-"));
    assert_eq!(ping.headers.get("content-length"), Some("0"));

    // Not due again until the interval elapses.
    assert!(!ka.due(t0 + Duration::from_secs(5)));
    assert!(ka.due(t0 + Duration::from_secs(10)));

    // Failures accumulate to Dead, and a 2xx resets them.
    let ok = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers: sip::Headers::new(),
        body: Vec::new(),
    };
    assert_eq!(ka.on_timeout(), KeepaliveStatus::Unhealthy(408));
    assert_eq!(ka.on_response(&ok), KeepaliveStatus::Alive);
    assert_eq!(ka.failures(), 0);
    assert_eq!(ka.on_timeout(), KeepaliveStatus::Unhealthy(408));
    assert_eq!(ka.on_timeout(), KeepaliveStatus::Dead);
    assert!(ka.is_dead());
}

// --- INV-004: forked INVITE (multiple 2xx) --------------------------------

#[test]
fn inv_004_a_forked_2xx_is_acked_then_bye_d() {
    use ims::{Call, CallEvent, ImsProfile};

    let mut call = Call::new(ImsProfile::lab_default(), "sip:b@ims.example");
    let _ = call.invite();

    let mut first = sip::Headers::new();
    first.push(sip::Header::new("CSeq", "1 INVITE"));
    first.push(sip::Header::new("To", "<sip:b@ims.example>;tag=branch-a"));
    first.push(sip::Header::new("Contact", "<sip:b@10.0.0.1:5060>"));
    let ok = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers: first,
        body: Vec::new(),
    };
    assert!(matches!(
        call.on_response(&ok),
        CallEvent::Established { .. }
    ));

    // A second 200 for the same INVITE forks: ACK it, then BYE that branch.
    let mut second = sip::Headers::new();
    second.push(sip::Header::new("CSeq", "1 INVITE"));
    second.push(sip::Header::new("To", "<sip:b@ims.example>;tag=branch-b"));
    second.push(sip::Header::new("Contact", "<sip:b@10.0.0.2:5060>"));
    let fork = sip::Response {
        status: 200,
        reason: "OK".into(),
        headers: second,
        body: Vec::new(),
    };
    match call.on_response(&fork) {
        CallEvent::Forked { ack, bye } => {
            assert_eq!(ack.method, sip::Method::Ack);
            assert_eq!(bye.method, sip::Method::Bye);
            assert!(ack.headers.get("to").unwrap().contains("branch-b"));
            assert!(bye.headers.get("to").unwrap().contains("branch-b"));
        }
        other => panic!("unexpected {other:?}"),
    }
    // The first dialog remains the active one.
    assert!(call.is_established());
}

// --- SDP-003: second media line -------------------------------------------

#[test]
fn sdp_003_second_media_line_is_rejected_not_dropped() {
    use ims::sdp::Attribute;
    use ims::Sdp;

    let mut offer = Sdp::amr_wb_offer(&[0, 1, 2], true, "192.0.2.20");
    offer.add_media_line(
        "video",
        49174,
        "RTP/AVP",
        &["96"],
        vec![Attribute::new("rtpmap", Some("96 H264/90000"))],
    );
    let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
    assert_eq!(answer.media.len(), 2);
    assert_ne!(answer.media[0].port, 0);
    // RFC 3264 §6.2: unaccepted media lines are returned with port 0.
    assert_eq!(answer.media[1].port, 0);
    assert_eq!(answer.rejected_media().count(), 1);
}
