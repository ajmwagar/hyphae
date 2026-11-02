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

// --- SEC-003: authenticated ESP (TS 33.203 §7, RFC 2403/2404) -------------

#[test]
fn sec_003_esp_authenticates_frames_and_rejects_replay() {
    use transport::esp::{EspError, EspIntegrity, EspSa, NEXT_HDR_UDP};

    // IK from IMS-AKA; null encryption is the mandatory profile.
    let ik = [0x2b; 16];
    let mut out = EspSa::new(0x2710, EspIntegrity::HmacMd5_96, &ik, &[]).unwrap();
    let mut inbound = EspSa::new(0x2710, EspIntegrity::HmacMd5_96, &ik, &[]).unwrap();

    let frame = out.encapsulate(b"REGISTER sip:ims SIP/2.0", NEXT_HDR_UDP);
    let packet = inbound.decapsulate(&frame).unwrap();
    assert_eq!(packet.payload, b"REGISTER sip:ims SIP/2.0");
    assert_eq!(packet.seq, 1);

    // Replay of the same sequence is rejected.
    assert_eq!(inbound.decapsulate(&frame), Err(EspError::Replay(1)));

    // Any bit flip in the protected region breaks the ICV.
    let mut tampered = out.encapsulate(b"tampered", NEXT_HDR_UDP);
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert_eq!(inbound.decapsulate(&tampered), Err(EspError::BadIcv));

    // HMAC-SHA-1-96 is the other TS 33.203 integrity algorithm.
    let mut out = EspSa::new(0x2711, EspIntegrity::HmacSha1_96, &ik, &[]).unwrap();
    let mut inbound = EspSa::new(0x2711, EspIntegrity::HmacSha1_96, &ik, &[]).unwrap();
    let frame = out.encapsulate(b"sha1", NEXT_HDR_UDP);
    assert_eq!(inbound.decapsulate(&frame).unwrap().payload, b"sha1");
    assert_eq!(
        EspIntegrity::from_ims("hmac-md5-96"),
        Some(EspIntegrity::HmacMd5_96)
    );
}

// --- SEC-004: SA negotiation and XFRM programming -------------------------

#[test]
fn sec_004_negotiates_sas_and_renders_xfrm_commands() {
    use transport::ipsec::{IpsecAgreement, SecurityParams, XfrmProgram};

    let client = SecurityParams::parse(
        "algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5062;port-s=5064",
    )
    .unwrap();
    let server = SecurityParams::parse(
        "algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5062;port-s=5064",
    )
    .unwrap();
    // CK/IK are what the USIM's AUTHENTICATE produced.
    let ck = [0x11u8; 16];
    let ik = [0x22u8; 16];
    let agreement =
        IpsecAgreement::negotiate(&client, &server, &ck, &ik, "10.32.0.2", "10.32.0.1").unwrap();
    assert_eq!(agreement.outbound_spi(), 10000);
    assert_eq!(agreement.inbound_spi(), 10001);

    // Two SAs and two policies, exactly as `ip xfrm` expects.
    let program = XfrmProgram::build(&agreement);
    let rendered = program.render();
    assert_eq!(rendered.len(), 4);
    assert!(rendered[0].contains("state add src 10.32.0.2 dst 10.32.0.1"));
    assert!(rendered[0].contains("auth hmac(md5) 0x22222222222222222222222222222222"));
    assert!(rendered[1].contains("spi 0x2711"));
    assert!(rendered[2].contains("policy add dir out"));
    assert!(rendered[3].contains("policy add dir in"));

    // Kernel programming is Linux-only; elsewhere it reports so, not panics.
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        program.apply(),
        Err(transport::ipsec::IpsecError::PlatformUnsupported)
    );
}

// --- USIM-002/003: modem card access (QMI UIM, AT+CSIM) -------------------

#[test]
fn usim_002_qmi_send_apdu_frames_and_reaches_the_card() {
    use usim::qmi::{decode_qmux, encode_qmux, send_apdu_tlvs, MSG_SEND_APDU, SERVICE_UIM};
    use usim::{AkaOutput, CardResponse, QmiApdu, QmiExchange, Usim, UsimCard, UsimError};

    // QMUX: 01 | len(2) | 00 | service | client | QMI(flags,txid,msg) | TLVs
    let tlvs = send_apdu_tlvs(1, 0, &[0x00, 0x88]);
    let frame = encode_qmux(SERVICE_UIM, 9, 0x0102, MSG_SEND_APDU, &tlvs);
    assert_eq!(frame[0], 0x01);
    assert_eq!(&frame[3..6], &[0x00, SERVICE_UIM, 9]);
    assert_eq!(&frame[7..9], &[0x02, 0x01]); // transaction LE
    assert_eq!(&frame[9..11], &[0x3B, 0x00]); // message LE
    let len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
    assert_eq!(len + 3, frame.len());

    // A fake modem answers Send APDU with a 3G AUTHENTICATE body + 90 00.
    struct Modem;
    impl QmiExchange for Modem {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, UsimError> {
            let mut apdu = vec![0xDB, 8];
            apdu.extend_from_slice(&[0xA5; 8]);
            apdu.push(16);
            apdu.extend_from_slice(&[0xB4; 16]);
            apdu.push(16);
            apdu.extend_from_slice(&[0xF7; 16]);
            apdu.extend_from_slice(&[0x90, 0x00]);
            let mut value = (apdu.len() as u16).to_le_bytes().to_vec();
            value.extend_from_slice(&apdu);
            let mut qmi = vec![0x00, request[7], request[8], 0x3B, 0x00];
            for (kind, val) in [(0x02u8, vec![0u8, 0, 0, 0]), (0x10u8, value)] {
                qmi.push(kind);
                qmi.extend_from_slice(&(val.len() as u16).to_le_bytes());
                qmi.extend_from_slice(&val);
            }
            let mut out = vec![0x02];
            out.extend_from_slice(&((3 + qmi.len()) as u16).to_le_bytes());
            out.extend_from_slice(&[0x00, SERVICE_UIM, request[5]]);
            out.extend_from_slice(&qmi);
            Ok(out)
        }
    }

    let mut card = UsimCard::new(QmiApdu::new(Modem, 9, 1));
    match card.authenticate(&[0x11; 16], &[0x22; 16]).unwrap() {
        AkaOutput::Success { res, .. } => assert_eq!(res, vec![0xA5; 8]),
        other => panic!("unexpected {other:?}"),
    }
    // The response frame decodes back through the same codec.
    assert!(decode_qmux(&encode_qmux(SERVICE_UIM, 1, 1, MSG_SEND_APDU, &[])).is_ok());
    let _ = CardResponse::from_apdu_response(&[0x90, 0x00]).unwrap();
}

#[test]
fn usim_003_at_csim_round_trips_an_apdu() {
    use usim::at::{csim_command, parse_csim_response, AtApdu, AtChannel};
    use usim::{apdu::authenticate_command, ApduChannel, UsimError};

    let apdu = authenticate_command(&[0x11; 16], &[0x22; 16]).to_bytes();
    let cmd = csim_command(&apdu);
    assert!(cmd.starts_with("AT+CSIM=80,\"0088"));
    assert!(cmd.ends_with('"'));
    assert_eq!(
        parse_csim_response("+CSIM: 6,\"DB9000\"").unwrap(),
        vec![0xDB, 0x90, 0x00]
    );

    struct At;
    impl AtChannel for At {
        fn command(&mut self, _c: &str) -> Result<String, UsimError> {
            Ok("+CSIM: 4,\"9000\"".into())
        }
    }
    let mut channel = AtApdu::new(At);
    let response = channel.transmit(&apdu).unwrap();
    assert_eq!((response.sw1, response.sw2), (0x90, 0x00));
}

// --- AUDIO-001: call-audio plumbing --------------------------------------

#[test]
fn audio_001_pcm_moves_through_a_ring_buffer_and_a_wav() {
    use media::audio::{AudioSink, AudioSource, Loopback, Pacing, RingBuffer, Wav};
    use std::time::{Duration, Instant};

    // Bounded queue: overflow drops the oldest, underrun pads silence.
    let mut ring = RingBuffer::new(4);
    ring.push(&[1, 2, 3, 4, 5, 6]);
    assert_eq!(ring.dropped(), 2);
    let mut out = [0i16; 6];
    assert_eq!(ring.pop_into(&mut out), 4);
    assert_eq!(out, [3, 4, 5, 6, 0, 0]);
    assert_eq!(ring.underruns(), 1);

    // Connected sink/source pair, as a device adapter would be wired.
    let (mut sink, mut source) = Loopback::pair(480);
    sink.write(&[10, 20, 30]).unwrap();
    let mut pcm = [0i16; 4];
    assert_eq!(source.read(&mut pcm, Duration::from_millis(10)).unwrap(), 3);
    assert_eq!(pcm, [10, 20, 30, 0]);

    // Capture sink produces a valid RIFF/WAVE file.
    let mut wav = Wav::new(16_000, 1);
    wav.write(&[1, -1]).unwrap();
    let bytes = wav.to_bytes();
    assert_eq!(&bytes[0..4], b"RIFF");
    assert_eq!(&bytes[8..12], b"WAVE");
    assert_eq!(&bytes[36..40], b"data");

    // Playback pacing: 20 ms at 16 kHz is one 320-sample frame.
    let t0 = Instant::now();
    let mut pacing = Pacing::new(16_000, t0);
    assert_eq!(pacing.due(t0), 0);
    assert_eq!(pacing.due(t0 + Duration::from_millis(20)), 320);
}

// --- VOICE-001/002: continuity -------------------------------------------

#[test]
fn voice_001_invite_failures_classify_to_continuity_events() {
    use ims::{classify_invite_failure, FallbackReason};

    let response = |status: u16, retry: Option<&str>| {
        let mut headers = sip::Headers::new();
        if let Some(r) = retry {
            headers.push(sip::Header::new("Retry-After", r));
        }
        sip::Response {
            status,
            reason: " ".into(),
            headers,
            body: Vec::new(),
        }
    };

    // The network cannot serve VoLTE: fall back to CS (TS 23.216).
    assert_eq!(
        classify_invite_failure(&response(488, None)),
        Some(FallbackReason::EpsFallback)
    );
    assert_eq!(
        classify_invite_failure(&response(580, None)),
        Some(FallbackReason::EpsFallback)
    );
    // 503 is a retry hint, not a fallback.
    assert_eq!(
        classify_invite_failure(&response(503, Some("30"))),
        Some(FallbackReason::ServiceNotProvided {
            retry_after_s: Some(30)
        })
    );
    // Ordinary rejections are not continuity events.
    assert_eq!(classify_invite_failure(&response(486, None)), None);
}

#[test]
fn voice_002_media_liveness_degrades_then_is_lost() {
    use ims::{ContinuityEvent, ContinuityMonitor};
    use std::time::{Duration, Instant};

    let t0 = Instant::now();
    let mut monitor = ContinuityMonitor::new(Duration::from_secs(6));
    monitor.start(t0);
    assert_eq!(
        monitor.poll(t0 + Duration::from_secs(1)),
        ContinuityEvent::Healthy
    );
    assert_eq!(
        monitor.poll(t0 + Duration::from_secs(3)),
        ContinuityEvent::Degraded
    );
    assert_eq!(
        monitor.poll(t0 + Duration::from_secs(6)),
        ContinuityEvent::Lost
    );
    // A late packet revives the session.
    monitor.on_activity(t0 + Duration::from_secs(6));
    assert_eq!(
        monitor.poll(t0 + Duration::from_secs(6)),
        ContinuityEvent::Healthy
    );
}

// --- EPDG-001: EAP-AKA' key hierarchy (Wi-Fi calling core) ----------------

#[test]
fn epdg_001_eap_aka_prime_derives_the_full_key_set() {
    use aka::eap_aka_prime::{
        at_mac, bidding_attribute, ck_ik_prime, derive_keys, kdf_attribute, kdf_input_attribute,
        parse_attributes, prf_prime, separation_bit_set, AT_BIDDING, AT_KDF, AT_KDF_INPUT,
    };

    // 3GPP TS 33.402: CK'/IK' are bound to the access-network name.
    let ck = [0x11u8; 16];
    let ik = [0x22u8; 16];
    let (ck_p, _ik_p) = ck_ik_prime(&ck, &ik, "WLAN").unwrap();
    let (ck_q, _) = ck_ik_prime(&ck, &ik, "OTHER").unwrap();
    assert_ne!(ck_p, ck_q, "the network name must bind the keys");

    // RFC 5448 §3.3: PRF' expands IK'|CK' into the EAP key set.
    assert!(separation_bit_set(&[0x80, 0x00]));
    let keys = derive_keys(&ck, &ik, "WLAN", "user@example", &[0x80, 0x00]).unwrap();
    assert_eq!(keys.msk.len(), 64);
    assert_eq!(keys.emsk.len(), 64);
    // A clear AMF separation bit is not an EAP-AKA' challenge.
    assert!(derive_keys(&ck, &ik, "WLAN", "user@example", &[0x00, 0x00]).is_err());

    // PRF' is prefix-stable: asking for more output extends the same stream.
    let prf_key = [0x33u8; 32];
    let short = prf_prime(&prf_key, b"seed", 32);
    let long = prf_prime(&prf_key, b"seed", 208);
    assert_eq!(&long[..32], &short[..]);

    // Attributes: length-prefixed network name, KDF selector, bidding bit.
    let attrs = [
        kdf_input_attribute("WLAN").unwrap(),
        kdf_attribute(1),
        bidding_attribute(true),
    ]
    .concat();
    assert_eq!(attrs.len() % 4, 0);
    let parsed = parse_attributes(&attrs).unwrap();
    assert_eq!(parsed[0].0, 0x80 | AT_KDF_INPUT);
    assert_eq!(parsed[1].0, 0x80 | AT_KDF);
    assert_eq!(parsed[2].0, AT_BIDDING);
    assert_eq!(parsed[2].1[0] & 0x80, 0x80);

    // AT_MAC is HMAC-SHA-256-128 over the packet with the MAC field zeroed.
    let mut packet = vec![0x8b, 0x05];
    packet.extend_from_slice(&[0xaa; 16]);
    let mac = at_mac(&keys.k_aut, &packet, 2).unwrap();
    let mut zeroed = packet.clone();
    zeroed[2..18].fill(0);
    assert_eq!(mac, at_mac(&keys.k_aut, &zeroed, 2).unwrap());
    assert_eq!(mac.len(), 16);
}

// --- EPDG-002: IKEv2 message and payload codec ----------------------------

#[test]
fn epdg_002_ikev2_message_round_trips_the_wire() {
    use epdg::ikev2::{
        encode_payloads, ExchangeType, Header, Ke, Message, Payload, PayloadType, Proposal, Sa,
        Transform, FLAG_INITIATOR, HEADER_LEN, PROTO_ESP, TRANSFORM_DH, TRANSFORM_ENCR,
    };

    let header = Header {
        initiator_spi: [0x11; 8],
        responder_spi: [0; 8],
        next_payload: PayloadType::Sa,
        exchange: ExchangeType::IkeSaInit,
        flags: FLAG_INITIATOR,
        message_id: 0,
    };

    // A realistic IKE_SA_INIT: SA + KE + Nonce.
    let message = Message {
        header,
        payloads: vec![
            Payload {
                kind: PayloadType::Sa,
                critical: false,
                body: Sa {
                    proposals: vec![Proposal {
                        number: 1,
                        protocol_id: PROTO_ESP,
                        spi: vec![],
                        transforms: vec![
                            Transform {
                                transform_type: TRANSFORM_ENCR,
                                id: 12, // AES-CBC
                                attributes: vec![],
                            },
                            Transform {
                                transform_type: TRANSFORM_DH,
                                id: 14, // MODP 2048
                                attributes: vec![],
                            },
                        ],
                    }],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Ke,
                critical: false,
                body: Ke {
                    dh_group: 14,
                    key_data: vec![0x42; 256],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Nonce,
                critical: false,
                body: vec![0xAB; 32],
            },
        ],
    };

    let bytes = message.encode();
    // 28-octet header, version 2.0, exchange IKE_SA_INIT.
    assert_eq!(bytes[17], 0x20);
    assert_eq!(bytes[18], 34);
    assert_eq!(bytes[19], FLAG_INITIATOR);
    assert_eq!(
        u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]) as usize,
        bytes.len()
    );
    assert_eq!(bytes[16], PayloadType::Sa as u8);
    assert_eq!(&bytes[..8], &[0x11; 8]);

    let decoded = Message::decode(&bytes).unwrap();
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.payloads, message.payloads);
    assert_eq!(
        HEADER_LEN + encode_payloads(&message.payloads).len(),
        bytes.len()
    );

    // The payload chain links SA -> KE -> NONCE.
    let ke = decoded.find(PayloadType::Ke).unwrap();
    assert_eq!(Ke::decode(&ke.body).unwrap().dh_group, 14);
}

// --- EPDG-003: EAP-AKA' challenge / response ------------------------------

#[test]
fn epdg_003_eap_aka_prime_peer_answers_the_challenge() {
    use aka::eap_aka_prime::{
        at_mac, attribute, ck_ik_prime, derive_keys, kdf_input_attribute, AT_MAC_LEN,
    };
    use epdg::eap::{
        attribute_value_offset, AkaPrimePeer, EapPacket, AT_MAC, AT_RES, EAP_REQUEST, EAP_RESPONSE,
        EAP_TYPE_AKA_PRIME, SUBTYPE_CHALLENGE,
    };

    let network = "WLAN";
    let identity = "user@example";
    let res = [0xA5u8; 8];

    // The USIM produced CK/IK; EAP-AKA' re-derives them for this access network.
    let (ck, ik) = ck_ik_prime(&[0x11; 16], &[0x22; 16], network).unwrap();
    let keys = derive_keys(&ck, &ik, network, identity, &[0x80, 0x00]).unwrap();

    // Server: EAP-Request/AKA'-Challenge with AT_KDF_INPUT and a valid AT_MAC.
    let mut attributes = kdf_input_attribute(network).unwrap();
    attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));
    let mut challenge =
        EapPacket::response(7, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &attributes);
    challenge[0] = EAP_REQUEST;
    let mac_at = 4 + 2 + attribute_value_offset(&attributes, AT_MAC).unwrap();
    let server_mac = at_mac(&keys.k_aut, &challenge, mac_at).unwrap();
    challenge[mac_at..mac_at + AT_MAC_LEN].copy_from_slice(&server_mac);

    // Peer: verify, then answer with AT_RES and its own AT_MAC.
    let mut peer = AkaPrimePeer::new(network, keys.clone(), res.to_vec());
    let response = peer.on_request(&challenge).unwrap();
    let parsed = EapPacket::parse(&response).unwrap();
    assert_eq!(parsed.code, EAP_RESPONSE);
    assert_eq!(parsed.identifier, 7);

    let res_at = attribute_value_offset(&parsed.attributes, AT_RES).unwrap();
    assert_eq!(
        u16::from_be_bytes([parsed.attributes[res_at], parsed.attributes[res_at + 1]]),
        64
    );
    assert_eq!(&parsed.attributes[res_at + 2..res_at + 10], &res[..]);

    // The peer's AT_MAC verifies with K_aut.
    let our_mac_at = attribute_value_offset(&parsed.attributes, AT_MAC).unwrap();
    let packet_mac = 4 + 2 + our_mac_at;
    let mut zeroed = response.clone();
    zeroed[packet_mac..packet_mac + AT_MAC_LEN].fill(0);
    assert_eq!(
        &response[packet_mac..packet_mac + AT_MAC_LEN],
        &at_mac(&keys.k_aut, &zeroed, packet_mac).unwrap()[..]
    );

    // A challenge for a different access network is refused.
    let other_keys = derive_keys(
        &ck_ik_prime(&[0x11; 16], &[0x22; 16], "OTHER").unwrap().0,
        &ck_ik_prime(&[0x11; 16], &[0x22; 16], "OTHER").unwrap().1,
        "OTHER",
        identity,
        &[0x80, 0x00],
    )
    .unwrap();
    let mut wrong_attrs = kdf_input_attribute("OTHER").unwrap();
    wrong_attrs.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));
    let mut wrong =
        EapPacket::response(8, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &wrong_attrs);
    wrong[0] = EAP_REQUEST;
    let wrong_mac_at = 4 + 2 + attribute_value_offset(&wrong_attrs, AT_MAC).unwrap();
    let m = at_mac(&other_keys.k_aut, &wrong, wrong_mac_at).unwrap();
    wrong[wrong_mac_at..wrong_mac_at + AT_MAC_LEN].copy_from_slice(&m);
    let mut peer = AkaPrimePeer::new(network, keys, res.to_vec());
    assert!(peer.on_request(&wrong).is_err());
}

// --- EPDG-004/005: IKEv2 Diffie-Hellman and key schedule ------------------

#[test]
fn epdg_004_ikev2_diffie_hellman_agrees() {
    use epdg::dh::{group_parameters, DhError, DhKeyPair};

    // Group 14 is the RFC 3526 2048-bit MODP group that IKEv2 requires.
    let (prime, generator) = group_parameters(14).unwrap();
    assert_eq!(prime.bits(), 2048);
    assert_eq!(generator, 2);

    let alice = DhKeyPair::from_private(14, &[0x11; 32]).unwrap();
    let bob = DhKeyPair::from_private(14, &[0x22; 32]).unwrap();
    let a = alice.agree(&bob.public_bytes()).unwrap();
    let b = bob.agree(&alice.public_bytes()).unwrap();
    assert_eq!(a, b, "both sides derive the same g^ir");
    assert_eq!(a.len(), 256, "shared secret is modulus-length padded");

    // Out-of-range peer values are rejected rather than used.
    assert_eq!(alice.agree(&[0x00]), Err(DhError::BadPeerPublic));
    assert_eq!(alice.agree(&[0x01]), Err(DhError::BadPeerPublic));
    assert_eq!(
        group_parameters(19).unwrap_err(),
        DhError::UnsupportedGroup(19)
    );
}

#[test]
fn epdg_005_ikev2_key_schedule_splits_the_prf_stream() {
    use epdg::keys::{derive_keys, prf_plus, skeyseed, IkeKeySizes};

    let shared = [0xAAu8; 256];
    let ni = [0x01u8; 32];
    let nr = [0x02u8; 32];

    // SKEYSEED = prf(Ni|Nr, g^ir).
    let seed = skeyseed(&ni, &nr, &shared);
    assert_eq!(seed, skeyseed(&ni, &nr, &shared));
    assert_ne!(seed, skeyseed(&nr, &ni, &shared));

    // {SK_d|..|SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr) — RFC 7296 §2.14.
    let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
    let (spi_i, spi_r) = ([0x11u8; 8], [0x44u8; 8]);
    let keys = derive_keys(&seed, &ni, &nr, spi_i, spi_r, sizes);
    // Both SPIs feed the expansion, so changing either changes every key.
    let other = derive_keys(&seed, &ni, &nr, spi_i, [0x45u8; 8], sizes);
    assert_ne!(keys.sk_d, other.sk_d);
    assert_ne!(keys.sk_ai, other.sk_ai);
    assert_eq!(keys.sk_d.len(), 32);
    assert_eq!(keys.sk_ei.len(), 16);
    assert_eq!(keys.sk_er.len(), 16);
    assert_eq!(keys.sk_ai.len(), 32);
    assert_eq!(keys.sk_pr.len(), 32);

    // The expansion seed carries the SPIs as well as the nonces.
    let both = [&ni[..], &nr[..], &spi_i[..], &spi_r[..]].concat();
    let material = prf_plus(&seed, &both, 32 + 32 + 32 + 16 + 16 + 32 + 32);
    assert_eq!(keys.sk_d, material[..32]);
    assert_eq!(keys.sk_ai, material[32..64]);
    assert_eq!(keys.sk_ar, material[64..96]);
    assert_eq!(keys.sk_ei, material[96..112]);
    assert_eq!(keys.sk_er, material[112..128]);
    assert_eq!(keys.sk_pi, material[128..160]);
    assert_eq!(keys.sk_pr, material[160..192]);
}

// --- EPDG-006: SK (encrypted payload) layer -------------------------------

#[test]
fn epdg_006_sk_seals_and_opens_with_aes_cbc_and_hmac() {
    use epdg::ikev2::{ExchangeType, Header, Payload, PayloadType, FLAG_INITIATOR};
    use epdg::sk::Sk;

    let sk = Sk::aes_cbc_128_sha256_128(&[0x11; 16], &[0x22; 32]).unwrap();
    let header = Header {
        initiator_spi: [0x01; 8],
        responder_spi: [0x02; 8],
        next_payload: PayloadType::None,
        exchange: ExchangeType::IkeAuth,
        flags: FLAG_INITIATOR,
        message_id: 3,
    };
    let payloads = vec![
        Payload {
            kind: PayloadType::Idi,
            critical: false,
            body: vec![2, 0, 0, 0, b'u', b's', b'e', b'r'],
        },
        Payload {
            kind: PayloadType::Nonce,
            critical: false,
            body: vec![0xAA; 24],
        },
    ];

    let sealed = sk.seal(header, &payloads, &[0x33; 16]);
    // The outer next payload is ENCRYPTED and the plaintext is not on the wire.
    assert_eq!(sealed[16], PayloadType::Encrypted as u8);
    assert!(!sealed.windows(4).any(|w| w == b"user"));
    let total = u32::from_be_bytes([sealed[24], sealed[25], sealed[26], sealed[27]]) as usize;
    assert_eq!(total, sealed.len());

    let opened = sk.open(&sealed).unwrap();
    assert_eq!(opened.payloads, payloads);
    assert_eq!(opened.header.message_id, 3);

    // Any bit flip is rejected by the ICV.
    let mut tampered = sealed.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    assert!(sk.open(&tampered).is_err());
}

// --- EPDG-007: IKE_SA_INIT handshake --------------------------------------

#[test]
fn epdg_007_ike_sa_init_derives_matching_keys() {
    use epdg::dh::DhKeyPair;
    use epdg::ikev2::{Ke, Message, PayloadType};
    use epdg::keys::{derive_keys, skeyseed, IkeKeySizes};
    use epdg::sa::{sa_init_response, SaInitInitiator};

    let mut initiator = SaInitInitiator::new([0x11; 8], &[0x22; 32], vec![0x33; 32], 14).unwrap();
    let request = initiator.first_message();
    assert_eq!(request.header.next_payload, PayloadType::Sa);
    assert_eq!(
        Message::decode(&request.encode()).unwrap(),
        request,
        "the first message survives its own codec"
    );

    let response = sa_init_response(&request, [0x44; 8], &[0x55; 32], vec![0x66; 32], 14).unwrap();
    let sizes = IkeKeySizes::aes_cbc_128_sha256_128();
    let initiator_keys = initiator.on_response(&response, sizes).unwrap();
    assert_eq!(initiator.responder_spi(), Some([0x44; 8]));

    // The responder computes the same schedule from its own exponent.
    let responder = DhKeyPair::from_private(14, &[0x55; 32]).unwrap();
    let ke = Ke::decode(&request.find(PayloadType::Ke).unwrap().body).unwrap();
    let shared = responder.agree(&ke.key_data).unwrap();
    let seed = skeyseed(&[0x33; 32], &[0x66; 32], &shared);
    let responder_keys = derive_keys(&seed, &[0x33; 32], &[0x66; 32], [0x11; 8], [0x44; 8], sizes);
    assert_eq!(initiator_keys, responder_keys);
}

// --- EPDG-008: AUTH payloads and child key material -----------------------

#[test]
fn epdg_008_auth_payload_and_child_keymat() {
    use epdg::auth::{
        auth_payload, child_keymat, signed_octets_initiator, signed_octets_responder,
    };

    let msk = [0x11u8; 64];
    let signed = signed_octets_initiator(b"msg1", &[0x22; 32], &[0x33; 32], b"id-i");
    // AUTH = prf(prf(secret, "Key Pad for IKEv2"), SignedOctets).
    let auth = auth_payload(&msk, &signed);
    assert_eq!(auth.len(), 32);
    assert_eq!(auth, auth_payload(&msk, &signed));
    assert_ne!(auth, auth_payload(&msk, b"other octets"));

    // The responder's signed octets are a different construction.
    let r = signed_octets_responder(b"msg2", &[0x22; 32], &[0x33; 32], b"id-r");
    assert_ne!(signed, r);

    // Child SA key material is prf+(SK_d, Ni | Nr).
    let sk_d = [0x44u8; 32];
    let a = child_keymat(&sk_d, &[1], &[2], 64);
    let b = child_keymat(&sk_d, &[1], &[2], 128);
    assert_eq!(a.len(), 64);
    assert_eq!(&b[..64], &a[..]);
    assert_ne!(a, child_keymat(&sk_d, &[1], &[3], 64));
}

// --- EPDG-009: IKE_AUTH with EAP-AKA' (RFC 5998) --------------------------

#[test]
fn epdg_009_ike_auth_eap_flow_establishes() {
    use aka::eap_aka_prime::{
        at_mac, attribute, ck_ik_prime, derive_keys as eap_keys, kdf_input_attribute, AT_MAC_LEN,
    };
    use epdg::auth::{auth_payload, child_keymat, signed_octets_responder};
    use epdg::eap::{
        attribute_value_offset, AkaPrimePeer, EapPacket, AT_MAC, EAP_REQUEST, EAP_SUCCESS,
        EAP_TYPE_AKA_PRIME, SUBTYPE_CHALLENGE,
    };
    use epdg::ike_auth::{AuthStep, IkeAuthInitiator};
    use epdg::ikev2::{
        ExchangeType, Header, Id, Payload, PayloadType, Proposal, Sa, TrafficSelectors, Transform,
        FLAG_RESPONSE, ID_RFC822_ADDR, PROTO_ESP, TRANSFORM_ENCR, TRANSFORM_INTEG,
    };
    use epdg::keys::{derive_keys, skeyseed, IkeKeySizes};
    use epdg::sk::{Sk, BLOCK_LEN};

    let network = "WLAN";
    let identity = "user@example";
    let res = [0xA5u8; 8];
    let iv = [0x55u8; BLOCK_LEN];

    // EAP-AKA' keys for this access network, and the IKE SA keys.
    let (ck, ik) = ck_ik_prime(&[0x11; 16], &[0x22; 16], network).unwrap();
    let eap = eap_keys(&ck, &ik, network, identity, &[0x80, 0x00]).unwrap();
    let seed = skeyseed(&[0x33; 32], &[0x66; 32], &[0x77; 256]);
    let keys = derive_keys(
        &seed,
        &[0x33; 32],
        &[0x66; 32],
        [0x01; 8],
        [0x02; 8],
        IkeKeySizes::aes_cbc_128_sha256_128(),
    );

    let sk_out = Sk::aes_cbc_128_sha256_128(&keys.sk_ei, &keys.sk_ai).unwrap();
    let sk_in = Sk::aes_cbc_128_sha256_128(&keys.sk_er, &keys.sk_ar).unwrap();

    let responder = |message_id: u32, payloads: Vec<Payload>| {
        let header = Header {
            initiator_spi: [0x01; 8],
            responder_spi: [0x02; 8],
            next_payload: PayloadType::Encrypted,
            exchange: ExchangeType::IkeAuth,
            flags: FLAG_RESPONSE,
            message_id,
        };
        sk_in.seal(header, &payloads, &iv)
    };

    let mut auth = IkeAuthInitiator::new(
        keys.clone(),
        [0x01; 8],
        [0x02; 8],
        vec![0x33; 32],
        vec![0x66; 32],
        b"real-message-1".to_vec(),
        b"real-message-2".to_vec(),
        identity,
        [0xDE, 0xAD, 0xBE, 0xEF],
    );
    let mut peer = AkaPrimePeer::new(network, eap.clone(), res.to_vec());

    // 1. SK{ IDi, SAi2, TSi, TSr, N(EAP_ONLY) } — encrypted, identity hidden.
    let first = auth.first_request(&iv).unwrap();
    assert!(!first.windows(4).any(|w| w == b"user"));
    let opened = sk_out.open(&first).unwrap();
    assert_eq!(opened.payloads[0].kind, PayloadType::Idi);

    // 2. Responder sends the AKA' challenge.
    let mut attributes = kdf_input_attribute(network).unwrap();
    attributes.extend_from_slice(&attribute(0x80 | AT_MAC, &[0u8; AT_MAC_LEN]));
    let mut challenge =
        EapPacket::response(7, EAP_TYPE_AKA_PRIME, Some(SUBTYPE_CHALLENGE), &attributes);
    challenge[0] = EAP_REQUEST;
    let mac_at = 4 + 2 + attribute_value_offset(&attributes, AT_MAC).unwrap();
    let mac = at_mac(&eap.k_aut, &challenge, mac_at).unwrap();
    challenge[mac_at..mac_at + AT_MAC_LEN].copy_from_slice(&mac);

    let msg = responder(
        1,
        vec![Payload {
            kind: PayloadType::Eap,
            critical: false,
            body: challenge,
        }],
    );
    let AuthStep::Send(response) = auth.on_response(&msg, &iv, &mut peer).unwrap() else {
        panic!("expected an EAP response");
    };
    let opened = sk_out.open(&response).unwrap();
    assert_eq!(
        EapPacket::parse(&opened.payloads[0].body).unwrap().code,
        2 // EAP-Response
    );

    // 3. Responder sends EAP Success; we answer with AUTH.
    let msg = responder(
        2,
        vec![Payload {
            kind: PayloadType::Eap,
            critical: false,
            body: vec![EAP_SUCCESS, 7, 0, 4],
        }],
    );
    let AuthStep::Send(our_auth_msg) = auth.on_response(&msg, &iv, &mut peer).unwrap() else {
        panic!("expected AUTH");
    };
    let opened = sk_out.open(&our_auth_msg).unwrap();
    assert_eq!(opened.payloads[0].kind, PayloadType::Auth);

    // 4. Responder sends IDr + AUTH + SAr2; the AUTH uses the EAP MSK.
    let idr = Id {
        id_type: ID_RFC822_ADDR,
        data: b"epdg.example".to_vec(),
    }
    .encode();
    let signed = signed_octets_responder(b"real-message-2", &[0x33; 32], &keys.sk_pr, &idr);
    let responder_auth = auth_payload(&peer.keys().msk, &signed);
    let msg = responder(
        3,
        vec![
            Payload {
                kind: PayloadType::Idr,
                critical: false,
                body: idr,
            },
            Payload {
                kind: PayloadType::Auth,
                critical: false,
                body: responder_auth,
            },
            Payload {
                kind: PayloadType::Sa,
                critical: false,
                body: Sa {
                    proposals: vec![Proposal {
                        number: 1,
                        protocol_id: PROTO_ESP,
                        spi: vec![0x00, 0x00, 0x20, 0x00],
                        transforms: vec![
                            Transform {
                                transform_type: TRANSFORM_ENCR,
                                id: epdg::child::ENCR_AES_CBC,
                                attributes: vec![0x80, 0x0E, 0x00, 0x80],
                            },
                            Transform {
                                transform_type: TRANSFORM_INTEG,
                                id: epdg::child::AUTH_HMAC_SHA2_256_128,
                                attributes: vec![],
                            },
                        ],
                    }],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Tsi,
                critical: false,
                body: TrafficSelectors {
                    selectors: vec![epdg::ikev2::Selector {
                        ts_type: 7,
                        ip_protocol: 0,
                        start_port: 0,
                        end_port: 0xffff,
                        start_address: vec![10, 32, 0, 7],
                        end_address: vec![10, 32, 0, 7],
                    }],
                }
                .encode(),
            },
            Payload {
                kind: PayloadType::Tsr,
                critical: false,
                body: TrafficSelectors {
                    selectors: vec![epdg::ikev2::Selector {
                        ts_type: 7,
                        ip_protocol: 0,
                        start_port: 0,
                        end_port: 0xffff,
                        start_address: vec![10, 32, 0, 0],
                        end_address: vec![10, 32, 0, 255],
                    }],
                }
                .encode(),
            },
        ],
    );
    let AuthStep::Established {
        child,
        config,
        child_keys,
    } = auth.on_response(&msg, &iv, &mut peer).unwrap()
    else {
        panic!("expected Established");
    };
    // The child SA the exchange negotiated, ready to hand to transport::ipsec.
    assert_eq!(child.outbound.spi, 0x2000);
    assert_eq!(child.inbound.spi, 0xDEADBEEF);
    assert_eq!(child.inbound.encryption.key(), &child_keys[48..64]);
    assert_eq!(child.tsr[0].start_address, vec![10, 32, 0, 0]);
    assert_eq!(child.tsr[0].end_address, vec![10, 32, 0, 255]);
    // No CFG_REPLY was sent in this exchange.
    assert!(config.is_none());
    assert_eq!(
        child_keys,
        child_keymat(&keys.sk_d, &[0x33; 32], &[0x66; 32], 128)
    );
    assert!(auth.is_established());
}

// --- EPDG-010: the Configuration payload --------------------------------

#[test]
fn epdg_010_configuration_payload_carries_the_ims_address() {
    use epdg::cp::{
        ConfigAttribute, ConfigPayload, CFG_REPLY, CFG_REQUEST, INTERNAL_IP4_ADDRESS,
        INTERNAL_IP4_DNS,
    };

    // A request carries the types with no value.
    let request = ConfigPayload::s2b_request();
    assert_eq!(request.kind, CFG_REQUEST);
    assert_eq!(request.encode(), vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0]);

    // A reply carries the address the ePDG assigned plus its DNS servers.
    let reply = ConfigPayload::reply(vec![
        ConfigAttribute::new(INTERNAL_IP4_ADDRESS, [10, 32, 0, 7]),
        ConfigAttribute::new(INTERNAL_IP4_DNS, [10, 32, 0, 1]),
        ConfigAttribute::new(INTERNAL_IP4_DNS, [10, 32, 0, 2]),
    ]);
    let decoded = ConfigPayload::decode(&reply.encode()).unwrap();
    assert_eq!(decoded.kind, CFG_REPLY);
    assert_eq!(decoded.internal_ip4_address(), Some([10, 32, 0, 7]));
    assert_eq!(
        decoded.internal_ip4_dns(),
        vec![[10, 32, 0, 1], [10, 32, 0, 2]]
    );

    // Values are padded to a 4-octet boundary; the length excludes the padding.
    let odd = ConfigPayload::reply(vec![ConfigAttribute::new(
        epdg::cp::APPLICATION_VERSION,
        b"hyphae".to_vec(),
    )]);
    let bytes = odd.encode();
    assert_eq!(bytes.len() % 4, 0);
    assert_eq!(&bytes[8..14], b"hyphae");
    assert_eq!(
        ConfigPayload::decode(&bytes).unwrap().attributes[0].text(),
        Some("hyphae")
    );
}

// --- EPDG-011: the child SA ---------------------------------------------

#[test]
fn epdg_011_child_sa_splits_keymat_per_direction() {
    use epdg::child::{ChildError, ChildSa, AUTH_HMAC_SHA2_256_128, ENCR_AES_CBC};
    use epdg::ikev2::{Proposal, Transform, TRANSFORM_ENCR, TRANSFORM_INTEG};

    // AES-CBC-128 (KEY_LENGTH 128) plus HMAC-SHA-256-128.
    let proposal = Proposal {
        number: 1,
        protocol_id: epdg::ikev2::PROTO_ESP,
        spi: vec![0x00, 0x00, 0x10, 0x00], // the responder's SPI
        transforms: vec![
            Transform {
                transform_type: TRANSFORM_ENCR,
                id: ENCR_AES_CBC,
                attributes: vec![0x80, 0x0E, 0x00, 0x80],
            },
            Transform {
                transform_type: TRANSFORM_INTEG,
                id: AUTH_HMAC_SHA2_256_128,
                attributes: vec![],
            },
        ],
    };
    let keymat: Vec<u8> = (0..96).map(|i| i as u8).collect();
    let local_spi = 0x0000_1001;

    let sa = ChildSa::from_proposal(&proposal, local_spi, &keymat, vec![], vec![]).unwrap();

    // Outbound is the responder's SPI; inbound is the one we chose.
    assert_eq!(sa.outbound.spi, 0x1000);
    assert_eq!(sa.inbound.spi, 0x1001);
    // Initiator→responder keys come first, in proposal order.
    assert_eq!(sa.outbound.encryption.key(), &keymat[0..16]);
    assert_eq!(sa.outbound.integrity.key(), &keymat[16..48]);
    assert_eq!(sa.inbound.encryption.key(), &keymat[48..64]);
    assert_eq!(sa.inbound.integrity.key(), &keymat[64..96]);
    assert_eq!(sa.outbound.encryption.xfrm_name(), "cbc(aes)");
    assert_eq!(sa.outbound.integrity.xfrm_name(), "hmac(sha256)");

    // Short key material is refused, not silently truncated.
    assert_eq!(
        ChildSa::from_proposal(&proposal, local_spi, &keymat[..95], vec![], vec![]),
        Err(ChildError::ShortKeymat { need: 96, got: 95 })
    );
}

// --- EPDG-012: installing the S2b tunnel --------------------------------

#[test]
fn epdg_012_s2b_tunnel_program_installs_both_directions() {
    use transport::ipsec::{S2bTunnel, TunnelEncryption, TunnelIntegrity, TunnelProgram, TunnelSa};

    let tunnel = S2bTunnel {
        interface: "ipsec0".into(),
        if_id: 9,
        local_addr: "192.0.2.10".into(),
        remote_addr: "192.0.2.1".into(),
        inbound: TunnelSa {
            spi: 0x2001,
            encryption: TunnelEncryption::AesCbc {
                key: vec![0xa1; 16],
            },
            integrity: TunnelIntegrity::HmacSha256_128 {
                key: vec![0xb2; 32],
            },
        },
        outbound: TunnelSa {
            spi: 0x2000,
            encryption: TunnelEncryption::AesCbc {
                key: vec![0xc3; 16],
            },
            integrity: TunnelIntegrity::HmacSha256_128 {
                key: vec![0xd4; 32],
            },
        },
        local_ts: "10.32.0.7/32".into(),
        remote_ts: "10.32.0.0/24".into(),
    };
    let rendered = TunnelProgram::build(&tunnel).render();

    // The interface is created and bound by if_id.
    assert_eq!(rendered[0], "ip link add ipsec0 type xfrm if_id 9");

    // Both SA directions are tunnel mode and carry the same if_id.
    let out = &rendered[2];
    assert!(out.contains("spi 0x2000") && out.contains("mode tunnel") && out.contains("if_id 9"));
    // The ICV must be pinned to 128 bits: bare `auth` installs 96.
    assert!(
        out.contains(&format!(
            "auth-trunc hmac(sha256) 0x{} 128",
            "d4".repeat(32)
        )),
        "{out}"
    );
    assert!(out.contains(&format!("enc cbc(aes) 0x{}", "c3".repeat(16))));
    assert!(rendered[3].contains("spi 0x2001"));

    // Policies key on the traffic selectors and carry if_id in the template.
    let policy_out = &rendered[4];
    assert!(policy_out.contains("dir out"));
    assert!(policy_out.contains("src 10.32.0.7/32 dst 10.32.0.0/24"));
    assert!(policy_out.contains("tmpl src 192.0.2.10 dst 192.0.2.1"));
    assert!(policy_out.contains("if_id 9"));
    assert!(
        !policy_out.contains("sport"),
        "S2b is not the Gm UDP profile"
    );

    // The inner address and route complete the install.
    assert_eq!(rendered[6], "ip addr add 10.32.0.7/32 dev ipsec0");
    assert_eq!(rendered[7], "ip route add 10.32.0.0/24 dev ipsec0");

    // Teardown reverses it.
    let teardown = TunnelProgram::teardown(&tunnel).render();
    assert_eq!(teardown[0], "ip route del 10.32.0.0/24 dev ipsec0");
    assert_eq!(teardown.last().unwrap(), "ip link delete ipsec0");
}

// --- EPDG-017: ePDG discovery names -------------------------------------

#[test]
fn epdg_017_discovery_fqdns_match_the_specification_examples() {
    use epdg::discovery::{
        epdg_fqdn, epdg_fqdn_5gs_tai, epdg_fqdn_lac, epdg_fqdn_tai, visited_country_fqdn, PlmnId,
    };

    // TS 23.003 uses MCC 345 / MNC 12 throughout its examples.
    let plmn = PlmnId::new("345", "12").unwrap();

    assert_eq!(
        epdg_fqdn(&plmn),
        "epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
    );
    assert_eq!(
        epdg_fqdn_tai(&plmn, 0x0B21),
        "tac-lb21.tac-hb0b.tac.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
    );
    assert_eq!(
        epdg_fqdn_lac(&plmn, 0x0B21),
        "lac0b21.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
    );
    assert_eq!(
        epdg_fqdn_5gs_tai(&plmn, 0x0B1A21),
        "tac-lb21.tac-mb1a.tac-hb0b.5gstac.epdg.epc.mnc012.mcc345.pub.3gppnetwork.org"
    );
    assert_eq!(
        visited_country_fqdn("345").unwrap(),
        "epdg.epc.mcc345.visited-country.pub.3gppnetwork.org"
    );

    // A three-digit MNC is not padded again.
    let us = PlmnId::new("310", "260").unwrap();
    assert_eq!(epdg_fqdn(&us), "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org");
}
