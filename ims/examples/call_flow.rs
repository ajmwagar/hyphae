//! Print the IMS call-establishment ladder (INVITE/183/PRACK/200/ACK) without a
//! socket, driving the caller state machine against an in-memory mock server.
//!
//! Run: `cargo run -p ims --example call_flow`
//!
//! The mock server here is a stand-in for the P-CSCF/S-CSCF + callee. A real
//! client sends the same messages through a transport adapter.

use ims::{Call, CallEvent, CallState, ImsProfile, Sdp};
use sip::{Header, Headers, Message, Response};
use std::time::Duration;
use transport::{MockTransport, Transport};

fn dump(label: &str, message: &Message) {
    println!("== {label} ==");
    print!("{message}");
}

fn resp(status: u16, reason: &str, cseq: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
    let mut headers = Headers::new();
    headers.push(Header::new("CSeq", cseq.to_string()));
    for &(k, v) in extra {
        headers.push(Header::new(k, v));
    }
    Response {
        status,
        reason: reason.into(),
        headers,
        body: body.to_vec(),
    }
}

fn main() {
    let (mut client, mut server) = MockTransport::pair();
    let mut call = Call::new(
        ImsProfile::lab_default(),
        "sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org",
    );
    let timeout = Duration::from_millis(200);

    // 1. INVITE with an AMR-WB offer goes onto the wire.
    let CallEvent::Send(invite) = call.invite() else {
        panic!("expected INVITE");
    };
    let invite_cseq = invite.headers.cseq().unwrap().seq;
    let invite_msg = Message::Request(invite.clone());
    client.send(&invite_msg).unwrap();
    dump("1. client -> server: INVITE (AMR-WB offer)", &invite_msg);

    // The mock server answers the INVITE with a reliable 183 carrying the answer.
    let Message::Request(got) = server.recv(timeout).unwrap().unwrap() else {
        panic!("server did not receive the INVITE");
    };
    let offer = Sdp::parse(core::str::from_utf8(&got.body).unwrap()).unwrap();
    let answer = Sdp::answer_amr_wb(&offer, "192.0.2.11").unwrap();
    let answer_bytes = answer.to_text().into_bytes();
    let cseq_invite = format!("{invite_cseq} INVITE");
    let cseq_prack = format!("{} PRACK", invite_cseq + 1);
    let progress = resp(
        183,
        "Session Progress",
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
    );
    dump(
        "2. server -> client: 183 Session Progress (reliable)",
        &Message::Response(progress.clone()),
    );

    // 100 Trying needs no action; the 183 is PRACKed.
    let _ = call.on_response(&resp(100, "Trying", &cseq_invite, &[], &[]));
    let CallEvent::Send(prack) = call.on_response(&progress) else {
        panic!("expected PRACK");
    };
    let prack_msg = Message::Request(prack.clone());
    client.send(&prack_msg).unwrap();
    dump("3. client -> server: PRACK (RAck)", &prack_msg);

    // 4. 200 OK to PRACK, then 200 OK to INVITE.
    server
        .send(&Message::Response(resp(200, "OK", &cseq_prack, &[], &[])))
        .unwrap();
    let invite_ok = resp(200, "OK", &cseq_invite, &[], &[]);
    dump(
        "4. server -> client: 200 OK (to PRACK, then to INVITE)",
        &Message::Response(invite_ok.clone()),
    );
    server.send(&Message::Response(invite_ok)).unwrap();

    let _ = call.on_response(&resp(200, "OK", &cseq_prack, &[], &[]));
    let CallEvent::Established { ack, .. } =
        call.on_response(&resp(200, "OK", &cseq_invite, &[], &[]))
    else {
        panic!("expected the call to be established");
    };

    // 5. ACK completes the handshake.
    let ack_msg = Message::Request(ack.clone());
    client.send(&ack_msg).unwrap();
    dump("5. client -> server: ACK", &ack_msg);
    println!(
        "call state: {:?}; established = {}",
        call.state(),
        call.is_established()
    );
    assert_eq!(call.state(), CallState::Established);

    // 6. Release the session.
    let bye = call.bye().expect("BYE on an established call");
    dump("6. client -> server: BYE", &Message::Request(bye));
    println!("call state: {:?}", call.state());
}
