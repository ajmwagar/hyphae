//! Print the IMS REGISTER ladder without opening a socket.
//!
//! Run: `cargo run -p ims --example register_flow`
//!
//! Replace the simulated 401 with a real challenge and the fixed RES with the
//! USIM/AKA output to use this against the lab once a transport adapter exists.

use ims::{ImsProfile, Registration, RegistrationEvent};
use sip::{Header, Headers, Message, Response};

fn main() {
    let profile = ImsProfile::lab_default();
    let mut reg = Registration::new(profile);

    println!("== 1. initial REGISTER (Security-Client, no credentials) ==");
    let first = reg.register_request();
    print!("{}", Message::Request(first).to_text());

    let mut headers = Headers::new();
    headers.push(Header::new("Call-ID", reg.call_id()));
    headers.push(Header::new(
        "WWW-Authenticate",
        "Digest realm=\"ims.mnc001.mcc001.3gppnetwork.org\", nonce=\"bm9uY2U=\", algorithm=AKAv1-MD5, qop=\"auth\"",
    ));
    let challenge = Response {
        status: 401,
        reason: "Unauthorized".into(),
        headers,
        body: Vec::new(),
    };

    println!("== 2. 401 challenge ==");
    print!("{}", Message::Response(challenge.clone()).to_text());

    let RegistrationEvent::Challenge(c) = reg.on_response(&challenge) else {
        panic!("expected challenge");
    };

    // Public 3GPP TS 35.208 test-set RES. A real client receives this from the
    // USIM/ISIM AKA command, never from a constant.
    let res = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];
    let second = reg.authorize(&c, &res, "0a4f113b");

    println!("== 3. challenged REGISTER (Authorization) ==");
    print!("{}", Message::Request(second).to_text());

    println!("== 4. expected 200 OK ==");
    println!("SIP/2.0 200 OK");
    println!("Service-Route: <sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>");
    println!("P-Associated-URI: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>");
    println!("Content-Length: 0");
    println!();
    println!("State after a real 200 OK would be Registered; send this through a");
    println!("transport adapter, not through this example.");
}
