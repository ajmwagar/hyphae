//! The Ub exchange driven end to end against a mock BSF.
//!
//! The mock is the network: it generates a real AKA vector with Milenage from
//! the same K/OPc the USIM holds, builds the RFC 3310 nonce, checks the digest
//! the UE returns, and answers with an Annex C `BootstrappingInfo`. Nothing is
//! faked except the transport — which is the point: a digest bug shows up here
//! even though no socket is opened.

#![forbid(unsafe_code)]

use base64::Engine as _;
use gba::http::{HttpRequest, HttpResponse};
use gba::ub::{
    decode_nonce, parse_bootstrapping_info, Bootstrapped, UbClient, UbStep, GBA_USER_AGENT,
};
use gba::GbaError;
use usim::{SoftwareUsim, Usim};

const IMPI: &str = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const BSF: &str = "bsf.mnc001.mcc001.pub.3gppnetwork.org";
const K: [u8; 16] = [0x46; 16];
const OPC: [u8; 16] = [0x53; 16];
const SQN: [u8; 6] = [0, 0, 0, 0, 0, 1];

/// The network side: holds the subscriber key and knows the expected digest.
struct MockBsf {
    milenage: aka::Milenage,
    sqn: [u8; 6],
    /// The B-TID handed out on success.
    b_tid: String,
    /// The cipher/integrity keys from the vector it issued.
    ck: [u8; 16],
    ik: [u8; 16],
    /// The challenge it is currently expecting an answer to.
    challenge: Option<String>,
    challenge_nonce: Option<String>,
    authorized: bool,
    /// How many requests it has seen, so the test can assert the shape.
    pub requests: Vec<HttpRequest>,
}

impl MockBsf {
    fn new() -> Self {
        Self {
            milenage: aka::Milenage::new_with_opc(K, OPC),
            sqn: SQN,
            b_tid: "YmFzZTY0QlRJRA==".to_string(),
            ck: [0; 16],
            ik: [0; 16],
            challenge: None,
            challenge_nonce: None,
            authorized: false,
            requests: Vec::new(),
        }
    }

    fn handle(&mut self, request: &HttpRequest) -> HttpResponse {
        self.requests.push(request.clone());

        // The first request carries an empty nonce and response.
        let authorization = request.get("authorization").unwrap_or("");
        let nonce = param(authorization, "nonce").unwrap_or_default();
        let response = param(authorization, "response").unwrap_or_default();

        if nonce.is_empty() {
            // Issue a fresh vector and challenge.
            let rand = [0x11u8; 16];
            let amf = [0x80u8, 0x00];
            let vector = self.milenage.compute(&rand, &self.sqn, &amf);
            self.ck = vector.ck;
            self.ik = vector.ik;
            let autn = build_autn(&vector, &SQN, &amf);
            let mut nonce_bytes = Vec::new();
            nonce_bytes.extend_from_slice(&rand);
            nonce_bytes.extend_from_slice(&autn);
            nonce_bytes.extend_from_slice(b"srv"); // server-specific data
            let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);

            self.challenge = Some(hex(&vector.res));
            self.challenge_nonce = Some(nonce_b64.clone());
            return HttpResponse::new(401).header(
                "WWW-Authenticate",
                format!(
                    "Digest realm=\"{BSF}\", nonce=\"{nonce_b64}\", qop=auth-int, algorithm=AKAv1-MD5"
                ),
            );
        }

        // Verify the digest the UE computed. This is the assertion that matters:
        // if our `auth-int` HA2 were wrong, the value would not match.
        let expected = aka::digest::digest_response(&aka::digest::DigestInput {
            impi: IMPI,
            realm: BSF,
            res: &hex_decode(self.challenge.as_deref().unwrap()),
            method: "GET",
            digest_uri: "/",
            nonce: &nonce,
            nc: "00000001",
            cnonce: &param(authorization, "cnonce").unwrap_or_default(),
            qop: Some("auth-int"),
            entity_body: Some(b""),
        });
        if response != expected {
            return HttpResponse::new(401).header("WWW-Authenticate", "Digest realm=\"BSF\"");
        }

        self.authorized = true;
        HttpResponse::new(200)
            .header("Content-Type", "application/vnd.3gpp.bsf+xml")
            .body(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <BootstrappingInfo xmlns=\"uri:3gpp-gba\">\n\
                 <btid>{}</btid>\n\
                 <lifetime>2030-01-01T00:00:00Z</lifetime>\n\
                 <Extension><currenttime>2026-01-01T00:00:00Z</currenttime></Extension>\n\
                 </BootstrappingInfo>\n",
                self.b_tid
            ))
    }
}

/// AUTN = (SQN xor AK) ‖ AMF ‖ MAC-A (TS 33.102 §6.3.3).
fn build_autn(vector: &aka::MilenageOutputs, sqn: &[u8; 6], amf: &[u8; 2]) -> [u8; 16] {
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn[i] ^ vector.ak[i];
    }
    autn[6..8].copy_from_slice(amf);
    autn[8..].copy_from_slice(&vector.mac_a);
    autn
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Extract a `key="value"` directive from a header value.
fn param(header: &str, name: &str) -> Option<String> {
    for part in header.split(',') {
        let (key, value) = part.split_once('=')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

#[test]
fn the_ub_exchange_yields_a_ks_and_a_b_tid() {
    let mut bsf = MockBsf::new();
    let expected_ks = {
        // The UE and the BSF must land on the same Ks.
        let mut usim = SoftwareUsim::with_opc(K, OPC, SQN);
        let rand = [0x11u8; 16];
        let amf = [0x80u8, 0x00];
        let vector = aka::Milenage::new_with_opc(K, OPC).compute(&rand, &SQN, &amf);
        let autn = build_autn(&vector, &SQN, &amf);
        match usim.authenticate(&rand, &autn).unwrap() {
            usim::AkaOutput::Success { ck, ik, .. } => {
                let mut ks = [0u8; 32];
                ks[..16].copy_from_slice(&ck);
                ks[16..].copy_from_slice(&ik);
                ks
            }
            other => panic!("unexpected {other:?}"),
        }
    };

    let mut usim = SoftwareUsim::with_opc(K, OPC, SQN);
    let mut client = UbClient::new(IMPI, BSF, "0a4f113b", &mut usim);

    // 1. The first request: empty nonce and response (TS 24.109 §4.2 a).
    let start = client.start();
    assert_eq!(start.method, "GET");
    assert_eq!(start.uri, format!("http://{BSF}/"));
    assert_eq!(start.get("user-agent"), Some(GBA_USER_AGENT));
    let auth = start.get("authorization").unwrap();
    assert!(auth.contains(&format!("username=\"{IMPI}\"")));
    assert!(auth.contains(&format!("realm=\"{BSF}\"")));
    assert!(auth.contains("nonce=\"\""));
    assert!(auth.contains("response=\"\""));

    // 2. The BSF challenges; the UE runs AKA and answers in one step.
    let challenge = bsf.handle(&start);
    assert_eq!(challenge.status, 401);
    let step = client.on_response(&challenge).unwrap();
    let UbStep::Send(answer) = step else {
        panic!("expected a retry after 401");
    };
    let auth = answer.get("authorization").unwrap();
    assert!(auth.contains("qop=auth-int"));
    assert!(auth.contains("algorithm=AKAv1-MD5"));
    assert!(!auth.contains("response=\"\""));

    // The nonce really was base64(RAND ‖ AUTN ‖ server data).
    let nonce = param(auth, "nonce").unwrap();
    let decoded = decode_nonce(&nonce).unwrap();
    assert_eq!(decoded.rand, [0x11u8; 16]);
    assert_eq!(decoded.server_data, b"srv");

    // 3. The BSF verifies the digest and hands out the association.
    let ok = bsf.handle(&answer);
    assert_eq!(ok.status, 200);
    let step = client.on_response(&ok).unwrap();
    let UbStep::Done(Bootstrapped {
        ks,
        b_tid,
        lifetime,
    }) = step
    else {
        panic!("expected the association");
    };
    assert_eq!(ks, expected_ks, "UE and BSF must agree on Ks");
    assert_eq!(b_tid, bsf.b_tid);
    assert_eq!(lifetime, "2030-01-01T00:00:00Z");
    assert!(bsf.authorized);
}

#[test]
fn the_ks_feeds_the_naf_key_derivation() {
    // The point of Ub is that it produces the input GBA-002 needs.
    let ks = [0xABu8; 32];
    let rand = [0x11u8; 16];
    let naf_id = b"entitlement.example.com\x01\x00\x00\x00";
    let key = gba::ks_naf(&ks, &rand, IMPI, naf_id).unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn a_wrong_response_is_challenged_again() {
    let mut bsf = MockBsf::new();
    let mut usim = SoftwareUsim::with_opc(K, OPC, SQN);
    let mut client = UbClient::new(IMPI, BSF, "0a4f113b", &mut usim);

    let challenge = bsf.handle(&client.start());
    assert_eq!(challenge.status, 401);
    // Replay the challenge with a digest computed over the wrong RES: the BSF
    // must not accept it.
    let mut forged = HttpResponse::new(200); // wrong status on purpose
    forged.status = 401;
    let step = client.on_response(&challenge).unwrap();
    let UbStep::Send(answer) = step else { panic!() };
    let mut tampered = answer.clone();
    tampered.headers = tampered
        .headers
        .iter()
        .map(|(n, v)| {
            if n.eq_ignore_ascii_case("authorization") {
                (n.clone(), v.replace("response=\"", "response=\"00"))
            } else {
                (n.clone(), v.clone())
            }
        })
        .collect();
    assert_eq!(bsf.handle(&tampered).status, 401);
    assert!(!bsf.authorized);
}

#[test]
fn an_unreadable_bootstrapping_info_is_an_error() {
    assert!(parse_bootstrapping_info("<BootstrappingInfo></BootstrappingInfo>").is_none());
    assert!(parse_bootstrapping_info("not xml").is_none());
    let ok = parse_bootstrapping_info(
        "<BootstrappingInfo xmlns=\"uri:3gpp-gba\"><btid>abc</btid><lifetime>2030-01-01T00:00:00Z</lifetime></BootstrappingInfo>",
    )
    .unwrap();
    assert_eq!(ok.b_tid, "abc");
    assert_eq!(ok.current_time, None);
}

#[test]
fn a_short_nonce_is_refused() {
    let short = base64::engine::general_purpose::STANDARD.encode([0u8; 20]);
    assert!(matches!(decode_nonce(&short), Err(GbaError::Ub(_))));
    assert!(decode_nonce("not base64!!").is_err());
}
