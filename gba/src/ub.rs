//! The Ub reference point: the UE asking a BSF for a `Ks` (TS 24.109 §4).
//!
//! Ub is HTTP Digest over AKA — the same RFC 3310 mechanism IMS registration
//! uses, with three differences that matter (TS 24.109 §4.2):
//!
//! * `qop` **shall be `auth-int`**, so the digest folds in a hash of the entity
//!   body rather than just the method and URI;
//! * `username` is the IMPI (or the TMPI, which this crate does not do);
//! * the challenge `nonce` is RFC 3310's AKA nonce:
//!   `base64(RAND ‖ AUTN ‖ server data)`, which the USIM consumes directly.
//!
//! The flow is a small state machine because it must be: the UE sends a
//! request with an empty `nonce` and `response`, the BSF answers `401` with the
//! AKA challenge, the UE runs `AUTHENTICATE` and retries, and the BSF answers
//! `200` with a `BootstrappingInfo` document carrying the B-TID and the key
//! lifetime (Annex C).
//!
//! Nothing here performs I/O: the caller passes an [`HttpChannel`] and a
//! [`Usim`], so the whole exchange can be driven against a mock BSF with real
//! Milenage vectors.

#![forbid(unsafe_code)]

use base64::Engine as _;

use usim::{Autn, Rand, Usim};

use crate::http::{HttpRequest, HttpResponse};
use crate::GbaError;

/// The `User-Agent` product token that marks this as a GBA client.
pub const GBA_USER_AGENT: &str = "3gpp-gba";

/// A bootstrapped security association (TS 33.220 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    /// `Ks = CK ‖ IK`, the key everything else is derived from.
    pub ks: [u8; 32],
    /// The B-TID, which the NAF is given in place of an identity.
    pub b_tid: String,
    /// The key lifetime, as the `xs:dateTime` string the BSF sent.
    pub lifetime: String,
}

/// The next thing to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UbStep {
    /// Send this request and feed the response back to
    /// [`UbClient::on_response`].
    Send(HttpRequest),
    /// The security association is established.
    Done(Bootstrapped),
}

/// The AKA challenge pulled out of a `401`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Challenge {
    realm: String,
    nonce: String,
    qop: String,
    algorithm: String,
}

/// The UE side of the Ub exchange.
pub struct UbClient<'a> {
    impi: String,
    bsf: String,
    cnonce: String,
    usim: &'a mut dyn Usim,
    challenge: Option<Challenge>,
    /// `CK ‖ IK` from the successful AKA run, held until the `200` arrives.
    ck_ik: Option<[u8; 32]>,
    rounds: u8,
}

/// The BSF may challenge again after a wrong response; TS 24.109 §4.3 leaves the
/// count to local policy, so this is our limit rather than a protocol constant.
const MAX_ROUNDS: u8 = 3;

impl<'a> UbClient<'a> {
    /// A client for `impi` talking to the BSF named `bsf`.
    ///
    /// `cnonce` is supplied by the caller because this tree has no RNG by
    /// design; it should be unique per bootstrapping run.
    pub fn new(
        impi: impl Into<String>,
        bsf: impl Into<String>,
        cnonce: impl Into<String>,
        usim: &'a mut dyn Usim,
    ) -> Self {
        Self {
            impi: impi.into(),
            bsf: bsf.into(),
            cnonce: cnonce.into(),
            usim,
            challenge: None,
            ck_ik: None,
            rounds: 0,
        }
    }

    /// The first request: `username`/`realm` set, `nonce` and `response` empty
    /// (TS 24.109 §4.2 a).
    pub fn start(&self) -> HttpRequest {
        self.request_with(&format!(
            "Digest username=\"{}\", realm=\"{}\", uri=\"/\", nonce=\"\", response=\"\"",
            self.impi, self.bsf
        ))
    }

    /// Handle the BSF's answer.
    pub fn on_response(&mut self, response: &HttpResponse) -> Result<UbStep, GbaError> {
        match response.status {
            401 => {
                self.rounds += 1;
                if self.rounds > MAX_ROUNDS {
                    return Err(GbaError::Ub("the BSF kept challenging".into()));
                }
                let challenge = parse_challenge(response)?;
                let nonce = decode_nonce(&challenge.nonce)?;
                let rand: Rand = nonce.rand;
                let autn: Autn = nonce.autn;
                let output = self
                    .usim
                    .authenticate(&rand, &autn)
                    .map_err(|e| GbaError::Usim(e.to_string()))?;

                match output {
                    usim::AkaOutput::Success { res, ck, ik } => {
                        let mut ks = [0u8; 32];
                        ks[..16].copy_from_slice(&ck);
                        ks[16..].copy_from_slice(&ik);
                        self.ck_ik = Some(ks);
                        let response = crate::digest(
                            &self.impi,
                            &challenge.realm,
                            &res,
                            "GET",
                            "/",
                            &challenge.nonce,
                            &self.cnonce,
                            &challenge.qop,
                            &[],
                        );
                        self.challenge = Some(challenge.clone());
                        Ok(UbStep::Send(
                            self.authorization(&challenge, &response, None),
                        ))
                    }
                    // RFC 3310 §3.4: the response uses an empty password, and
                    // the AUTS goes back so the network can resynchronise.
                    usim::AkaOutput::SyncFailure { auts } => {
                        let response = crate::digest(
                            &self.impi,
                            &challenge.realm,
                            b"",
                            "GET",
                            "/",
                            &challenge.nonce,
                            &self.cnonce,
                            &challenge.qop,
                            &[],
                        );
                        self.challenge = Some(challenge.clone());
                        Ok(UbStep::Send(self.authorization(
                            &challenge,
                            &response,
                            Some(&auts),
                        )))
                    }
                }
            }
            200 => {
                let ks = self
                    .ck_ik
                    .ok_or_else(|| GbaError::Ub("200 without a challenge first".into()))?;
                let text = response
                    .body_text()
                    .ok_or_else(|| GbaError::Ub("BootstrappingInfo is not UTF-8".into()))?;
                let info = parse_bootstrapping_info(text)
                    .ok_or_else(|| GbaError::Ub("no BootstrappingInfo in the response".into()))?;
                Ok(UbStep::Done(Bootstrapped {
                    ks,
                    b_tid: info.b_tid,
                    lifetime: info.lifetime,
                }))
            }
            other => Err(GbaError::Ub(format!("BSF answered {other}"))),
        }
    }

    fn authorization(
        &self,
        challenge: &Challenge,
        response: &str,
        auts: Option<&[u8; 14]>,
    ) -> HttpRequest {
        let mut value = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"/\", response=\"{response}\", algorithm={}, qop={}, nc=00000001, cnonce=\"{}\"",
            self.impi, challenge.realm, challenge.nonce, challenge.algorithm, challenge.qop, self.cnonce
        );
        if let Some(auts) = auts {
            value.push_str(&format!(
                ", auts=\"{}\"",
                base64::engine::general_purpose::STANDARD.encode(auts)
            ));
        }
        self.request_with(&value)
    }

    fn request_with(&self, authorization: &str) -> HttpRequest {
        HttpRequest::new("GET", format!("http://{}/", self.bsf))
            .header("User-Agent", GBA_USER_AGENT)
            .header("Authorization", authorization)
    }
}

/// A decoded RFC 3310 AKA nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaNonce {
    /// The RAND, first 16 octets.
    pub rand: Rand,
    /// The AUTN, next 16 octets.
    pub autn: Autn,
    /// Any server-specific data after them, which is passed through untouched.
    pub server_data: Vec<u8>,
}

/// Split an RFC 3310 nonce: `base64(RAND ‖ AUTN ‖ server data)` (§3.2).
pub fn decode_nonce(nonce: &str) -> Result<AkaNonce, GbaError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(nonce)
        .map_err(|e| GbaError::Ub(format!("nonce is not base64: {e}")))?;
    if decoded.len() < 32 {
        return Err(GbaError::Ub(format!(
            "nonce is {} octets, need at least 32 for RAND and AUTN",
            decoded.len()
        )));
    }
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&decoded[..16]);
    let mut autn = [0u8; 16];
    autn.copy_from_slice(&decoded[16..32]);
    Ok(AkaNonce {
        rand,
        autn,
        server_data: decoded[32..].to_vec(),
    })
}

fn parse_challenge(response: &HttpResponse) -> Result<Challenge, GbaError> {
    let header = response
        .get_all("www-authenticate")
        .into_iter()
        .find(|v| v.trim_start().to_ascii_lowercase().starts_with("digest"))
        .ok_or_else(|| GbaError::Ub("401 without a Digest challenge".into()))?;
    let value = header.trim_start()[6..].trim();

    let param = |name: &str| -> Option<String> {
        for part in value.split(',') {
            let (key, val) = part.split_once('=')?;
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(val.trim().trim_matches('"').to_string());
            }
        }
        None
    };

    Ok(Challenge {
        realm: param("realm").ok_or_else(|| GbaError::Ub("challenge without realm".into()))?,
        nonce: param("nonce").ok_or_else(|| GbaError::Ub("challenge without nonce".into()))?,
        qop: param("qop").unwrap_or_else(|| "auth-int".to_string()),
        algorithm: param("algorithm").unwrap_or_else(|| "AKAv1-MD5".to_string()),
    })
}

/// A parsed `BootstrappingInfo` document (TS 24.109 Annex C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrappingInfo {
    /// The B-TID.
    pub b_tid: String,
    /// The key lifetime as an `xs:dateTime` string.
    pub lifetime: String,
    /// The server's current time, when it sent one.
    pub current_time: Option<String>,
}

/// Parse the Annex C document.
///
/// The schema is `uri:3gpp-gba` with a `BootstrappingInfo` root holding `btid`,
/// `lifetime` and an optional `Extension`. Like the other small XML bodies in
/// this tree, this is a strict extractor rather than a general parser: the
/// document tells us how long a key lives, so an unreadable one has to fail.
pub fn parse_bootstrapping_info(body: &str) -> Option<BootstrappingInfo> {
    if !body.contains("BootstrappingInfo") {
        return None;
    }
    let b_tid = text_of(body, "btid")?;
    let lifetime = text_of(body, "lifetime")?;
    Some(BootstrappingInfo {
        b_tid,
        lifetime,
        current_time: text_of(body, "currenttime"),
    })
}

fn text_of(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let start = body.find(&open)?;
    let after = start + open.len();
    let gt = body[after..].find('>')? + after + 1;
    let end = body[gt..].find(&close)? + gt;
    let text = body.get(gt..end)?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}
