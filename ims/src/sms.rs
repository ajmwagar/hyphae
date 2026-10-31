//! SMS over IMS (REG-001 sibling): a SIP `MESSAGE` carrying RP-DATA over CP.
//!
//! Spec references: 3GPP TS 24.341 (SMS over IP), GSMA IR.92 §5, and the GSM
//! 03.40 PDU it wraps (TS 23.038 7-bit packing). This is a deliberately small,
//! host-side implementation: it builds the RP-DATA wrapper around a GSM 03.40
//! `SMS-SUBMIT` PDU and the SIP `MESSAGE` request the UE sends to the IP-SM-GW.
//! It does not implement the full CP state machine or an SMSC submission path —
//! the wire shape and the PDU round-trip are what the conformance row checks.
//!
//! ## Unsafe policy
//!
//! Pure Rust, no FFI: `#![forbid(unsafe_code)]` is inherited from the crate.

#![forbid(unsafe_code)]

use sip::{Header, Headers, Method, Request};

/// A GSM 03.40 `SMS-SUBMIT` PDU (the MO direction the UE sends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsSubmit {
    /// Service centre number (semi-octet encoded, no leading `+`).
    pub service_center: String,
    /// Destination (called) number.
    pub destination: String,
    /// TP-Protocol-Identifier.
    pub pid: u8,
    /// TP-Data-coding/message class. `0x00` = GSM 7-bit default alphabet.
    pub dcs: u8,
    /// User data (the text). Limited to 160 GSM 7-bit characters.
    pub text: String,
}

impl SmsSubmit {
    /// Encode the mandatory GSM 03.40 fields into the PDU octets.
    ///
    /// Layout: TP-MTI (0x01 SMS-SUBMIT) · TP-DA · TP-PID · TP-DCS · TP-ML ·
    /// TP-UD. The service centre and destination use semi-octet, reversed
    /// digit pairs with a type-of-address prefix.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.text.len());
        // TP-MTI: SMS-SUBMIT (0x01), no batch.
        out.push(0x01);
        // Service centre: type-of-address + length + semi-octet digits.
        encode_bcd_address(&self.service_center, &mut out);
        // Destination: type-of-address + length + semi-octet digits.
        encode_bcd_address(&self.destination, &mut out);
        out.push(self.pid);
        out.push(self.dcs);
        let len = self.text.chars().count().min(160);
        out.push(len as u8);
        out.extend_from_slice(&pack_7bit(&self.text));
        out
    }
}

/// Encode a phone number as GSM semi-octet digits (reversed pairs) preceded by
/// the type-of-address octet. International numbers carry the `0x80` bit.
fn encode_bcd_address(number: &str, out: &mut Vec<u8>) {
    let digits: Vec<u8> = number
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    let has_intl = number.starts_with('+');
    // Type-of-address: bit 7 set, bit 6 = 0 for international, 1 for national.
    out.push(if has_intl { 0x81 } else { 0x80 });
    out.push(digits.len() as u8);
    let mut i = 0;
    while i < digits.len() {
        let lo = digits[i];
        let hi = if i + 1 < digits.len() {
            digits[i + 1]
        } else {
            0x0f
        };
        out.push((lo & 0x0f) | ((hi & 0x0f) << 4));
        i += 2;
    }
}

/// Pack GSM 7-bit characters into octets per TS 23.038 §5.2.
///
/// Character `i`'s bit `j` (LSB first) lands at stream bit `i*7 + j`; stream
/// bit `p` maps to octet `p/8`, bit `p%8`.
pub fn pack_7bit(text: &str) -> Vec<u8> {
    let n = text.chars().count().min(160);
    let bytes = (7 * n).div_ceil(8);
    let mut out = vec![0u8; bytes];
    for (i, ch) in text.chars().take(n).enumerate() {
        let c = (ch as u32) & 0x7f;
        for j in 0..7 {
            let bit = (c >> j) & 1;
            let p = i * 7 + j;
            out[p / 8] |= (bit as u8) << (p % 8);
        }
    }
    out
}

/// Unpack GSM 7-bit octets back into characters (inverse of [`pack_7bit`]).
pub fn unpack_7bit(bytes: &[u8], count: usize) -> String {
    let mut s = String::with_capacity(count);
    for i in 0..count {
        let mut c = 0u32;
        for j in 0..7 {
            let p = i * 7 + j;
            let bit = (bytes[p / 8] >> (p % 8)) & 1;
            c |= (bit as u32) << j;
        }
        s.push(char::from((c & 0x7f) as u8));
    }
    s
}

/// Decode the GSM 03.40 `SMS-SUBMIT` PDU back into a [`SmsSubmit`]. Used by the
/// conformance round-trip; real receivers also walk the CP layer.
pub fn decode_submit(pdu: &[u8]) -> Option<SmsSubmit> {
    let mut d = Decoder { buf: pdu, pos: 0 };
    if d.u8()? != 0x01 {
        return None; // not an SMS-SUBMIT
    }
    let service_center = read_bcd_address(&mut d)?;
    let destination = read_bcd_address(&mut d)?;
    let pid = d.u8()?;
    let dcs = d.u8()?;
    let len = d.u8()? as usize;
    let text = unpack_7bit(&d.buf[d.pos..], len);
    Some(SmsSubmit {
        service_center,
        destination,
        pid,
        dcs,
        text,
    })
}

fn read_bcd_address(d: &mut Decoder) -> Option<String> {
    let _ty = d.u8()?;
    let len = d.u8()? as usize; // number of digits (semi-octets)
    let octets = len.div_ceil(2); // GSM counts digits, the wire carries octets
    let mut digits = Vec::with_capacity(len);
    for _ in 0..octets {
        let oct = d.u8()?;
        digits.push(oct & 0x0f);
        let hi = (oct >> 4) & 0x0f;
        if hi != 0x0f {
            digits.push(hi);
        }
    }
    digits.truncate(len);
    let s: String = digits.into_iter().map(|n| (b'0' + n) as char).collect();
    Some(s)
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
}

/// The UE-side SMS transaction: owns Call-ID/CSeq/branch state and builds one
/// SIP `MESSAGE` per RP-DATA unit.
///
/// A fresh sender is one SMS session; real deployments may reuse it across a
/// CP dialogue. It deliberately does not model the CP retransmission timers.
pub struct SmsSender {
    call_id: String,
    cseq: u32,
    branch_counter: u32,
    from_tag: String,
}

impl SmsSender {
    pub fn new(public_identity: &str, contact_host: &str, contact_port: u16) -> Self {
        Self {
            call_id: format!("fungos-sms-{}@{}", public_identity, contact_host),
            cseq: 0,
            branch_counter: 0,
            from_tag: format!("fungos-sms-{}", contact_port),
        }
    }

    /// Build the next SIP `MESSAGE` carrying RP-DATA over CP.
    pub fn message(
        &mut self,
        profile: &crate::profile::ImsProfile,
        request_uri: &str,
        submit: &SmsSubmit,
    ) -> Request {
        self.cseq += 1;
        self.branch_counter += 1;
        let branch = format!("z9hG4bK-fungos-{}-{}", self.cseq, self.branch_counter);

        // RP-DATA: RP-SM-Data preceded by Address-of-MS (the sender), RP-SSR
        // and RP-cause. Address-of-MS is semi-octet with a type prefix.
        let sender = profile
            .public_identity
            .strip_prefix("sip:")
            .unwrap_or(&profile.public_identity)
            .split('@')
            .next()
            .unwrap_or("");
        let mut pdu = submit.encode();
        let mut body = Vec::with_capacity(pdu.len() + 8);
        encode_bcd_address(sender, &mut body);
        body.push(0x00); // RP-SSR
        body.push(0x00); // RP-cause: success
        body.append(&mut pdu);

        let mut headers = Headers::new();
        headers.push(Header::new(
            "Via",
            format!(
                "SIP/2.0/{} {}:{};branch={};rport",
                profile.transport, profile.contact_host, profile.contact_port, branch
            ),
        ));
        headers.push(Header::new("Max-Forwards", "70"));
        headers.push(Header::new(
            "From",
            format!("<{}>;tag={}", profile.public_identity, self.from_tag),
        ));
        headers.push(Header::new("To", format!("<sip:{}>", request_uri)));
        headers.push(Header::new("Call-ID", self.call_id.clone()));
        headers.push(Header::new("CSeq", format!("{} MESSAGE", self.cseq)));
        headers.push(Header::new("User-Agent", profile.user_agent.clone()));
        headers.push(Header::new("Content-Type", "application/vnd.3gpp.sms"));
        headers.push(Header::new("Content-Length", body.len().to_string()));
        Request {
            method: Method::Message,
            uri: request_uri.to_string(),
            headers,
            body,
        }
    }
}

/// Build the SIP `MESSAGE` request the UE sends to the IP-SM-GW in a one-shot
/// sender (convenience for callers that do not keep an [`SmsSender`]).
pub fn message_request(
    profile: &crate::profile::ImsProfile,
    request_uri: &str,
    submit: &SmsSubmit,
) -> Request {
    let mut sender = SmsSender::new(
        &profile.public_identity,
        &profile.contact_host,
        profile.contact_port,
    );
    sender.message(profile, request_uri, submit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_round_trips_destination_and_text() {
        let submit = SmsSubmit {
            service_center: "15551000000".into(),
            destination: "15552000000".into(),
            pid: 0,
            dcs: 0,
            text: "Hello IMS".into(),
        };
        let pdu = submit.encode();
        let decoded = decode_submit(&pdu).expect("decode");
        assert_eq!(decoded.destination, "15552000000");
        assert_eq!(decoded.service_center, "15551000000");
        assert_eq!(decoded.text, "Hello IMS");
        assert_eq!(decoded.pid, 0);
        assert_eq!(decoded.dcs, 0);
    }

    #[test]
    fn seven_bit_packing_matches_ts23038() {
        // "abc" packs to 0x61 0xF1 0x18 with the standard LSB-first algorithm:
        // octet 0 holds 'a' in bits 0..6 and 'b' in bit 7, and so on.
        assert_eq!(pack_7bit("abc"), vec![0x61, 0xF1, 0x18]);
        assert_eq!(unpack_7bit(&[0x61, 0xF1, 0x18], 3), "abc");
    }

    #[test]
    fn message_request_carries_sms_content_type_and_pdu() {
        let profile = crate::profile::ImsProfile::lab_default();
        let submit = SmsSubmit {
            service_center: "15551000000".into(),
            destination: "15552000000".into(),
            pid: 0,
            dcs: 0,
            text: "ping".into(),
        };
        let pdu = submit.encode();
        let req = message_request(
            &profile,
            "sip:ip-sm-gw@ims.mnc001.mcc001.3gppnetwork.org",
            &submit,
        );
        assert_eq!(req.method, Method::Message);
        assert_eq!(
            req.headers.get("content-type"),
            Some("application/vnd.3gpp.sms")
        );
        assert_eq!(
            req.headers.get("content-length"),
            Some(req.body.len().to_string().as_str())
        );
        // RP-DATA = Address-of-MS + RP-SSR + RP-cause + GSM 03.40 PDU; the PDU
        // is the tail and must decode back to the text.
        assert!(req.body.ends_with(&pdu));
        assert_eq!(decode_submit(&pdu).unwrap().text, "ping");
    }

    #[test]
    fn sms_sender_increments_cseq_and_call_id() {
        let profile = crate::profile::ImsProfile::lab_default();
        let mut tx = SmsSender::new(&profile.public_identity, &profile.contact_host, 5060);
        let submit = SmsSubmit {
            service_center: "15551000000".into(),
            destination: "15552000000".into(),
            pid: 0,
            dcs: 0,
            text: "one".into(),
        };
        let first = tx.message(
            &profile,
            "sip:ip-sm-gw@ims.mnc001.mcc001.3gppnetwork.org",
            &submit,
        );
        let second = tx.message(
            &profile,
            "sip:ip-sm-gw@ims.mnc001.mcc001.3gppnetwork.org",
            &submit,
        );
        assert_eq!(first.headers.cseq().unwrap().seq, 1);
        assert_eq!(second.headers.cseq().unwrap().seq, 2);
        assert_eq!(first.headers.get("call-id"), second.headers.get("call-id"));
        assert_ne!(
            first.headers.get("via").unwrap(),
            second.headers.get("via").unwrap()
        );
    }
}
