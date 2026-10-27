//! Milenage (3GPP TS 35.206) over USIM-provided K/OP, and the RFC 3310
//! IMS-AKA digest response.
//!
//! The USIM is the root of trust. On a Linux phone the modem exposes AKA
//! through QMI/AT (or a USIM reader); this crate takes the already-derived
//! `RAND`/`AUTN` and the subscriber key `K` and computes the network-side
//! vectors. No secrets are logged.

#![forbid(unsafe_code)]

mod aes;

pub use aes::encrypt_block;

/// 128-bit subscriber key K.
pub type Key = [u8; 16];
/// 128-bit operator constant OP (or the derived OPc).
pub type Operator = [u8; 16];
/// 48-bit sequence number SQN.
pub type Sqn = [u8; 6];
/// 16-bit authentication management field AMF.
pub type Amf = [u8; 2];
/// 128-bit random challenge RAND.
pub type Rand = [u8; 16];

/// Outputs of the Milenage function set (TS 35.206 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilenageOutputs {
    /// f1: network authentication code MAC-A (64 bits).
    pub mac_a: [u8; 8],
    /// f2: response RES (64 bits).
    pub res: [u8; 8],
    /// f3: cipher key CK (128 bits).
    pub ck: [u8; 16],
    /// f4: integrity key IK (128 bits).
    pub ik: [u8; 16],
    /// f5: anonymity key AK (48 bits).
    pub ak: [u8; 6],
}

/// Milenage instance bound to one subscriber key and operator constant.
#[derive(Debug, Clone, Copy)]
pub struct Milenage {
    k: Key,
    opc: Operator,
}

impl Milenage {
    /// Build from K and OP, deriving OPc = E_K(OP) ⊕ OP (TS 35.206 §3.1).
    pub fn new(k: Key, op: Operator) -> Self {
        let opc = xor16(&encrypt_block(&k, &op), &op);
        Self { k, opc }
    }

    /// Build from K and a pre-derived OPc (as some USIMs export).
    pub fn new_with_opc(k: Key, opc: Operator) -> Self {
        Self { k, opc }
    }

    pub fn opc(&self) -> Operator {
        self.opc
    }

    /// Run f1..f5 for one RAND/SQN/AMF tuple.
    pub fn compute(&self, rand: &Rand, sqn: &Sqn, amf: &Amf) -> MilenageOutputs {
        let (res, ck, ik, ak) = self.f2345(rand);
        let out1 = self.f1_base(rand, sqn, amf);
        let mut mac_a = [0u8; 8];
        mac_a.copy_from_slice(&out1[..8]);
        MilenageOutputs {
            mac_a,
            res,
            ck,
            ik,
            ak,
        }
    }

    /// f2/f3/f4/f5 combined (TS 35.206 §4.1.3): RES, CK, IK, AK.
    pub fn f2345(&self, rand: &Rand) -> ([u8; 8], [u8; 16], [u8; 16], [u8; 6]) {
        // TEMP = E_K(RAND ⊕ OPc)
        let temp = encrypt_block(&self.k, &xor16(rand, &self.opc));

        // f2: OUT2 = E_K((TEMP ⊕ OPc) ⊕ c2) ⊕ OPc, c2 = 0..01
        let mut in2 = xor16(&temp, &self.opc);
        in2[15] ^= 1;
        let out2 = xor16(&encrypt_block(&self.k, &in2), &self.opc);
        let mut res = [0u8; 8];
        res.copy_from_slice(&out2[8..]);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out2[..6]);

        // f3: rotate right by r3=32 bits, c3 = 0..02
        let ck = self.rotated_output(&temp, 12, 2);
        // f4: rotate right by r4=64 bits, c4 = 0..04
        let ik = self.rotated_output(&temp, 8, 4);

        (res, ck, ik, ak)
    }

    fn f1_base(&self, rand: &Rand, sqn: &Sqn, amf: &Amf) -> [u8; 16] {
        let temp = encrypt_block(&self.k, &xor16(rand, &self.opc));
        let mut in1 = [0u8; 16];
        in1[..6].copy_from_slice(sqn);
        in1[6..8].copy_from_slice(amf);
        in1[8..14].copy_from_slice(sqn);
        in1[14..16].copy_from_slice(amf);

        // IN1* = rot(IN1 ⊕ OPc, r1=64) ⊕ TEMP
        let mut input = [0u8; 16];
        for i in 0..16 {
            input[(i + 8) % 16] = in1[i] ^ self.opc[i];
        }
        for i in 0..16 {
            input[i] ^= temp[i];
        }
        xor16(&encrypt_block(&self.k, &input), &self.opc)
    }

    fn rotated_output(&self, temp: &[u8; 16], rotate: usize, c: u8) -> [u8; 16] {
        let mut input = [0u8; 16];
        for i in 0..16 {
            input[(i + rotate) % 16] = temp[i] ^ self.opc[i];
        }
        input[15] ^= c;
        xor16(&encrypt_block(&self.k, &input), &self.opc)
    }

    /// f1* used to build AUTS for a sequence-number resynchronisation.
    /// TS 35.206 §4.1.2: MAC-S = the second half of the f1 output block.
    pub fn f1_star(&self, rand: &Rand, sqn_ms: &Sqn, amf: &Amf) -> [u8; 8] {
        let out = self.f1_base(rand, sqn_ms, amf);
        let mut mac_s = [0u8; 8];
        mac_s.copy_from_slice(&out[8..]);
        mac_s
    }

    /// f5* derives the resynchronisation anonymity key; TS 35.206 §4.1.6.
    pub fn f5_star(&self, rand: &Rand) -> [u8; 6] {
        let temp = encrypt_block(&self.k, &xor16(rand, &self.opc));
        let out = self.rotated_output(&temp, 4, 8);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out[..6]);
        ak
    }
}

/// Result of verifying an AUTN from the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutnCheck {
    /// f1 MAC-A matched the AUTN MAC-S field.
    pub mac_valid: bool,
    /// Recovered SQN (only meaningful when `mac_valid`).
    pub sqn: Sqn,
    /// Anonymity key used to unmask SQN.
    pub ak: [u8; 6],
}

/// Verify AUTN and recover SQN: AUTN = (SQN ⊕ AK) || AMF || MAC-A.
pub fn verify_autn(m: &Milenage, rand: &Rand, autn: &[u8; 16]) -> AutnCheck {
    let mut masked_sqn = [0u8; 6];
    masked_sqn.copy_from_slice(&autn[..6]);
    let mut amf = [0u8; 2];
    amf.copy_from_slice(&autn[6..8]);
    let mut received_mac = [0u8; 8];
    received_mac.copy_from_slice(&autn[8..16]);

    let (_, _, _, ak) = m.f2345(rand);
    let mut sqn = [0u8; 6];
    for i in 0..6 {
        sqn[i] = masked_sqn[i] ^ ak[i];
    }
    let expected = m.compute(rand, &sqn, &amf);
    AutnCheck {
        mac_valid: constant_time_eq(&expected.mac_a, &received_mac),
        sqn,
        ak,
    }
}

/// RFC 3310 §3.2 / TS 24.229: the IMS AKA digest `response` is the hex
/// representation of RES. Uppercase to match common IMS core expectations.
pub fn ims_aka_response(res: &[u8]) -> String {
    let mut s = String::with_capacity(res.len() * 2);
    for b in res {
        use core::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Parse a 32-hex-character key/operator constant.
pub fn parse_hex16(s: &str) -> Result<[u8; 16], HexError> {
    let s = s.trim();
    if s.len() != 32 {
        return Err(HexError::Length(s.len()));
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| HexError::Digit)?;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    Length(usize),
    Digit,
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HexError::Length(n) => write!(f, "expected 32 hex chars, got {n}"),
            HexError::Digit => f.write_str("invalid hex digit"),
        }
    }
}

impl std::error::Error for HexError {}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 16] {
        parse_hex16(s).unwrap()
    }

    /// 3GPP TS 35.208 test set 1 (also used by open-source Milenage tests).
    fn test_set_1() -> (Milenage, Rand, Sqn, Amf, MilenageOutputs) {
        let k = h("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = h("cdc202d5123e20f62b6d676ac72cb318");
        let rand = h("23553cbe9637a89d218ae64dae47bf35");
        let sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
        let amf = [0xb9, 0xb9];
        let m = Milenage::new(k, op);
        let out = m.compute(&rand, &sqn, &amf);
        (m, rand, sqn, amf, out)
    }

    #[test]
    fn ts35208_test_set_1() {
        let (_, _, _, _, out) = test_set_1();
        assert_eq!(out.mac_a, [0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3]);
        assert_eq!(out.res, [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf]);
        assert_eq!(
            out.ck,
            [
                0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05, 0xbb, 0xf0, 0xd9, 0x87, 0xb2, 0x1b,
                0xf8, 0xcb
            ]
        );
        assert_eq!(
            out.ik,
            [
                0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04, 0x12, 0x76, 0x72, 0x71, 0x1c, 0x6d,
                0x34, 0x41
            ]
        );
        assert_eq!(out.ak, [0xaa, 0x68, 0x9c, 0x64, 0x83, 0x70]);
    }

    #[test]
    fn op_and_opc_agree() {
        let k = h("465b5ce8b199b49faa5f0a2ee238a6bc");
        let op = h("cdc202d5123e20f62b6d676ac72cb318");
        let a = Milenage::new(k, op);
        let b = Milenage::new_with_opc(k, a.opc());
        let rand = h("23553cbe9637a89d218ae64dae47bf35");
        let sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
        let amf = [0xb9, 0xb9];
        assert_eq!(a.compute(&rand, &sqn, &amf), b.compute(&rand, &sqn, &amf));
    }

    #[test]
    fn autn_round_trip() {
        let (m, rand, sqn, amf, out) = test_set_1();
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = sqn[i] ^ out.ak[i];
        }
        autn[6..8].copy_from_slice(&amf);
        autn[8..].copy_from_slice(&out.mac_a);
        let check = verify_autn(&m, &rand, &autn);
        assert!(check.mac_valid);
        assert_eq!(check.sqn, sqn);
    }

    #[test]
    fn rfc3310_response_is_hex_res() {
        let (_, _, _, _, out) = test_set_1();
        assert_eq!(ims_aka_response(&out.res), "A54211D5E3BA50BF");
    }
}
