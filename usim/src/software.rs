//! A Milenage-backed USIM for the lab and for host tests.
//!
//! This is a **software stand-in for the card**, not a replacement for it: on a
//! real device the USIM runs Milenage internally and only ever emits RES/CK/IK.
//! Here the same arithmetic runs in-process so the whole AKA path is testable
//! without a reader.
//!
//! Behaviour mirrors TS 31.102 §7.1.1.1:
//! * verify `MAC-A` in AUTN, else [`UsimError::MacFailure`];
//! * if the sequence number is not acceptable, return `AUTS` for resync;
//! * otherwise return RES/CK/IK.

#![forbid(unsafe_code)]

use crate::{AkaOutput, Autn, Rand, Usim, UsimError};
use aka::{Amf, Key, Milenage, Operator, Sqn};

/// A USIM implemented over the [`aka`] Milenage function set.
///
/// `K` and `OPc` are private and not exposed in `Debug`.
pub struct SoftwareUsim {
    milenage: Milenage,
    /// Highest acceptable sequence number (`SQN_MS`).
    sqn_ms: Sqn,
    /// Whether SQN is accepted strictly above `sqn_ms` (true) or also a small
    /// window below it (false). The lab default accepts `<= sqn_ms` so a static
    /// test vector replays.
    strict: bool,
}

impl core::fmt::Debug for SoftwareUsim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareUsim")
            .field("sqn_ms", &self.sqn_ms)
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

impl SoftwareUsim {
    /// Build from `K` and `OP` (deriving `OPc`), with an initial `SQN_MS`.
    pub fn new(k: Key, op: Operator, sqn_ms: Sqn) -> Self {
        Self {
            milenage: Milenage::new(k, op),
            sqn_ms,
            strict: false,
        }
    }

    /// Build from `K` and a pre-derived `OPc`.
    pub fn with_opc(k: Key, opc: Operator, sqn_ms: Sqn) -> Self {
        Self {
            milenage: Milenage::new_with_opc(k, opc),
            sqn_ms,
            strict: false,
        }
    }

    /// Require strictly increasing sequence numbers (real-network behaviour).
    pub fn strict_sqn(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Update `SQN_MS` after a successful run (the card persists this).
    pub fn set_sqn_ms(&mut self, sqn: Sqn) {
        self.sqn_ms = sqn;
    }

    /// The current `SQN_MS`.
    pub fn sqn_ms(&self) -> Sqn {
        self.sqn_ms
    }
}

impl Usim for SoftwareUsim {
    fn authenticate(&mut self, rand: &Rand, autn: &Autn) -> Result<AkaOutput, UsimError> {
        let check = aka::verify_autn(&self.milenage, rand, autn);
        if !check.mac_valid {
            return Err(UsimError::MacFailure);
        }
        // Sequence-number window (TS 31.102 §7.1.1.1). The real card keeps the
        // last 32 SQNs; this lab model accepts up to SQN_MS unless strict.
        let acceptable = if self.strict {
            check.sqn > self.sqn_ms
        } else {
            check.sqn <= self.sqn_ms
        };
        if !acceptable {
            // AUTS = (SQN_MS XOR f5*(RAND)) || f1*(SQN_MS || RAND || AMF=0)
            let ak = self.milenage.f5_star(rand);
            let mut conc = [0u8; 6];
            for i in 0..6 {
                conc[i] = self.sqn_ms[i] ^ ak[i];
            }
            let zero_amf: Amf = [0, 0];
            let mac_s = self.milenage.f1_star(rand, &self.sqn_ms, &zero_amf);
            let mut auts = [0u8; 14];
            auts[..6].copy_from_slice(&conc);
            auts[6..].copy_from_slice(&mac_s);
            return Ok(AkaOutput::SyncFailure { auts });
        }

        let mut amf = [0u8; 2];
        amf.copy_from_slice(&autn[6..8]);
        let out = self.milenage.compute(rand, &check.sqn, &amf);
        Ok(AkaOutput::Success {
            res: out.res.to_vec(),
            ck: out.ck,
            ik: out.ik,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 3GPP TS 35.208 test set 1 (public test vector).
    const K: Key = [
        0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6,
        0xbc,
    ];
    const OP: Operator = [
        0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3,
        0x18,
    ];
    const SQN: Sqn = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
    const RAND: Rand = [
        0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf,
        0x35,
    ];
    const AMF: Amf = [0xb9, 0xb9];

    fn autn_for(u: &SoftwareUsim) -> Autn {
        // Build an AUTN the card will accept: (SQN XOR AK) || AMF || MAC-A.
        // AUTN masks SQN with f5 (not f5*, which is only for AUTS).
        let ak = u.milenage.f2345(&RAND).3;
        let mut autn = [0u8; 16];
        for i in 0..6 {
            autn[i] = SQN[i] ^ ak[i];
        }
        autn[6..8].copy_from_slice(&AMF);
        let mac = u.milenage.compute(&RAND, &SQN, &AMF).mac_a;
        autn[8..].copy_from_slice(&mac);
        autn
    }

    #[test]
    fn software_usim_matches_the_milenage_vector() {
        // Published TS 35.208 test set 1 outputs, reached through the USIM
        // boundary exactly as the ME would.
        let mut usim = SoftwareUsim::new(K, OP, SQN);
        let autn = autn_for(&usim);
        let out = usim.authenticate(&RAND, &autn).unwrap();
        match out {
            AkaOutput::Success { res, ck, ik } => {
                assert_eq!(res, vec![0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf]);
                assert_eq!(
                    ck,
                    [
                        0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05, 0xbb, 0xf0, 0xd9, 0x87,
                        0xb2, 0x1b, 0xf8, 0xcb
                    ]
                );
                assert_eq!(
                    ik,
                    [
                        0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04, 0x12, 0x76, 0x72, 0x71,
                        0x1c, 0x6d, 0x34, 0x41
                    ]
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn bad_mac_is_a_failure() {
        let mut usim = SoftwareUsim::new(K, OP, SQN);
        let mut autn = autn_for(&usim);
        autn[15] ^= 0xFF;
        assert_eq!(usim.authenticate(&RAND, &autn), Err(UsimError::MacFailure));
    }

    #[test]
    fn out_of_range_sqn_returns_auts() {
        // SQN_MS above the AUTN's SQN in strict mode => replay, so the card
        // asks for resynchronisation instead of accepting the challenge.
        let high_sqn: Sqn = [0xff; 6];
        let mut usim = SoftwareUsim::new(K, OP, high_sqn).strict_sqn(true);
        let autn = autn_for(&usim);
        match usim.authenticate(&RAND, &autn).unwrap() {
            AkaOutput::SyncFailure { auts } => {
                // AUTS must be the concealed SQN_MS followed by MAC-S.
                let ak = usim.milenage.f5_star(&RAND);
                let mut conc = [0u8; 6];
                for i in 0..6 {
                    conc[i] = high_sqn[i] ^ ak[i];
                }
                assert_eq!(&auts[..6], &conc);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let usim = SoftwareUsim::new(K, OP, SQN);
        let text = format!("{usim:?}");
        assert!(text.contains("SoftwareUsim"));
        assert!(!text.contains("46"));
        assert!(!text.contains("cdc2"));
    }
}
