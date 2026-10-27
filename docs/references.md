# References and legal provenance

This project is spec-derived. Nothing in `sip/`, `aka/`, `ims/`, `carrier/`,
`codec/`, `codec-amr/src/rtp.rs`, or `transport/` is copied, decompiled,
translated, or reconstructed from a vendor binary.

## Normative specifications

| Area | Documents |
|---|---|
| SIP | RFC 3261 (core), RFC 3262 (100rel/PRACK), RFC 3264 (offer/answer), RFC 3265/6665 (events), RFC 3311 (UPDATE), RFC 3329 (Security-Client/Verify), RFC 3608 (Service-Route), RFC 2617/3310 (Digest/AKA), RFC 4566 (SDP), RFC 4867 (AMR/AMR-WB RTP payload), RFC 3550 (RTP/RTCP), RFC 4303 (ESP) |
| IMS / 3GPP | TS 23.003 (identities, APN, IMS domain), TS 23.228 (IMS architecture), TS 24.229 (SIP/IMS call control), TS 26.114 (MTSI media), TS 33.102 (3G security), TS 33.203 (IMS security/AKA), TS 35.205/35.206 (Milenage), TS 35.208 (Milenage test data), TS 24.341 (SMS over IMS), TS 24.301 (EPS NAS/PCO) |
| GSMA | IR.92 (VoLTE/MMTel), IR.94 (video share/IR.92 extension) |
| Codec | RFC 6716 (Opus), RFC 4867 (AMR/AMR-WB RTP), FIPS-197 (AES) |

Public copies are available from the IETF Datatracker, 3GPP FTP, and GSMA.
Citations in code and fixtures point at the clause, not a vendor manual.

## Open-source references and their terms

| Project | Licence | How we may use it |
|---|---|---|
| **AOSP ImsService / MmTel** (`packages/services/MmTel` and framework IMS) | Apache-2.0 | May read and adapt algorithms/architecture with attribution and licence notice. We do **not** copy files wholesale; any adapted portion must carry the Apache-2.0 notice and a "changes made" statement. |
| **doubango / imsdroid** | GPLv3 | Read for architecture and interoperability ideas only. Because this project is GPL-3.0-or-later, careful attribution is possible, but we avoid copying code to keep provenance simple. Do not paste GPL code without a provenance record. |
| **osmocom** (libosmocore, osmo-sim, pySim) | GPLv2/GPLv3 (per project) | Reference for USIM/AKA command shapes and test vectors. Architecture/reference only; no copy into this tree without a compatible-licence review and attribution. |
| **libopencore-amr / opencore-amr** | Apache-2.0 | Optional system library for AMR-WB decode, behind a feature. No source vendoring. Patents are **not** granted by Apache-2.0; see `codec-amr/PATENTS.md`. |
| **Open5GS / Kamailio** | AGPL-3.0 / GPLv2+ | Lab deployment only, not linked into the client. |

The ADR at
`/Users/ajmwagar/Documents/src/reversal/cat-s22/docs/adr-ims-codec-licensing.md`
is binding for the codec boundary and distribution model.

## Vendor facts

Facts observed from vendor binaries or device ROMs (UA strings, feature tags,
APN shapes, timer values) are **not** code. If recorded, they go in
[`facts/`](facts/) with provenance: source package/partition, method, date,
exact observed value, and confidence. They may inform a configuration default
only after being checked against a public specification. They must never be
turned into copied code, copied strings, or decompiled logic.

This scaffold currently contains **no vendor-derived constants**. The lab
profile uses public PLMN/APN/feature-tag shapes and the 3GPP Milenage test
vector.

## Dependency policy

Default build: pure-Rust, small, no async runtime, no C.

* `toml` (carrier profile parsing)
* `md5` (RFC 2617 digest; MD5 is not used for authentication security on its
  own — IMS-AKA supplies RES, and the digest is wrapped by the 3GPP AKA)
* `pkg-config` (build-time only, `codec-amr`)
* optional `libloading` (`codec-amr` dlopen feature)
* optional `opus` (`codec` feature; royalty-free)

C code is allowed only behind an explicit codec feature and only as a system
library boundary, never as vendored source in a core crate.
