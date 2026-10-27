# Contributing to hyphae

## Sign the CLA first

Contributions require the [Contributor License Agreement](CLA.md). It is a
**copyright licence grant**: you keep ownership of your contribution and grant
the maintainer a perpetual, irrevocable, sublicensable licence that includes the
right to license the project commercially. The public tree always stays
GPL-3.0-or-later.

To sign, comment on your pull request:

```
I have read the CLA Document and I hereby sign the CLA.
```

That text is the electronic acceptance described in section 16 of `CLA.md`;
signing once covers all future contributions to this project. If you are
contributing on behalf of an employer, section 10 requires that you have
authority to bind them, or their written authorisation.

Also use `git commit -s` (DCO sign-off) so the provenance of every patch is
recorded in history. The CLA is the binding instrument; the sign-off is the
trail.

## Why a CLA and not just a DCO

A DCO grant is enough for a project that will only ever be GPL. It is not enough
to dual-license: commercial licensing needs either copyright ownership or an
explicit right to relicense, and asking every contributor for that later is how
projects get permanently stuck. The CLA is the standard instrument for this,
and it is the same one used by `ajmwagar/pedalkernel`.

## Two non-negotiable rules

### 1. No vendor-derived code

Acceptable sources:

- 3GPP / GSMA / IETF specifications
- public open-source projects with compatible licences (AOSP MmTel is
  Apache-2.0, doubango/imsdroid is GPLv3, osmocom is GPL)
- protocol captures taken from devices or labs you are authorised to observe

Not acceptable:

- anything derived from decompiled or disassembled vendor binaries (KaiOS,
  MediaTek, Qualcomm, TCL, CAT stacks, vendor `libimsma*`, `lib-imscmservice*`)
- copy-paste from a project whose licence is incompatible with GPL-3.0

Recording *observable facts* is fine: a `User-Agent` string, a feature tag, an
APN name, a timing value. Those are facts, not expression. If in doubt, record
the fact in `docs/facts/` with where you observed it, and implement from the
spec.

### 2. Every requirement has a test

A behaviour lands with:

- a clause reference (`3GPP TS 24.229 §5.1.1`, `RFC 3261 §8.1.3`),
- a row in `docs/specs.md`,
- a test that fails without the implementation.

## Codec policy

`codec` has a trait and Opus, and that is all the default build may contain.

**AMR-WB** is permitted only as the optional `codec-amr` member behind the
non-default `amr-wb` feature, binding to the system `libopencore-amrwb` and
carrying its own `PATENTS.md`. It must never be pulled in by default, by
`--all-features` in CI for the default artifact, or by any published core crate.

**EVS** stays out of tree entirely. See [PATENTS.md](PATENTS.md) and
[docs/adr/0001-codec-licensing.md](docs/adr/0001-codec-licensing.md).

## Style

- Rust 2021, `#![forbid(unsafe_code)]` in every crate unless there is a written
  justification in the crate docs.
- Parsing is total: no panics on network input, ever. Malformed input is an
  error value, not an `unwrap`.
- keep `cargo check` green while iterating, `cargo test` green before opening a
  PR.
