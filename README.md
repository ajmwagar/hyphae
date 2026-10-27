# hyphae — an open IMS/VoLTE client

A GPL-3.0-or-later, spec-derived IMS client for Linux phones. The AP-side IMS
stack has never been open source; when 2G/3G was switched off, Linux phones lost
voice. This is the missing control plane: SIP, IMS-AKA, registration, dialogs,
SDP, carrier profiles and a codec-agnostic media boundary.

Status: **scaffold**. The control-plane state machine, Milenage/AKA, SDP,
RFC 4867 payload format, carrier loader and mock transport compile and have
spec-derived tests. RTP/RTCP, IPsec, the modem transport adapters and a
standalone CLI are TODO phases (see [`docs/specs.md`](docs/specs.md)).

## Why it matters

- VoLTE/IMS is the only voice path left on many networks; there is no libre
  AP-side client to put on a Linux phone.
- The modem side (QMI/CCCI), network side (Open5GS/Kamailio) and OS side exist.
  The client is the gap.
- The design keeps protocol work independent of patent-encumbered codecs, so the
  GPL core can be built, tested and distributed without a codec royalty.

## Legal posture in five lines

1. This tree is GPL-3.0-or-later and contains **no** AMR-WB/EVS implementation;
   `codec` ships the `Codec` trait plus royalty-free Opus.
2. AMR-WB lives in a separate, feature-off, patent-noticed package
   ([`codec-amr/PATENTS.md`](codec-amr/PATENTS.md)); its Apache-2.0 library does
   **not** grant AMR-WB patent rights.
3. Retrofit mode runs the phone's own licensed codec on that unit; manufacture
   mode uses an ODM/our licensed build. Vendor blobs are never redistributed.
4. No code, strings or constants were derived from decompiled KaiOS/MTK/Qualcomm
   binaries; sources and licences are recorded in
   [`docs/references.md`](docs/references.md), vendor facts (if any) go in
   [`docs/facts/`](docs/facts/) and never become code.
5. The binding decisions are in the project ADR
   `~/Documents/src/reversal/cat-s22/docs/adr-ims-codec-licensing.md`,
   mirrored in-tree at [`docs/adr/0001-codec-licensing.md`](docs/adr/0001-codec-licensing.md).

## Workspace

```text
sip/        RFC 3261 messages, headers, transactions; no I/O
aka/        Milenage f1–f5, AUTN verification, RFC 3310 RES; pure functions
ims/        profile, REGISTER/401/407, SDP offer/answer, PRACK/UPDATE/BYE
carrier/    TOML profiles keyed by MCC/MNC + lab profile 00101
codec/      Codec trait + optional Opus (feature `opus`); PCM only
codec-amr/  RFC 4867 payload format + optional AMR-WB FFI (separate package)
transport/  Transport trait + in-memory MockTransport
tests/      conformance harness + golden fixtures with spec citations
lab/        docker-compose plan for Open5GS + Kamailio IMS + USIM
docs/       specs matrix, architecture, ARM targets, references, facts
```

The protocol crates never start a thread, open a socket, or link a codec.

## Quickstart (host, no modem, no network)

```sh
cargo check --workspace
cargo test -p sip -p aka -p ims -p carrier -p codec -p codec-amr -p transport -p conformance
cargo run -p ims --example register_flow
```

`register_flow` prints the exact initial REGISTER, a simulated 401 and the
authorized REGISTER with an AKAv1-MD5 digest. It does not touch the network.

### ARM cross-check (a gate, same weight as host check)

```sh
rustup target add aarch64-unknown-linux-gnu
rustup target add armv7-unknown-linux-gnueabihf
cargo check --workspace --target aarch64-unknown-linux-gnu
cargo check --workspace --target armv7-unknown-linux-gnueabihf
```

We can type-check ARM locally; we cannot run ARM tests on this host. See
[`docs/targets.md`](docs/targets.md) for exactly what is and is not verified.

### Optional codecs

```sh
# Opus (royalty-free, in-tree via the `opus` crate)
cargo test -p codec --features opus

# RFC 4867 payload format is always available; no C, no feature
cargo test -p codec-amr

# AMR-WB against the SYSTEM libopencore-amrwb (patents NOT granted)
cargo test -p codec-amr --features amr-wb

# No build-host library: load the same symbols at runtime
cargo check -p codec-amr --features amr-wb-dlopen
```

AMR-WB cross-builds need a target sysroot and `PKG_CONFIG_ALLOW_CROSS=1` or
`OPENCODE_AMR_DIR`; see [`codec-amr/README.md`](codec-amr/README.md). Read
[`codec-amr/PATENTS.md`](codec-amr/PATENTS.md) and the root
[`PATENTS.md`](PATENTS.md) before enabling it.

## How to run the lab

The lab is a plan plus a compose file; it has not been run here. Full steps,
expected REGISTER ladder and success criteria are in
[`lab/README.md`](lab/README.md). Short version:

```sh
cd lab
cp .env.example .env
# Add the upstream Open5GS and Kamailio IMS configs under lab/config/.
docker compose config
docker compose up -d
docker compose logs -f open5gs kamailio
```

What success looks like: initial REGISTER with `Security-Client` → 401 with
`WWW-Authenticate: ... algorithm=AKAv1-MD5` → REGISTER with
`Authorization: Digest ...` → 200 OK with `Service-Route`. Your K/OP must match
between the programmable USIM and the HSS. Use test credentials only.

## Documentation

- [`docs/specs.md`](docs/specs.md) — requirement → clause → test → crate matrix
  (with TODO phases marked honestly).
- [`docs/architecture.md`](docs/architecture.md) — codec-service boundary,
  retrofit vs manufacture, transport backends (AT/QMI now, MTK CCCI later).
- [`docs/targets.md`](docs/targets.md) — ARM gate and its limits.
- [`docs/references.md`](docs/references.md) — legal provenance and open-source
  reference terms.
- [`docs/facts/`](docs/facts/) — provenance-only vendor facts; never code.

## Contributing discipline

- Specs first: every behaviour needs a normative citation and a named test.
- No vendor-derived code, strings or constants. Facts go in `docs/facts/`.
- Keep the default build pure-Rust and ARM-buildable; C only behind a feature.
- Do not add an async runtime until the synchronous state machine is trusted.
- AMR-WB/EVS never enter a core crate; they stay behind the `Codec` trait in a
  separate, patent-noticed package.
