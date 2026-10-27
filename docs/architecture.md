# Architecture

## 1. Crates and boundaries

```text
+---------------------------- application / UI ----------------------------+
|                                                                          |
|   ims        registration state, IMS profile, SDP offer/answer,          |
|              dialog construction (PRACK / UPDATE / BYE)                  |
|     |                |                          |                        |
|     | sip::Message   | codec::Codec             | transport::Transport   |
|     v                v                          v                        |
|   sip          codec (trait, Opus only)     transport (trait, mock)      |
|   RFC 3261     PCM frames in/out             UDP/TCP later; AT/QMI now;  |
|   no I/O                                     MTK CCCI later             |
|                                                                          |
|   aka          RFC 3310 / Milenage, pure functions over USIM output       |
|   carrier      TOML profiles keyed by MCC/MNC (data only)                 |
+--------------------------------------------------------------------------+
```

No crate in the diagram starts a thread, opens a socket, or links a codec. The
`ims` crate depends on `sip` and `aka`; media and transport are injected by the
application. This is what makes the default test gate run on a laptop with no
modem.

`codec-amr` is deliberately **outside** the core: it carries the optional
AMR-WB FFI backend and the pure-Rust RFC 4867 packet layout. Its C features are
off by default.

## 2. Codec-service boundary

The binding decision is in
`/Users/ajmwagar/Documents/src/reversal/cat-s22/docs/adr-ims-codec-licensing.md`
(mirrored at [`adr/0001-codec-licensing.md`](adr/0001-codec-licensing.md)).
The implementation consequence:

```text
                 ims / media engine (GPL, in tree)
                          │  PCM i16 frames only
                          ▼
                    codec::Codec trait
        ┌─────────────────┼──────────────────────────┐
        │                 │                          │
   codec::Opus      codec-amr (optional)       retrofit helper
   in tree,         AMR-WB decode via          device vendor codec
   royalty-free     system libopencore-amrwb    via libhybris/service
        │           (feature off by default)          │
        ▼                 ▼                          ▼
   RFC 6716          Apache-2.0 impl          OEM blob, never redistributed
                     patents NOT granted      runs only on its own unit
```

The protocol engine never learns which backend is present. It negotiates codec
names in SDP (`AMR-WB/16000`, `opus`) and hands PCM to the trait. Unknown or
disabled backends return `CodecError::Unavailable`; the call fails loudly rather
than silently falling back to a different codec.

### Modes

| Mode | Codec source | Patent position | In-tree support |
|---|---|---|---|
| **Retrofit** | the phone's own vendor codec through a narrow helper ABI (libhybris or a service process) | exhausted for that unit; blob never redistributed | helper ABI is a future transport-like boundary; no vendor code here |
| **Manufacture** | ODM codec or our licensed build | project/ODM holds pool licence per device | build-time choice, not a source-tree change |

The GPL client (this tree) ships Opus only. AMR-WB/EVS stay in separate,
patent-noticed packages or device-local retrofit services. See
[`codec-amr/PATENTS.md`](../codec-amr/PATENTS.md) and
[`references.md`](references.md).

## 3. Signalling path

1. `carrier::CarrierProfile` supplies the APN, P-CSCF discovery mode, identities,
   UA, feature tags and timers.
2. `ims::ImsProfile` is the runtime profile (IMPI/IMPU, home domain, resolved
   P-CSCF, Security-Client, Service-Route).
3. `ims::Registration` builds REGISTER, consumes 401/407, asks the USIM/AKA
   layer for RES, and emits an authorized REGISTER. `aka::Milenage` is the pure
   computation; the actual USIM command path is a transport-side integration.
4. `sip` parses/serialises every message and models transactions. No message is
   ever handed to a socket as an ad-hoc string.
5. `transport::Transport` is the only wire boundary. The mock serialises and
   re-parses through `sip`, so tests exercise the real codec.

## 4. Where transport backends plug in

| Backend | Status | Shape |
|---|---|---|
| `MockTransport` | in tree | in-memory channels; used by all tests |
| UDP/TCP/TLS | TODO | `std::net` adapter; TLS is a later dependency decision |
| AT command channel | TODO (phase 3) | adapter that writes SIP over the modem's IMS PDN or AT tunnel; does not change `ims` |
| QMI | TODO (phase 3) | IMS PDN + P-CSCF/PCO discovery; adapter supplies `ImsProfile` |
| MTK CCCI | TODO (phase 5) | vendor channel shim; protocol bytes stay spec-derived, no vendor code copied |

Transport adapters own platform failure, retries and MTU behaviour. They must
not parse or rewrite SIP semantics; they move `sip::Message` bytes.

## 5. ARM-first targets

First devices are 32-bit ARM (TCL 4058G, armv7l) and 64-bit ARM (CAT S22
msm8937 hardware, mainline aarch64). Therefore:

* default dependencies are pure Rust (`toml`, `md5`, `pkg-config`, optional
  `libloading`);
* no `usize == u64` assumptions; lengths are bounded by protocol fields;
* no 64-bit-only atomics;
* C dependencies exist only behind `codec-amr` features;
* `cargo check` runs for both `aarch64-unknown-linux-gnu` and
  `armv7-unknown-linux-gnueabihf` (see [`targets.md`](targets.md)).

We can type-check ARM locally but cannot execute ARM tests on this host. Runtime
testing on device is a separate gate and is stated as such in `targets.md`.
