# Architecture

## 1. Crates and boundaries

```text
+---------------------------- application / UI ----------------------------+
|                                                                          |
|   ims        registration state, IMS profile, SDP offer/answer,          |
|              dialogs, MO/MT calls, SMS, emergency request construction   |
|     |                |                          |                        |
|     | sip::Message   | codec::Codec             | transport::Transport   |
|     v                v                          v                        |
|   sip          codec (trait, Opus only)     transport (trait, mock)      |
|   RFC 3261     PCM frames in/out            UDP/TCP, AT/QMI, MBIM,       |
|   no I/O                                    CCCI boundary, ESP/IPsec     |
|                                                                          |
|   aka / usim   RFC 3310 / Milenage / TS 31.102 AUTHENTICATE (no I/O)     |
|   carrier      TOML profiles keyed by MCC/MNC (data only)                |
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
| UDP/TCP | in tree | `std::net` adapter (`transport::net`); TLS is a later dependency decision |
| IPsec (Gm) | in tree | `transport::esp` + `transport::ipsec`; Linux XFRM installs the SAs, other platforms report unsupported |
| AT command channel | modelled | adapter that writes SIP over the modem's IMS PDN or AT tunnel; does not change `ims` |
| QMI | modelled | IMS PDN + P-CSCF/PCO discovery; adapter supplies `ImsProfile` |
| MBIM | modelled | control-frame wire shape + IMS PDN session; local addr is modem-assigned |
| MTK CCCI | boundary only | `VendorChannel` trait + this tree's own length framing; no vendor code copied |

Transport adapters own platform failure, retries and MTU behaviour. They must
not parse or rewrite SIP semantics; they move `sip::Message` bytes.

**Emergency (E911).** `ims::emergency` builds the TS 24.229 §5.1.6.3 emergency
INVITE as pure messages. It never transmits: the CLI `emergency` subcommand
only accepts the mock transport, refuses `udp`/`tcp`, and prints the request.
Live emergency calling is a regulated product gate, not a test feature.

## 5. Security plane (Gm IPsec)

IMS does **not** run IKE on Gm. During registration the UE offers its IPsec
parameters in `Security-Client`; the P-CSCF answers with `Security-Server`; both
sides already hold the same `CK`/`IK` from IMS-AKA, so the SAs are programmed
directly (TS 33.203 §7, RFC 3329).

```text
  usim/aka ── CK/IK ──┐
                      ▼
  Security-Client/Server ──► transport::ipsec::IpsecAgreement
                                    │  outbound SA (spi-c), inbound SA (spi-s)
                                    ▼
                    transport::esp  (HMAC-MD5-96 / HMAC-SHA-1-96, null enc)
                                    │
                    Linux:  ip xfrm state|policy  (kernel ESP data path)
                    macOS:  no XFRM — needs an out-of-tree userspace data path
```

* `transport::esp` is a real codec: 96-bit ICV, null encryption, ESP padding,
  and a 64-packet anti-replay window (RFC 4303 §3.4.3).
* `transport::ipsec` parses the `Security-*` parameters, builds the SA pair from
  `CK`/`IK`, and renders `ip xfrm` commands. `XfrmProgram::apply()` is Linux-only
  and needs `CAP_NET_ADMIN`.
* On macOS there is no XFRM; the kernel does not take these SAs. The codec and
  negotiation still run, but a live SA needs an out-of-tree userspace ESP data
  path (utun/raw sockets) or a Linux VM/container.

The modem is not involved: it only provides the IP bearer. SAs bind to that
PDN interface and its addresses.

## 6. Voice continuity and the audio seam

Two integration seams matter more than any remaining protocol work, and both are
pure Rust with the device side out of tree.

**Continuity** (`ims::continuity`). EPS fallback and SRVCC are radio decisions
the AP cannot take. The client classifies and reports:

* a final INVITE of `488`/`580` means the network cannot serve the session over
  IMS → `FallbackReason::EpsFallback` (TS 23.216), and `503` + `Retry-After`
  is a retry hint;
* a `ContinuityMonitor` fed every RTP/RTCP packet reports `Degraded` at half the
  timeout and `Lost` at the timeout, which is the SRVCC eligibility signal.

The platform (telephony daemon + radio) decides whether to use CS.

**Call audio** (`media::audio`). The codec side already produces 16-bit mono PCM
frames. This module is the seam:

```text
  codec/evs/codec-amr ── PCM ──► RingBuffer ──► AudioSink ──► device
                                      ▲                        (ALSA adapter,
  AudioSource ◄── PCM ────────────────┘                         out of tree)
```

* `AudioSink`/`AudioSource` are the device traits; an ALSA/PulseAudio adapter
  implements them out of tree, so the default build links no audio library and
  stays `#![forbid(unsafe_code)]`.
* `RingBuffer` accounts for drops and underruns, `Loopback` connects a pair for
  tests, `Wav` captures a call to a 16-bit PCM file, and `Pacing` releases
  samples at the frame rate.

On modem-side IMS the AP never touches call audio; this seam exists for the
AP-side path, where the modem's voice PCM has to reach userspace.

**Wi-Fi calling (ePDG).** The alternative to VoLTE is an IKEv2 tunnel to an
ePDG authenticated with EAP-AKA'. The crypto core is in
`aka::eap_aka_prime`: `CK'/IK'` bound to the access-network name, the RFC 5448
`PRF'` expansion into `K_encr`/`K_aut`/`K_re`/`MSK`/`EMSK`, the AT attribute
framing and `AT_MAC`. The `epdg` crate adds the IKEv2 message/payload codec and
an EAP-AKA' peer that verifies the server MAC and answers with `AT_RES`. `epdg::dh` adds the RFC 3526 MODP groups, `epdg::keys` the `SKEYSEED`/`prf+`
schedule, `epdg::sk` the AES-CBC + HMAC-SHA-256-128 encrypted payload, and
`epdg::sa` the IKE_SA_INIT initiator (both sides derive the same keys in the
conformance test), and `epdg::ike_auth` the EAP-only IKE_AUTH exchange
(RFC 5998): encrypted `IDi/SAi2/TSi/TSr`, EAP-AKA' round trips inside SK, then
`AUTH` computed over the EAP MSK with per-direction SignedOctets.

`epdg::child` then turns the exchange's KEYMAT into the child SA — both SPIs,
the AES-CBC and HMAC-SHA-256-128 keys, and the agreed traffic selectors — and
`epdg::cp` reads the `CFG_REPLY` that carries the IMS address the ePDG assigned.
`transport::ipsec::TunnelProgram` renders the S2b install: an XFRM interface
bound by `if_id`, tunnel-mode ESP states, traffic-selector policies carrying the
same `if_id`, and the inner address and route. `lab/s2b/verify.sh` runs the
generated commands against a real kernel in two namespaces and pings across the
tunnel, which is how two subtle requirements were found — the kernel defaults
`auth` to a 96-bit ICV, and a policy template must repeat the state's `if_id`.

`lab/epdg` is the driver: `UeClient` runs the exchange over UDP holding `K`/`OPc`
and evaluating Milenage as a USIM would, and `StandInEpdg` is an ePDG that
shares nothing with it but the subscriber key — so a completed exchange means
the key chain agreed, not that both sides used one fixture.

Identity comes from the card: `usim::isim` reads `EF_IMPI`/`EF_IMPU`/`EF_DOMAIN`
through the same APDU channel as `AUTHENTICATE`, and `ImsProfile::apply_isim`
lets those values override the IMSI-derived ones (TS 31.103). When the card has
no ISIM the IMSI derivation stands, which is the common case on older SIMs.
`ims::pani` reports the access network — `IEEE-802.11` with `i-wlan-node-id` for
Wi-Fi calling, `3GPP-E-UTRAN-*` with `utran-cell-id-3gpp` for cellular.

Not implemented yet: the PC/SC adapter that would put a real USIM behind the
same driver.

### Deliberately deferred

`docs/adr/` records the decisions *not* taken, with the trigger that would
reopen each. `ADR 0002` defers GBA (TS 33.220) for carrier entitlement: it is
the specified way to authenticate to an operator application with the SIM, but
entitlement itself is carrier business logic with no normative request shape, so
it cannot be spec-derived — only the bootstrapping primitive can. It is not
claimed by any matrix row.

### Cryptographic primitives

No primitive is implemented in this tree. AES, SHA-1, SHA-256, HMAC and
constant-time comparison come from RustCrypto; the accepted cost is five small
pure-Rust dependencies, and the accepted benefit is that a primitive is never
validated only against itself.

That distinction is not academic. Hand-written AES, SHA-256 and HMAC passed
every test in the tree for months, because the only peers they ever talked to
were each other. They were replaced after an independent IKEv2 implementation
disagreed; each is now pinned to a published vector (FIPS 197, RFC 4231,
RFC 2202, RFC 3174) rather than to a round-trip.

The MODP modular exponentiation still comes from `num-bigint`, which is *not*
constant-time. The only secret it handles is the per-session Diffie-Hellman
private exponent, so the exposure is bounded by how many handshakes an attacker
can drive; replacing it with `crypto-bigint` is tracked as a known limitation
rather than silently ignored.

## 7. ARM-first targets

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
