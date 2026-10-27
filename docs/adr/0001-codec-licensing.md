# ADR: IMS client codec licensing and distribution model

**Status:** proposed · **Scope:** the Rust IMS/VoLTE client (`ims`), its codec
subsystems, and how the rust client is distributed vs. manufactured.

## Context

A libre IMS client is the missing piece for Linux phones: the modem side
(QMI/CCCI), the network side (Open5GS, Kamailio IMS) and the OS side are all
solved or solvable, but the AP-side IMS client has never been open-sourced.

Two facts constrain the design:

1. **VoLTE codecs are patent-encumbered.** GSMA IR.92 mandates **AMR-WB**;
   HD+/newer networks add **EVS**. Both are in patent pools (Via LA). Opus is
   royalty-free but is *not* in the 3GPP MTSI set, so carriers will not
   negotiate it, even though it is perfect for development.
2. **Patent exhaustion is per-unit; licensing is per-design.** A user who
   installs a libre OS on a phone they bought keeps the rights associated with
   that unit. A manufacturer of new units does not inherit anything.

Additionally, vendor codec binaries (`libstagefright_soft_amrwb*.so` and MTK's
`libimsma*`) are **32-bit and bionic-linked**, so they are not directly usable
from a glibc userspace at any bitness. Reusing them requires a bionic bridge
(libhybris) or an Android container.

## Decision

### 1. The IMS client ships codec-agnostic, with Opus only

The `ims` crate depends on a `Codec` trait and includes an Opus implementation
(royalty-free). AMR-WB and EVS are *not* in the main tree. This is the same
pattern Debian/Fedora use for patent-encumbered media: the base is clean, the
encumbered parts are a separate, clearly-labelled package.

### 2. Codecs are a runtime service, not a linked library

```
codec trait (in tree)
  ├── opus            (in tree, royalty-free, lab + app-to-app)
  ├── amr-wb / evs    (separate package, patent notice, not in the GPL client)
  └── hybris backend  (retrofit: uses the device's own licensed codec)
```

The client never learns which backend it talks to. It negotiates the codec in
SDP and sends/receives PCM frames over a narrow helper ABI.

### 3. Two supported modes, one client

| Mode | Codec source | Who holds the patent licence |
|---|---|---|
| **Retrofit** (user's existing phone) | the unit's vendor codec, wrapped via libhybris | already paid by the OEM; exhausted for that unit |
| **Manufacture** (fungOS hardware) | ODM-supplied or our own licensed codec build | us / the ODM, per device |

Retrofit is deliberately a *device-local* convenience: the vendor blob is never
redistributed, only executed on the hardware it came with.

### 4. FOSS distribution carries no codec obligation

Shipping `ims` as GPL source (Opus-only) creates no per-device royalty anywhere.
Downstream users and distributions may add AMR-WB/EVS under their own terms; the
project's own binaries remain free of encumbered code. The project will publish
a patent statement saying exactly this, modelled on the Linux-distro practice of
separating encumbered codecs into an optional package.

### 5. Manufacturing licensing is a product-time line item

For new hardware we take the pool licence (AMR-WB, plus EVS if HD voice is
required) **per device**, or inherit coverage from the ODM or a licensed codec
vendor (e.g. Fraunhofer for EVS). The cost that matters at low volume is the
annual minimum, not the per-unit rate. This is a contract with a legal entity,
so it is signed at company formation, not during development.

## Consequences

- Codec work never gates the protocol work. The SIP/AKA/RTP state machine can be
  built and tested entirely with Opus in a lab (Open5GS + Kamailio IMS).
- The GPL client stays attractive to OEMs and distros that cannot accept
  encumbered code in core.
- Retrofit mode gives Linux-phone users in-the-box VoLTE on hardware they
  already own, without the project ever shipping a codec it has no rights to.
- Extra complexity: a helper process boundary and, in retrofit mode, a
  libhybris dependency that is version-fragile across vendor blobs.

## Rejected alternatives

| Alternative | Why not |
|---|---|
| Ship AMR-WB (opencore-amr) in the main tree | puts patent exposure on every downstream distributor |
| Depend on the vendor codec always | ties a GPL client to closed 32-bit bionic blobs |
| Use Opus for carrier VoLTE | carriers will not negotiate it (IR.92 codec set) |
| Extract codec/IMS logic from KaiOS or vendor ROMs | proprietary expression; taints a GPL implementation. Facts (UA strings, feature tags, APN shapes) may be recorded; code may not be derived |
| Skip voice entirely | the whole point is that Linux phones lost calls when 2G/3G sunset |

## Open questions

1. Is **EVS** mandatory on the target carriers, or is AMR-WB still sufficient?
   (Determines whether one pool licence or two.)
2. Retrofit performance: is a libhybris codec hop fast enough for conversation
   latency on a 2018-era SoC, or is a 32-bit userspace the simpler answer?
3. For a product, does the ODM already carry codec coverage we can inherit
   (most do), making a direct pool licence unnecessary?
4. Emergency-call (E911) requirements per market — legal, not codec, but it
   gates shipping the same way.

## Amendment 1 — feature-gated AMR-WB crate (2026-10-26)

The original decision said AMR-WB/EVS stay *out of the repository*. That is
narrowed, not reversed:

- AMR-WB may exist in-tree **only** as the optional workspace member `codec-amr`,
  behind a **non-default** cargo feature (`amr-wb`).
- The default build, the published core crates and any `--no-default-features`
  build must contain **no codec implementation at all** — only the `Codec` trait
  and Opus. Distribution of the default artifact therefore still carries no codec
  royalty exposure.
- `codec-amr` binds to the **system** `libopencore-amrwb` (Apache-2.0
  implementation) and vendors **no C source**; patent rights are explicitly not
  granted (`codec-amr/PATENTS.md`).
- EVS remains out of tree entirely (no acceptable implementation to bind).

Rationale: the retrofit story needs AMR-WB on real hardware, and a feature flag
keeps the default artifact clean while letting a device image (or a distributor
with a licence) enable it deliberately. The two rules that do not change: the
core stays codec-free, and codec patents are the device maker's problem.
