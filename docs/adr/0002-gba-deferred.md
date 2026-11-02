# ADR: GBA (TS 33.220) for carrier entitlement — deferred

**Status:** deferred · **Scope:** any carrier-facing provisioning or entitlement
step that sits *outside* the 3GPP ePDG/IMS protocols.

## Context

Wi-Fi calling needs two things that are easy to conflate:

1. **The line is provisioned for VoWiFi** — a fact in the carrier's
   subscription database. The ePDG enforces it during EAP-AKA'.
2. **The device is entitled / configured** — for several carriers an HTTPS
   exchange with an entitlement server that returns policy and configuration.

Only (1) is 3GPP. (2) is carrier business logic: no spec defines it, and the
request shape differs per operator.

GBA (Generic Bootstrapping Architecture) is the *specified* way to authenticate
to an operator application using the SIM: the UE runs HTTP Digest over AKA with
a BSF on **Ub**, derives `Ks_NAF`, and uses it on **Ua** with the NAF. Interfaces
**Zh** (BSF↔HSS) and **Zn** (NAF→BSF, TS 29.109) are network-side; a UE never
speaks them.

## Decision

**Do not implement GBA now.** Revisit only when a real network refuses us in a
way that points at entitlement.

### What deferring it blocks

- Carriers whose entitlement step is a hard gate before the ePDG or IMS core
  will serve the subscriber. Unknown whether this applies to any of the test
  SIMs.
- Any NAF-fronted service in general (MCPTT, carrier portals, eMBMS keys).
  Out of scope for this project.
- **Diagnosis, not function:** without GBA, a refusal cannot be attributed to
  "device not entitled" versus "line not provisioned". That ambiguity is the
  real cost.

### What it does not block

- IKEv2, EAP-AKA′, child SA, S2b, NAT-T — entirely independent of GBA.
- IMS `REGISTER` over the tunnel. Registration is authenticated by AKA, not by
  GBA; the entitlement exchange is not part of TS 24.229 registration.
- The "SIM + Wi-Fi calling" milestone on any network where (1) alone is enough.

### Trigger to revisit

Any of:

- the ePDG accepts EAP-AKA′ but `REGISTER` is refused in a way not explained by
  our own headers or security agreement;
- an operator document states entitlement is mandatory for third-party clients;
- a refusal that survives fixing the IKE proposal set and AKA′ parameters.

A refusal that we cannot distinguish from "our IKE_SA_INIT was wrong" is *not* a
trigger — it is a reason to fix the protocol layer first.

## Structure, if it is built

Split along the same line as `epdg` / `lab-epdg`:

- **`gba` crate — protocol, no I/O.** BSF discovery names (same construction as
  ePDG discovery, TS 23.003), the Ub challenge and 401 handling (the nonce is
  wrapped with server data per TS 24.109 — to be read from the spec, not
  guessed), `Ks` → `Ks_NAF` derivation via the 3GPP KDF, and the Ua digest.
  Testable against a mock BSF and NAF, the same way `epdg` is tested against a
  stand-in responder.
- **`HttpChannel` trait — I/O.** Implemented by the userland/client crate with a
  real TLS stack, and by a mock in tests.

### Prerequisites (worth doing independently)

1. Move the RFC 3310 AKA digest out of `ims::auth` into `aka` — Ub needs exactly
   that primitive and it should not be duplicated.
2. Move `PlmnId` out of `epdg::discovery` to a neutral home, so `gba` does not
   depend on `epdg` for a type.

### The real decision it forces

GBA means the project's **first TLS client** and a new dependency class
(`rustls` + roots, or openssl). That changes the "small, pure-Rust, no async"
dependency story and deserves its own ADR rather than arriving behind a feature
flag.

## Known limitation of the idea

**GBA is the lock, not the door.** It authenticates the subscriber to a NAF; it
does not define what request the NAF expects. Even with GBA working, an
operator's entitlement API shape is vendor-derived and belongs in `docs/facts/`,
never in a protocol crate.
