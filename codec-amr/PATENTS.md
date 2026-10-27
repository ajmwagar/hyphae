# AMR-WB patent notice

The optional AMR-WB backend in this crate links the **system**
`libopencore-amrwb`, an Apache-2.0-licensed implementation (OpenCORE).

The Apache-2.0 licence covers the **implementation**. It does **not** grant
any rights under the AMR-WB patent pool (Via LA / VoiceAge and others).

- The `amr-wb` and `amr-wb-dlopen` Cargo features are **off by default**.
- A default build contains no AMR-WB codec and links no C library.
- Distributors who enable the feature do so under their own patent analysis
  and are responsible for any licensing obligation in their jurisdiction.
- This repository does not vendor or redistribute libopencore-amrwb source or
  binaries. It only declares an optional link/dynamic-load dependency.

The pure-Rust RFC 4867 payload-format module (`src/rtp.rs`) is public IETF
specification work and carries no codec implementation. It remains available
with the feature off.

See the workspace `docs/references.md` and the binding ADR at
`/Users/ajmwagar/Documents/src/reversal/cat-s22/docs/adr-ims-codec-licensing.md`
for the full legal posture.
