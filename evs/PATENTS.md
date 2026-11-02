# EVS patent notice

This crate implements the **payload (packet) format** of the 3GPP Enhanced
Voice Services (EVS) codec, following **TS 26.445 appendix A** *Header-Full*
format. It is the EVS analogue of the RFC 4867 module in `codec-amr`.

EVS is a patented 3GPP speech/audio codec. Its patents sit in a licensing pool
(Via LA administers the EVS pool on behalf of holders that include
Fraunhofer and others). As with AMR-WB, the text of this repository's
Apache-2.0 / GPL-3.0-or-later licences covers the **implementation** but does
**not** grant any rights under the EVS patent pool.

- The crate ships **no EVS speech codec**. It never encodes or decodes audio;
  it only lays out and parses RTP packets. There is no C and no `unsafe`.
- The payload-format module (`src/rtp.rs`) is public 3GPP specification work.
  It remains available with everything off.
- The Header-Compact, storage and multi-channel EVS payloads are **not**
  implemented; they return an explicit `Unsupported` error rather than
  guessing at bit packing or channel interleaving. Only the Header-Full format
  is provided.
- Distributors who use the EVS payload format on the wire do so under their own
  EVS pool analysis and are responsible for any licensing obligation in their
  jurisdiction.

The binding decisions on codec licensing and distribution are in the project
ADR `~/Documents/src/reversal/cat-s22/docs/adr-ims-codec-licensing.md`,
mirrored in-tree at [`docs/adr/0001-codec-licensing.md`](docs/adr/0001-codec-licensing.md).
See the workspace `docs/references.md` for the full legal posture.
