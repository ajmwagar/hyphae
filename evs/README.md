# evs

The pure-Rust RTP **payload format** for the 3GPP Enhanced Voice Services (EVS)
codec, following **TS 26.445 appendix A** *Header-Full*. It is the EVS analogue
of the RFC 4867 module in [`codec-amr`](../codec-amr/README.md): packet layout
and frame classification for IMS/RTP, and nothing else.

## Default build

- No C dependency, no `unsafe` (crate-level `forbid(unsafe_code)`).
- `rtp` module:
  - the CMR byte (`H=1`, `T`, `D`) and its TS 26.445 Table A.3 rate table;
  - the ToC byte (`H=0`, `F`, `FT`), with **no** Q/P bits because every EVS
    frame is byte-aligned;
  - both EVS frame tables — Primary (`FT 0..=15`) and AMR-WB IO
    (`FT 16..=31`) — with speech/SID/SPEECH_LOST/NO_DATA classification;
  - single- and multi-frame serialise/parse round-trips with frame-size
    validation;
  - the Header-Compact, storage and multi-channel formats return
    `EvsError::Unsupported` (see below).
- Ships **no EVS speech codec**: it never encodes or decodes audio.

## What is deliberately not here

- **Header-Compact / storage / multi-channel.** These need bit-packing or
  channel interleaving that must not be inferred from a Header-Full buffer, so
  they return `EvsError::Unsupported`. This mirrors how `codec-amr` rejects the
  RFC 4867 bandwidth-efficient mode.
- **The codec itself.** Encoding/decoding EVS audio is a separate,
  feature-gated, patent-noticed package behind the `codec::Codec` trait.

## Example

```rust
use evs::rtp::{Cmr, Frame, ModeSet, Payload};

// One 13.2 kbps EVS Primary speech frame (33 octets).
let p = Payload::single_speech(4, vec![0xA5; 33]).unwrap();
let wire = p.to_bytes().unwrap();          // CMR byte + ToC + 33 octets
let back = Payload::parse(&wire).unwrap();
assert_eq!(back, p);
```

## Legal

Read [`PATENTS.md`](PATENTS.md). EVS is in a patent pool; the pool rights are
not granted by this tree's licences. The payload-format module carries no codec
implementation, but distributors still owe pool rights for any EVS use.
