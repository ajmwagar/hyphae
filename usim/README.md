# usim

USIM AKA adapter for the IMS client: the **TS 31.102 `AUTHENTICATE`** APDU
codec, the card boundary, and a Milenage-backed software USIM for the lab.

## What is here

| Module | Contents |
|---|---|
| `apdu` | `AUTHENTICATE` command build and response parse, TS 31.102 §7.1.2 |
| `card` | `ApduChannel` trait, `UsimCard`, `LoopbackChannel`, `decode_authenticate_command` |
| `software` | `SoftwareUsim` — Milenage in-process, for host tests and the lab |

## The APDU (TS 31.102 §7.1.2.1)

```text
00 88 00 01 22  10 <RAND:16> 10 <AUTN:16>  00
CLA INS P1 P2 Lc
```

* `P2 = 01` selects the 3G/EPS/5G security context.
* Success response: `DB L3 <RES> L4 <CK> L5 <IK> [08 <KC:8>]`
* Sync failure: `DC L1 <AUTS:14>`

Both parsers bound-check every length field.

## No FFI

This crate never opens a reader. A real PC/SC (`libpcsclite`) adapter lives
outside the tree and implements `ApduChannel`:

```rust
use usim::{ApduChannel, CardResponse, UsimCard, UsimError};

struct Pcsc { /* ... */ }

impl ApduChannel for Pcsc {
    fn transmit(&mut self, _command: &[u8]) -> Result<CardResponse, UsimError> {
        // SCardTransmit(...) and split the trailing status word.
        unimplemented!("out-of-tree adapter")
    }
}
```

The crate is `#![forbid(unsafe_code)]` and has no C dependency.

## Lab / tests

`SoftwareUsim` runs the same Milenage arithmetic the card would, so the whole
path is testable without hardware:

```rust
use usim::{LoopbackChannel, SoftwareUsim, Usim, UsimCard};

let mut card = UsimCard::new(LoopbackChannel::new(SoftwareUsim::new(k, op, sqn)));
let out = card.authenticate(&rand, &autn)?;   // RES / CK / IK, or AUTS
# Ok::<(), usim::UsimError>(())
```

The test vector is 3GPP **TS 35.208 test set 1**.

## Secrets

`K`/`OPc` live only inside `SoftwareUsim`, are never formatted into an error,
and `Debug` does not print them.
