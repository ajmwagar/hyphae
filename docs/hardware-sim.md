# Hardware SIM bring-up

The IMS client is complete enough that the next dependency is real AKA vectors.
The hardware path is now a real `usim::ApduChannel`:

```text
USIM AUTHENTICATE (TS 31.102)
        │
        ├─ usim-pcsc  PC/SC reader (host / USB smart-card reader)
        ├─ usim::QmiApdu  modem UIM Send APDU (later, after modem bring-up)
        └─ usim::AtApdu   AT+CSIM (later, modem/AT channel)
```

`usim-pcsc` is a separate package, excluded from the default workspace so
`cargo test --workspace` stays pure Rust. It owns the PC/SC FFI; the core `usim`
crate remains `#![forbid(unsafe_code)]`.

## Build and inspect

Linux needs `libpcsclite-dev` and a running `pcscd`; macOS uses the system
PC/SC framework.

```sh
cargo run --manifest-path usim-pcsc/Cargo.toml -- list
cargo run --manifest-path usim-pcsc/Cargo.toml -- atr
cargo run --manifest-path usim-pcsc/Cargo.toml -- apdu 00A40004023F00
```

`--reader NAME` selects a specific reader; otherwise the first reader is used.
`apdu` prints the response data and status word. A bare `6A82` is a normal
"file not found" response, not a transport failure.

## AKA against a test card

For the stand-in ePDG, program a test SIM with the public TS 35.208 test set 1
(K/OPc) and run the same WiFi-calling exchange with the card in the reader:

```sh
cargo run -p epdg-lab --features pcsc -- --pcsc
```

Or against a listener:

```sh
cargo run -p epdg-lab --features pcsc -- --pcsc "ACS ACR38U" --connect 10.0.0.1:500
```

The `--pcsc` build reads the challenge from the ePDG, sends the TS 31.102
`AUTHENTICATE` APDU to the card, and uses the card's RES/CK/IK for EAP-AKA'.
It does not hold K/OPc in the client. The stand-in responder still uses the
public test key, so a test card is required for loopback.

For a one-off card check:

```sh
cargo run --manifest-path usim-pcsc/Cargo.toml -- \
  auth RAND_HEX AUTN_HEX --reader "ACS ACR38U"
```

The card must accept the AUTN; otherwise it returns `9862` (MAC failure) or an
AUTS synchronisation failure. The tool prints `res`, `ck`, `ik` or `auts`.

## Software proof without a reader

`lab/epdg` has `a_usim_backed_client_completes_the_exchange`: it uses the same
`UsimCard` boundary with a `LoopbackChannel` + `SoftwareUsim`, so the
USIM-backed ePDG path is exercised by `cargo test -p epdg-lab`.

## Order of work

1. **Hardware SIM** — PC/SC adapter and ePDG USIM boundary (this commit).
2. **WiFi calling** — run `epdg-lab --features pcsc` against the stand-in, then
   a real ePDG/operator profile. The protocol path is already complete; the
   remaining work is the real ePDG address, credentials and policy.
3. **Modem bring-up** — start MSS/remoteproc and use `usim::QmiApdu`
   (`/dev/cdc-wdm*` / QRTR) or `usim::AtApdu` for the phone's own SIM. Do not
   use a production SIM for lab testing; do not copy SIM secrets.

The phone's current mainline boot does not have the modem running, so the
phone's own SIM is not reachable until step 3. The PC/SC path is the lab bridge
that lets steps 1–2 proceed first.
