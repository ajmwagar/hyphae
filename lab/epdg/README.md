# ePDG lab — the Wi-Fi calling exchange over UDP

The protocol crates contain no sockets, so this crate owns the network. It is
the closest thing in the tree to a real Wi-Fi calling client, and it runs
without a modem, a SIM reader, or an operator network.

## Two halves

- **`UeClient`** — the UE. Drives IKE_SA_INIT, then the EAP-only IKE_AUTH of
  RFC 5998. It holds `K`/`OPc` and runs Milenage **as a USIM would**: the RAND
  the network picks is what drives `RES`, `CK`, `IK`, `CK'`/`IK'` and the EAP
  key set.
- **`StandInEpdg`** — a stand-in ePDG. Picks the RAND, issues the AKA'
  challenge, verifies `AT_RES` and the client's `AUTH`, and answers with a child
  SA and a `CFG_REPLY`.

The two share **only the subscriber key**. A completed exchange therefore means
the whole key chain agreed, not that both sides used one fixture.

## Run

```sh
cargo run -p epdg-lab            # both halves on loopback
cargo run -p epdg-lab -- --listen 0.0.0.0:500
cargo run -p epdg-lab -- --connect 10.0.0.1:500
```

Expected:

```text
hyphae-epdg: established; UE IMS address 10.32.0.7, out spi 0x1000, in spi 0x1001
hyphae-epdg: authenticated; IMS address 10.32.0.7
hyphae-epdg: child SA out spi 0x1000 (cbc(aes)) in spi 0x1001 (hmac(sha256))
hyphae-epdg: DNS 10.32.0.1
```

## What it caught

- **The message id was stamped after sealing, not before.** The client answered
  the challenge with the same id it had just received, instead of starting a new
  exchange. The unit test missed it because its hand-built responder used 1, 2, 3
  regardless; a responder that echoes the id it received fails immediately.
- **`parse_attributes` returns values with their padding**, because the EAP
  attribute length counts 4-octet units (RFC 4187 §10.1) and the value/padding
  boundary is not on the wire. `AT_RAND` arrives as 20 octets for a 16-octet
  value.

## What it is not

No rekeying, no liveness check, no NAT-T, a fixed RAND, and — because the crates
have no RNG — IVs derived from the message id. A real client must use a fresh
unpredictable IV; reusing one under the same key is a break.
