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

# Hardware SIM: the UE asks the PC/SC card for RES/CK/IK instead of holding K/OPc.
cargo run -p epdg-lab --features pcsc -- --pcsc
cargo run -p epdg-lab --features pcsc -- --pcsc "ACS ACR38U" --connect 10.0.0.1:500
```

`--pcsc` requires a PC/SC reader (Linux: `libpcsclite-dev` + `pcscd`) and a
test card programmed with the public TS 35.208 test set 1 for the stand-in
responder. The default build stays pure Rust and does not link PC/SC.

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

## NAT traversal

`--force-nat-t` exercises the encapsulated path even when the path has no NAT,
so the 4500 framing can be tested on its own:

```sh
epdg-lab --listen 0.0.0.0:500            # binds 500 and 4500
epdg-lab --connect <host>:500 --force-nat-t
```

Verified end to end across a real WAN (a Mac on one side, `pris` on the other):
IKE_SA_INIT on 500, then every IKE_AUTH datagram on 4500 with the 4-octet
non-ESP marker, exchange complete. The same path is covered by
`the_ike_exchange_completes_with_udp_encapsulation`, which uses two sockets to
stand in for 500 and 4500. Detection itself is exercised by the unit tests and by
`epdg::sa`'s notify round-trip; a tailnet path passes addresses through
unchanged, so it correctly reports no NAT.

## Interop notes

Driving the client against strongSwan is possible up to a point, and the point
is informative:

- strongSwan 6.0.1 **cannot be an ePDG responder**. Its `eap-aka` plugin
  advertises `EAP_AKA` (type 23) only; `src/libstrongswan/eap/eap.h` defines no
  type 50, and `grep -rni "aka.prime"` over the tree finds nothing. Wi-Fi
  calling needs EAP-AKA' (TS 33.402), so a strongSwan peer stops after issuing
  an AKA challenge.
- Everything before that *does* interoperate, which is how the three bugs in
  "What it caught" were found: charon verifies the SK ICV, decrypts, parses
  `IDi`, matches the NAI to a peer config, and starts EAP.

To interop all the way, the responder needs an EAP-AKA' server — hostapd ships
one (`eap_server_aka_prime`), reachable from strongSwan through its
`eap-radius` plugin.

## What it is not

No rekeying, no liveness check, no NAT-T, a fixed RAND, and — because the crates
have no RNG — IVs derived from the message id. A real client must use a fresh
unpredictable IV; reusing one under the same key is a break.
