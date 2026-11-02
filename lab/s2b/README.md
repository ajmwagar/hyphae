# S2b tunnel verification

`transport::ipsec::TunnelProgram` renders the `ip` commands that install the
Wi-Fi calling tunnel. This directory checks that those commands *work*, not
merely that `ip` accepts the syntax.

## What it does

1. Renders both sides of a tunnel with
   `cargo run -p transport --example s2b_commands -- ue|epdg`.
2. Builds two network namespaces joined by a veth pair — the "UE" and the
   "ePDG" — and applies each side's generated commands.
3. Pings across the tunnel in both directions. The kernel does the ESP.

A pass means the generated states, policies and routes form a working SA pair.

## Run

```sh
./lab/s2b/verify.sh          # Linux container via docker
./lab/s2b/verify.sh --local       # directly, needs root + iproute2
./lab/s2b/verify.sh --remote pris # render here, run the container on pris
```

Expected:

```text
=== ue -> epdg (10.1.0.1) ===
PASS
=== epdg -> ue (10.1.2.3) ===
PASS
ok: the generated S2b commands carry traffic both ways
```

## What it caught

Two things that are invisible without a kernel:

- **`auth` defaults the ICV to 96 bits.** `ip xfrm state add ... auth
  hmac(sha256) <key>` installs a 96-bit ICV, not the 128 bits RFC 4868
  negotiates for `AUTH_HMAC_SHA2_256_128`. The generator emits
  `auth-trunc hmac(sha256) <key> 128`.
- **A policy template must repeat the state's `if_id`.** A state created with
  `if_id N` is only found by a template that also carries `if_id N`; otherwise
  the bundle lookup fails with `XfrmOutNoStates` and every packet is dropped.
  Policies therefore carry `if_id` instead of `dev`.

Both were found by running the commands against iproute2 6.1 on a real kernel.
