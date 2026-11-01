# PRIS lab run — the client against a live P-CSCF socket

The `lab/` compose file targets Docker + `network_mode: host`, which needs a
Linux host and images/configs that are not vendored in this repo. This directory
runs the **same REGISTER ladder** on any host that can bind a UDP socket —
including macOS — by replacing the Open5GS/Kamailio P-CSCF with a faithful
stand-in that exercises the client's real `transport::net` UDP path.

## What it proves

The client's live control-plane path, not the mock:

1. `REGISTER` with `Security-Client`, no `Authorization` →
   `401 Unauthorized` with `WWW-Authenticate: AKAv1-MD5` + a nonce.
2. `REGISTER` with `Authorization: Digest response=…, nc=00000001` → the
   stand-in **verifies** the AKAv1-MD5 response against the public TS 35.208
   test-set-1 RES and returns `200 OK` with `Service-Route` + `P-Associated-URI`.

A wrong RES is rejected with another 401 (the server does not rubber-stamp).

## Run

```sh
cd lab/pris
./run.sh
```

This starts `pcscf.py` on `127.0.0.1:5060`, runs the built `hyphae` CLI over UDP
from `127.0.0.1:5061`, and tears the server down. Expected tail:

```text
hyphae: registered (200 OK) as sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org; Service-Route sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr
```

## Files

- `pcscf.py` — a ~180-line UDP SIP P-CSCF stand-in: issues the AKAv1-MD5
  challenge, verifies the client's digest, returns the 200 OK. Uses only the
  Python standard library.
- `run.sh` — starts the stand-in, runs the client with the public test
  credentials, tears down.

## Credentials

Public test vector only (3GPP TS 35.208 test set 1), supplied via
`HYPPHAE_RES_HEX` / `HYPPHAE_OPC_HEX`. No production SIM and no USIM adapter are
involved; the RES stands in for what a USIM AKA adapter would return.

## Relationship to the Docker lab

This is the runnable subset of `lab/README.md` "What a successful REGISTER
looks like". The full Open5GS + Kamailio deployment (HSS, SMF/UPF, GTP-U, real
IPsec SA) is the larger `lab/` plan and still needs a Linux host with Docker.
