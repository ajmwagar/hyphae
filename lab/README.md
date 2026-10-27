# IMS lab: Open5GS + Kamailio IMS + programmable USIM

Status: **plan plus a compose file**. The compose file has not been run in this
repository. The client-side protocol tests do not need the lab. This document is
the exact path to a real REGISTER once the images/configs are pinned.

## Target lab topology

```text
             SIP (UDP/TCP)                  SIP (ISC/Mw)
  ims client ───────────────► P-CSCF ─────────────────► S-CSCF
      │                         │                          │
      │ IMS PDN (APN=ims)       │ Rx                        │ Cx
      ▼                         ▼                           ▼
  Open5GS SMF/UPF  ◄────── PCRF (optional)          HSS (Open5GS)
      │
      └── GTP-U / N6 → application network
```

| Item | Lab value |
|---|---|
| MCC / MNC | `001` / `01` |
| IMS domain | `ims.mnc001.mcc001.3gppnetwork.org` |
| IMS APN | `ims` |
| P-CSCF | `pcscf.ims.mnc001.mcc001.3gppnetwork.org` |
| S-CSCF | `scscf.ims.mnc001.mcc001.3gppnetwork.org` |
| IMPI | `001010000000001@ims.mnc001.mcc001.3gppnetwork.org` |
| Test K / OP | 3GPP TS 35.208 test set 1 (public; see `.env.example`) |

The client profile is `carrier/profiles/00101.toml` and
`ims::ImsProfile::lab_default()`. It uses **static P-CSCF discovery** so the lab
works before PCO/DHCP is wired; switch `p_cscf_discovery` to `pco` only after the
modem adapter supplies the P-CSCF.

## Prerequisites

- Linux host (Ubuntu 22.04/24.04 recommended) with Docker Engine + Compose v2.
- 4 GB RAM, 20 GB disk.
- UDP/TCP 5060 free; GTP-U 2152; SBI 7777; DNS 53.
- A programmable USIM (sysmoUSIM-SJS1, 5G/eSIM test card) **or** a modem/QEMU
  path that can expose the same K/OP and IMSI. No production SIM is required.

## Step 1 — prepare configs

The compose file mounts `config/` so the images stay unmodified:

```sh
cd lab
cp .env.example .env
mkdir -p config/open5gs config/kamailio config/dns
```

1. **Open5GS** — take the upstream `open5gs-docker` config set and set the PLMN
   and subscriber store. Point the AMF/SMF at Mongo (`mongodb://mongo:27017` if
   you switch off host networking, or `mongodb://127.0.0.1:27017` with host
   networking). The IMS APN must be `ims`.
2. **Kamailio IMS** — use the `kamailio-ims` example config (P-CSCF + S-CSCF)
   from the Kamailio tree. Replace the realm/domain with
   `ims.mnc001.mcc001.3gppnetwork.org` and set the S-CSCF to fetch credentials
   from the HSS. Mount the result at `config/kamailio/kamailio.cfg`.
3. **DNS** — a minimal Corefile:

   ```text
   .:53 {
       errors
       hosts {
           172.22.0.10 pcscf.ims.mnc001.mcc001.3gppnetwork.org
           172.22.0.10 scscf.ims.mnc001.mcc001.3gppnetwork.org
           172.22.0.10 hss.ims.mnc001.mcc001.3gppnetwork.org
           fallthrough
       }
       forward . 1.1.1.1
   }
   ```

   With host networking, point the client's `/etc/hosts` at the same addresses
   or run the Corefile resolver on 127.0.0.1:53.

## Step 2 — provision the test subscriber

Using the public TS 35.208 test set 1 values from `.env.example`:

```sh
# Example with the Open5GS CLI; adapt to the version in your image.
open5gs-dbctl add 001010000000001 \
  465b5ce8b199b49faa5f0a2ee238a6bc \
  cdc202d5123e20f62b6d676ac72cb318
```

If the image has no `open5gs-dbctl`, insert the same IMSI/K/OP through the
Open5GS WebUI or `mongosh`. Verify the subscriber has APN `ims` and that the
AMF/SMF config uses MCC `001`, MNC `01`.

## Step 3 — start the lab

```sh
cd lab
docker compose config          # validate interpolation/mounts first
docker compose up -d
docker compose logs -f open5gs kamailio
```

On a non-Linux host, run this inside a Linux VM; `network_mode: host` is part of
the plan.

## Step 4 — program the USIM (or emulate)

With `pySim` and a PC/SC reader:

```sh
# Inspect first; do not overwrite an unknown card.
pySim-shell.py -p 0
# In pySim-shell: select ADf.ISIM / ADf.USIM and write IMSI, K, OP/OPc,
# plus the IMPU/domain if your card carries ISIM. The lab also works with a
# USIM-only card because IMPI is derived from IMSI per TS 23.003.
```

Record the card's K/OP in the HSS. If you use a modem with an internal eSIM,
provision the same values through the modem vendor tooling; the client only
needs the USIM AKA interface.

## Step 5 — run the client path

Until the standalone `ims` CLI lands, the executable checks are:

```sh
cargo test -p conformance
cargo run -p ims --example register_flow   # prints the exact REGISTER ladder
```

The example does not open a socket; it prints the bytes the transport would
send. A real REGISTER needs a transport adapter (phase 3) plus the USIM AKA
path. The expected sequence is:

```text
client → P-CSCF   REGISTER (Security-Client, Contact, Expires, feature tag)
P-CSCF → client   401 Unauthorized (WWW-Authenticate: AKAv1-MD5)
client → P-CSCF   REGISTER (Authorization: Digest ..., Security-Verify)
P-CSCF → client   200 OK (Service-Route, P-Associated-URI)
```

## What a successful REGISTER looks like

Kamailio/P-CSCF side:

```text
REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0
...
Security-Client: algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;...
...
SIP/2.0 401 Unauthorized
WWW-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org",
                  nonce="...", algorithm=AKAv1-MD5, qop="auth"
...
REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0
Authorization: Digest username="001010000000001@ims...", ...
...
SIP/2.0 200 OK
Service-Route: <sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>
P-Associated-URI: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>
Contact: <sip:001010000000001@<client-ip>:5060>;expires=600000
```

PCAP check:

```sh
sudo tcpdump -i any -n -s0 -w register.pcap udp port 5060
tshark -r register.pcap -Y sip -V | less
```

Success criteria:

1. First REGISTER has no `Authorization` but has one `Security-Client`.
2. The 401/407 challenge has `algorithm=AKAv1-MD5` and a nonce.
3. Second REGISTER has `Authorization` (or `Proxy-Authorization`) with
   `response=` and `nc=00000001`.
4. 200 OK carries `Service-Route`; the client stores it and uses it for the
   next in-dialog request.
5. A second REGISTER before expiry (with the same Call-ID and incremented CSeq)
   also returns 200.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 403 on first REGISTER | IMPI/IMPU not provisioned, or APN not `ims` |
| 401 loops forever | K/OP mismatch between USIM and HSS; wrong RES encoding |
| `Security-Client` rejected | P-CSCF IPsec profile/SPI mismatch; try `ealg=null` and a test SPI first |
| No P-CSCF resolution | DNS zone/hosts missing, or client still on `static` pointing at the wrong address |
| Media not establishing | expected: RTP/RTCP and IPsec are phase 3 TODO; this scaffold is control-plane only |
| `cargo test` tries the lab | it should not; default tests use `transport::MockTransport` and no network |

## Legal / safety

Use only test identities and test K/OP. Do not attach the lab to a production
network. The lab images are separate deployments (AGPL/GPL) and are not linked
into this GPL client.
