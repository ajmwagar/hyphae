# hyphae-modem

QMI over QRTR modem bring-up in Rust: open the BAM DMUX data port, start an
LTE bearer on it, configure the interface, and keep it alive.

This replaces the Python/libqmi prototype that validated the sequence on a
Qualcomm msm8937 (CAT S22 Flip). No `libqmi`, no GLib, no C library.

## What it does

```text
  DPM  Open Port             service 47, 0x0020   starts the BAM DMUX handshake
  WDS  Bind Mux Data Port    service  1, 0x00a2   on the client that will start
  WDS  Start Network         service  1, 0x0020   APN, IPv4 -> packet data handle
  WDS  Get Current Settings  service  1, 0x002d   address, gateway, DNS, MTU
  WDS  Stop Network          service  1, 0x0021   on teardown
```

The two constraints that shape the crate:

* **The DPM port comes first.** Opening it is what makes the modem start the
  BAM DMUX power-control handshake; without it the data path never comes up.
* **The bind and the start must share one WDS client.** `Bind Mux Data Port`
  applies to the client that sent it, and on QRTR a client *is* the socket the
  request arrived on. `qmicli` allows one action per invocation, so the bind was
  always lost before `Start Network` ran and the modem answered
  `INVALID_OPERATION` (70). That is the whole reason the prototype was a Python
  program, and it is why `bearer::Modem` keeps one client for the life of the
  bearer.

## Modules

| module | role |
|---|---|
| `qrtr` | addresses, the 20-byte control packet, `NEW_LOOKUP`, the `AF_QIPCRTR` socket |
| `qmi` | 7-byte frame, TLVs, transaction correlation, protocol errors |
| `dpm` | `Open Port`, endpoint types, BAM DMUX pipe ids |
| `wds` | bind/start/stop/get-current-settings, `BearerConfig` |
| `bearer` | the `Unbound → PortOpen → Bound → Connected → Lost` state machine |
| `netlink` | rtnetlink encoders and the interface configuration |
| `link` | the QRTR/QMI implementation of `bearer::Modem` |
| `cli` | the `hyphae-modem` command line |

## Feature gate

`modem-qmi` is **off by default**:

* default build — codecs, state machine and netlink encoders, no `libc`, no
  sockets, no `unsafe`. The IMS and lab builds keep their dependency graph.
* `--features modem-qmi` — adds `libc` and compiles the sockets, `link` and the
  binary. Linux only; on another host those modules are not compiled and the
  binary exits with a message.

```console
$ cargo test -p hyphae-modem
$ cargo check -p hyphae-modem --features modem-qmi --target aarch64-unknown-linux-gnu
$ cargo clippy -p hyphae-modem --all-targets
```

## Unsafe policy

`#![deny(unsafe_code)]` at the crate root, with `#[allow(unsafe_code)]` on two
modules that exist only to make syscalls: `qrtr`'s socket (`socket`, `bind`,
`getsockname`, `sendto`, `recvfrom`, `poll`) and `netlink`'s (`socket`, `bind`,
`send`, `recv`, `poll`, `if_nametoindex`). Each block is one syscall over
locally built arguments and carries a `// SAFETY:` note. `forbid` is not
reachable — `AF_QIPCRTR` and `NETLINK_ROUTE` have no `std` wrapper — so `deny`
plus two named modules is the strongest policy this crate can satisfy.

## Where the wire facts come from

This matters more than usual here: a wrong message id is a silent failure, and
the Python prototype is not in the tree. Every constant in the crate has one of
the provenances below.

**Captured from the target** (`MPSS.JO.3.3-...SDM439_GENNS_PACK`, kernel 7.3
`-fungos+`, msm8937) with a read-only probe: sockets built with `ctypes`, one
QRTR lookup, two WDS reads and one netlink dump. These exact bytes are in the
tests.

| capture | used by |
|---|---|
| `NEW_LOOKUP` request `0a 00 00 00 ...` to `(local node, 0xfffffffe)` | `qrtr::CtrlPacket` |
| `NEW_SERVER` replies for DPM (`service 47`, node 0, port 37) and WDS (`service 1`, node 0, port 39), and the all-zero terminator | `qrtr::CtrlPacket` |
| `Get Current Settings` request `00 02 00 2d 00 07 00 10 04 00 10 23 00 00` | `wds` request mask 0x2310 |
| `Get Current Settings` rejected with `OUT_OF_CALL` (15) on a client that owns no call | `qmi` result mapping |
| a successful WDS response (result 0/0 plus a TLV) | `qmi` decoder |
| an `RTM_GETADDR` dump (lo, usb0, wlan0 + `NLMSG_DONE`) | `netlink` parser |

One captured detail is easy to miss: the QMI frame over QRTR has a **7-byte**
header — type, transaction, message id **and a 16-bit TLV length**. The same
request without the length field was answered `NO_MEMORY`; with it, the modem
parsed the request and answered `OUT_OF_CALL`.

**From public protocol sources.** Message and TLV ids are the ones libqmi
publishes in `data/qmi-service-{dpm,wds}.json`, which `qmicli` — installed on
the target — uses against this firmware; QRTR's control numbering is libqrtr's
`include/libqrtr.h`. Endpoint type 5 is `BAM_DMUX`, IP family 4 is IPv4, and
the requested-settings bits (address 1<<8, gateway 1<<9, DNS 1<<4, MTU 1<<13)
are the same enumerations.

**From the device, as facts** (recorded here rather than in `docs/facts/`
because this crate owns them for now): the BAM DMUX pipes `tx 4` / `rx 5` come
from the device tree's `dmas = <&bam_dmux_dma 4>, <&bam_dmux_dma 5>` named
`tx`, `rx`; the modem is QRTR node 0 and the host node 1; the APN for the
installed SIM is `fast.t-mobile.com`; the validated bearer reported address
`192.0.0.2`, gateway `192.0.0.1`, DNS `192.0.0.1`, MTU `1472`, and
`ping -c3 8.8.8.8` answered 3/3 at 23–31 ms.

## What is verified, and what is not

Verified without hardware:

* every codec against the vectors above, including the error path;
* the state machine against a mock modem that enforces "bind on the same
  client", covering the happy path, `INVALID_OPERATION` on start, and recovery
  after a simulated reset;
* the interface layer's ordering rules, which run under
  `cargo test -p hyphae-modem --features modem-qmi --target x86_64-unknown-linux-gnu`:
  building the configurator never needs the interface to exist, and
  `configure` waits for it.

Verified on the CAT S22 (`40b89e5c`): the whole sequence — DPM open, bind,
start, settings and the rtnetlink writes — brings `wwan0` up with
`192.0.0.2/32` and a default route via `192.0.0.1 dev wwan0`; `ping -c3 8.8.8.8`
answered 3/3 at 45–52 ms. That run settles the IPv4 byte order: the address is
`192.0.0.2`, not `2.0.0.192`.

Not yet verified on hardware:

* the DNS and MTU values that run read (same parsing path as the address, but
  the values are not in its record);
* recovery after a real modem reset — the state machine covers it with a mock,
  the device has not had one while the bearer was up;
* `--lookup` and `--dry-run` on the device.

## Running it on the phone

Cross-compile on a Linux host with an aarch64 toolchain (this macOS checkout can
only `cargo check` the target):

```console
$ cargo build -p hyphae-modem --release --features modem-qmi \
      --target aarch64-unknown-linux-gnu
$ ssh root@192.168.77.2 'cat > /usr/local/bin/hyphae-modem && chmod +x /usr/local/bin/hyphae-modem' \
      < target/aarch64-unknown-linux-gnu/release/hyphae-modem
```

Then, on the phone, in this order:

```console
# 0. read-only: does the name service still publish the two services?
/usr/local/bin/hyphae-modem --lookup

# 1. the QMI sequence, printing what the modem reported; the interface is
#    untouched, but a real data call IS started and then stopped
/usr/local/bin/hyphae-modem --apn fast.t-mobile.com --dry-run

# 2. the real thing: bring the bearer up, configure wwan0, hold it for a minute
/usr/local/bin/hyphae-modem --apn fast.t-mobile.com --hold 60

# 3. in another shell while it holds
ping -c3 8.8.8.8
ip -4 addr show wwan0; ip route show default
```

Step 2 prints the address, gateway, DNS and MTU the modem reported and the
state transitions as they happen; it needs `CAP_NET_ADMIN` (root) and an
interface named `wwan0` (`--iface` if the driver names it differently).

`configure` runs right after `Start Network` and waits up to five seconds for
`wwan0` to appear, because `bam-dmux` creates the netdev from a work item once
the modem opens its channel. On a cold device that is the first moment the name
resolves, so nothing has to be brought up by hand before step 2.

## Known gaps

* No `WDS` event-report subscription: loss is noticed when a request fails or
  the QRTR node disappears, reported through `Supervisor::note_loss`.
* The DPM port is never closed. It is one-shot per modem boot — opening it
  again after a reset is what restarts the handshake — so teardown leaves it.
* MTU is read but not applied to the interface; the prototype did not set it
  either.
* `docs/facts/` would be the repo-idiomatic home for the device facts above;
  they live here until the crate is merged.
