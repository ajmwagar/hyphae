#!/bin/sh
# Prove that the generated S2b install commands actually carry traffic.
#
# Builds two mirrored XFRM tunnels — one per network namespace, the kernel doing
# the ESP — and pings across them. This checks the *result* of
# `transport::ipsec::TunnelProgram`, not just that `ip` accepted the syntax.
#
#   ./lab/s2b/verify.sh              # run in a local Linux docker container
#   ./lab/s2b/verify.sh --local      # run directly (needs root + iproute2)
#   ./lab/s2b/verify.sh --remote H   # render here, run the container on H
#
# Rendering the command files needs cargo; running them needs a Linux kernel.
# `--remote` covers the common case: a Mac dev box with cargo, a Linux lab host
# with docker. Run from the repo root.

set -eu

MODE=${1:-docker}
HOST=$2
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "gen: rendering the two sides"
cargo run -q -p transport --example s2b_commands -- ue >"$WORK/ue.sh"
cargo run -q -p transport --example s2b_commands -- epdg >"$WORK/epdg.sh"

run_local() {
    NS=ue   apply "$WORK/ue.sh"
    NS=epdg apply "$WORK/epdg.sh"
    hdr "ue -> epdg (10.1.0.1)"
    ip netns exec ue ping -c2 -W1 10.1.0.1 >/dev/null && echo PASS || { echo FAIL; exit 1; }
    hdr "epdg -> ue (10.1.2.3)"
    ip netns exec epdg ping -c2 -W1 10.1.2.3 >/dev/null && echo PASS || { echo FAIL; exit 1; }
}

hdr() { echo "=== $* ==="; }

apply() {
    while IFS= read -r line; do
        set -- $line
        shift                        # the file's first word is "ip"
        ip -n "$NS" "$@" || {
            echo "  !! failed in $NS: $line"
            exit 1
        }
    done <"$1"
}

cleanup_ns() {
    ip netns del ue 2>/dev/null || true
    ip netns del epdg 2>/dev/null || true
    ip link del veth0 2>/dev/null || true
}

setup() {
    cleanup_ns
    ip link add veth0 type veth peer name veth1
    ip netns add ue
    ip netns add epdg
    ip link set veth0 netns ue
    ip link set veth1 netns epdg
    ip -n ue addr add 192.0.2.10/24 dev veth0
    ip -n epdg addr add 192.0.2.1/24 dev veth1
    ip -n ue link set veth0 up
    ip -n epdg link set veth1 up
    ip -n ue link set lo up
    ip -n epdg link set lo up
}

# The ePDG owns a host address inside its own selector; the generator only
# assigns the UE's inner address, so add one for the loopback ping.
epdg_host_addr() {
    ip -n epdg addr add 10.1.0.1/16 dev ipsec0 2>/dev/null || true
    ip -n epdg del 10.1.0.0/16 dev ipsec0 2>/dev/null || true
}

if [ "$MODE" = "--local" ]; then
    setup
    run_local
    epdg_host_addr
    echo "ok: the generated S2b commands carry traffic both ways"
    cleanup_ns
    exit 0
fi

CONTAINER=$(cat <<'INNER'
docker run --rm --privileged -v /tmp/hyphae-s2b:/mnt:ro docker.io/library/debian:12-slim sh -c '
set -e
apt-get -qq update >/dev/null 2>&1
apt-get -qq install -y iproute2 iputils-ping >/dev/null 2>&1
mkdir -p /run/netns
cp /mnt/ue.sh /ue.sh
cp /mnt/epdg.sh /epdg.sh
ip link add veth0 type veth peer name veth1
ip netns add ue
ip netns add epdg
ip link set veth0 netns ue
ip link set veth1 netns epdg
ip -n ue   addr add 192.0.2.10/24 dev veth0
ip -n epdg addr add 192.0.2.1/24  dev veth1
ip -n ue   link set veth0 up
ip -n epdg link set veth1 up
ip -n ue   link set lo up
ip -n epdg link set lo up

apply() {
  while IFS= read -r line; do
    set -- $line
    shift
    ip -n "$NS" "$@" || { echo "  !! failed in $NS: $line"; exit 1; }
  done < "$1"
}
NS=ue;   apply /ue.sh
NS=epdg; apply /epdg.sh
ip -n epdg addr add 10.1.0.1/16 dev ipsec0 2>/dev/null || true
ip -n epdg del 10.1.0.0/16 dev ipsec0 2>/dev/null || true

echo "=== ue -> epdg (10.1.0.1) ==="
ip netns exec ue ping -c2 -W1 10.1.0.1 >/dev/null && echo PASS || { echo FAIL; exit 1; }
echo "=== epdg -> ue (10.1.2.3) ==="
ip netns exec epdg ping -c2 -W1 10.1.2.3 >/dev/null && echo PASS || { echo FAIL; exit 1; }
echo "ok: the generated S2b commands carry traffic both ways"
'
INNER
)

if [ "$MODE" = "--remote" ]; then
    [ -n "${HOST:-}" ] || { echo "usage: $0 --remote <host>" >&2; exit 2; }
    echo "run: copying the rendered sides to $HOST"
    ssh "$HOST" 'rm -rf /tmp/hyphae-s2b && mkdir -p /tmp/hyphae-s2b'
    scp -q "$WORK/ue.sh" "$WORK/epdg.sh" "$HOST:/tmp/hyphae-s2b/"
    ssh "$HOST" "$CONTAINER"
    exit $?
fi

sh -c "$CONTAINER"
