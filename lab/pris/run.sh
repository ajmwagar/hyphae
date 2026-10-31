#!/usr/bin/env bash
# Lab run against the PRIS P-CSCF stand-in (no Docker). Drives the real hyphae
# UDP/TCP REGISTER path against a live SIP socket and tears everything down.
#
# Works from either the main working tree or a git worktree: it locates the
# workspace root (the dir holding the top-level Cargo.toml) and builds the CLI
# there if it is not already built.
#
# Usage:  ./run.sh            (lab-only test credentials, TS 35.208 set 1)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Walk up to the workspace root (the dir with the top-level Cargo.toml).
REPO_ROOT="$HERE"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/Cargo.toml" ]]; do
  REPO_ROOT="$(dirname "$REPO_ROOT")"
done
if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "could not find workspace root (top-level Cargo.toml) from $HERE" >&2
  exit 1
fi
BIN="$REPO_ROOT/target/debug/hyphae"

PORT="${PCSCF_PORT:-5060}"
CLIENT_PORT="${CLIENT_PORT:-5061}"

if [[ ! -x "$BIN" ]]; then
  echo "building hyphae-cli at $REPO_ROOT ..."
  cargo build -q --manifest-path "$REPO_ROOT/Cargo.toml" -p hyphae-cli
fi

# Lab-only public test credentials (3GPP TS 35.208 test set 1).
export HYPPHAE_RES_HEX=a54211d5e3ba50bf
export HYPPHAE_OPC_HEX=cd63cb71954a9f4e48a5994e37a02baf

echo "== workspace root: $REPO_ROOT"
echo "== starting P-CSCF stand-in on udp 127.0.0.1:$PORT =="
python3 "$HERE/pcscf.py" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 0.3
echo "== running hyphae (real UDP transport) =="
echo "    client binds 127.0.0.1:$CLIENT_PORT -> P-CSCF 127.0.0.1:$PORT"
"$BIN" \
  --transport udp \
  --p-cscf "127.0.0.1:$PORT" \
  --local-addr "127.0.0.1:$CLIENT_PORT" \
  --imsi 001010000000001 \
  --once \
  --verbose
rc=$?

echo "== exit code: $rc =="
exit $rc
