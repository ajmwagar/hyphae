#!/usr/bin/env python3
"""Minimal P-CSCF stand-in for the hyphae lab run (no Docker required).

This reproduces exactly the wire behaviour the Open5GS + Kamailio lab would
exercise for a REGISTER, per lab/README.md "What a successful REGISTER looks
like":

  1. client -> P-CSCF  REGISTER (Security-Client, no Authorization)
  2. P-CSCF -> client  401 Unauthorized (WWW-Authenticate: AKAv1-MD5, nonce)
  3. client -> P-CSCF  REGISTER (Authorization: Digest response=..., nc=00000001)
  4. P-CSCF -> client  200 OK (Service-Route, P-Associated-URI)

Unlike the mock transport inside the client, this server *verifies* the
client's AKAv1-MD5 response against the public TS 35.208 test-set-1 RES, so a
wrong RES is rejected with another 401. It listens on UDP because the client's
lab transport is UDP by default.

Run:  python3 pcscf.py            (binds 127.0.0.1:5060)
"""

import os
import socket
import sys
import time
from hashlib import md5

# 3GPP TS 35.208 test set 1. Public test vector; lab/mock only.
RES_HEX = "A54211D5E3BA50BF"          # uppercase hex, as aka_password() emits it
IMSI = "001010000000001"
MCC, MNC = "001", "01"
DOMAIN = f"ims.mnc{MNC}.mcc{MCC}.3gppnetwork.org"
SCSCF = f"scscf.{DOMAIN}"
BIND = "127.0.0.1"
PORT = int(os.environ.get("PCSCF_PORT", "5060"))

# Last nonce handed out; the client must answer that exact nonce.
_last_nonce = None


def log(msg: str) -> None:
    print(f"[pcscf {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def parse_request(raw: bytes):
    """Return (method, request_uri, headers-dict, from_tag) or None."""
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    method, req_uri, _ver = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    from_tag = None
    from_h = headers.get("from", "")
    if ";tag=" in from_h:
        from_tag = from_h.split(";tag=", 1)[1].strip()
    return method, req_uri, headers, from_tag


def split_params(digest: str):
    """Parse a `Digest ...` header body into a dict of lower-cased keys."""
    params = {}
    for part in digest.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = v.strip().strip('"')
    return params


def verify(headers: dict) -> tuple[bool, str]:
    """Recompute the client's AKAv1-MD5 response and compare."""
    auth = headers.get("authorization", "")
    if not auth.startswith("Digest"):
        return False, "no Authorization"
    p = split_params(auth[len("Digest"):].strip())
    realm = p.get("realm", DOMAIN)
    nc = p.get("nc", "00000001")
    qop = p.get("qop", "auth")
    ha1 = md5(f'{p.get("username", "")}:{realm}:{RES_HEX}'.encode()).hexdigest()
    ha2 = md5(f'REGISTER:{p.get("uri", "")}'.encode()).hexdigest()
    expected = md5(
        f'{ha1}:{p.get("nonce", "")}:{nc}:{p.get("cnonce", "")}:{qop}:{ha2}'.encode()
    ).hexdigest()
    got = p.get("response", "")
    return (got == expected), f"expected {expected}, got {got}"


def reply(sock, dest, status_line, headers, nonce=None):
    """Build and send a SIP response, echoing Via/Call-ID/CSeq/From."""
    parts = [status_line]
    for k, v in headers:
        parts.append(f"{k}: {v}")
    parts.append("Content-Length: 0")
    msg = "\r\n".join(parts) + "\r\n\r\n"
    sock.sendto(msg.encode(), dest)
    log(f"-> {status_line}" + (f"  (nonce {nonce[:8]}…)" if nonce else ""))


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND, PORT))
    log(f"listening on udp {BIND}:{PORT}; realm={DOMAIN}")
    try:
        while True:
            raw, dest = sock.recvfrom(65535)
            parsed = parse_request(raw)
            if not parsed:
                log(f"<- {len(raw)} bytes (unparseable)")
                continue
            method, req_uri, headers, from_tag = parsed
            log(f"<- {method} {req_uri}  via {headers.get('via', '')[:60]}")
            cseq = headers.get("cseq", "")
            call_id = headers.get("call-id", "")
            via = headers.get("via", f"SIP/2.0/UDP {BIND}:{PORT}")
            from_h = headers.get("from", f"<sip:{IMSI}@{DOMAIN}>")
            to_h = headers.get("to", f"<sip:{IMSI}@{DOMAIN}>")

            if "authorization" not in headers:
                # Step 2: challenge with AKAv1-MD5.
                global _last_nonce
                nonce = md5(os.urandom(16)).hexdigest()
                _last_nonce = nonce
                www_auth = (
                    f'Digest realm="{DOMAIN}", nonce="{nonce}", '
                    "algorithm=AKAv1-MD5, qop=\"auth\""
                )
                to_tag = md5(nonce.encode()).hexdigest()[:8]
                reply(
                    sock, dest, "SIP/2.0 401 Unauthorized",
                    [
                        ("Via", via),
                        ("From", from_h),
                        ("To", f"{to_h};tag={to_tag}"),
                        ("Call-ID", call_id),
                        ("CSeq", cseq),
                        ("WWW-Authenticate", www_auth),
                    ],
                    nonce=nonce,
                )
                continue

            # Step 3/4: authorized REGISTER — verify then 200 OK.
            ok, why = verify(headers)
            if not ok:
                log(f"  digest mismatch: {why}")
                reply(
                    sock, dest, "SIP/2.0 401 Unauthorized",
                    [
                        ("Via", via),
                        ("From", from_h),
                        ("To", f"{to_h};tag={md5(_last_nonce.encode()).hexdigest()[:8]}"),
                        ("Call-ID", call_id),
                        ("CSeq", cseq),
                        ("WWW-Authenticate",
                         f'Digest realm="{DOMAIN}", nonce="{_last_nonce}", '
                         "algorithm=AKAv1-MD5, qop=\"auth\""),
                    ],
                    nonce=_last_nonce,
                )
                continue
            log(f"  digest OK: {why}")
            contact = headers.get("contact", f"<sip:{IMSI}@{BIND}:{PORT}>")
            reply(
                sock, dest, "SIP/2.0 200 OK",
                [
                    ("Via", via),
                    ("From", from_h),
                    ("To", f"{to_h};tag={md5(_last_nonce.encode()).hexdigest()[:8]}"),
                    ("Call-ID", call_id),
                    ("CSeq", cseq),
                    ("Contact", contact),
                    ("Service-Route", f"<sip:orig@{SCSCF};lr>"),
                    ("P-Associated-URI", f"<sip:{IMSI}@{DOMAIN}>"),
                ],
            )
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
