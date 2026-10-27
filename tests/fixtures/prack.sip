# PRACK for the reliable 183 above. RFC 3262 §4, RFC 3261 §12.
PRACK sip:001010000000002@192.0.2.11:5060 SIP/2.0
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-prack;rport
Max-Forwards: 70
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=caller-tag
To: <sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag
Call-ID: golden-call-1@192.0.2.10
CSeq: 2 PRACK
RAck: 1 1 INVITE
Contact: <sip:001010000000001@192.0.2.10:5060>
User-Agent: fungos-ims/0.1 (Linux)
Content-Length: 0
