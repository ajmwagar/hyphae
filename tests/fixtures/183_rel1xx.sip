# Reliable provisional response: PRACK is required.
# RFC 3262 §3 (100rel), 3GPP TS 24.229 §5.1.3 / GSMA IR.92 §4.3.
SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-invite;rport
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=caller-tag
To: <sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag
Call-ID: golden-call-1@192.0.2.10
CSeq: 1 INVITE
Require: 100rel
RSeq: 1
Contact: <sip:001010000000002@192.0.2.11:5060>
Content-Type: application/sdp
Content-Length: 0
