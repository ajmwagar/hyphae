# 200 OK to REGISTER with the S-CSCF Service-Route set.
# 3GPP TS 24.229 §5.1.1.2, RFC 3608 §6 (Service-Route), RFC 3261 §10.3.
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-2;rport
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=golden-tag
To: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=scscf-tag
Call-ID: golden-register-1@192.0.2.10
CSeq: 2 REGISTER
Service-Route: <sip:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org;lr>
Contact: <sip:001010000000001@192.0.2.10:5060>;expires=600000
Content-Length: 0
