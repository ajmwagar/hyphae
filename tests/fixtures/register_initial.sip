# REGISTER with Security-Client, feature tag and P-CSCF-facing identity.
# 3GPP TS 24.229 §5.1.1.2 (initial REGISTER), RFC 3261 §10.2,
# RFC 3329 §2.2 (Security-Client), GSMA IR.92 §4.1 (MMTel feature tag).
REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-1;rport
Max-Forwards: 70
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=golden-tag
To: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>
Call-ID: golden-register-1@192.0.2.10
CSeq: 1 REGISTER
Contact: <sip:001010000000001@192.0.2.10:5060>;expires=600000;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
Expires: 600000
Security-Client: algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5062;port-s=5064
Supported: path,100rel
User-Agent: fungos-ims/0.1 (Linux)
Content-Length: 0
