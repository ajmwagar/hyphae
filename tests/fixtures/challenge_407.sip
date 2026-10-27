# 407 proxy challenge from the P-CSCF. RFC 3261 §22.3, TS 24.229 §5.1.1.2.
# The client answers with Proxy-Authorization, not Authorization.
SIP/2.0 407 Proxy Authentication Required
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-1;rport
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=golden-tag
To: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=pcscf-tag
Call-ID: golden-register-1@192.0.2.10
CSeq: 1 REGISTER
Proxy-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="bm9uY2U=", algorithm=AKAv1-MD5, qop="auth"
Content-Length: 0
