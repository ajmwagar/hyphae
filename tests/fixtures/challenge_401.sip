# 401 challenge. 3GPP TS 33.203 §7 / RFC 3310: AKAv1-MD5 digest,
# nonce carries RAND||AUTN to the USIM/ISIM. RFC 3329 §2.3 Security-Server.
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-1;rport
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=golden-tag
To: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=scscf-tag
Call-ID: golden-register-1@192.0.2.10
CSeq: 1 REGISTER
WWW-Authenticate: Digest realm="ims.mnc001.mcc001.3gppnetwork.org", nonce="bm9uY2U=", algorithm=AKAv1-MD5, qop="auth"
Security-Server: ipsec-3gpp;alg=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=20000;spi-s=20001;port-c=6062;port-s=6064
Content-Length: 0
