# In-dialog UPDATE carrying an SDP offer/answer. RFC 3311 §5.1,
# 3GPP TS 24.229 §5.1.3 (MMTel session modification).
UPDATE sip:001010000000002@192.0.2.11:5060 SIP/2.0
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-golden-update;rport
Max-Forwards: 70
From: <sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=caller-tag
To: <sip:001010000000002@ims.mnc001.mcc001.3gppnetwork.org>;tag=callee-tag
Call-ID: golden-call-1@192.0.2.10
CSeq: 3 UPDATE
Contact: <sip:001010000000001@192.0.2.10:5060>
Content-Type: application/sdp
Content-Length: 304

v=0
o=- 0 0 IN IP4 192.0.2.10
s=-
c=IN IP4 192.0.2.10
t=0 0
m=audio 49170 RTP/AVP 116 101
a=rtpmap:116 AMR-WB/16000/1
a=fmtp:116 octet-align=1;mode-set=0,1,2,3,4,5,6,7;mode-change-capability=2;max-red=0
a=rtpmap:101 telephone-event/16000
a=fmtp:101 0-15
a=ptime:20
a=maxptime:240
a=sendrecv
