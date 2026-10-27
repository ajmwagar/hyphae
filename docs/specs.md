# Specification traceability matrix

Requirement id → normative clause → executable test → owning crate.

Tests named without a crate prefix live in
`tests/conformance/tests/conformance.rs`; unit-test names are shown with their
module. "TODO" rows are deliberately not claimed as implemented.

| ID | Requirement | Normative source | Test | Crate |
|---|---|---|---|---|
| REG-001 | Initial REGISTER carries Security-Client, Contact feature tag, Expires, Supported | 3GPP TS 24.229 §5.1.1.2; RFC 3329 §2.2; GSMA IR.92 §4.1 | `reg_001_initial_register_has_security_client` | ims, sip, conformance |
| REG-002 | REGISTER parses and serialises with CRLF and Content-Length | RFC 3261 §7.5, §10.2, §20 | `reg_002_register_round_trips_wire_format` | sip |
| REG-003 | 401 Unauthorized yields a challenge, not a failure | RFC 3261 §22.1; 3GPP TS 33.203 §7 | `reg_003_401_challenge_handling` | ims, sip |
| REG-004 | Challenged REGISTER carries an AKAv1-MD5 Digest response derived from RES | RFC 3310 §3.2; RFC 2617 §3.2.2.1 | `reg_004_authorized_register_has_digest` | ims, aka |
| REG-005 | 407 Proxy Authentication Required uses Proxy-Authorization | RFC 3261 §22.3 | `reg_005_407_proxy_challenge_handling` | ims, sip |
| REG-006 | 200 OK to REGISTER adopts the Service-Route set | RFC 3608 §6; 3GPP TS 24.229 §5.1.1.2 | `reg_006_200_sets_service_route` | ims |
| REG-007 | Deregistration is REGISTER with Expires: 0 | RFC 3261 §10.2.2 | `reg_007_deregister_sets_expires_zero` | ims |
| REG-008 | A complete REGISTER traverses the transport boundary unchanged | RFC 3261 §18 | `reg_008_mock_transport_delivers_register` | transport |
| TX-001 | A final response moves the client transaction to Completed | RFC 3261 §17.1.2 | `tx_001_client_transaction_401_then_200` | sip |
| AKA-001 | Milenage f1–f5 match 3GPP test set 1 | 3GPP TS 35.206 §4; TS 35.208 §4 | `aka_001_ts35208_test_set_1`, `ts35208_test_set_1` | aka |
| AKA-002 | AUTN verifies, SQN recovers, f1*/f5* match vectors | 3GPP TS 35.206 §4.1.2, §4.1.6; TS 33.102 §6.3.3 | `aka_002_autn_verification_and_resync_key` | aka |
| AKA-003 | Milenage AES-128 primitive matches FIPS-197 | FIPS-197 Appendix C.1 | `fips197_vector` | aka |
| SDP-001 | AMR-WB offer has rtpmap, octet-align, mode-set, ptime | RFC 4566; RFC 4867 §8; 3GPP TS 26.114 §5.2.1 | `sdp_001_amr_wb_offer` | ims |
| SDP-002 | Answer selects AMR-WB and echoes the offered parameters | RFC 3264 §6; 3GPP TS 26.114 §5.2.1 | `sdp_002_offer_answer_selects_amr_wb` | ims |
| RTP-001 | RFC 4867 octet-aligned payload round-trips, CMR/ToC/F/FT/Q/P | RFC 4867 §3.3, §4.1 | `rtp_001_rfc4867_octet_aligned_round_trip`, `golden_multi_frame_f_bit` | codec-amr |
| RTP-002 | Speech/SID/no-data/lost frame classification | RFC 4867 §4.2, §4.3 | `sid_no_data_and_lost_classification`, `all_wb_modes_round_trip` | codec-amr |
| RTP-003 | Bandwidth-efficient and storage modes are rejected, not guessed | RFC 4867 §3.4 | `bandwidth_efficient_is_explicitly_unsupported` | codec-amr |
| PRACK-001 | 100rel RSeq produces a PRACK with RAck | RFC 3262 §3, §4 | `prack_001_100rel_and_rack` | ims, sip |
| DLG-001 | In-dialog UPDATE carries SDP; BYE terminates the dialog | RFC 3311 §5.1; RFC 3261 §12, §15; 3GPP TS 24.229 §5.1.3 | `dialog_001_update_and_bye` | ims |
| PR-001 | Carrier profile loads APN, P-CSCF discovery, codec policy, timers | GSMA IR.92 §4.1; 3GPP TS 23.003 §9.1, §13.2 | `carrier_001_lab_profile_loads`, `loads_embedded_lab_profile` | carrier |
| PR-002 | Carrier profile's `amr_wb_modes` feeds the SDP offer | GSMA IR.92 §4.3; 3GPP TS 26.114 §5.2.1 | **TODO** (phase 2) | carrier, ims |
| SEC-001 | Security-Server response is echoed as Security-Verify | RFC 3329 §2.3, §3.2 | **TODO** (phase 2; currently stored but not asserted) | ims |
| SEC-002 | Actual IPsec SA setup and ESP encapsulation | 3GPP TS 33.203 §7; RFC 4303 | **TODO** (phase 3; transport backend) | transport |
| REG-009 | Registration refresh before expiry and re-REGISTER on network change | RFC 3261 §10.2.4; 3GPP TS 24.229 §5.1.1.3 | **TODO** (phase 2) | ims |
| REG-010 | Network-initiated deregistration (NOTIFY `deactivated`) | RFC 3265; 3GPP TS 24.229 §5.1.1.4 | **TODO** (phase 4) | ims |
| INV-001 | INVITE/183/PRACK/200/ACK full session establishment | RFC 3261 §13; RFC 3262; 3GPP TS 24.229 §5.1.3 | **TODO** (phase 2) | ims |
| INV-002 | Preconditions and `100rel` SDP answer handling | RFC 3312; 3GPP TS 24.229 §5.1.3 | **TODO** (phase 3) | ims |
| SMS-001 | SMS over IMS (RP/CP and SIP MESSAGE) | 3GPP TS 24.341; GSMA IR.92 §5 | **TODO** (phase 4) | ims |
| EVS-001 | EVS negotiation and codec package | 3GPP TS 26.445; GSMA IR.92 (EVS) | **TODO** (separate patent-noticed package) | codec-* |
| E911-001 | Emergency session identity and call routing | 3GPP TS 24.229 §5.1.6; local regulation | **TODO** (product gate) | ims |
| MEDIA-001 | RTP/RTCP framing, jitter buffer, PLC | RFC 3550; RFC 4867 §9 | **TODO** (phase 3) | new media crate |
| TRN-001 | AT/QMI transport on a modem-managed IMS PDN | 3GPP TS 27.007; QMI IMS | **TODO** (phase 3) | transport |
| TRN-002 | MTK CCCI backend | Vendor channel; no vendor code may enter the tree | **TODO** (phase 5) | transport |

## Notes on scope

* "AMR-WB" appears above only as SDP/RTP **negotiation and packet layout**.
  There is no AMR-WB speech implementation in `codec` (Opus-only) or in any
  core crate. `codec-amr` is a separate, feature-off, patent-noticed package.
* Tests are all host-side and use `transport::MockTransport`; no network,
  modem, USIM, or codec C dependency is required for the default gate.
* Rows marked TODO are not counted as implemented and must not be cited as
  conformance evidence until a named test exists.
