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
| SIP-002 | Byte-level `Message::parse_bytes` preserves a binary body verbatim (RP-DATA is not UTF-8); transports parse bytes, not `str` | RFC 3261 §7; 3GPP TS 24.341 | `binary_body_survives_byte_parsing` | sip |
| TX-001 | A final response moves the client transaction to Completed | RFC 3261 §17.1.2 | `tx_001_client_transaction_401_then_200` | sip |
| AKA-001 | Milenage f1–f5 match 3GPP test set 1 | 3GPP TS 35.206 §4; TS 35.208 §4 | `aka_001_ts35208_test_set_1`, `ts35208_test_set_1` | aka |
| AKA-002 | AUTN verifies, SQN recovers, f1*/f5* match vectors | 3GPP TS 35.206 §4.1.2, §4.1.6; TS 33.102 §6.3.3 | `aka_002_autn_verification_and_resync_key` | aka |
| AKA-003 | Milenage AES-128 primitive matches FIPS-197 | FIPS-197 Appendix C.1 | `fips197_vector` | aka |
| SDP-001 | AMR-WB offer has rtpmap, octet-align, mode-set, ptime | RFC 4566; RFC 4867 §8; 3GPP TS 26.114 §5.2.1 | `sdp_001_amr_wb_offer` | ims |
| SDP-002 | Answer selects AMR-WB and echoes the offered parameters | RFC 3264 §6; 3GPP TS 26.114 §5.2.1 | `sdp_002_offer_answer_selects_amr_wb` | ims |
| SDP-003 | Multiple media lines: accepted audio plus every unaccepted `m=` line returned with port 0 | RFC 3264 §6.2 | `sdp_003_second_media_line_is_rejected_not_dropped` | ims, conformance |
| RTP-001 | RFC 4867 octet-aligned payload round-trips, CMR/ToC/F/FT/Q/P | RFC 4867 §3.3, §4.1 | `rtp_001_rfc4867_octet_aligned_round_trip`, `golden_multi_frame_f_bit` | codec-amr |
| RTP-002 | Speech/SID/no-data/lost frame classification | RFC 4867 §4.2, §4.3 | `sid_no_data_and_lost_classification`, `all_wb_modes_round_trip` | codec-amr |
| RTP-003 | Bandwidth-efficient and storage modes are rejected, not guessed | RFC 4867 §3.4 | `bandwidth_efficient_is_explicitly_unsupported` | codec-amr |
| PRACK-001 | 100rel RSeq produces a PRACK with RAck | RFC 3262 §3, §4 | `prack_001_100rel_and_rack` | ims, sip |
| DLG-001 | In-dialog UPDATE carries SDP; BYE terminates the dialog | RFC 3311 §5.1; RFC 3261 §12, §15; 3GPP TS 24.229 §5.1.3 | `dialog_001_update_and_bye` | ims |
| PR-001 | Carrier profile loads APN, P-CSCF discovery, codec policy, timers | GSMA IR.92 §4.1; 3GPP TS 23.003 §9.1, §13.2 | `carrier_001_lab_profile_loads`, `loads_embedded_lab_profile` | carrier |
| PR-002 | Carrier profile's `amr_wb_modes` feeds the SDP offer | GSMA IR.92 §4.3; 3GPP TS 26.114 §5.2.1 | `carrier_002_amr_wb_modes_feed_sdp_offer` | carrier, ims |
| SEC-001 | Security-Server response is echoed as Security-Verify | RFC 3329 §2.3, §3.2 | `sec_001_security_server_echoed_as_security_verify` | ims |
| SEC-002 | ESP encapsulation with real integrity: HMAC-MD5-96/HMAC-SHA-1-96 ICV, null encryption, 64-packet anti-replay window, sequence numbering | 3GPP TS 33.203 §7; RFC 4303; RFC 2403; RFC 2404 | `round_trips_inner_packet`, `sequence_advances_per_packet`, `icv_is_enforced`, `replay_is_rejected` | transport |
| SEC-003 | SA negotiation from `Security-Client`/`Security-Server` and programming the kernel SAs; Linux XFRM command generation | 3GPP TS 33.203 §7; RFC 3329; RFC 4303 | `sec_003_esp_authenticates_frames_and_rejects_replay` | transport, conformance |
| SEC-004 | IPsec agreement from the AKA CK/IK and `ip xfrm state/policy` rendering (Linux apply, other platforms report unsupported) | 3GPP TS 33.203 §7; RFC 3329 | `sec_004_negotiates_sas_and_renders_xfrm_commands` | transport, conformance |
| REG-009 | Registration refresh before expiry and re-REGISTER on network change | RFC 3261 §10.2.4; 3GPP TS 24.229 §5.1.1.3 | `reg_009_refresh_before_expiry_and_re_register_on_network_change` | ims |
| REG-010 | Network-initiated deregistration (NOTIFY `deactivated`) | RFC 3265; 3GPP TS 24.229 §5.1.1.4 | `reg_010_network_initiated_deregistration` | ims |
| REG-011 | Multiple contacts for one IMPU are all carried in a single REGISTER | RFC 3261 §10.2 | `reg_011_multiple_contacts_third_party_and_pcscf_failover` | ims, conformance |
| REG-012 | Third-party registration: `To` is the address-of-record being registered, `From` stays the registrant | RFC 3261 §10.3; 3GPP TS 24.229 §5.1.1.2 | `reg_011_multiple_contacts_third_party_and_pcscf_failover` | ims, conformance |
| REG-013 | P-CSCF failover walks the configured candidate list once, then stops | RFC 3261 §18.1 | `reg_011_multiple_contacts_third_party_and_pcscf_failover` | ims, conformance |
| KEEP-001 | Out-of-dialog OPTIONS keepalive: due/interval accounting, well-formed ping, consecutive-failure tracking with a dead threshold | RFC 3261 §11; 3GPP TS 24.229 §5.1.2.2 | `keep_001_options_ping_and_failure_accounting` | ims, conformance |
| INV-001 | INVITE/183/PRACK/200/ACK full session establishment | RFC 3261 §13; RFC 3262; 3GPP TS 24.229 §5.1.3 | `inv_001_full_call_establishment`, `inv_001_busy_returns_failed_and_blocks_bye` | ims |
| INV-002 | Preconditions and `100rel` SDP answer handling | RFC 3312; 3GPP TS 24.229 §5.1.3 | `inv_002_preconditions_offered_and_answered`, `parses_rfc3312_preconditions` | ims |
| INV-003 | Outgoing CANCEL reuses the INVITE branch and CSeq number; 200 to CANCEL + 487 to INVITE ends the attempt | RFC 3261 §9.1, §9.2 | `inv_003_cancel_reuses_the_invite_transaction` | ims, conformance |
| INV-004 | Forked INVITE: every additional 2xx is ACKed and BYE-ed while the first dialog stays active | RFC 3261 §13.2.2.4 | `inv_004_a_forked_2xx_is_acked_then_bye_d` | ims, conformance |
| UAS-001 | Incoming call (UAS): INVITE builds the callee dialog, 180 Ringing with RSeq under 100rel, 200 OK with the SDP answer, ACK confirms, BYE/CANCEL teardown | RFC 3261 §12.1.1, §13.3, §9.2; RFC 3262 §3; RFC 3264 | `uas_001_incoming_call_rings_and_answers_and_tears_down`, `uas_001_cancel_answers_200_and_487` | ims, conformance |
| UAS-002 | Received re-INVITE and in-dialog UPDATE carrying an offer are answered with a mirrored SDP answer (sendonly offer -> recvonly answer); ACK keeps the dialog confirmed | RFC 3261 §14.1; RFC 3264 §6.1, §6.2 | `uas_002_reinvite_and_update_renegotiate_hold` | ims, conformance |
| SMS-001 | SMS over IMS (RP/CP and SIP MESSAGE) | 3GPP TS 24.341; GSMA IR.92 §5 | `sms_001_sip_message_carries_rp_data`, `pdu_round_trips_destination_and_text` | ims |
| SMS-002 | Mobile-terminated SMS: RP-DATA (network-to-MS) wrapping an SMS-DELIVER TPDU is decoded, and acknowledged with an RP-ACK in the 200 OK | 3GPP TS 24.341; TS 24.011 §7.3; GSM 03.40 | `sms_002_mt_deliver_is_decoded_and_acknowledged` | ims, conformance |
| SUP-001 | Hold/resume: caller re-INVITEs with `a=sendonly`/`a=sendrecv`; the ACK reuses the re-INVITE CSeq | RFC 3261 §14.1; RFC 3264 §6.1 | `sup_001_hold_and_resume_reinvite_directions` | ims, conformance |
| SUP-002 | Call waiting: an INVITE arriving during an established call is either accepted by holding the active call, or declined with 486 Busy Here | RFC 3261 §21.4.24; 3GPP TS 24.604 | `sup_002_call_waiting_holds_the_active_call_and_answers`, `sup_002_declining_a_waiting_call_is_486` | ims, conformance |
| EVS-001 | EVS RTP payload format (TS 26.445 app. A, Header-Full): CMR/ToC bytes, Primary + AMR-WB IO frame tables, speech/SID/lost/no-data classification, multi-frame round-trip, frame-size validation; Compact/storage/multi-channel rejected | 3GPP TS 26.445 §appendix A (A.1–A.3); clock 48 kHz, 20 ms frames | `evs_001_cmr_toc_byte_round_trips`, `evs_001_frame_table_classification`, `evs_001_primary_speech_frame_sizes`, `evs_001_multi_frame_round_trips`, `evs_001_compact_format_is_rejected` | evs, conformance |
| E911-001 | Emergency session identity and routing: RFC 5031 `urn:service:sos[.*]` target, registered or IMSI-derived temporary identity, PIDF-LO location, and the TS 24.229 §5.1.6.3 emergency INVITE (`Resource-Priority: esnet.0`, `Geolocation-Routing: yes`). Request building only — the CLI refuses every non-mock transport and never transmits an emergency request | RFC 5031; 3GPP TS 24.229 §5.1.6; RFC 4119/5491 (PIDF-LO); RFC 4412; RFC 6442 | `e911_001_emergency_invite_targets_the_service_urn`, `e911_001_geolocation_is_routed_as_pidf_lo` | ims, conformance |
| MEDIA-001 | RTP/RTCP framing, jitter buffer, PLC | RFC 3550; RFC 4867 §9 | `media_001_rtp_amr_frame_round_trips_the_wire`, `media_001_rtcp_sender_report_survives_the_wire`, `media_001_jitter_buffer_reorders_and_flags_loss`, `media_001_plc_conceals_a_lost_frame` | media |
| USIM-001 | USIM `AUTHENTICATE` over a pluggable card channel: TS 31.102 §7.1.2 command/response APDU, RES/CK/IK and AUTS decoding, Milenage-backed software USIM against the TS 35.208 vector; PC/SC adapter is out of tree (no FFI) | 3GPP TS 31.102 §7.1; TS 35.208 | `usim_001_authenticate_apdu_matches_ts_31_102`, `usim_001_software_usim_returns_the_ts_35_208_vector` | usim, conformance |
| USIM-002 | QMI UIM Send APDU: QMUX/QMI framing, Send APDU TLVs, operation-result handling, and the full APDU path through the modem's card | libqmi UIM `Send APDU` (service 0x0B, message 0x3B); TS 31.102 | `usim_002_qmi_send_apdu_frames_and_reaches_the_card` | usim, conformance |
| USIM-003 | AT+CSIM card access: length-prefixed command and `+CSIM` response parsing through the APDU boundary | 3GPP TS 27.007 `+CSIM`; TS 31.102 | `usim_003_at_csim_round_trips_an_apdu` | usim, conformance |
| USIM-004 | PC/SC hardware card channel: reader selection/list, `data || SW1 || SW2` split, bare-status-word and short-response handling; optional hardware package outside the pure-Rust workspace | PC/SC Workgroup; ISO 7816-4 | `splits_data_and_status_word`, `accepts_a_bare_status_word`, `rejects_a_truncated_response` | usim-pcsc |
| VOICE-001 | Voice continuity: 488/580 classify as EPS fallback to CS and 503 as a retry hint; the platform decides | 3GPP TS 23.216; TS 24.229 §5.1.3; RFC 3261 §21 | `voice_001_invite_failures_classify_to_continuity_events` | ims, conformance |
| VOICE-002 | Media liveness for SRVCC eligibility: degrade at half the timeout, lost at the timeout, revived by a late packet | 3GPP TS 23.216; RFC 3550 §6.3 | `voice_002_media_liveness_degrades_then_is_lost` | ims, conformance |
| EPDG-001 | Wi-Fi calling core: EAP-AKA' key hierarchy — CK'/IK' bound to the access-network name, PRF' expansion into K_encr/K_aut/K_re/MSK/EMSK, AT attribute framing, AT_MAC (HMAC-SHA-256-128), AMF separation-bit check. The IKEv2/ePDG tunnel itself is not implemented | RFC 5448 §3.3–3.4; 3GPP TS 33.402; RFC 4187; FIPS 180-4; RFC 4231 | `epdg_001_eap_aka_prime_derives_the_full_key_set` | aka, conformance |
| EPDG-002 | IKEv2 message and payload codec: 28-octet header, next-payload chain, and typed SA/KE/Nonce/ID/AUTH/Notify/traffic-selector payloads | RFC 7296 §3.1–3.7 | `epdg_002_ikev2_message_round_trips_the_wire` | epdg, conformance |
| EPDG-003 | EAP-AKA' peer exchange: EAP framing, server AT_MAC verification, AT_KDF_INPUT network check, and an AT_RES + AT_MAC response | RFC 4187 §10; RFC 5448 §3 | `epdg_003_eap_aka_prime_peer_answers_the_challenge` | epdg, conformance |
| EPDG-004 | IKEv2 Diffie-Hellman: MODP groups 14/15/16 (RFC 3526 primes), caller-supplied private exponent, peer-public range checks, modulus-length padding | RFC 7296 §2.12; RFC 3526 §3–5 | `epdg_004_ikev2_diffie_hellman_agrees` | epdg, conformance |
| EPDG-005 | IKEv2 key schedule: `SKEYSEED = prf(Ni|Nr, g^ir)` and `prf+` expansion into SK_d/SK_ai/SK_ar/SK_ei/SK_er/SK_pi/SK_pr | RFC 7296 §2.13–2.14 | `epdg_005_ikev2_key_schedule_splits_the_prf_stream` | epdg, conformance |
| EPDG-006 | SK encrypted payload: AES-CBC with IKEv2 padding, HMAC-SHA-256-128 ICV over the whole message, seal/open round-trip and tamper rejection | RFC 7296 §3.14; RFC 3602 (AES-CBC); RFC 4868 | `epdg_006_sk_seals_and_opens_with_aes_cbc_and_hmac` | epdg, conformance |
| EPDG-007 | IKE_SA_INIT initiator: SAi1/KEi/Ni, responder SAr1/KEr/Nr, DH agreement and matching key schedules on both sides | RFC 7296 §2.1, §3.3–3.4 | `epdg_007_ike_sa_init_derives_matching_keys` | epdg, conformance |
| EPDG-008 | AUTH payloads over the EAP MSK and child-SA key material: `AUTH = prf(prf(secret, "Key Pad for IKEv2"), SignedOctets)` with per-direction SignedOctets, and `KEYMAT = prf+(SK_d, Ni|Nr)` | RFC 7296 §2.15–2.17; RFC 5998 §3.2 | `epdg_008_auth_payload_and_child_keymat` | epdg, conformance |
| EPDG-009 | IKE_AUTH with EAP-only authentication: encrypted `IDi/SAi2/TSi/TSr/N(EAP_ONLY)`, EAP-AKA' round trips over SK, AUTH over the MSK, responder AUTH verification and child keys | RFC 5998 §3; RFC 7296 §2.2 | `epdg_009_ike_auth_eap_flow_establishes` | epdg, conformance |
| EPDG-010 | Configuration payload: CFG_REQUEST/CFG_REPLY framing, zero-length request attributes, 16-bit type/length with 4-octet padding, `INTERNAL_IP4_ADDRESS` and repeated `INTERNAL_IP4_DNS` extraction | RFC 7296 §3.15 | `epdg_010_configuration_payload_carries_the_ims_address` | epdg, conformance |
| EPDG-011 | Child SA from the IKE_AUTH response: ESP proposal and SPI taken from the responder, KEYMAT split initiator→responder first in proposal order, AES-CBC key length from `KEY_LENGTH`, HMAC-SHA-256-128 integrity | RFC 7296 §2.17, §3.3.1–3.3.2; RFC 4868 §2.2 | `epdg_011_child_sa_splits_keymat_per_direction` | epdg, conformance |
| EPDG-012 | S2b tunnel programming: XFRM interface with `if_id`, tunnel-mode ESP states bound to it, traffic-selector policies carrying the same `if_id`, inner address assignment and route; `auth-trunc` pinned to a 128-bit ICV | TS 23.402 §7.3; RFC 7296 §2.23; RFC 4301 §4.4 | `epdg_012_s2b_tunnel_program_installs_both_directions` | transport, conformance |
| EPDG-013 | End-to-end Wi-Fi calling exchange over UDP: IKE_SA_INIT, EAP-AKA' challenge/response with Milenage at both ends, AUTH over the MSK, child SA and `CFG_REPLY`, with the message id advancing per request | RFC 7296 §2.2; RFC 5998 §3; RFC 5448 | `the_ike_exchange_completes_over_udp` | epdg-lab |
| EPDG-014 | The prf+ expansion seed is `Ni | Nr | SPIi | SPIr`, not just the nonces: changing either IKE SPI must change every derived key | RFC 7296 §2.14 | `the_spis_are_part_of_the_expansion_seed` | epdg |
| EPDG-015 | The SK payload length covers IV, ciphertext **and ICV**, and the IKE header length matches the message size | RFC 7296 §3.14 | `the_sk_payload_length_includes_the_icv` | epdg |
| EPDG-016 | EAP-Request/Identity is answered with EAP-Response/Identity carrying the NAI, before the AKA' challenge | RFC 3748 §5.2; RFC 5998 §3 | `an_eap_identity_request_is_answered_before_the_challenge` | epdg |
| EPDG-017 | ePDG discovery FQDNs built from the PLMN: Operator Identifier, 2-octet TAC, 3-octet 5GS TAC, LAC and Visited Country, with MCC/MNC forced to three digits and TAC/LAC rendered in hex | TS 23.003 §19.4.2.9.2–19.4.2.9.4 | `epdg_017_discovery_fqdns_match_the_specification_examples` | epdg, conformance |
| USIM-004 | ISIM access: `SELECT` by AID `A0000000871004`, `EF_IMPI`/`EF_DOMAIN` transparent reads, `EF_IMPU` linear-fixed records, and the `80` identity TLV; ISIM identities override IMSI-derived ones | TS 31.103 §4.2.2–4.2.4; ETSI TS 101 220 Annex E | `epdg_018_isim_provisions_the_ims_identity` | usim, ims, conformance |
| SIP-005 | `P-Access-Network-Info` for WLAN and E-UTRAN: `i-wlan-node-id` as bare hex MAC, `utran-cell-id-3gpp` as MCC + unpadded MNC + TAC + ECI in hex | RFC 3455 §5.4; TS 24.229 (PANI access-type rules) | `epdg_019_pani_reports_the_access_network` | ims, conformance |
| SIP-006 | P-CSCF discovery over DNS: NAPTR service fields `SIP+D2U`/`SIP+D2T`/`SIPS+D2T`, `_sip._udp`/`_sip._tcp`/`_sips._tcp` SRV names, NAPTR order-then-preference, SRV priority-then-weight (RFC 2782), default ports 5060/5061 | RFC 3263 §4.1–4.2; RFC 2782; TS 24.229 §9.2.1 (defers to RFC 3263) | `sip_006_pcscf_discovery_follows_rfc3263` | ims, conformance |
| GBA-001 | BSF discovery: the USIM form derived from MCC/MNC and the ISIM form derived from the IMPI domain, inserting `pub` before a delegated `3gppnetwork.org` and prefixing `bsf.` otherwise | TS 23.003 §16.2 | `gba_001_bsf_discovery_matches_the_specification_examples` | gba, conformance |
| GBA-002 | NAF key derivation `Ks_NAF = KDF(Ks, "gba-me", RAND, IMPI, NAF_Id)`, `Ks_ext_NAF` with the same label and `Ks_int_NAF` with `"gba-u"`, over the generic 3GPP KDF (`S = FC‖P0‖L0‖P1‖L1…`, HMAC-SHA-256); non-ASCII identifiers are refused rather than NFKC-approximated | TS 33.220 §4.5.3, Annex B.2–B.3 | `gba_002_ks_naf_matches_the_annex_b3_derivation` | gba, aka, conformance |
| GBA-003 | TODO: Ub (UE↔BSF, HTTP Digest over AKA) and Ua (UE↔NAF) exchanges; needs an HTTP/TLS seam outside the protocol crates. Deferred — see `docs/adr/0002-gba-deferred.md`. Not implemented, not claimed. | TS 24.109; TS 33.220 §4.3–4.5 | (none — deferred) | — |
| AUDIO-001 | Call-audio seam: bounded ring buffer with drop/underrun accounting, loopback sink/source pair, 16-bit PCM WAV capture, and frame-rate playback pacing; the device adapter is out of tree | 3GPP TS 26.114 (media); 16-bit PCM conventions | `audio_001_pcm_moves_through_a_ring_buffer_and_a_wav` | media, conformance |
| TRN-001 | AT/QMI transport on a modem-managed IMS PDN | 3GPP TS 27.007; QMI IMS | `local_addr_is_the_modem_pdn_address`, `delivers_over_the_pdn_loopback` | transport |
| TRN-002 | MTK CCCI vendor-channel shim: SIP survives a length-framed vendor channel; the `/dev/ccci_*` adapter is a pluggable, out-of-tree `VendorChannel` | Vendor channel; no vendor code may enter the tree | `trn_002_sip_survives_the_ccci_channel_boundary` | transport |
| TRN-003 | MBIM transport: control-frame wire shape and an IMS PDN session whose local address is the modem-assigned one | USB-IF MBIM 1.0 §8.2.1, §9.4; libmbim | `trn_003_mbim_frame_and_session_round_trip` | transport |

## Notes on scope

* "AMR-WB" and "EVS" appear above only as SDP/RTP **negotiation and packet
  layout**. There is no AMR-WB or EVS speech implementation in `codec`
  (Opus-only) or in any core crate. `codec-amr` (RFC 4867) and `evs`
  (TS 26.445 appendix A) are separate, feature-off, patent-noticed packages
  that ship the payload format but no codec.
* Tests are all host-side and use `transport::MockTransport`; no network,
  modem, USIM, or codec C dependency is required for the default gate.
* Rows marked TODO are not counted as implemented and must not be cited as
  conformance evidence until a named test exists.
* **IPsec (Gm).** IMS does **not** use IKE: the Gm SAs are keyed directly from
  the AKA `CK`/`IK` and negotiated by the `Security-Client` /
  `Security-Server` headers (TS 33.203 §7, RFC 3329). `transport::esp` is a real
  ESP codec (HMAC-MD5-96 / HMAC-SHA-1-96, null encryption, anti-replay), and
  `transport::ipsec` negotiates the SA pair and renders `ip xfrm state|policy`
  commands; the data path on Linux is the kernel's XFRM. IKEv2/EAP-AKA′ belongs
  to the separate ePDG/Wi-Fi-calling path and is out of scope here.
* **Modeled backends.** `TRN-001` (modem IMS PDN, `transport::modem`) covers the
  *contract* — modem-assigned PDN addressing — while the AT/QMI byte-level I/O
  remains a documented stub pending a modem device. `TRN-003` (MBIM,
  `transport::mbim`) models the control-frame wire shape and the modem-assigned
  IMS PDN session. `TRN-002` (CCCI, `transport::ccci`) ships only the vendor
  *boundary* — a `VendorChannel` trait plus this tree's own length framing —
  because CCCI is a vendor interface with no public spec, so no vendor header
  or device code can enter the tree. `EVS-001` is implemented as the TS 26.445
  appendix A *Header-Full* RTP payload format only (no speech codec); see the
  media-path note below.
* **Media path.** The `media` crate frames RTP/RTCP and buffers playout. It
  wraps the `codec-amr` payload (RFC 4867 §9) but never decodes speech, so it
  stays royalty-free; the AMR-WB/EVS codec itself is still the separate
  feature-gated package. The `evs` payload format is likewise packet layout
  only. Real network I/O is `transport`; `media` is socket-free and tested over
  in-memory packets.
