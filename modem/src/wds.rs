//! Wireless Data Service (WDS) — service 1: the bearer's four messages.
//!
//! ```text
//!   Bind Mux Data Port  (0x00a2)  TLV 0x10 { endpoint type, interface }, TLV 0x11 mux id
//!   Start Network       (0x0020)  TLV 0x14 APN, TLV 0x19 IP family = 4 (IPv4)
//!                                 -> TLV 0x01 packet data handle
//!   Get Current Settings(0x002d)  TLV 0x10 requested-settings mask
//!                                 -> 0x1e address, 0x20 gateway, 0x15/0x16 DNS, 0x29 MTU
//!   Stop Network        (0x0021)  TLV 0x01 packet data handle
//! ```
//!
//! ## One client, or the bind is thrown away
//!
//! `Bind Mux Data Port` applies to the WDS *client* that sent it, and on QRTR
//! a client is the socket the request arrived on. `qmicli` allows one WDS
//! action per invocation, so the bind and the start always ran on different
//! clients and the modem answered `INVALID_OPERATION` (70) — which is why the
//! validated prototype had to hold one client across both requests. This crate
//! has the same constraint by construction: [`crate::bearer::Modem`] keeps one
//! WDS client for the life of the bearer and the supervisor calls the bind
//! before the start on it.
//!
//! ## Endianness of the settings TLVs
//!
//! Address, gateway, DNS and MTU are `guint32` TLVs declared little-endian in
//! the public WDS service definition, so they are read with
//! [`u32::from_le_bytes`] and turned into an address with [`Ipv4Addr::from`]
//! (which reads the `u32` as network-order octets). The happy-path vector in
//! the tests is built to that reading; the captured error-path vector from the
//! target (`OUT_OF_CALL`) pins the surrounding framing.

use std::fmt;
use std::net::Ipv4Addr;

use crate::qmi::{Message, Op, Tlv};
use crate::Error;

/// The QRTR service id of the Wireless Data Service.
pub const SERVICE: u16 = 1;

/// `WDS Bind Mux Data Port`: applies to one client, so it must share the
/// client that starts the call.
pub const BIND_MUX_DATA_PORT: Op = Op::new("WDS Bind Mux Data Port", 0x00A2);
/// `WDS Start Network`: brings the call up and returns its packet data handle.
pub const START_NETWORK: Op = Op::new("WDS Start Network", 0x0020);
/// `WDS Stop Network`: tears the call down.
pub const STOP_NETWORK: Op = Op::new("WDS Stop Network", 0x0021);
/// `WDS Get Current Settings`: reports what the network handed out.
pub const GET_CURRENT_SETTINGS: Op = Op::new("WDS Get Current Settings", 0x002D);

/// `QMI_WDS_IP_FAMILY_IPV4`.
pub const IP_FAMILY_IPV4: u8 = 4;

/// `QmiDataEndpointType::BAM_DMUX`.
pub const ENDPOINT_BAM_DMUX: u32 = 5;

const TLV_PACKET_DATA_HANDLE: u8 = 0x01;
const TLV_ENDPOINT_INFO: u8 = 0x10;
const TLV_MUX_ID: u8 = 0x11;
const TLV_APN: u8 = 0x14;
const TLV_IP_FAMILY: u8 = 0x19;
const TLV_REQUESTED_SETTINGS: u8 = 0x10;
const TLV_PRIMARY_DNS: u8 = 0x15;
const TLV_SECONDARY_DNS: u8 = 0x16;
const TLV_IPV4_ADDRESS: u8 = 0x1E;
const TLV_IPV4_GATEWAY: u8 = 0x20;
const TLV_MTU: u8 = 0x29;

/// The `requested settings` bits of `Get Current Settings`
/// (`QmiWdsGetCurrentSettingsRequestedSettings`).
pub mod requested {
    /// IPv4 address (bit 8).
    pub const IP_ADDRESS: u32 = 1 << 8;
    /// Gateway address (bit 9).
    pub const GATEWAY_INFO: u32 = 1 << 9;
    /// DNS addresses, primary and secondary (bit 4).
    pub const DNS_ADDRESS: u32 = 1 << 4;
    /// MTU (bit 13).
    pub const MTU: u32 = 1 << 13;
}

/// The four settings the bearer needs, and the mask the target answered.
pub const REQUESTED_SETTINGS: u32 =
    requested::IP_ADDRESS | requested::GATEWAY_INFO | requested::DNS_ADDRESS | requested::MTU;

/// The mux endpoint a WDS client binds to before starting a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxEndpoint {
    /// Endpoint type, [`ENDPOINT_BAM_DMUX`] on this board.
    pub endpoint_type: u32,
    /// Interface number.
    pub interface: u32,
    /// Mux id: which call on that interface this client owns.
    pub mux_id: u8,
}

impl MuxEndpoint {
    /// The BAM DMUX endpoint with `mux_id`.
    pub fn bam_dmux(mux_id: u8) -> Self {
        Self {
            endpoint_type: ENDPOINT_BAM_DMUX,
            interface: 0,
            mux_id,
        }
    }

    /// The `Bind Mux Data Port` request TLVs.
    pub fn bind_tlvs(&self) -> Vec<Tlv> {
        let mut info = Vec::with_capacity(8);
        info.extend_from_slice(&self.endpoint_type.to_le_bytes());
        info.extend_from_slice(&self.interface.to_le_bytes());
        vec![
            Tlv::new(TLV_ENDPOINT_INFO, info),
            Tlv::u8(TLV_MUX_ID, self.mux_id),
        ]
    }
}

/// The `Start Network` request TLVs: the APN and an IPv4 preference.
pub fn start_network_tlvs(apn: &str) -> Result<Vec<Tlv>, Error> {
    if apn.is_empty() {
        return Err(Error::Malformed {
            what: "empty APN cannot be sent to WDS Start Network",
        });
    }
    Ok(vec![
        Tlv::string(TLV_APN, apn)?,
        Tlv::u8(TLV_IP_FAMILY, IP_FAMILY_IPV4),
    ])
}

/// The packet data handle from a `Start Network` response.
pub fn packet_data_handle(response: &Message) -> Result<u32, Error> {
    response
        .tlv(TLV_PACKET_DATA_HANDLE)
        .ok_or(Error::MissingTlv {
            op: START_NETWORK,
            tlv: TLV_PACKET_DATA_HANDLE,
        })?
        .as_u32_le()
}

/// The `Stop Network` request TLVs.
pub fn stop_network_tlvs(handle: u32) -> Vec<Tlv> {
    vec![Tlv::u32_le(TLV_PACKET_DATA_HANDLE, handle)]
}

/// The `Get Current Settings` request TLVs.
pub fn current_settings_tlvs() -> Vec<Tlv> {
    vec![Tlv::u32_le(TLV_REQUESTED_SETTINGS, REQUESTED_SETTINGS)]
}

/// What the network handed out, as the interface layer needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BearerConfig {
    /// The address assigned to the bearer.
    pub address: Ipv4Addr,
    /// The gateway to route through.
    pub gateway: Ipv4Addr,
    /// Primary and secondary DNS, as far as the modem reported them.
    pub dns: [Option<Ipv4Addr>; 2],
    /// The MTU the network negotiated.
    pub mtu: u32,
}

impl BearerConfig {
    /// Read a `Get Current Settings` response.
    ///
    /// The address, the gateway and the MTU are required: a bearer without
    /// them cannot be configured. DNS is optional — the secondary server is
    /// genuinely absent on some networks.
    pub fn from_current_settings(response: &Message) -> Result<Self, Error> {
        Ok(Self {
            address: ipv4(response, TLV_IPV4_ADDRESS)?,
            gateway: ipv4(response, TLV_IPV4_GATEWAY)?,
            dns: [
                optional_ipv4(response, TLV_PRIMARY_DNS)?,
                optional_ipv4(response, TLV_SECONDARY_DNS)?,
            ],
            mtu: ipv4_u32(response, TLV_MTU)?,
        })
    }
}

impl fmt::Display for BearerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "address {} gateway {} mtu {}",
            self.address, self.gateway, self.mtu
        )?;
        match self.dns {
            [Some(primary), Some(secondary)] => write!(f, " dns {primary}, {secondary}"),
            [Some(primary), None] => write!(f, " dns {primary}"),
            [None, Some(secondary)] => write!(f, " dns {secondary}"),
            [None, None] => write!(f, " dns (none reported)"),
        }
    }
}

fn ipv4_u32(message: &Message, tlv: u8) -> Result<u32, Error> {
    message
        .tlv(tlv)
        .ok_or(Error::MissingTlv {
            op: GET_CURRENT_SETTINGS,
            tlv,
        })?
        .as_u32_le()
}

fn ipv4(message: &Message, tlv: u8) -> Result<Ipv4Addr, Error> {
    Ok(Ipv4Addr::from(ipv4_u32(message, tlv)?))
}

fn optional_ipv4(message: &Message, tlv: u8) -> Result<Option<Ipv4Addr>, Error> {
    match message.tlv(tlv) {
        Some(value) => Ok(Some(Ipv4Addr::from(value.as_u32_le()?))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi;
    use crate::test_support::{hex, unhex, Peer};
    use std::time::Duration;

    #[test]
    fn bind_mux_request_is_byte_exact() {
        let frame =
            qmi::encode(BIND_MUX_DATA_PORT, 1, &MuxEndpoint::bam_dmux(0).bind_tlvs()).unwrap();
        let expected = unhex(concat!(
            "000100a2000f00",          // header, tlv_length 15
            "10080005000000 00000000", // endpoint type 5, interface 0
            "11010000",                // mux id 0
        ));
        assert_eq!(hex(&frame), hex(&expected));
    }

    #[test]
    fn start_network_request_is_byte_exact() {
        let frame = qmi::encode(
            START_NETWORK,
            1,
            &start_network_tlvs("fast.t-mobile.com").unwrap(),
        )
        .unwrap();
        let expected = unhex(concat!(
            "00010020001900",
            "14120011666173742e742d6d6f62696c652e636f6d",
            "19010004",
        ));
        assert_eq!(hex(&frame), hex(&expected));
    }

    #[test]
    fn stop_network_request_is_byte_exact() {
        let frame = qmi::encode(STOP_NETWORK, 1, &stop_network_tlvs(0x1234_5678)).unwrap();
        let expected = unhex("00010021000700010400 78563412");
        assert_eq!(hex(&frame), hex(&expected));
    }

    #[test]
    fn get_current_settings_request_matches_the_capture() {
        // Captured request the target answered: transaction 2, mask 0x2310.
        let frame = qmi::encode(GET_CURRENT_SETTINGS, 2, &current_settings_tlvs()).unwrap();
        assert_eq!(hex(&frame), "0002002d00070010040010230000");
        assert_eq!(REQUESTED_SETTINGS, 0x2310);
    }

    #[test]
    fn decodes_a_successful_current_settings_response() {
        // Shape and TLV ids come from the WDS service definition; the values
        // are the ones the target reported on the validated bearer.
        let raw = unhex(concat!(
            "0201002d002300",
            "02040000000000",  // result 0, error 0
            "1e04000200 00c0", // 192.0.0.2, little-endian u32
            "2004000100 00c0", // 192.0.0.1
            "1504000100 00c0", // primary DNS 192.0.0.1
            "290400c005 0000", // MTU 1472
        ));
        let message = qmi::decode(&raw).unwrap();
        let config = BearerConfig::from_current_settings(&message).unwrap();
        assert_eq!(
            config,
            BearerConfig {
                address: Ipv4Addr::new(192, 0, 0, 2),
                gateway: Ipv4Addr::new(192, 0, 0, 1),
                dns: [Some(Ipv4Addr::new(192, 0, 0, 1)), None],
                mtu: 1472,
            }
        );
        assert_eq!(
            config.to_string(),
            "address 192.0.0.2 gateway 192.0.0.1 mtu 1472 dns 192.0.0.1"
        );
    }

    #[test]
    fn the_captured_out_of_call_response_is_reported_with_the_wds_operation() {
        // Captured: the target answered a fresh WDS client that asked for
        // settings without owning a call. The capture is transaction 2 and a
        // client's first request is transaction 1, so the transaction byte is
        // normalised here; `qmi` tests the untouched capture.
        let mut raw = unhex("0202002d000700 0204000100 0f00");
        raw[1] = 0x01;
        let mut client = qmi::Client::new(Peer::with_replies(&[&raw]), Duration::from_millis(50));
        assert_eq!(
            client.call(GET_CURRENT_SETTINGS, &current_settings_tlvs()),
            Err(Error::Modem {
                op: GET_CURRENT_SETTINGS,
                error: crate::ProtocolError::OUT_OF_CALL,
            })
        );
    }

    #[test]
    fn a_response_without_an_address_is_rejected() {
        let raw = unhex("0201002d000700 0204000000 0000");
        let message = qmi::decode(&raw).unwrap();
        assert_eq!(
            BearerConfig::from_current_settings(&message),
            Err(Error::MissingTlv {
                op: GET_CURRENT_SETTINGS,
                tlv: TLV_IPV4_ADDRESS,
            })
        );
    }

    #[test]
    fn the_packet_data_handle_is_required() {
        let raw = unhex("02010020000700 0204000000 0000");
        let message = qmi::decode(&raw).unwrap();
        assert_eq!(
            packet_data_handle(&message),
            Err(Error::MissingTlv {
                op: START_NETWORK,
                tlv: TLV_PACKET_DATA_HANDLE,
            })
        );
        let raw = unhex("02010020000700 0204000000 0000");
        assert!(qmi::decode(&raw).is_ok());
        let with_handle = unhex("02010020000e00 02040000000000 01040090f1ab0f");
        assert_eq!(
            packet_data_handle(&qmi::decode(&with_handle).unwrap()),
            Ok(0x0fab_f190)
        );
    }

    #[test]
    fn an_empty_apn_is_rejected() {
        assert!(start_network_tlvs("").is_err());
    }
}
