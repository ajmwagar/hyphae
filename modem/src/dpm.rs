//! Data Port Mapper (DPM) — service 47.
//!
//! The DPM service tells the modem which data path to expose. On msm8937 the
//! path is BAM DMUX: opening a DPM port is what makes the modem start the
//! BAM DMUX power-control handshake, so it is the first step of every bearer
//! bring-up, before any WDS request is sent.
//!
//! One message is enough here:
//!
//! ```text
//!   Open Port (0x0020)
//!     TLV 0x10 control ports    array: { port name, endpoint type, interface }
//!     TLV 0x11 hardware ports   array: { endpoint type, interface, rx id, tx id }
//!     TLV 0x12 software ports   array: { endpoint type, interface, port name }
//!   response: result TLV only
//! ```
//!
//! The endpoint type is `BAM_DMUX` (5). The pipe ids come from the device
//! tree: `dmas = <&bam_dmux_dma 4>, <&bam_dmux_dma 5>` named `tx`, `rx`, i.e.
//! tx 4 and rx 5 on this board. They are arguments rather than constants
//! because they belong to the board, not to the protocol.
//!
//! Message and TLV ids are the public DPM service definition (libqmi's
//! `qmi-service-dpm.json`), the same one `qmicli --dpm-open-port` encodes, and
//! the request built here is byte-identical to what that tool sends for the
//! captured `key=value` list.

use crate::qmi::{Op, Tlv};
use crate::Error;

/// The QRTR service id of the Data Port Mapper.
pub const SERVICE: u16 = 47;

/// `DPM Open Port`.
pub const OPEN_PORT: Op = Op::new("DPM Open Port", 0x0020);

/// `QmiDataEndpointType::BAM_DMUX`.
pub const BAM_DMUX: u32 = 5;

const TLV_CONTROL_PORTS: u8 = 0x10;
const TLV_HARDWARE_PORTS: u8 = 0x11;
const TLV_SOFTWARE_PORTS: u8 = 0x12;

/// A `control ports` element: the name the driver uses, plus the endpoint it
/// maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPort {
    /// Endpoint type, [`BAM_DMUX`] on this board.
    pub endpoint_type: u32,
    /// Interface number.
    pub interface: u32,
    /// Port name as the data driver knows it, e.g. `bam-dmux`.
    pub name: String,
}

/// A `hardware ports` element: the BAM pipes carrying the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwarePort {
    /// Endpoint type, [`BAM_DMUX`] on this board.
    pub endpoint_type: u32,
    /// Interface number.
    pub interface: u32,
    /// RX endpoint number (BAM pipe 5 on this board).
    pub rx_id: u32,
    /// TX endpoint number (BAM pipe 4 on this board).
    pub tx_id: u32,
}

/// A `software ports` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftwarePort {
    /// Endpoint type, [`BAM_DMUX`] on this board.
    pub endpoint_type: u32,
    /// Interface number.
    pub interface: u32,
    /// Port name as the modem knows it, e.g. `bam-dmux`.
    pub name: String,
}

/// The three endpoints that make up one data port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConfig {
    /// The control endpoint.
    pub control: ControlPort,
    /// The hardware (BAM DMUX) data endpoint.
    pub hardware: HardwarePort,
    /// The software data endpoint.
    pub software: SoftwarePort,
}

impl PortConfig {
    /// The BAM DMUX port this board uses, with the device-tree pipe ids.
    ///
    /// `tx_id` is the first `dmas` entry, `rx_id` the second; the captured
    /// values for the CAT S22 are tx 4 and rx 5. Note that the message carries
    /// RX *before* TX.
    pub fn bam_dmux(tx_id: u32, rx_id: u32) -> Self {
        Self {
            control: ControlPort {
                endpoint_type: BAM_DMUX,
                interface: 0,
                name: "bam-dmux".to_string(),
            },
            hardware: HardwarePort {
                endpoint_type: BAM_DMUX,
                interface: 0,
                rx_id,
                tx_id,
            },
            software: SoftwarePort {
                endpoint_type: BAM_DMUX,
                interface: 0,
                name: "bam-dmux".to_string(),
            },
        }
    }

    /// The `Open Port` request TLVs.
    pub fn open_port_tlvs(&self) -> Result<Vec<Tlv>, Error> {
        let mut control = vec![1]; // one element
        control.push(string_len(&self.control.name)?);
        control.extend_from_slice(self.control.name.as_bytes());
        control.extend_from_slice(&self.control.endpoint_type.to_le_bytes());
        control.extend_from_slice(&self.control.interface.to_le_bytes());

        let mut hardware = vec![1]; // one element
        hardware.extend_from_slice(&self.hardware.endpoint_type.to_le_bytes());
        hardware.extend_from_slice(&self.hardware.interface.to_le_bytes());
        hardware.extend_from_slice(&self.hardware.rx_id.to_le_bytes());
        hardware.extend_from_slice(&self.hardware.tx_id.to_le_bytes());

        let mut software = vec![1]; // one element
        software.extend_from_slice(&self.software.endpoint_type.to_le_bytes());
        software.extend_from_slice(&self.software.interface.to_le_bytes());
        software.push(string_len(&self.software.name)?);
        software.extend_from_slice(self.software.name.as_bytes());

        Ok(vec![
            Tlv::new(TLV_CONTROL_PORTS, control),
            Tlv::new(TLV_HARDWARE_PORTS, hardware),
            Tlv::new(TLV_SOFTWARE_PORTS, software),
        ])
    }
}

/// QMI strings inside a TLV are length-prefixed with one byte.
fn string_len(value: &str) -> Result<u8, Error> {
    u8::try_from(value.len()).map_err(|_| Error::Malformed {
        what: "DPM port name longer than 255 bytes",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmi;
    use crate::test_support::{hex, unhex};

    #[test]
    fn open_port_request_is_byte_exact() {
        // `qmicli --dpm-open-port=ctrl-ep-type=bam-dmux,ctrl-ep-iface-number=0,
        //   ctrl-port-name=bam-dmux,hw-data-ep-type=bam-dmux,
        //   hw-data-ep-iface-number=0,hw-data-rx-id=5,hw-data-tx-id=4,
        //   sw-data-ep-type=bam-dmux,sw-data-ep-iface-number=0,
        //   sw-data-port-name=bam-dmux`
        // encodes to these TLVs; the values are the board's device-tree pipes.
        let tlvs = PortConfig::bam_dmux(4, 5).open_port_tlvs().unwrap();
        let frame = qmi::encode(OPEN_PORT, 1, &tlvs).unwrap();
        let expected = unhex(concat!(
            "00010020003e00",                             // header, tlv_length 62
            "101200010862616d2d646d75780500000000000000", // control port
            "1111000105000000000000000500000004000000",   // hardware, rx 5 tx 4
            "1212000105000000000000000862616d2d646d7578", // software port
        ));
        assert_eq!(hex(&frame), hex(&expected));
    }

    #[test]
    fn the_hardware_ports_carry_rx_before_tx() {
        let tlvs = PortConfig::bam_dmux(4, 5).open_port_tlvs().unwrap();
        let hardware = tlvs
            .iter()
            .find(|tlv| tlv.kind == TLV_HARDWARE_PORTS)
            .unwrap();
        // count, endpoint, interface, rx, tx
        assert_eq!(
            &hardware.value[9..17],
            &[0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn overlong_port_names_are_rejected() {
        let mut config = PortConfig::bam_dmux(4, 5);
        config.control.name = "x".repeat(256);
        assert!(config.open_port_tlvs().is_err());
    }
}
