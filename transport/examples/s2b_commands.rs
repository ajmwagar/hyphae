//! Print the `ip` commands that install one side of a sample S2b tunnel.
//!
//! Used to check the generated grammar — and the resulting data path — against
//! a real kernel:
//!
//! ```sh
//! cargo run -p transport --example s2b_commands -- ue
//! cargo run -p transport --example s2b_commands -- epdg
//! ```
//!
//! The two roles mirror each other: the `ue` side's outbound SA is the `epdg`
//! side's inbound SA. Addresses and keys are synthetic.

use transport::ipsec::{S2bTunnel, TunnelEncryption, TunnelIntegrity, TunnelProgram, TunnelSa};

fn tunnel(role: &str) -> S2bTunnel {
    // Shared synthetic material; both roles derive from the same values.
    let ue = ("192.0.2.10", "10.1.2.3/32");
    let epdg = ("192.0.2.1", "10.1.0.0/16");
    let ue_out = TunnelSa {
        spi: 0x1000,
        encryption: TunnelEncryption::AesCbc {
            key: vec![0xc3; 16],
        },
        integrity: TunnelIntegrity::HmacSha256_128 {
            key: vec![0xd4; 32],
        },
    };
    let ue_in = TunnelSa {
        spi: 0x1001,
        encryption: TunnelEncryption::AesCbc {
            key: vec![0xa1; 16],
        },
        integrity: TunnelIntegrity::HmacSha256_128 {
            key: vec![0xb2; 32],
        },
    };
    match role {
        "ue" => S2bTunnel {
            interface: "ipsec0".into(),
            if_id: 7,
            local_addr: ue.0.into(),
            remote_addr: epdg.0.into(),
            inbound: ue_in,
            outbound: ue_out,
            local_ts: ue.1.into(),
            remote_ts: epdg.1.into(),
        },
        "epdg" => S2bTunnel {
            interface: "ipsec0".into(),
            if_id: 7,
            // The ePDG's outbound keys are the UE's inbound keys.
            local_addr: epdg.0.into(),
            remote_addr: ue.0.into(),
            inbound: ue_out,
            outbound: ue_in,
            local_ts: epdg.1.into(),
            remote_ts: ue.1.into(),
        },
        other => panic!("role must be ue or epdg, got {other:?}"),
    }
}

fn main() {
    let role = std::env::args().nth(1).unwrap_or_else(|| "ue".into());
    for line in TunnelProgram::build(&tunnel(&role)).render() {
        println!("{line}");
    }
}
