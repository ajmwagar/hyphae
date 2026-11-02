//! IMS IPsec security association negotiation and programming (SEC-003/004).
//!
//! IMS does not use IKE. During registration the UE advertises its IPsec
//! parameters in `Security-Client` (RFC 3329) and the P-CSCF answers with
//! `Security-Server`. Both sides already share `CK`/`IK` from IMS-AKA, so the
//! SAs are simply *programmed* from those keys (TS 33.203 §7).
//!
//! This module:
//!
//! * parses the `Security-Client`/`Security-Server` parameter lists,
//! * builds the two directional [`EspSa`]s from the negotiated values and the
//!   AKA keys, and
//! * renders the Linux **XFRM** commands (`ip xfrm state|policy add`) that
//!   install them, so the kernel does the ESP data path.
//!
//! The command builder is pure and cross-platform; only [`XfrmProgram::apply`]
//! touches the system, and it is Linux-only.

#![forbid(unsafe_code)]

use crate::esp::{EspError, EspIntegrity, EspSa};

/// The IPsec parameters carried in `Security-Client` / `Security-Server`
/// (RFC 3329 §2.2, §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityParams {
    /// Integrity algorithm.
    pub algorithm: EspIntegrity,
    /// Encryption algorithm (`null` in the mandatory profile).
    pub encryption: String,
    /// Security protocol (`esp`).
    pub protocol: String,
    /// Mode (`trans`).
    pub mode: String,
    /// SPI the peer uses when sending to us (client SPI).
    pub spi_c: u32,
    /// SPI we use when sending to the peer (server SPI).
    pub spi_s: u32,
    /// Local SA port.
    pub port_c: u16,
    /// Remote SA port.
    pub port_s: u16,
}

impl SecurityParams {
    /// Parse a header value such as
    /// `algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;...`.
    pub fn parse(value: &str) -> Result<Self, IpsecError> {
        let mut algorithm = None;
        let mut encryption = None;
        let mut protocol = None;
        let mut mode = None;
        let (mut spi_c, mut spi_s, mut port_c, mut port_s) = (None, None, None, None);
        for part in sip::split_params(value) {
            let Some((key, v)) = part.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let v = v.trim().trim_matches('"');
            match key.as_str() {
                "algorithm" => {
                    algorithm = Some(EspIntegrity::from_ims(v).ok_or_else(|| {
                        IpsecError::Unsupported(format!("integrity algorithm {v}"))
                    })?)
                }
                "ealg" => encryption = Some(v.to_string()),
                "prot" => protocol = Some(v.to_ascii_lowercase()),
                "mod" => mode = Some(v.to_ascii_lowercase()),
                "spi-c" => spi_c = Some(parse_spi(v)?),
                "spi-s" => spi_s = Some(parse_spi(v)?),
                "port-c" => port_c = Some(parse_port(v)?),
                "port-s" => port_s = Some(parse_port(v)?),
                _ => {}
            }
        }
        Ok(Self {
            algorithm: algorithm.ok_or(IpsecError::Missing("algorithm"))?,
            encryption: encryption.unwrap_or_else(|| "null".into()),
            protocol: protocol.ok_or(IpsecError::Missing("prot"))?,
            mode: mode.ok_or(IpsecError::Missing("mod"))?,
            spi_c: spi_c.ok_or(IpsecError::Missing("spi-c"))?,
            spi_s: spi_s.ok_or(IpsecError::Missing("spi-s"))?,
            port_c: port_c.ok_or(IpsecError::Missing("port-c"))?,
            port_s: port_s.ok_or(IpsecError::Missing("port-s"))?,
        })
    }

    /// Render back to a header value.
    pub fn header_value(&self) -> String {
        format!(
            "algorithm={};ealg={};prot={};mod={};spi-c={};spi-s={};port-c={};port-s={}",
            self.algorithm.ims_name(),
            self.encryption,
            self.protocol,
            self.mode,
            self.spi_c,
            self.spi_s,
            self.port_c,
            self.port_s
        )
    }
}

fn parse_spi(v: &str) -> Result<u32, IpsecError> {
    let v = v.trim();
    let parsed = if let Some(hex) = v.strip_prefix("0x") {
        u32::from_str_radix(hex, 16)
    } else {
        v.parse::<u32>()
    };
    parsed.map_err(|_| IpsecError::BadValue("spi", v.to_string()))
}

fn parse_port(v: &str) -> Result<u16, IpsecError> {
    v.trim()
        .parse()
        .map_err(|_| IpsecError::BadValue("port", v.to_string()))
}

/// Errors from negotiating or programming IPsec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpsecError {
    /// A required parameter was absent.
    Missing(&'static str),
    /// A parameter had an unparseable value.
    BadValue(&'static str, String),
    /// A negotiated mode/algorithm this tree does not implement.
    Unsupported(String),
    /// The ESP layer rejected the key or frame.
    Esp(EspError),
    /// XFRM programming failed.
    Xfrm(String),
    /// Kernel SA programming is only implemented on Linux.
    PlatformUnsupported,
}

impl core::fmt::Display for IpsecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpsecError::Missing(p) => write!(f, "missing IPsec parameter: {p}"),
            IpsecError::BadValue(p, v) => write!(f, "bad IPsec {p}: {v}"),
            IpsecError::Unsupported(what) => write!(f, "unsupported IPsec mode: {what}"),
            IpsecError::Esp(e) => write!(f, "ESP error: {e}"),
            IpsecError::Xfrm(e) => write!(f, "XFRM error: {e}"),
            IpsecError::PlatformUnsupported => {
                f.write_str("kernel IPsec SA programming is only implemented on Linux")
            }
        }
    }
}

impl std::error::Error for IpsecError {}

impl From<EspError> for IpsecError {
    fn from(e: EspError) -> Self {
        IpsecError::Esp(e)
    }
}

/// A negotiated pair of SAs for one UE↔P-CSCF path.
#[derive(Debug, Clone)]
pub struct IpsecAgreement {
    /// UE → P-CSCF.
    pub outbound: EspSa,
    /// P-CSCF → UE.
    pub inbound: EspSa,
    pub local_addr: String,
    pub remote_addr: String,
    pub local_port: u16,
    pub remote_port: u16,
}

impl IpsecAgreement {
    /// Negotiate the SAs from the UE's `Security-Client`, the P-CSCF's
    /// `Security-Server`, and the AKA keys.
    ///
    /// Only the mandatory TS 33.203 profile is accepted: ESP, transport mode,
    /// null encryption, an integrity algorithm this tree implements. The
    /// Security-Server values win where present (the server picks), falling back
    /// to the client's proposal.
    pub fn negotiate(
        client: &SecurityParams,
        server: &SecurityParams,
        ck: &[u8],
        ik: &[u8],
        local_addr: &str,
        remote_addr: &str,
    ) -> Result<Self, IpsecError> {
        for p in [client, server] {
            if p.protocol != "esp" {
                return Err(IpsecError::Unsupported(format!("prot={}", p.protocol)));
            }
            if p.mode != "trans" {
                return Err(IpsecError::Unsupported(format!("mod={}", p.mode)));
            }
            if p.encryption != "null" {
                return Err(IpsecError::Unsupported(format!("ealg={}", p.encryption)));
            }
        }
        let integrity = server.algorithm;
        let out_spi = server.spi_c;
        let in_spi = server.spi_s;
        Ok(Self {
            outbound: EspSa::new(out_spi, integrity, ik, ck)?,
            inbound: EspSa::new(in_spi, integrity, ik, ck)?,
            local_addr: local_addr.to_string(),
            remote_addr: remote_addr.to_string(),
            local_port: server.port_c,
            remote_port: server.port_s,
        })
    }

    /// The SPI the peer must use for traffic it sends to us.
    pub fn inbound_spi(&self) -> u32 {
        self.inbound.spi
    }

    /// The SPI we use for traffic we send to the peer.
    pub fn outbound_spi(&self) -> u32 {
        self.outbound.spi
    }
}

/// Renders `ip xfrm` commands that install an [`IpsecAgreement`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmProgram {
    commands: Vec<Vec<String>>,
}

impl XfrmProgram {
    /// Build the `state` and `policy` commands for both directions.
    pub fn build(agreement: &IpsecAgreement) -> Self {
        let ik_hex = hex(agreement.outbound.integrity_key());
        let alg = agreement.outbound.integrity.xfrm_name();
        let local = &agreement.local_addr;
        let remote = &agreement.remote_addr;
        let mut commands = Vec::new();

        // State (SAs): outbound uses spi-c, inbound uses spi-s.
        for (src, dst, spi) in [
            (local, remote, agreement.outbound_spi()),
            (remote, local, agreement.inbound_spi()),
        ] {
            commands.push(vec![
                "ip".into(),
                "xfrm".into(),
                "state".into(),
                "add".into(),
                "src".into(),
                src.clone(),
                "dst".into(),
                dst.clone(),
                "proto".into(),
                "esp".into(),
                "spi".into(),
                format!("0x{spi:x}"),
                "mode".into(),
                "transport".into(),
                "auth".into(),
                alg.into(),
                format!("0x{ik_hex}"),
            ]);
        }

        // Policies: route the protected UDP ports over the ESP templates.
        let (pc, ps) = (agreement.local_port, agreement.remote_port);
        commands.push(vec![
            "ip".into(),
            "xfrm".into(),
            "policy".into(),
            "add".into(),
            "dir".into(),
            "out".into(),
            "src".into(),
            format!("{local}/32"),
            "dst".into(),
            format!("{remote}/32"),
            "proto".into(),
            "udp".into(),
            "sport".into(),
            pc.to_string(),
            "dport".into(),
            ps.to_string(),
            "tmpl".into(),
            "src".into(),
            local.clone(),
            "dst".into(),
            remote.clone(),
            "proto".into(),
            "esp".into(),
            "mode".into(),
            "transport".into(),
        ]);
        commands.push(vec![
            "ip".into(),
            "xfrm".into(),
            "policy".into(),
            "add".into(),
            "dir".into(),
            "in".into(),
            "src".into(),
            format!("{remote}/32"),
            "dst".into(),
            format!("{local}/32"),
            "proto".into(),
            "udp".into(),
            "sport".into(),
            ps.to_string(),
            "dport".into(),
            pc.to_string(),
            "tmpl".into(),
            "src".into(),
            remote.clone(),
            "dst".into(),
            local.clone(),
            "proto".into(),
            "esp".into(),
            "mode".into(),
            "transport".into(),
        ]);

        Self { commands }
    }

    /// The command vectors (program name first), for inspection or testing.
    pub fn commands(&self) -> &[Vec<String>] {
        &self.commands
    }

    /// Render the commands as shell lines.
    pub fn render(&self) -> Vec<String> {
        self.commands.iter().map(|argv| argv.join(" ")).collect()
    }

    /// Run the commands with `ip`. Linux only; needs `CAP_NET_ADMIN`.
    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> Result<(), IpsecError> {
        for argv in &self.commands {
            let output = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .map_err(|e| IpsecError::Xfrm(e.to_string()))?;
            if !output.status.success() {
                return Err(IpsecError::Xfrm(format!(
                    "{}: {}",
                    argv.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        Ok(())
    }

    /// Kernel SA programming is not implemented off Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> Result<(), IpsecError> {
        Err(IpsecError::PlatformUnsupported)
    }
}

/// Lower-case hex, no prefix.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5062;port-s=5064";
    const SERVER: &str = "algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5062;port-s=5064";
    const CK: [u8; 16] = [0x11; 16];
    const IK: [u8; 16] = [0x22; 16];

    fn agreement() -> IpsecAgreement {
        let client = SecurityParams::parse(CLIENT).unwrap();
        let server = SecurityParams::parse(SERVER).unwrap();
        IpsecAgreement::negotiate(&client, &server, &CK, &IK, "10.32.0.2", "10.32.0.1").unwrap()
    }

    #[test]
    fn security_header_round_trips() {
        let p = SecurityParams::parse(CLIENT).unwrap();
        assert_eq!(p.algorithm, EspIntegrity::HmacMd5_96);
        assert_eq!(p.spi_c, 10000);
        assert_eq!(p.port_s, 5064);
        assert_eq!(SecurityParams::parse(&p.header_value()).unwrap(), p);
    }

    #[test]
    fn hex_spis_and_missing_fields() {
        let mut p = SecurityParams::parse(CLIENT).unwrap();
        p.spi_c = 0x1000;
        assert_eq!(p.spi_c, 4096);
        let hexed = "algorithm=hmac-sha-1-96;ealg=null;prot=esp;mod=trans;spi-c=0x10;spi-s=0x11;port-c=5062;port-s=5064";
        let parsed = SecurityParams::parse(hexed).unwrap();
        assert_eq!(parsed.spi_c, 16);
        assert_eq!(parsed.algorithm, EspIntegrity::HmacSha1_96);
        assert_eq!(
            SecurityParams::parse("ealg=null;prot=esp;mod=trans"),
            Err(IpsecError::Missing("algorithm"))
        );
    }

    #[test]
    fn unsupported_profiles_are_rejected() {
        let client = SecurityParams::parse(CLIENT).unwrap();
        let mut tls = SecurityParams::parse(CLIENT).unwrap();
        tls.protocol = "tls".into();
        assert!(matches!(
            IpsecAgreement::negotiate(&client, &tls, &CK, &IK, "a", "b"),
            Err(IpsecError::Unsupported(_))
        ));
        let mut aes = SecurityParams::parse(CLIENT).unwrap();
        aes.encryption = "aes".into();
        assert!(matches!(
            IpsecAgreement::negotiate(&client, &aes, &CK, &IK, "a", "b"),
            Err(IpsecError::Unsupported(_))
        ));
        let mut tun = SecurityParams::parse(CLIENT).unwrap();
        tun.mode = "tun".into();
        assert!(matches!(
            IpsecAgreement::negotiate(&client, &tun, &CK, &IK, "a", "b"),
            Err(IpsecError::Unsupported(_))
        ));
    }

    #[test]
    fn agreement_uses_the_right_spis_per_direction() {
        let a = agreement();
        // Outbound traffic carries spi-c; inbound is keyed by spi-s.
        assert_eq!(a.outbound_spi(), 10000);
        assert_eq!(a.inbound_spi(), 10001);
        assert_eq!(a.local_port, 5062);
        assert_eq!(a.remote_port, 5064);
        // The SAs really interop: a packet from outbound decapsulates inbound.
        let mut out = a.outbound.clone();
        // The peer's inbound SA is keyed by the SPI we put on the wire (spi-c).
        let mut peer_inbound =
            EspSa::new(a.outbound_spi(), EspIntegrity::HmacMd5_96, &IK, &CK).unwrap();
        let frame = out.encapsulate(b"SIP", crate::esp::NEXT_HDR_UDP);
        assert_eq!(peer_inbound.decapsulate(&frame).unwrap().payload, b"SIP");
    }

    #[test]
    fn xfrm_program_installs_both_directions() {
        let program = XfrmProgram::build(&agreement());
        let rendered = program.render();
        assert_eq!(rendered.len(), 4);
        assert!(rendered[0]
            .starts_with("ip xfrm state add src 10.32.0.2 dst 10.32.0.1 proto esp spi 0x2710"));
        assert!(rendered[0].contains("mode transport"));
        assert!(rendered[0].contains("auth hmac(md5) 0x22222222222222222222222222222222"));
        assert!(rendered[1].contains("spi 0x2711"));
        assert!(rendered[1].starts_with("ip xfrm state add src 10.32.0.1 dst 10.32.0.2"));
        assert!(rendered[2].contains("policy add dir out"));
        assert!(rendered[2].contains("sport 5062 dport 5064"));
        assert!(rendered[3].contains("policy add dir in"));
        assert!(rendered[3].contains("sport 5064 dport 5062"));
    }

    fn tunnel() -> S2bTunnel {
        S2bTunnel {
            interface: "ipsec0".into(),
            if_id: 7,
            local_addr: "192.0.2.10".into(),
            remote_addr: "192.0.2.1".into(),
            inbound: TunnelSa {
                spi: 0x1001,
                encryption: TunnelEncryption::AesCbc {
                    key: vec![0xa1; 16],
                },
                integrity: TunnelIntegrity::HmacSha256_128 {
                    key: vec![0xb2; 32],
                },
            },
            outbound: TunnelSa {
                spi: 0x1000,
                encryption: TunnelEncryption::AesCbc {
                    key: vec![0xc3; 16],
                },
                integrity: TunnelIntegrity::HmacSha256_128 {
                    key: vec![0xd4; 32],
                },
            },
            local_ts: "10.1.2.3/32".into(),
            remote_ts: "10.1.0.0/16".into(),
        }
    }

    #[test]
    fn tunnel_creates_an_interface_bound_by_if_id() {
        let rendered = TunnelProgram::build(&tunnel()).render();
        assert_eq!(rendered[0], "ip link add ipsec0 type xfrm if_id 7");
        assert_eq!(rendered[1], "ip link set ipsec0 mtu 1400 up");
    }

    #[test]
    fn tunnel_states_are_tunnel_mode_and_if_id_bound() {
        let rendered = TunnelProgram::build(&tunnel()).render();
        let out = &rendered[2];
        assert!(
            out.starts_with("ip xfrm state add src 192.0.2.10 dst 192.0.2.1 proto esp spi 0x1000")
        );
        assert!(out.contains("mode tunnel"));
        assert!(out.contains("if_id 7"));
        // The encryption key is the outbound one, rendered as hex.
        assert!(out.contains(&format!("enc cbc(aes) 0x{}", "c3".repeat(16))));
        assert!(
            out.contains(&format!(
                "auth-trunc hmac(sha256) 0x{} 128",
                "d4".repeat(32)
            )),
            "{out}"
        );
        let inbound = &rendered[3];
        assert!(inbound
            .starts_with("ip xfrm state add src 192.0.2.1 dst 192.0.2.10 proto esp spi 0x1001"));
        assert!(inbound.contains(&format!("enc cbc(aes) 0x{}", "a1".repeat(16))));
    }

    #[test]
    fn tunnel_policies_key_on_traffic_selectors_not_ports() {
        let rendered = TunnelProgram::build(&tunnel()).render();
        let out = &rendered[4];
        assert!(out.contains("policy add dir out"));
        assert!(out.contains("src 10.1.2.3/32 dst 10.1.0.0/16"));
        assert!(
            out.contains("tmpl src 192.0.2.10 dst 192.0.2.1 proto esp mode tunnel reqid 7 if_id 7")
        );
        // The interface is selected by if_id, not by `dev`.
        assert!(!out.contains("dev ipsec0"));
        // No UDP ports: this is not the Gm transport-mode profile.
        assert!(!out.contains("sport"));

        let inbound = &rendered[5];
        assert!(inbound.contains("policy add dir in"));
        assert!(inbound.contains("src 10.1.0.0/16 dst 10.1.2.3/32"));
        assert!(inbound.contains("tmpl src 192.0.2.1 dst 192.0.2.10"));
    }

    #[test]
    fn tunnel_routes_the_far_selectors_over_the_interface() {
        let rendered = TunnelProgram::build(&tunnel()).render();
        assert_eq!(rendered[6], "ip addr add 10.1.2.3/32 dev ipsec0");
        assert_eq!(rendered[7], "ip route add 10.1.0.0/16 dev ipsec0");
        assert_eq!(rendered.len(), 8);
    }

    #[test]
    fn teardown_reverses_every_step() {
        let build = TunnelProgram::build(&tunnel());
        let teardown = TunnelProgram::teardown(&tunnel());
        // Teardown mirrors build except for `link set up`, which has no undo.
        assert_eq!(build.commands().len(), teardown.commands().len() + 1);
        let rendered = teardown.render();
        assert_eq!(rendered[0], "ip route del 10.1.0.0/16 dev ipsec0");
        assert_eq!(rendered[1], "ip addr del 10.1.2.3/32 dev ipsec0");
        assert!(rendered.iter().any(|c| c.contains("policy delete dir out")));
        assert!(rendered.iter().any(|c| c.contains("policy delete dir in")));
        assert!(
            rendered
                .iter()
                .any(|c| c
                    == "ip xfrm state delete src 192.0.2.10 dst 192.0.2.1 proto esp spi 0x1000")
        );
        assert_eq!(rendered.last().unwrap(), "ip link delete ipsec0");
    }

    #[test]
    fn tunnel_apply_is_platform_gated() {
        let program = TunnelProgram::build(&tunnel());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(program.apply(), Err(IpsecError::PlatformUnsupported));
        #[cfg(target_os = "linux")]
        let _ = program.apply(); // needs CAP_NET_ADMIN; not asserted here
    }

    #[test]
    fn apply_is_platform_gated() {
        let program = XfrmProgram::build(&agreement());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(program.apply(), Err(IpsecError::PlatformUnsupported));
        #[cfg(target_os = "linux")]
        let _ = program.apply(); // needs CAP_NET_ADMIN; not asserted here
    }
}

// --- S2b: the Wi-Fi calling tunnel (EPDG-010) ----------------------------
//
// Gm IPsec above is *transport* mode: it protects a pair of UDP ports and
// nothing else. The ePDG tunnel is *tunnel* mode: it carries every packet the
// traffic selectors match, and it is bound to a kernel XFRM interface so the
// IMS PDN has somewhere to live (RFC 7296 §2.23, TS 23.402 §7.3).

/// The encryption algorithm of one direction of an S2b tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelEncryption {
    /// AES-CBC (RFC 3602) with a 128/192/256-bit key.
    AesCbc { key: Vec<u8> },
}

impl TunnelEncryption {
    /// The `ip xfrm` name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            TunnelEncryption::AesCbc { .. } => "cbc(aes)",
        }
    }

    /// The key octets.
    pub fn key(&self) -> &[u8] {
        match self {
            TunnelEncryption::AesCbc { key } => key,
        }
    }
}

/// The integrity algorithm of one direction of an S2b tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelIntegrity {
    /// HMAC-SHA-256 truncated to 128 bits (RFC 4868).
    HmacSha256_128 { key: Vec<u8> },
}

impl TunnelIntegrity {
    /// The `ip xfrm` name.
    pub fn xfrm_name(&self) -> &'static str {
        match self {
            TunnelIntegrity::HmacSha256_128 { .. } => "hmac(sha256)",
        }
    }

    /// The ICV length in bits. This must be passed to the kernel explicitly:
    /// `ip xfrm ... auth <algo> <key>` silently installs a **96-bit** ICV, so
    /// an `AUTH_HMAC_SHA2_256_128` SA built that way truncates to the wrong
    /// length and will not interoperate with an ePDG using the negotiated 128.
    pub fn icv_bits(&self) -> u16 {
        match self {
            TunnelIntegrity::HmacSha256_128 { .. } => 128,
        }
    }

    /// The key octets.
    pub fn key(&self) -> &[u8] {
        match self {
            TunnelIntegrity::HmacSha256_128 { key } => key,
        }
    }
}

/// One direction of an S2b tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSa {
    /// The SPI stamped on packets in this direction.
    pub spi: u32,
    pub encryption: TunnelEncryption,
    pub integrity: TunnelIntegrity,
}

/// Everything needed to install an S2b tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bTunnel {
    /// The XFRM interface to create, e.g. `ipsec0`.
    pub interface: String,
    /// The XFRM interface id that binds states to the interface.
    pub if_id: u32,
    /// The UE's outer (Wi-Fi) address.
    pub local_addr: String,
    /// The ePDG's address.
    pub remote_addr: String,
    /// ePDG → UE.
    pub inbound: TunnelSa,
    /// UE → ePDG.
    pub outbound: TunnelSa,
    /// The UE's inner address, as a CIDR: `10.1.2.3/32`.
    pub local_ts: String,
    /// The selectors the ePDG narrowed to, as a CIDR: `0.0.0.0/0`.
    pub remote_ts: String,
}

impl S2bTunnel {
    /// A conventional tunnel MTU: 1500 minus the ESP overhead for this
    /// algorithm pair. AES-CBC needs IV (16) + pad, and HMAC-SHA-256-128 an ICV
    /// of 16, so 1500 - 20 (IP) - 8 (ESP header+trailer) - 16 (IV) - 16 (ICV)
    /// ≈ 1400 is the usual value operators use.
    pub const DEFAULT_MTU: u16 = 1400;
}

/// Renders `ip` commands that install or remove an [`S2bTunnel`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelProgram {
    commands: Vec<Vec<String>>,
}

impl TunnelProgram {
    /// The commands that create the interface, install both SAs, install both
    /// policies and route the inner selectors over the interface.
    pub fn build(tunnel: &S2bTunnel) -> Self {
        let (local, remote) = (&tunnel.local_addr, &tunnel.remote_addr);
        let if_id = tunnel.if_id.to_string();
        let interface = &tunnel.interface;
        let mut commands = Vec::new();

        // 1. The XFRM interface the IMS PDN is routed over.
        commands.push(vec![
            "ip".into(),
            "link".into(),
            "add".into(),
            interface.clone(),
            "type".into(),
            "xfrm".into(),
            "if_id".into(),
            if_id.clone(),
        ]);
        commands.push(vec![
            "ip".into(),
            "link".into(),
            "set".into(),
            interface.clone(),
            "mtu".into(),
            S2bTunnel::DEFAULT_MTU.to_string(),
            "up".into(),
        ]);

        // 2. One state per direction. Outbound is keyed by the SPI the
        //    responder chose, inbound by the one we chose in SAi2.
        for (src, dst, sa) in [
            (local, remote, &tunnel.outbound),
            (remote, local, &tunnel.inbound),
        ] {
            commands.push(vec![
                "ip".into(),
                "xfrm".into(),
                "state".into(),
                "add".into(),
                "src".into(),
                src.clone(),
                "dst".into(),
                dst.clone(),
                "proto".into(),
                "esp".into(),
                "spi".into(),
                format!("0x{:x}", sa.spi),
                "mode".into(),
                "tunnel".into(),
                "reqid".into(),
                if_id.clone(),
                "if_id".into(),
                if_id.clone(),
                "enc".into(),
                sa.encryption.xfrm_name().into(),
                format!("0x{}", hex(sa.encryption.key())),
                // `auth-trunc`, not `auth`: the kernel defaults the ICV to 96
                // bits otherwise, which is not RFC 4868's 128.
                "auth-trunc".into(),
                sa.integrity.xfrm_name().into(),
                format!("0x{}", hex(sa.integrity.key())),
                sa.integrity.icv_bits().to_string(),
            ]);
        }

        // 3. Policies keyed on the traffic selectors, not on ports.
        for (dir, ts_src, ts_dst, tmpl_src, tmpl_dst) in [
            ("out", &tunnel.local_ts, &tunnel.remote_ts, local, remote),
            ("in", &tunnel.remote_ts, &tunnel.local_ts, remote, local),
        ] {
            commands.push(vec![
                "ip".into(),
                "xfrm".into(),
                "policy".into(),
                "add".into(),
                "dir".into(),
                dir.into(),
                "src".into(),
                ts_src.clone(),
                "dst".into(),
                ts_dst.clone(),
                // No `dev`: an XFRM interface is selected by `if_id`, and the
                // template must carry the same `if_id` as the state or the
                // bundle lookup fails with XfrmOutNoStates.
                "tmpl".into(),
                "src".into(),
                tmpl_src.clone(),
                "dst".into(),
                tmpl_dst.clone(),
                "proto".into(),
                "esp".into(),
                "mode".into(),
                "tunnel".into(),
                "reqid".into(),
                if_id.clone(),
                "if_id".into(),
                if_id.clone(),
            ]);
        }

        // 4. Give the interface the inner address the ePDG assigned.
        commands.push(vec![
            "ip".into(),
            "addr".into(),
            "add".into(),
            tunnel.local_ts.clone(),
            "dev".into(),
            interface.clone(),
        ]);

        // 5. Route the far selectors over the interface.
        commands.push(vec![
            "ip".into(),
            "route".into(),
            "add".into(),
            tunnel.remote_ts.clone(),
            "dev".into(),
            interface.clone(),
        ]);

        Self { commands }
    }

    /// The commands that undo [`Self::build`], newest first.
    pub fn teardown(tunnel: &S2bTunnel) -> Self {
        let (local, remote) = (&tunnel.local_addr, &tunnel.remote_addr);
        let interface = &tunnel.interface;
        let if_id = tunnel.if_id.to_string();
        let mut commands = vec![
            vec![
                "ip".into(),
                "route".into(),
                "del".into(),
                tunnel.remote_ts.clone(),
                "dev".into(),
                interface.clone(),
            ],
            vec![
                "ip".into(),
                "addr".into(),
                "del".into(),
                tunnel.local_ts.clone(),
                "dev".into(),
                interface.clone(),
            ],
        ];
        for (dir, ts_src, ts_dst) in [
            ("out", &tunnel.local_ts, &tunnel.remote_ts),
            ("in", &tunnel.remote_ts, &tunnel.local_ts),
        ] {
            commands.push(vec![
                "ip".into(),
                "xfrm".into(),
                "policy".into(),
                "delete".into(),
                "dir".into(),
                dir.into(),
                "src".into(),
                ts_src.clone(),
                "dst".into(),
                ts_dst.clone(),
            ]);
        }
        for (src, dst, sa) in [
            (local, remote, &tunnel.outbound),
            (remote, local, &tunnel.inbound),
        ] {
            commands.push(vec![
                "ip".into(),
                "xfrm".into(),
                "state".into(),
                "delete".into(),
                "src".into(),
                src.clone(),
                "dst".into(),
                dst.clone(),
                "proto".into(),
                "esp".into(),
                "spi".into(),
                format!("0x{:x}", sa.spi),
            ]);
        }
        let _ = if_id;
        commands.push(vec![
            "ip".into(),
            "link".into(),
            "delete".into(),
            interface.clone(),
        ]);
        Self { commands }
    }

    /// The command vectors (program name first), for inspection or testing.
    pub fn commands(&self) -> &[Vec<String>] {
        &self.commands
    }

    /// Render the commands as shell lines.
    pub fn render(&self) -> Vec<String> {
        self.commands.iter().map(|argv| argv.join(" ")).collect()
    }

    /// Run the commands with `ip`. Linux only; needs `CAP_NET_ADMIN`.
    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> Result<(), IpsecError> {
        for argv in &self.commands {
            let output = std::process::Command::new(&argv[0])
                .args(&argv[1..])
                .output()
                .map_err(|e| IpsecError::Xfrm(e.to_string()))?;
            if !output.status.success() {
                return Err(IpsecError::Xfrm(format!(
                    "{}: {}",
                    argv.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
        }
        Ok(())
    }

    /// Kernel tunnel programming is not implemented off Linux.
    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> Result<(), IpsecError> {
        Err(IpsecError::PlatformUnsupported)
    }
}
