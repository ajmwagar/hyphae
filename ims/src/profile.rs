//! IMS subscriber and endpoint profile.
//!
//! Values are configuration (public identities, home domain, P-CSCF discovery
//! result, security parameters). They are not derived from vendor binaries.

use carrier::CarrierProfile;
use sip::split_params;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityClient {
    /// `hmac-md5-96` (AKAv1-MD5) or `hmac-sha-1-96` (AKAv2).
    pub algorithm: String,
    /// `null` in the common IMS profile, or `aes` with an external KDF.
    pub encryption: String,
    /// `esp` (TS 33.203) or `tls`.
    pub protocol: String,
    /// `trans`, `tun`, or `tcp`.
    pub mode: String,
    pub spi_c: u32,
    pub spi_s: u32,
    pub port_c: u16,
    pub port_s: u16,
}

impl SecurityClient {
    /// A conservative TS 33.203 IPsec profile with values supplied by the caller.
    /// The SPIs/ports are local resources, not network constants.
    pub fn ipsec(
        algorithm: impl Into<String>,
        spi_c: u32,
        spi_s: u32,
        port_c: u16,
        port_s: u16,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            encryption: "null".into(),
            protocol: "esp".into(),
            mode: "trans".into(),
            spi_c,
            spi_s,
            port_c,
            port_s,
        }
    }

    /// `Security-Client` header value (RFC 3329 §2.2, TS 24.229 §5.1.1).
    pub fn header_value(&self) -> String {
        format!(
            "algorithm={};ealg={};prot={};mod={};spi-c={};spi-s={};port-c={};port-s={}",
            self.algorithm,
            self.encryption,
            self.protocol,
            self.mode,
            self.spi_c,
            self.spi_s,
            self.port_c,
            self.port_s
        )
    }

    pub fn parse(value: &str) -> Option<Self> {
        let mut algorithm = None;
        let mut encryption = None;
        let mut protocol = None;
        let mut mode = None;
        let (mut spi_c, mut spi_s, mut port_c, mut port_s) = (None, None, None, None);
        for p in split_params(value) {
            let Some((k, v)) = p.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches('"');
            match k.trim().to_ascii_lowercase().as_str() {
                "algorithm" => algorithm = Some(v.to_string()),
                "ealg" => encryption = Some(v.to_string()),
                "prot" => protocol = Some(v.to_string()),
                "mod" | "mode" => mode = Some(v.to_string()),
                "spi-c" => spi_c = v.parse().ok(),
                "spi-s" => spi_s = v.parse().ok(),
                "port-c" => port_c = v.parse().ok(),
                "port-s" => port_s = v.parse().ok(),
                _ => {}
            }
        }
        Some(Self {
            algorithm: algorithm?,
            encryption: encryption.unwrap_or_else(|| "null".into()),
            protocol: protocol?,
            mode: mode?,
            spi_c: spi_c?,
            spi_s: spi_s?,
            port_c: port_c?,
            port_s: port_s?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImsProfile {
    /// IMPI: `IMSI@ims.mnc...mcc....3gppnetwork.org` (TS 23.003 §13.2).
    pub private_identity: String,
    /// IMPU used in From/To and the REGISTER Contact.
    pub public_identity: String,
    pub home_domain: String,
    pub realm: String,
    /// Resolved P-CSCF endpoints (`host` or `host:port`).
    pub p_cscf: Vec<String>,
    /// Initial Service-Route set; normally learned from the 200 OK to REGISTER.
    pub service_route: Vec<String>,
    pub security_clients: Vec<SecurityClient>,
    pub user_agent: String,
    /// Contact feature tags, e.g. `+g.3gpp.icsi-ref="urn%3A..."`.
    pub feature_tags: Vec<String>,
    /// Local address advertised in Via/Contact.
    pub contact_host: String,
    pub contact_port: u16,
    pub register_expires: u32,
    pub supported: Vec<String>,
    /// Signalling transport token for Via (`UDP` or `TCP`).
    pub transport: String,
    /// AMR-WB mode-set to offer in SDP. Empty means do not offer AMR-WB.
    pub amr_wb_modes: Vec<u8>,
}

impl ImsProfile {
    /// Lab defaults for the Open5GS/Kamailio profile in `carrier/profiles/00101.toml`.
    pub fn lab_default() -> Self {
        let home_domain = "ims.mnc001.mcc001.3gppnetwork.org".to_string();
        Self {
            private_identity: format!("001010000000001@{home_domain}"),
            public_identity: format!("sip:001010000000001@{home_domain}"),
            home_domain: home_domain.clone(),
            realm: home_domain,
            p_cscf: vec!["pcscf.ims.mnc001.mcc001.3gppnetwork.org:5060".into()],
            service_route: Vec::new(),
            security_clients: vec![SecurityClient::ipsec(
                "hmac-md5-96",
                10_000,
                10_001,
                5062,
                5064,
            )],
            user_agent: "fungos-ims/0.1 (Linux)".into(),
            feature_tags: vec![
                "g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"".into(),
            ],
            contact_host: "192.0.2.10".into(),
            contact_port: 5060,
            register_expires: 600_000,
            supported: vec!["path".into(), "100rel".into()],
            transport: "UDP".into(),
            amr_wb_modes: vec![0, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    /// Build the runtime IMS profile from a carrier TOML profile plus the
    /// subscriber's IMSI (the carrier file cannot know the SIM identity).
    ///
    /// The P-CSCF list is the carrier's static list with `p_cscf_ports[0]`
    /// applied to entries that do not already carry a port. Discovery modes
    /// other than `static` still require the caller/modem to fill `p_cscf`.
    pub fn from_carrier(carrier: &CarrierProfile, imsi: &str) -> Self {
        let home_domain = carrier.ims_domain();
        let default_port = carrier.p_cscf_ports.first().copied();
        let p_cscf = carrier
            .p_cscf
            .iter()
            .map(|host| match default_port {
                Some(port) => with_default_port(host, port),
                None => host.clone(),
            })
            .collect();
        Self {
            private_identity: format!("{imsi}@{home_domain}"),
            public_identity: format!("sip:{imsi}@{home_domain}"),
            home_domain: home_domain.clone(),
            realm: home_domain,
            p_cscf,
            service_route: Vec::new(),
            security_clients: vec![SecurityClient::ipsec(
                "hmac-md5-96",
                10_000,
                10_001,
                5062,
                5064,
            )],
            user_agent: carrier.ua.clone(),
            feature_tags: carrier.feature_tags.clone(),
            contact_host: "127.0.0.1".into(),
            contact_port: 5060,
            register_expires: u32::try_from(carrier.timers.register_expires_s).unwrap_or(u32::MAX),
            supported: vec!["path".into(), "100rel".into()],
            transport: "UDP".into(),
            amr_wb_modes: carrier.amr_wb_modes.clone(),
        }
    }

    /// SDP offer using this profile's AMR-WB mode policy.
    pub fn amr_wb_offer(&self, address: &str, telephone_event: bool) -> crate::Sdp {
        crate::Sdp::amr_wb_offer(&self.amr_wb_modes, telephone_event, address)
    }

    /// IMPU without the `sip:` scheme, suitable for the Contact user part.
    pub fn public_user(&self) -> &str {
        self.public_identity
            .strip_prefix("sip:")
            .unwrap_or(&self.public_identity)
            .split('@')
            .next()
            .unwrap_or("")
    }

    pub fn contact_uri(&self) -> String {
        format!(
            "sip:{}@{}:{}",
            self.public_user(),
            self.contact_host,
            self.contact_port
        )
    }

    pub fn register_uri(&self) -> String {
        format!("sip:{}", self.home_domain)
    }

    pub fn feature_contact_params(&self) -> String {
        self.feature_tags
            .iter()
            .map(|t| format!(";+{t}"))
            .collect::<String>()
    }

    /// Adopt the Service-Route set returned by the S-CSCF (RFC 3608).
    pub fn set_service_route(&mut self, routes: Vec<String>) {
        self.service_route = routes;
    }
}

/// Append `port` unless the endpoint already has an explicit numeric port.
fn with_default_port(host: &str, port: u16) -> String {
    if host.starts_with('[') {
        let has_port = host
            .rsplit_once(']')
            .map(|(_, tail)| tail.starts_with(':'))
            .unwrap_or(false);
        return if has_port {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
    }
    if let Some((_, tail)) = host.rsplit_once(':') {
        if !host[..host.len() - tail.len() - 1].contains(':')
            && !tail.is_empty()
            && tail.chars().all(|c| c.is_ascii_digit())
        {
            return host.to_string();
        }
    }
    format!("{host}:{port}")
}

impl Default for ImsProfile {
    fn default() -> Self {
        Self::lab_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_client_round_trip() {
        let s = SecurityClient::ipsec("hmac-md5-96", 100, 101, 5062, 5064);
        let v = s.header_value();
        assert_eq!(v, "algorithm=hmac-md5-96;ealg=null;prot=esp;mod=trans;spi-c=100;spi-s=101;port-c=5062;port-s=5064");
        assert_eq!(SecurityClient::parse(&v), Some(s));
    }

    #[test]
    fn lab_profile_identities() {
        let p = ImsProfile::lab_default();
        assert_eq!(p.register_uri(), "sip:ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(p.contact_uri(), "sip:001010000000001@192.0.2.10:5060");
        assert_eq!(p.public_user(), "001010000000001");
        assert!(p.feature_contact_params().contains("+g.3gpp.icsi-ref="));
    }

    #[test]
    fn carrier_builds_ims_profile_and_policy() {
        let c = CarrierProfile::lab();
        let p = ImsProfile::from_carrier(&c, "001010000000001");
        assert_eq!(
            p.private_identity,
            "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(
            p.public_identity,
            "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(
            p.p_cscf,
            vec!["pcscf.ims.mnc001.mcc001.3gppnetwork.org:5060"]
        );
        assert_eq!(p.user_agent, c.ua);
        assert_eq!(p.feature_tags, c.feature_tags);
        assert_eq!(p.amr_wb_modes, c.amr_wb_modes);
        let offer = p.amr_wb_offer("192.0.2.10", true);
        assert!(offer
            .audio()
            .unwrap()
            .fmtp(116)
            .unwrap()
            .contains("mode-set=0,1,2,3,4,5,6,7"));
    }
}
