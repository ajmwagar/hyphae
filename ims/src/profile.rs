//! IMS subscriber and endpoint profile.
//!
//! Values are configuration (public identities, home domain, P-CSCF discovery
//! result, security parameters). They are not derived from vendor binaries.

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
        }
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
}
