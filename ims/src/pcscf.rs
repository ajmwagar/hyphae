//! P-CSCF discovery over DNS (RFC 3263), the fallback when the network does
//! not hand the address over in PCO or DHCP.
//!
//! 3GPP does not restate these mechanics: TS 24.229 points at RFC 3263 and
//! leaves the algorithm there. So does this module.
//!
//! The lookup is two steps deep:
//!
//! ```text
//!   NAPTR  <domain>            services SIP+D2U / SIP+D2T / SIPS+D2T
//!     ->  SRV  _sip._udp.<domain> / _sip._tcp.<domain> / _sips._tcp.<domain>
//!       ->  A/AAAA <target>
//! ```
//!
//! This module builds the query names and applies the two orderings the RFCs
//! define — NAPTR by order then preference (RFC 3263 §4.1), SRV by priority
//! then weight (RFC 2782). Resolution itself is the caller's: there is no
//! resolver and no RNG here, so the weighted selection takes the random number
//! as an argument.

#![forbid(unsafe_code)]

/// A SIP transport, as far as discovery is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    /// `SIP+D2U`, `_sip._udp`, port 5060.
    Udp,
    /// `SIP+D2T`, `_sip._tcp`, port 5060.
    Tcp,
    /// `SIPS+D2T`, `_sips._tcp`, port 5061.
    Tls,
}

impl Transport {
    /// The NAPTR service field (RFC 3263 §4.1, IANA registry).
    pub fn naptr_service(self) -> &'static str {
        match self {
            Transport::Udp => "SIP+D2U",
            Transport::Tcp => "SIP+D2T",
            Transport::Tls => "SIPS+D2T",
        }
    }

    /// The SRV service label without the leading underscore pair, e.g.
    /// `_sip._udp` (RFC 3263 §4.2).
    pub fn srv_label(self) -> &'static str {
        match self {
            Transport::Udp => "_sip._udp",
            Transport::Tcp => "_sip._tcp",
            Transport::Tls => "_sips._tcp",
        }
    }

    /// The port to use when no SRV record supplies one.
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 5060,
            Transport::Tls => 5061,
        }
    }

    /// The `Via` transport token.
    pub fn token(self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
        }
    }

    /// The transport a NAPTR service field names, if it is one we speak.
    pub fn from_naptr_service(service: &str) -> Option<Self> {
        match service.trim().to_ascii_uppercase().as_str() {
            "SIP+D2U" => Some(Transport::Udp),
            "SIP+D2T" => Some(Transport::Tcp),
            "SIPS+D2T" => Some(Transport::Tls),
            _ => None,
        }
    }
}

/// The SRV name to query for `transport` under `domain` (RFC 3263 §4.2).
pub fn srv_name(transport: Transport, domain: &str) -> String {
    format!("{}.{}", transport.srv_label(), domain.trim_end_matches('.'))
}

/// A NAPTR record, reduced to the fields discovery uses (RFC 3403).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naptr {
    pub order: u16,
    pub preference: u16,
    /// e.g. `SIP+D2U`.
    pub service: String,
    /// `S` (SRV), `A` (address) or `U` (URI); empty means the record is opaque.
    pub flags: String,
    /// The domain the flag points at.
    pub replacement: String,
}

impl Naptr {
    /// The transport this record offers, if it names one this tree speaks.
    pub fn transport(&self) -> Option<Transport> {
        Transport::from_naptr_service(&self.service)
    }
}

/// Order NAPTR records the way RFC 3263 §4.1 requires: lowest order first,
/// then lowest preference, keeping only records that name a transport we speak.
///
/// Records whose flags are not `S` are dropped: with `S` the replacement is an
/// SRV name, and without it the RFC leaves the semantics to the service, which
/// is not something discovery can act on.
pub fn order_naptr(records: &[Naptr]) -> Vec<Naptr> {
    let mut usable: Vec<Naptr> = records
        .iter()
        .filter(|r| r.transport().is_some() && r.flags.eq_ignore_ascii_case("s"))
        .cloned()
        .collect();
    usable.sort_by_key(|r| (r.order, r.preference));
    usable
}

/// An SRV record (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

impl Srv {
    /// `host:port`, the form the rest of this tree uses for P-CSCF endpoints.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.target.trim_end_matches('.'), self.port)
    }
}

/// Order SRV records per RFC 2782: lowest priority first, and within a priority
/// a weighted random selection.
///
/// `random` is supplied by the caller because this crate has no RNG; it must
/// return a value in `0..bound`. Passing a constant selects deterministically,
/// which is what the tests do.
pub fn order_srv(records: &[Srv], mut random: impl FnMut(u32) -> u32) -> Vec<Srv> {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|r| r.priority);

    let mut out = Vec::with_capacity(sorted.len());
    let mut at = 0;
    while at < sorted.len() {
        let priority = sorted[at].priority;
        let end = sorted[at..]
            .iter()
            .position(|r| r.priority != priority)
            .map(|offset| at + offset)
            .unwrap_or(sorted.len());
        let mut group: Vec<Srv> = sorted[at..end].to_vec();

        // RFC 2782: repeatedly pick a running-sum weighted entry and remove it,
        // so zero-weight entries are only chosen when nothing else remains.
        while !group.is_empty() {
            let total: u32 = group.iter().map(|r| r.weight as u32).sum();
            let pick = if total == 0 {
                0
            } else {
                random(total).min(total.saturating_sub(1))
            };
            let mut running = 0u32;
            let mut chosen = group.len() - 1;
            for (index, record) in group.iter().enumerate() {
                running += record.weight as u32;
                if pick < running {
                    chosen = index;
                    break;
                }
            }
            out.push(group.remove(chosen));
        }
        at = end;
    }
    out
}

/// A discovered P-CSCF endpoint, before it reaches the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub transport: Transport,
    /// `host:port`.
    pub endpoint: String,
}

impl Candidate {
    /// Build from a resolved host and port, applying the transport's default
    /// port when none was supplied.
    pub fn new(transport: Transport, host: &str, port: Option<u16>) -> Self {
        let port = port.unwrap_or_else(|| transport.default_port());
        Self {
            transport,
            endpoint: format!("{}:{port}", host.trim_end_matches('.')),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_names_follow_the_registry() {
        // RFC 3263 §4.1 service fields and §4.2 SRV labels.
        assert_eq!(Transport::Udp.naptr_service(), "SIP+D2U");
        assert_eq!(Transport::Tcp.naptr_service(), "SIP+D2T");
        assert_eq!(Transport::Tls.naptr_service(), "SIPS+D2T");

        assert_eq!(
            srv_name(Transport::Udp, "ims.mnc260.mcc310.3gppnetwork.org"),
            "_sip._udp.ims.mnc260.mcc310.3gppnetwork.org"
        );
        assert_eq!(
            srv_name(Transport::Tls, "example.com."),
            "_sips._tcp.example.com"
        );
    }

    #[test]
    fn default_ports_are_the_registered_ones() {
        assert_eq!(Transport::Udp.default_port(), 5060);
        assert_eq!(Transport::Tcp.default_port(), 5060);
        assert_eq!(Transport::Tls.default_port(), 5061);
    }

    #[test]
    fn naptr_is_ordered_by_order_then_preference() {
        let records = vec![
            Naptr {
                order: 100,
                preference: 10,
                service: "SIP+D2U".into(),
                flags: "S".into(),
                replacement: "_sip._udp.example.com".into(),
            },
            Naptr {
                order: 50,
                preference: 50,
                service: "SIPS+D2T".into(),
                flags: "S".into(),
                replacement: "_sips._tcp.example.com".into(),
            },
            Naptr {
                order: 100,
                preference: 5,
                service: "SIP+D2T".into(),
                flags: "S".into(),
                replacement: "_sip._tcp.example.com".into(),
            },
        ];
        let ordered = order_naptr(&records);
        assert_eq!(
            ordered
                .iter()
                .map(|r| r.service.as_str())
                .collect::<Vec<_>>(),
            vec!["SIPS+D2T", "SIP+D2T", "SIP+D2U"]
        );
        assert_eq!(ordered[0].transport(), Some(Transport::Tls));
    }

    #[test]
    fn naptr_drops_what_discovery_cannot_use() {
        let records = vec![
            Naptr {
                order: 1,
                preference: 1,
                service: "SIP+D2U".into(),
                flags: "A".into(), // address, not SRV
                replacement: "host.example.com".into(),
            },
            Naptr {
                order: 2,
                preference: 1,
                service: "SIP+D2S".into(), // SCTP: not a transport we speak
                flags: "S".into(),
                replacement: "_sip._sctp.example.com".into(),
            },
            Naptr {
                order: 3,
                preference: 1,
                service: "SIP+D2T".into(),
                flags: "S".into(),
                replacement: "_sip._tcp.example.com".into(),
            },
        ];
        let ordered = order_naptr(&records);
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].service, "SIP+D2T");
    }

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> Srv {
        Srv {
            priority,
            weight,
            port,
            target: target.into(),
        }
    }

    #[test]
    fn srv_orders_by_priority() {
        let records = vec![
            srv(20, 10, 5060, "b.example.com"),
            srv(10, 10, 5060, "a.example.com"),
        ];
        let ordered = order_srv(&records, |_| 0);
        assert_eq!(ordered[0].target, "a.example.com");
        assert_eq!(ordered[1].target, "b.example.com");
    }

    #[test]
    fn srv_breaks_ties_by_weight() {
        // Two equal-priority records: weight 9 vs 1. A draw below 9 prefers the
        // heavier one, a draw at or above 9 the lighter one.
        let records = vec![
            srv(10, 9, 5060, "heavy.example.com"),
            srv(10, 1, 5060, "light.example.com"),
        ];
        assert_eq!(order_srv(&records, |_| 0)[0].target, "heavy.example.com");
        assert_eq!(order_srv(&records, |_| 9)[0].target, "light.example.com");
        // Every record is still returned.
        assert_eq!(order_srv(&records, |_| 0).len(), 2);
    }

    #[test]
    fn zero_weight_is_only_chosen_last() {
        let records = vec![
            srv(10, 0, 5060, "backup.example.com"),
            srv(10, 5, 5060, "primary.example.com"),
        ];
        let ordered = order_srv(&records, |_| 0);
        assert_eq!(ordered[0].target, "primary.example.com");
        assert_eq!(ordered[1].target, "backup.example.com");
    }

    #[test]
    fn candidates_carry_a_port_and_a_transport() {
        let candidate = Candidate::new(Transport::Udp, "pcscf.example.com.", None);
        assert_eq!(candidate.endpoint, "pcscf.example.com:5060");
        let candidate = Candidate::new(Transport::Tls, "pcscf.example.com", Some(5061));
        assert_eq!(candidate.endpoint, "pcscf.example.com:5061");
        assert_eq!(
            Candidate::new(Transport::Tcp, "pcscf.example.com", None).transport,
            Transport::Tcp
        );
    }

    #[test]
    fn srv_endpoint_drops_the_trailing_dot() {
        let record = srv(1, 1, 5060, "pcscf.example.com.");
        assert_eq!(record.endpoint(), "pcscf.example.com:5060");
    }
}
