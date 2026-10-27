//! TOML carrier profiles.
//!
//! One file per PLMN, named `<mcc><mnc>.toml` (for example `00101.toml`). The
//! schema is deliberately data-only: it records the network's APN, discovery
//! method, codec policy, feature tags and timers. No vendor strings, blobs or
//! decompiled constants belong here — only public 3GPP/GSMA facts.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCscfDiscovery {
    /// P-CSCF address configured in this profile (`p_cscf`).
    Static,
    /// The modem/PDN supplies P-CSCF via PCO (TS 24.008 / 24.301).
    Pco,
    /// DHCPv4/v6 option 120 (RFC 3361/3319).
    Dhcp,
}

impl PCscfDiscovery {
    pub fn parse(s: &str) -> Result<Self, ProfileError> {
        match s.to_ascii_lowercase().as_str() {
            "static" => Ok(Self::Static),
            "pco" => Ok(Self::Pco),
            "dhcp" => Ok(Self::Dhcp),
            other => Err(ProfileError::Invalid {
                field: "p_cscf_discovery",
                detail: format!("unknown mode {other:?} (static|pco|dhcp)"),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Pco => "pco",
            Self::Dhcp => "dhcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timers {
    pub t1_ms: u64,
    pub t2_ms: u64,
    pub register_expires_s: u64,
    pub subscribe_expires_s: u64,
    pub invite_expires_s: u64,
    pub prack_wait_ms: u64,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            t1_ms: 500,
            t2_ms: 4_000,
            register_expires_s: 600_000,
            subscribe_expires_s: 600_000,
            invite_expires_s: 180,
            prack_wait_ms: 4_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierProfile {
    /// `<mcc><mnc>`, the lookup key.
    pub id: String,
    pub mcc: String,
    /// MNC without a leading zero, as written in the IMS domain.
    pub mnc: String,
    pub operator: String,
    pub display_name: String,
    pub ims_apn: String,
    pub p_cscf_discovery: PCscfDiscovery,
    pub p_cscf: Vec<String>,
    pub p_cscf_ports: Vec<u16>,
    pub volte: bool,
    pub evs: bool,
    /// AMR-WB mode-set offered in SDP. Empty means "do not offer AMR-WB".
    pub amr_wb_modes: Vec<u8>,
    pub sms_over_ims: bool,
    pub ua: String,
    pub feature_tags: Vec<String>,
    pub timers: Timers,
}

impl CarrierProfile {
    pub fn parse(input: &str) -> Result<Self, ProfileError> {
        let value: toml::Value =
            toml::from_str(input).map_err(|e| ProfileError::Toml(e.to_string()))?;
        let table = value.as_table().ok_or_else(|| ProfileError::Invalid {
            field: "profile",
            detail: "top level must be a table".into(),
        })?;

        let id = req_str(table, "id")?.to_string();
        let mcc = req_str(table, "mcc")?.to_string();
        let mnc = req_str(table, "mnc")?.to_string();
        if mcc.len() != 3 || !mcc.chars().all(|c| c.is_ascii_digit()) {
            return Err(ProfileError::Invalid {
                field: "mcc",
                detail: "must be exactly 3 digits".into(),
            });
        }
        if mnc.is_empty() || mnc.len() > 3 || !mnc.chars().all(|c| c.is_ascii_digit()) {
            return Err(ProfileError::Invalid {
                field: "mnc",
                detail: "must be 1-3 digits".into(),
            });
        }
        let expected_id = format!("{mcc}{mnc}");
        if id != expected_id {
            return Err(ProfileError::Invalid {
                field: "id",
                detail: format!("expected {expected_id} for mcc={mcc} mnc={mnc}"),
            });
        }

        let mut p_cscf = req_str_array(table, "p_cscf")?;
        let p_cscf_discovery = PCscfDiscovery::parse(req_str(table, "p_cscf_discovery")?)?;
        if p_cscf_discovery == PCscfDiscovery::Static && p_cscf.is_empty() {
            return Err(ProfileError::Missing("p_cscf"));
        }
        p_cscf.shrink_to_fit();

        let amr_wb_modes = req_int_array(table, "amr_wb_modes")?
            .into_iter()
            .map(|n| {
                u8::try_from(n).map_err(|_| ProfileError::Invalid {
                    field: "amr_wb_modes",
                    detail: format!("mode {n} is not a byte"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let timers = match table.get("timers") {
            Some(t) => {
                let t = t.as_table().ok_or_else(|| ProfileError::Invalid {
                    field: "timers",
                    detail: "must be a table".into(),
                })?;
                Timers {
                    t1_ms: opt_int(t, "t1_ms")?.unwrap_or(500),
                    t2_ms: opt_int(t, "t2_ms")?.unwrap_or(4_000),
                    register_expires_s: opt_int(t, "register_expires_s")?.unwrap_or(600_000),
                    subscribe_expires_s: opt_int(t, "subscribe_expires_s")?.unwrap_or(600_000),
                    invite_expires_s: opt_int(t, "invite_expires_s")?.unwrap_or(180),
                    prack_wait_ms: opt_int(t, "prack_wait_ms")?.unwrap_or(4_000),
                }
            }
            None => Timers::default(),
        };

        Ok(Self {
            id,
            mcc,
            mnc,
            operator: req_str(table, "operator")?.to_string(),
            display_name: req_str(table, "display_name")?.to_string(),
            ims_apn: req_str(table, "ims_apn")?.to_string(),
            p_cscf_discovery,
            p_cscf,
            p_cscf_ports: req_int_array_opt(table, "p_cscf_ports")?
                .into_iter()
                .map(|n| {
                    u16::try_from(n).map_err(|_| ProfileError::Invalid {
                        field: "p_cscf_ports",
                        detail: format!("port {n} out of range"),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            volte: req_bool(table, "volte")?,
            evs: req_bool(table, "evs")?,
            amr_wb_modes,
            sms_over_ims: req_bool(table, "sms_over_ims")?,
            ua: req_str(table, "ua")?.to_string(),
            feature_tags: req_str_array(table, "feature_tags")?,
            timers,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| ProfileError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let profile = Self::parse(&text)?;
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if stem != profile.id {
                return Err(ProfileError::Invalid {
                    field: "id",
                    detail: format!("file name {stem:?} does not match id {:?}", profile.id),
                });
            }
        }
        Ok(profile)
    }

    /// The built-in Open5GS/Kamailio lab profile (`profiles/00101.toml`).
    pub fn lab() -> Self {
        Self::parse(include_str!("../profiles/00101.toml"))
            .expect("embedded lab carrier profile must be valid")
    }

    /// IMS home domain: `ims.mnc<mnc>.mcc<mcc>.3gppnetwork.org` (TS 23.003 §13.2).
    pub fn ims_domain(&self) -> String {
        format!("ims.mnc{:0>3}.mcc{}.3gppnetwork.org", self.mnc, self.mcc)
    }
}

#[derive(Debug, Clone, Default)]
pub struct CarrierBook {
    profiles: BTreeMap<String, CarrierProfile>,
}

impl CarrierBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load every `*.toml` file in a directory, keyed by MCC/MNC.
    pub fn load_dir(dir: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let dir = dir.as_ref();
        let entries = std::fs::read_dir(dir).map_err(|e| ProfileError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        let mut book = Self::new();
        for entry in entries {
            let entry = entry.map_err(|e| ProfileError::Io {
                path: dir.display().to_string(),
                detail: e.to_string(),
            })?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let profile = CarrierProfile::from_file(&path)?;
            book.insert(profile);
        }
        Ok(book)
    }

    pub fn insert(&mut self, profile: CarrierProfile) -> Option<CarrierProfile> {
        self.profiles.insert(profile.id.clone(), profile)
    }

    pub fn get(&self, mcc: &str, mnc: &str) -> Option<&CarrierProfile> {
        self.profiles.get(&format!("{mcc}{mnc}"))
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &CarrierProfile)> {
        self.profiles.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    Toml(String),
    Io { path: String, detail: String },
    Missing(&'static str),
    Invalid { field: &'static str, detail: String },
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProfileError::Toml(e) => write!(f, "TOML parse error: {e}"),
            ProfileError::Io { path, detail } => write!(f, "{path}: {detail}"),
            ProfileError::Missing(field) => write!(f, "missing required field {field:?}"),
            ProfileError::Invalid { field, detail } => write!(f, "invalid {field}: {detail}"),
        }
    }
}

impl std::error::Error for ProfileError {}

fn req_str<'a>(table: &'a toml::Table, key: &'static str) -> Result<&'a str, ProfileError> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(ProfileError::Missing(key))
}

fn req_bool(table: &toml::Table, key: &'static str) -> Result<bool, ProfileError> {
    table
        .get(key)
        .and_then(|v| v.as_bool())
        .ok_or(ProfileError::Missing(key))
}

fn req_str_array(table: &toml::Table, key: &'static str) -> Result<Vec<String>, ProfileError> {
    let arr = table
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or(ProfileError::Missing(key))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| ProfileError::Invalid {
                    field: key,
                    detail: "array must contain strings".into(),
                })
        })
        .collect()
}

fn req_int_array(table: &toml::Table, key: &'static str) -> Result<Vec<i64>, ProfileError> {
    let arr = table
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or(ProfileError::Missing(key))?;
    arr.iter()
        .map(|v| {
            v.as_integer().ok_or_else(|| ProfileError::Invalid {
                field: key,
                detail: "array must contain integers".into(),
            })
        })
        .collect()
}

fn req_int_array_opt(table: &toml::Table, key: &'static str) -> Result<Vec<i64>, ProfileError> {
    match table.get(key) {
        Some(_) => req_int_array(table, key),
        None => Ok(Vec::new()),
    }
}

fn opt_int(table: &toml::Table, key: &'static str) -> Result<Option<u64>, ProfileError> {
    match table.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_integer()
            .and_then(|n| u64::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| ProfileError::Invalid {
                field: key,
                detail: "must be a non-negative integer".into(),
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_embedded_lab_profile() {
        let p = CarrierProfile::lab();
        assert_eq!(p.id, "00101");
        assert_eq!(p.mcc, "001");
        assert_eq!(p.mnc, "01");
        assert_eq!(p.ims_apn, "ims");
        assert_eq!(p.p_cscf_discovery, PCscfDiscovery::Static);
        assert_eq!(p.ims_domain(), "ims.mnc001.mcc001.3gppnetwork.org");
        assert!(p.volte);
        assert!(!p.evs);
        assert_eq!(p.amr_wb_modes.len(), 8);
        assert!(p.feature_tags.iter().any(|t| t.contains("icsi.mmtel")));
        assert_eq!(p.timers.register_expires_s, 600_000);
    }

    #[test]
    fn book_keys_by_mcc_mnc() {
        let mut book = CarrierBook::new();
        book.insert(CarrierProfile::lab());
        assert_eq!(book.len(), 1);
        assert!(book.get("001", "01").is_some());
        assert!(book.get("310", "260").is_none());
    }

    #[test]
    fn id_must_match_mcc_mnc() {
        let bad =
            include_str!("../profiles/00101.toml").replace("id = \"00101\"", "id = \"99999\"");
        let err = CarrierProfile::parse(&bad).unwrap_err();
        assert!(matches!(err, ProfileError::Invalid { field: "id", .. }));
    }

    #[test]
    fn static_discovery_requires_address() {
        let bad = include_str!("../profiles/00101.toml").replace(
            "p_cscf = [\"pcscf.ims.mnc001.mcc001.3gppnetwork.org\"]",
            "p_cscf = []",
        );
        let err = CarrierProfile::parse(&bad).unwrap_err();
        assert_eq!(err, ProfileError::Missing("p_cscf"));
    }

    #[test]
    fn rejects_bad_plmn() {
        let bad = include_str!("../profiles/00101.toml").replace("mcc = \"001\"", "mcc = \"1\"");
        assert!(CarrierProfile::parse(&bad).is_err());
    }
}
