use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateUnit {
    ReqsPerMin,
}

impl Default for RateUnit {
    fn default() -> Self {
        Self::ReqsPerMin
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyConfig {
    pub limit: u32,
    pub suffixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_true")]
    pub default_route: bool,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_addr")]
    pub tun_addr: String,
    #[serde(default = "default_tun_dest")]
    pub tun_dest: String,
    #[serde(default = "default_tun_netmask")]
    pub tun_netmask: String,
    #[serde(default)]
    pub uplink_iface: String,
    /// Policy-routing table for split-default capture (before Tailscale pref 5270).
    #[serde(default = "default_route_table_id")]
    pub route_table_id: u32,
    /// `ip rule` priority; must be lower than Tailscale's 5270.
    #[serde(default = "default_route_rule_priority")]
    pub route_rule_priority: u32,
    /// Free band until floor(limit * soft_ratio); default 0.7 → 14 of 20.
    #[serde(default = "default_soft_ratio")]
    pub soft_ratio: f64,
    /// Multiplier on soft-zone waits: (time_left / slots_left) * soft_pace.
    #[serde(default = "default_soft_pace")]
    pub soft_pace: f64,
    #[serde(default)]
    pub unit: RateUnit,
    pub families: BTreeMap<String, FamilyConfig>,
}

fn default_true() -> bool {
    true
}
fn default_tun_name() -> String {
    "safethrottle0".into()
}
fn default_tun_addr() -> String {
    "10.10.10.2".into()
}
fn default_tun_dest() -> String {
    "10.10.10.1".into()
}
fn default_tun_netmask() -> String {
    "255.255.255.0".into()
}
fn default_soft_ratio() -> f64 {
    0.7
}
fn default_soft_pace() -> f64 {
    0.7
}
fn default_route_table_id() -> u32 {
    crate::route::DEFAULT_TABLE_ID
}
fn default_route_rule_priority() -> u32 {
    crate::route::DEFAULT_RULE_PRIORITY
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("soft_ratio must be in (0, 1), got {0}")]
    SoftRatio(f64),
    #[error("soft_pace must be in (0, 1], got {0}")]
    SoftPace(f64),
    #[error("family `{0}` limit must be >= 1")]
    Limit(String),
    #[error("route_rule_priority must be < 5270 (Tailscale), got {0}")]
    RulePriority(u32),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn default_builtin() -> Self {
        let text = include_str!("../config.example.toml");
        toml::from_str(text).expect("builtin config parses")
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(self.soft_ratio > 0.0 && self.soft_ratio < 1.0) {
            return Err(ConfigError::SoftRatio(self.soft_ratio));
        }
        if !(self.soft_pace > 0.0 && self.soft_pace <= 1.0) {
            return Err(ConfigError::SoftPace(self.soft_pace));
        }
        if self.route_rule_priority >= 5270 {
            return Err(ConfigError::RulePriority(self.route_rule_priority));
        }
        for (name, fam) in &self.families {
            if fam.limit < 1 {
                return Err(ConfigError::Limit(name.clone()));
            }
        }
        Ok(())
    }

    pub fn route_options(&self) -> crate::route::RouteOptions {
        crate::route::RouteOptions {
            tun_name: self.tun_name.clone(),
            table_id: self.route_table_id,
            rule_priority: self.route_rule_priority,
        }
    }

    /// Rolling window for the configured unit (reqs/min → 60s).
    pub fn window_secs(&self) -> u64 {
        match self.unit {
            RateUnit::ReqsPerMin => 60,
        }
    }
}
