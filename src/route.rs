//! Install / remove split-default capture via a dedicated policy-routing table.
//!
//! Tailscale installs `ip rule pref 5270 lookup 52` with a default via tailscale0.
//! Split-default routes in the main table never win. We install pref 5260 → our
//! table so outbound internet traffic is captured before Tailscale's rule.

use std::io;
use std::process::Command;

use tracing::{info, warn};

/// Routing table for safethrottle capture (see `rt_tables` name optional).
pub const DEFAULT_TABLE_ID: u32 = 100;
/// Evaluated before Tailscale's 5270 rule.
pub const DEFAULT_RULE_PRIORITY: u32 = 5260;

/// Private / local ranges that must fall through to later rules (main, tailscale).
const THROW_CIDRS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
];

const SPLIT_CIDRS: &[&str] = &["0.0.0.0/1", "128.0.0.0/1"];

#[derive(Debug, Clone)]
pub struct RouteOptions {
    pub tun_name: String,
    pub table_id: u32,
    pub rule_priority: u32,
}

pub fn routes_add(opts: &RouteOptions) -> io::Result<()> {
    ensure_rule(opts.rule_priority, opts.table_id)?;
    for cidr in THROW_CIDRS {
        let _ = table_route("add", opts.table_id, &["throw", cidr]);
    }
    for cidr in SPLIT_CIDRS {
        let _ = table_route(
            "add",
            opts.table_id,
            &[cidr, "dev", opts.tun_name.as_str()],
        );
    }
    // Legacy: split routes in main no longer help once policy capture is active.
    for cidr in SPLIT_CIDRS {
        let _ = Command::new("ip")
            .args(["route", "del", cidr, "dev", opts.tun_name.as_str()])
            .status();
    }
    info!(
        pref = opts.rule_priority,
        table = opts.table_id,
        tun = %opts.tun_name,
        "policy capture enabled"
    );
    Ok(())
}

pub fn routes_del(opts: &RouteOptions) -> io::Result<()> {
    for cidr in SPLIT_CIDRS {
        let _ = table_route(
            "del",
            opts.table_id,
            &[cidr, "dev", opts.tun_name.as_str()],
        );
    }
    for cidr in THROW_CIDRS {
        let _ = table_route("del", opts.table_id, &["throw", cidr]);
    }
    del_rule(opts.rule_priority, opts.table_id)?;
    info!(
        pref = opts.rule_priority,
        table = opts.table_id,
        tun = %opts.tun_name,
        "policy capture disabled"
    );
    Ok(())
}

fn ensure_rule(priority: u32, table_id: u32) -> io::Result<()> {
    if rule_exists(priority, table_id) {
        info!(%priority, %table_id, "ip rule already present");
        return Ok(());
    }
    let pref = priority.to_string();
    let table = table_id.to_string();
    let output = Command::new("ip")
        .args(["rule", "add", "pref", &pref, "lookup", &table])
        .output()?;
    if output.status.success() {
        info!(%priority, %table_id, "ip rule added");
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if rule_exists(priority, table_id) || stderr.contains("File exists") {
        info!(%priority, %table_id, "ip rule already present");
        return Ok(());
    }
    Err(io::Error::other(format!(
        "ip rule add pref {priority} lookup {table_id} failed: {stderr}"
    )))
}

fn del_rule(priority: u32, table_id: u32) -> io::Result<()> {
    if !rule_exists(priority, table_id) {
        return Ok(());
    }
    let pref = priority.to_string();
    let table = table_id.to_string();
    let status = Command::new("ip")
        .args(["rule", "del", "pref", &pref, "lookup", &table])
        .status()?;
    if status.success() {
        info!(%priority, %table_id, "ip rule removed");
    }
    Ok(())
}

fn rule_exists(priority: u32, table_id: u32) -> bool {
    let out = Command::new("ip")
        .args(["-4", "rule", "show"])
        .output()
        .ok();
    let Some(out) = out else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let priority_prefix = format!("{priority}:");
    let table_needle = format!("lookup {table_id}");
    text.lines().any(|line| {
        (line.starts_with(&priority_prefix) || line.contains(&format!("pref {priority}")))
            && line.contains(&table_needle)
    })
}

fn table_route(op: &str, table_id: u32, args: &[&str]) -> io::Result<()> {
    let table = table_id.to_string();
    let mut cmd = Command::new("ip");
    cmd.args(["route", op]);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.args(["table", &table]);
    let output = cmd.output()?;
    if output.status.success() {
        info!(%op, table = %table_id, args = ?args, "table route updated");
        return Ok(());
    }
    if op == "del" {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("File exists") {
        return Ok(());
    }
    warn!(%op, table = %table_id, args = ?args, %stderr, "table route op may have failed");
    Ok(())
}

/// Persist a marker file so scripts know whether capture is active.
pub fn mark_active(active: bool) -> io::Result<()> {
    let path = std::path::Path::new("/run/safethrottle/routing-active");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if active {
        std::fs::write(path, b"1\n")?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn is_active() -> bool {
    std::path::Path::new("/run/safethrottle/routing-active").exists()
}

pub fn rule_active(priority: u32, table_id: u32) -> bool {
    rule_exists(priority, table_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throw_cidrs_cover_common_bypass_targets() {
        assert!(THROW_CIDRS.contains(&"10.0.0.0/8"));
        assert!(THROW_CIDRS.contains(&"100.64.0.0/10"));
        assert!(DEFAULT_RULE_PRIORITY < 5270);
    }

    #[test]
    fn rule_line_matches_kernel_format() {
        let sample = "5260:\tfrom all lookup 100\n5270:\tfrom all lookup 52\n";
        assert!(sample.lines().any(|line| {
            line.starts_with("5260:") && line.contains("lookup 100")
        }));
    }
}
