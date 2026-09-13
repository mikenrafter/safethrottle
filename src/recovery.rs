//! Gateway crash recovery and boot-scoped disable after repeated failure.

use std::any::Any;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tracing::{error, warn};

use crate::config::Config;
use crate::route;

pub const RUNTIME_DIR: &str = "/run/safethrottle";
const FAILED_ONCE_MARKER: &str = "recovery-failed-once";
const BOOT_DISABLED_MARKER: &str = "boot-disabled";
pub const RECOVERY_BUDGET: Duration = Duration::from_secs(5);
const RESTART_BACKOFF: Duration = Duration::from_millis(50);

fn marker_path(name: &str) -> PathBuf {
    Path::new(RUNTIME_DIR).join(name)
}

pub fn ensure_runtime_dir() -> io::Result<()> {
    std::fs::create_dir_all(RUNTIME_DIR)
}

pub fn is_boot_disabled() -> bool {
    marker_path(BOOT_DISABLED_MARKER).exists()
}

pub fn is_failed_once() -> bool {
    marker_path(FAILED_ONCE_MARKER).exists()
}

fn write_marker(name: &str) -> io::Result<()> {
    ensure_runtime_dir()?;
    std::fs::write(marker_path(name), b"1\n")
}

pub fn mark_failed_once() -> io::Result<()> {
    write_marker(FAILED_ONCE_MARKER)
}

pub fn mark_boot_disabled() -> io::Result<()> {
    write_marker(BOOT_DISABLED_MARKER)
}

pub fn notify(summary: &str) {
    match Command::new("notify-send")
        .args(["-u", "critical", "safethrottle", summary])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => warn!(?status, "notify-send returned non-success"),
        Err(e) => warn!("notify-send unavailable: {e}"),
    }
}

pub fn format_panic(payload: Box<dyn Any + Send>) -> String {
    if let Some(msg) = payload.downcast_ref::<&str>() {
        return (*msg).to_string();
    }
    if let Some(msg) = payload.downcast_ref::<String>() {
        return msg.clone();
    }
    "unknown panic payload".to_string()
}

pub async fn retry_start_within_budget<F, Fut, T>(
    mut start: F,
    budget: Duration,
) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let deadline = Instant::now() + budget;
    let mut attempt = 0u32;

    while Instant::now() < deadline {
        attempt += 1;
        warn!(
            attempt,
            remaining_ms = deadline.saturating_duration_since(Instant::now()).as_millis(),
            "retrying gateway start within recovery budget"
        );
        tokio::time::sleep(RESTART_BACKOFF).await;
        if let Ok(value) = start().await {
            return Some(value);
        }
    }

    None
}

pub async fn handle_recovery_failure(
    cfg: &Config,
    err: anyhow::Error,
    after_systemd_retry: bool,
) -> anyhow::Result<()> {
    disable_routing(cfg);

    if after_systemd_retry {
        mark_boot_disabled()?;
        notify("Disabled for this boot after repeated gateway failures.");
        error!("recovery exhausted after systemd restart: {err:#}");
        Ok(())
    } else {
        mark_failed_once()?;
        notify(&format!(
            "Gateway recovery failed ({err}). Routing disabled; systemd will retry once."
        ));
        error!("recovery failed; exiting for systemd restart: {err:#}");
        Err(err)
    }
}

fn disable_routing(cfg: &Config) {
    let routes = cfg.route_options();
    if let Err(e) = route::routes_del(&routes) {
        warn!("disable routing: {e}");
    }
    if let Err(e) = route::mark_active(false) {
        warn!("clear routing marker: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn marker_paths_under_runtime_dir() {
        assert!(marker_path(FAILED_ONCE_MARKER)
            .to_string_lossy()
            .contains(RUNTIME_DIR));
    }

    #[tokio::test]
    async fn retry_start_within_budget_recovers_before_deadline() {
        let attempts = AtomicU32::new(0);
        let result = retry_start_within_budget(
            || {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 2 {
                        Err(anyhow::anyhow!("start failed {n}"))
                    } else {
                        Ok(42)
                    }
                }
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(result, Some(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_start_within_budget_gives_up_after_deadline() {
        let attempts = AtomicU32::new(0);
        let result = retry_start_within_budget(
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err::<i32, _>(anyhow::anyhow!("always fail")) }
            },
            Duration::from_millis(200),
        )
        .await;

        assert!(result.is_none());
        assert!(attempts.load(Ordering::SeqCst) >= 2);
    }
}
