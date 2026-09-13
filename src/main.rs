mod classify;
mod config;
mod dial;
mod dns_cache;
mod gateway;
mod limiter;
mod recovery;
mod route;
mod sniff;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(name = "safethrottle", about = "Asymptotic domain rate-limit TUN gateway")]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/safethrottle/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the TUN gateway (foreground).
    Run,
    /// Install split-default routes into the TUN (enable capture).
    #[command(name = "enable-routing")]
    EnableRouting,
    /// Remove split-default routes (disable capture).
    #[command(name = "disable-routing")]
    DisableRouting,
    /// Alias for enable-routing (PATH wrapper name).
    Safethrottle,
    /// Alias for disable-routing (PATH wrapper name).
    Nothrottle,
    /// Print whether routing capture is marked active.
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    let config_path = resolve_config_path(&cli.config);
    let cfg = if config_path.exists() {
        Config::load(&config_path)?
    } else {
        info!(
            path = %config_path.display(),
            "config missing; using built-in defaults"
        );
        Config::default_builtin()
    };
    let routes = cfg.route_options();

    match cli.cmd {
        Commands::Run => gateway::run(cfg).await?,
        Commands::EnableRouting | Commands::Safethrottle => {
            route::routes_add(&routes)?;
            route::mark_active(true)?;
            println!(
                "safethrottle routing enabled on {} (pref {} table {})",
                routes.tun_name, routes.rule_priority, routes.table_id
            );
        }
        Commands::DisableRouting | Commands::Nothrottle => {
            route::routes_del(&routes)?;
            route::mark_active(false)?;
            println!("safethrottle routing disabled on {}", routes.tun_name);
        }
        Commands::Status => {
            println!(
                "routing_active={}",
                if route::is_active() { "yes" } else { "no" }
            );
            println!(
                "policy_rule_active={}",
                if route::rule_active(routes.rule_priority, routes.table_id) {
                    "yes"
                } else {
                    "no"
                }
            );
            println!(
                "rule_pref={} route_table={} tun={}",
                routes.rule_priority, routes.table_id, routes.tun_name
            );
            if config_path.exists() {
                println!("config={}", config_path.display());
            }
        }
    }
    Ok(())
}

fn resolve_config_path(cli_path: &std::path::Path) -> PathBuf {
    if cli_path.exists() {
        return cli_path.to_path_buf();
    }
    for fallback in ["/run/safethrottle/config.toml", "/etc/safethrottle/config.toml"] {
        let path = std::path::Path::new(fallback);
        if path.exists() {
            return path.to_path_buf();
        }
    }
    cli_path.to_path_buf()
}
