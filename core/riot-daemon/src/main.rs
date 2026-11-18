//! riot-daemon: runs as a LaunchDaemon (root) in production. For development:
//!
//! ```sh
//! RIOT_SETTINGS=dev/settings.json RIOT_DATA_DIR=/tmp/riot RIOT_SOCKET=/tmp/riot/agent.sock \
//!   cargo run -p riot-daemon
//! ```

mod agent;
mod config;
mod device;
mod gateway;
mod reports;
mod server;
mod sync;

use std::sync::Arc;

use riot_detect::{Engine, EngineConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        // launchd keeps stderr (the plist's StandardErrorPath).
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let paths = config::Paths::from_env();
    std::fs::create_dir_all(&paths.data_dir)?;

    let started = std::time::Instant::now();
    let engine = Engine::start(EngineConfig::default())?;
    tracing::info!(ms = started.elapsed().as_millis() as u64, "detection engine ready");

    let agent = Arc::new(agent::Agent::new(paths, engine)?);
    tokio::spawn(sync::run(agent.clone()));
    tokio::spawn(sync::flush_reports(agent.clone()));

    let gateway_addr = config::gateway_addr()?;
    tokio::select! {
        r = server::serve(agent.clone()) => r?,
        r = gateway::serve(agent.clone(), gateway_addr) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    let _ = std::fs::remove_file(&agent.paths.socket);
    Ok(())
}
