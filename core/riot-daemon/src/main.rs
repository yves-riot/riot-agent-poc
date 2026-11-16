//! riot-daemon: runs as a LaunchDaemon (root) in production. For development:
//!
//! ```sh
//! RIOT_SETTINGS=dev/settings.json RIOT_DATA_DIR=/tmp/riot RIOT_SOCKET=/tmp/riot/agent.sock \
//!   cargo run -p riot-daemon
//! ```

mod agent;
mod config;
mod device;
mod reports;
mod server;
mod sync;

use std::sync::Arc;

use riot_detect::{Engine, EngineConfig};
use riot_proxy::{Proxy, ProxyConfig, Upstream};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let paths = config::Paths::from_env();
    std::fs::create_dir_all(&paths.data_dir)?;

    let started = std::time::Instant::now();
    let engine = Engine::start(EngineConfig::default())?;
    tracing::info!(ms = started.elapsed().as_millis() as u64, "detection engine ready");

    let agent = Arc::new(agent::Agent::new(paths, engine)?);
    // Kept for the daemon's life: dropping it stops the listener.
    let _proxy = start_proxy(&agent).await;
    tokio::spawn(sync::run(agent.clone()));
    tokio::spawn(sync::flush_reports(agent.clone()));

    tokio::select! {
        r = server::serve(agent.clone()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
    }
    let _ = std::fs::remove_file(&agent.paths.socket);
    Ok(())
}

/// The proxy is one of the daemon's services, not a condition for the others: if it cannot
/// start (port taken, unwritable CA), the daemon runs without it and `status` shows no proxy.
async fn start_proxy(agent: &Arc<agent::Agent>) -> Option<Proxy<agent::Agent>> {
    let listen = agent.paths.proxy_addr?;
    let config = ProxyConfig { listen, ca_dir: agent.paths.ca_dir(), record: agent.paths.proxy_record, upstream: Upstream::default() };
    match Proxy::start(config, agent.clone()).await {
        Ok(proxy) => {
            let info = agent::ProxyInfo {
                addr: proxy.addr(),
                ca_cert: proxy.ca_cert().to_owned(),
                record: agent.paths.proxy_record,
                stats: proxy.stats_handle(),
            };
            let _ = agent.proxy.set(info);
            Some(proxy)
        }
        Err(e) => {
            tracing::error!(%listen, error = %e, "the proxy could not start");
            None
        }
    }
}
