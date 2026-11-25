//! riot-daemon: runs as a LaunchDaemon (root) on macOS, as the `RiotAgent` service
//! (LocalSystem, `riot-daemon.exe --service`) on Windows. For development:
//!
//! ```sh
//! RIOT_SETTINGS=dev/settings.json RIOT_DATA_DIR=/tmp/riot RIOT_SOCKET=/tmp/riot/agent.sock \
//!   cargo run -p riot-daemon
//! ```
//!
//! On Windows, `dev/run-dev.ps1` sets the same variables (`RIOT_SOCKET=\\.\pipe\riot-dev`).

// The Win32 calls no safe crate wraps are in `os/windows.rs`, which allows unsafe code; nothing
// else may (macOS needs none).
#![deny(unsafe_code)]

mod agent;
mod config;
mod device;
mod gateway;
mod os;
mod reports;
mod server;
#[cfg(windows)]
mod service;
mod sync;

use std::future::Future;
use std::sync::Arc;

use riot_detect::{Engine, EngineConfig};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let paths = config::Paths::from_env();
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--service") {
        return service::start(paths);
    }
    tracing_subscriber::fmt()
        .with_env_filter(env_filter())
        // launchd keeps stderr (the plist's StandardErrorPath).
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    os::prepare_data_dir(&paths.data_dir)?;
    runtime()?.block_on(run(paths, async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

fn env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build()
}

/// Until a server fails or `stop` completes.
async fn run(paths: config::Paths, stop: impl Future<Output = ()>) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let engine = Engine::start(EngineConfig::default())?;
    tracing::info!(ms = started.elapsed().as_millis() as u64, "detection engine ready");

    let agent = Arc::new(agent::Agent::new(paths, engine)?);
    tokio::spawn(sync::run(agent.clone()));
    tokio::spawn(sync::flush_reports(agent.clone()));
    tokio::spawn(agent.clone().watch_pause());

    let gateway_addr = config::gateway_addr()?;
    tokio::select! {
        r = server::serve(agent.clone()) => r?,
        r = gateway::serve(agent.clone(), gateway_addr) => r?,
        _ = stop => tracing::info!("stopping"),
    }
    #[cfg(unix)]
    let _ = std::fs::remove_file(&agent.paths.socket);
    Ok(())
}
