//! The Windows service: `riot-daemon.exe --service`, started by the service control manager as
//! LocalSystem. The LaunchDaemon's equivalent; the daemon itself is the same `run`.
//!
//! Registered for development (an elevated shell):
//!
//! ```text
//! sc.exe create RiotAgent binPath= "C:\…\riot-daemon.exe --service" start= auto obj= LocalSystem
//! sc.exe start RiotAgent
//! ```
//!
//! A service has no stderr: it logs to `%ProgramData%\Riot\logs\daemon.log` (inside the
//! protected data folder), the previous run's log kept as `daemon.log.1` once it passes 10 MB.

use std::ffi::OsString;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Notify;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::Paths;

pub const SERVICE_NAME: &str = "RiotAgent";
const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// The dispatcher calls `service_main` with no way to pass it anything.
static PATHS: OnceLock<Paths> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the service control manager; returns when the service has stopped.
pub fn start(paths: Paths) -> anyhow::Result<()> {
    crate::os::prepare_data_dir(&paths.data_dir)?;
    init_log(&paths)?;
    let _ = PATHS.set(paths);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn init_log(paths: &Paths) -> anyhow::Result<()> {
    let dir = paths.data_dir.join("logs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("daemon.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        std::fs::rename(&path, dir.join("daemon.log.1"))?;
    }
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
    tracing_subscriber::fmt().with_env_filter(crate::env_filter()).with_writer(Mutex::new(file)).with_ansi(false).init();
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "the service stopped on an error");
    }
}

fn run_service() -> anyhow::Result<()> {
    let paths = PATHS.get().cloned().ok_or_else(|| anyhow::anyhow!("started without paths"))?;
    let stop = Arc::new(Notify::new());
    let on_stop = stop.clone();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            on_stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |state, accepted, exit_code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::NO_ERROR)?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "service started");

    let runtime = crate::runtime()?;
    let result = runtime.block_on(crate::run(paths, async move { stop.notified().await }));
    // The engine's scans run on blocking threads: give them a moment, not forever.
    runtime.shutdown_timeout(Duration::from_secs(5));
    if let Err(e) = &result {
        tracing::error!(error = %e, "the daemon failed");
    }
    // A failure lets the service manager apply its recovery actions (restart).
    let exit_code = if result.is_ok() { ServiceExitCode::NO_ERROR } else { ServiceExitCode::ServiceSpecific(1) };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), exit_code)?;
    result
}
