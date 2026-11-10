//! Background work against parrot: enrollment, config refresh (15 min), heartbeat, and the
//! report outbox. A rejected device token is dropped and the device enrolls again at once; the
//! extension's 15 → 30 → 60 min backoff applies when enrolling itself is refused.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use riot_api::{ApiError, Client, EnrollRequest, Heartbeat};
use riot_ipc::Event;

use crate::agent::Agent;
use crate::config::{ManagedSettings, load_settings};
use crate::device::{DeviceFacts, Enrollment, is_installed};

const REFRESH: Duration = Duration::from_secs(15 * 60);
const UNCONFIGURED_POLL: Duration = Duration::from_secs(60);
const ERROR_BACKOFF: [Duration; 4] =
    [Duration::from_secs(15), Duration::from_secs(60), Duration::from_secs(5 * 60), Duration::from_secs(15 * 60)];
const AUTH_BACKOFF: [Duration; 3] =
    [Duration::from_secs(15 * 60), Duration::from_secs(30 * 60), Duration::from_secs(60 * 60)];

pub async fn run(agent: Arc<Agent>) {
    let facts = DeviceFacts::collect();
    let (mut errors, mut auth_errors) = (0usize, 0usize);
    loop {
        let wait = match sync_once(&agent, &facts).await {
            Ok(Synced::Unconfigured) => UNCONFIGURED_POLL,
            Ok(Synced::Done) => {
                (errors, auth_errors) = (0, 0);
                REFRESH
            }
            Err(ApiError::Unauthenticated) => {
                // Refused even after enrolling again: wrong or rotated workspace secret.
                forget_enrollment(&agent);
                set_error(&agent, "device not authorized by parrot");
                auth_errors += 1;
                AUTH_BACKOFF[(auth_errors - 1).min(AUTH_BACKOFF.len() - 1)]
            }
            Err(e) => {
                set_error(&agent, &e.to_string());
                errors += 1;
                ERROR_BACKOFF[(errors - 1).min(ERROR_BACKOFF.len() - 1)]
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = agent.refresh.notified() => {}
        }
    }
}

enum Synced {
    Unconfigured,
    Done,
}

fn set_error(agent: &Agent, message: &str) {
    tracing::warn!(error = message, "sync failed");
    agent.state.write().unwrap().last_error = Some(message.into());
    let _ = agent.events.send(Event::StateChanged);
}

async fn sync_once(agent: &Agent, facts: &DeviceFacts) -> Result<Synced, ApiError> {
    // Re-read every time: the MDM may install or change the profile after the daemon started.
    let settings = match load_settings(&agent.paths.settings) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, path = %agent.paths.settings.display(), "unreadable managed settings");
            None
        }
    };
    let Some(settings) = settings else {
        let mut state = agent.state.write().unwrap();
        if state.settings.take().is_some() {
            state.config = None;
            drop(state);
            let _ = agent.events.send(Event::StateChanged);
        }
        return Ok(Synced::Unconfigured);
    };

    let client = Client::new(&settings.api_url, agent.version)?;
    let (mut enrollment, fresh) = ensure_enrolled(agent, &client, &settings, facts).await?;
    let config = match client.config(&enrollment.device_token).await {
        // A stored token parrot no longer knows (device revoked, token rotated, parrot's data
        // reset): enroll again now rather than after the auth backoff.
        Err(ApiError::Unauthenticated) if !fresh => {
            tracing::info!(device_id = %enrollment.device_id, "device token rejected; enrolling again");
            forget_enrollment(agent);
            enrollment = ensure_enrolled(agent, &client, &settings, facts).await?.0;
            client.config(&enrollment.device_token).await?
        }
        other => other?,
    };

    let installed = config
        .active_policy()
        .into_iter()
        .flat_map(|p| p.services.iter())
        .flat_map(|s| s.desktop_apps.iter())
        .filter_map(|a| a.bundle_id.clone())
        .map(|id| {
            let installed = is_installed(&id);
            (id, installed)
        })
        .collect();

    {
        let mut state = agent.state.write().unwrap();
        state.settings = Some(settings);
        state.config = Some(config);
        state.installed = installed;
        state.last_sync = Some(Utc::now());
        state.last_error = None;
    }
    let _ = agent.events.send(Event::StateChanged);

    let status = agent.status().await;
    let heartbeat = Heartbeat {
        agent_version: agent.version.into(),
        os_version: facts.os_version.clone(),
        components: serde_json::json!({
            "daemon": "running",
            "monitoring": status.monitoring,
            "engineHeapMib": status.engine_heap_mib,
            "pendingReports": status.pending_reports,
            // Reported by the ES extension and the menu bar app once they register (step 3/4).
            "esExtension": serde_json::Value::Null,
            "menuBarApp": serde_json::Value::Null,
        }),
    };
    if let Err(e) = client.heartbeat(&enrollment.device_token, &heartbeat).await {
        tracing::warn!(error = %e, "heartbeat failed");
    }
    agent.reports_pending.notify_one();
    Ok(Synced::Done)
}

fn forget_enrollment(agent: &Agent) {
    Enrollment::remove(&agent.paths.data_dir);
    agent.state.write().unwrap().enrollment = None;
}

/// The device's credential, enrolling when there is none. `true` when it was just issued.
async fn ensure_enrolled(
    agent: &Agent,
    client: &Client,
    settings: &ManagedSettings,
    facts: &DeviceFacts,
) -> Result<(Enrollment, bool), ApiError> {
    let current = agent.state.read().unwrap().enrollment.clone();
    if let Some(e) = current.filter(|e| e.workspace_id == settings.workspace_id && e.api_url == settings.api_url) {
        return Ok((e, false));
    }
    let response = client
        .enroll(
            &settings.enrollment_secret,
            &EnrollRequest {
                workspace_id: settings.workspace_id.clone(),
                hardware_uuid: facts.hardware_uuid.clone(),
                serial_number: facts.serial_number.clone(),
                hostname: facts.hostname.clone(),
                os: facts.os.clone(),
                os_version: facts.os_version.clone(),
                agent_version: agent.version.into(),
                employee_email: settings.employee_email.clone(),
            },
        )
        .await?;
    let enrollment = Enrollment {
        device_id: response.device_id,
        device_token: response.device_token,
        workspace_id: settings.workspace_id.clone(),
        api_url: settings.api_url.clone(),
    };
    if let Err(e) = enrollment.save(&agent.paths.data_dir) {
        tracing::error!(error = %e, "could not persist enrollment; will re-enroll after restart");
    }
    tracing::info!(device_id = %enrollment.device_id, "device enrolled");
    agent.state.write().unwrap().enrollment = Some(enrollment.clone());
    Ok((enrollment, true))
}

/// Sends spooled reports whenever one is queued, and retries every minute while some remain.
pub async fn flush_reports(agent: Arc<Agent>) {
    loop {
        tokio::select! {
            _ = agent.reports_pending.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        let (token, url) = {
            let state = agent.state.read().unwrap();
            match (&state.enrollment, &state.settings) {
                (Some(e), Some(s)) => (e.device_token.clone(), s.api_url.clone()),
                _ => continue,
            }
        };
        let Ok(client) = Client::new(&url, agent.version) else { continue };
        for (path, report) in agent.spool.pending() {
            match client.report(&token, &report).await {
                Ok(()) => agent.spool.done(&path),
                // 422: parrot will never accept it; keeping it would block the queue forever.
                Err(ApiError::Status { status: 422, body }) => {
                    tracing::error!(%body, "report rejected; dropping it");
                    agent.spool.done(&path);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "report upload failed; will retry");
                    break;
                }
            }
        }
    }
}
