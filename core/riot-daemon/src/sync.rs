//! Background work against parrot: enrollment, the gateway's intermediate CA, config refresh
//! (15 min), heartbeat, and the report outbox. When parrot no longer knows the device, it
//! enrolls again at once, with the same device key; the extension's 15 → 30 → 60 min backoff
//! applies when enrolling itself is refused (wrong or revoked enrollment key).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use riot_api::{ApiError, Client, DeviceCredential, DeviceStatus, EnrollRequest, Heartbeat};
use riot_ipc::Event;
use sha2::{Digest, Sha256};

use crate::agent::Agent;
use crate::config::{ManagedSettings, load_settings};
use crate::device::{DeviceFacts, Enrollment, Intermediate, is_installed};
use crate::gateway::ca::Authority;

const REFRESH: Duration = Duration::from_secs(15 * 60);
const UNCONFIGURED_POLL: Duration = Duration::from_secs(60);
/// While an admin has to approve this Mac.
const PENDING_POLL: Duration = Duration::from_secs(5 * 60);
/// The intermediate (7 days) is renewed once less than this is left: parrot can be unreachable
/// for up to 3 days before the gateway stops decrypting.
const RENEW_BEFORE: time::Duration = time::Duration::days(3);
const ERROR_BACKOFF: [Duration; 4] =
    [Duration::from_secs(15), Duration::from_secs(60), Duration::from_secs(5 * 60), Duration::from_secs(15 * 60)];
const AUTH_BACKOFF: [Duration; 3] =
    [Duration::from_secs(15 * 60), Duration::from_secs(30 * 60), Duration::from_secs(60 * 60)];

pub async fn run(agent: Arc<Agent>) {
    if let Some(pem) = Intermediate::load(&agent.paths.data_dir) {
        install_intermediate(&agent, &pem, false);
    }
    let facts = DeviceFacts::collect();
    let (mut errors, mut auth_errors) = (0usize, 0usize);
    loop {
        let wait = match sync_once(&agent, &facts).await {
            Ok(Synced::Unconfigured) => UNCONFIGURED_POLL,
            Ok(Synced::Pending) => PENDING_POLL,
            Ok(Synced::Done) => {
                (errors, auth_errors) = (0, 0);
                REFRESH
            }
            Err(ApiError::Unauthenticated) => {
                // Refused even after enrolling again: wrong, revoked or expired enrollment key.
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
    /// Enrolled, waiting for an admin to approve this Mac's new key.
    Pending,
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
    let (enrollment, fresh) = ensure_enrolled(agent, &client, &settings, facts).await?;
    if enrollment.status == DeviceStatus::PendingApproval {
        return Ok(pending(agent, settings));
    }
    let mut device = credential(agent, &enrollment);
    let config = match client.config(&device).await {
        // A device parrot no longer knows (revoked, or parrot's data reset): enroll again now
        // rather than after the auth backoff.
        Err(ApiError::Unauthenticated) if !fresh => {
            tracing::info!(device_id = %enrollment.device_id, "device rejected; enrolling again");
            forget_enrollment(agent);
            let enrollment = ensure_enrolled(agent, &client, &settings, facts).await?.0;
            if enrollment.status == DeviceStatus::PendingApproval {
                return Ok(pending(agent, settings));
            }
            device = credential(agent, &enrollment);
            client.config(&device).await?
        }
        other => other?,
    };
    renew_intermediate(agent, &client, &device).await;

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
            "paused": status.paused,
            "engineHeapMib": status.engine_heap_mib,
            "pendingReports": status.pending_reports,
            // Reported by the ES extension and the menu bar app once they register (step 3/4).
            "esExtension": serde_json::Value::Null,
            "menuBarApp": serde_json::Value::Null,
        }),
    };
    if let Err(e) = client.heartbeat(&device, &heartbeat).await {
        tracing::warn!(error = %e, "heartbeat failed");
    }
    agent.reports_pending.notify_one();
    Ok(Synced::Done)
}

fn forget_enrollment(agent: &Agent) {
    Enrollment::remove(&agent.paths.data_dir);
    agent.state.write().unwrap().enrollment = None;
}

fn credential(agent: &Agent, enrollment: &Enrollment) -> DeviceCredential {
    DeviceCredential { device_id: enrollment.device_id.clone(), key: agent.keys.device.clone() }
}

fn pending(agent: &Agent, settings: crate::config::ManagedSettings) -> Synced {
    {
        let mut state = agent.state.write().unwrap();
        state.settings = Some(settings);
        state.config = None;
        state.last_error = Some("waiting for an admin to approve this Mac in Riot".into());
    }
    tracing::warn!("this Mac is enrolled with another key; waiting for an admin's approval");
    let _ = agent.events.send(Event::StateChanged);
    Synced::Pending
}

/// The device's enrollment, enrolling when there is none, when it is pending, or when the
/// enrollment key, the API URL or the device key changed. `true` when it was just made.
async fn ensure_enrolled(
    agent: &Agent,
    client: &Client,
    settings: &ManagedSettings,
    facts: &DeviceFacts,
) -> Result<(Enrollment, bool), ApiError> {
    let current = agent.state.read().unwrap().enrollment.clone();
    let enrollment_key_sha256 = hex::encode(Sha256::digest(settings.enrollment_key.as_bytes()));
    let device_key_thumbprint = agent.keys.device.thumbprint();
    if let Some(e) = current.filter(|e| {
        e.status == DeviceStatus::Active
            && e.enrollment_key_sha256 == enrollment_key_sha256
            && e.device_key_thumbprint == device_key_thumbprint
            && e.api_url == settings.api_url
    }) {
        return Ok((e, false));
    }
    let response = client
        .enroll(
            &settings.enrollment_key,
            &agent.keys.device,
            &EnrollRequest {
                hardware_uuid: facts.hardware_uuid.clone(),
                serial_number: facts.serial_number.clone(),
                hostname: facts.hostname.clone(),
                os: facts.os.clone(),
                os_version: facts.os_version.clone(),
                agent_version: agent.version.into(),
                employee_email: settings.employee_email.clone(),
                device_public_key: agent.keys.device.public_jwk(),
                ca_csr: agent.keys.csr.clone(),
            },
        )
        .await?;
    let enrollment = Enrollment {
        device_id: response.device_id,
        status: response.status,
        enrollment_key_sha256,
        device_key_thumbprint,
        api_url: settings.api_url.clone(),
    };
    if let Err(e) = enrollment.save(&agent.paths.data_dir) {
        tracing::error!(error = %e, "could not persist enrollment; will enroll again after restart");
    }
    if let Some(pem) = response.intermediate_pem {
        install_intermediate(agent, &pem, true);
    }
    tracing::info!(device_id = %enrollment.device_id, status = ?enrollment.status, "device enrolled");
    agent.state.write().unwrap().enrollment = Some(enrollment.clone());
    Ok((enrollment, true))
}

/// Asks parrot for a new intermediate when there is none or the current one ends within
/// [`RENEW_BEFORE`]. A failure keeps the current one, and is retried at the next sync.
async fn renew_intermediate(agent: &Agent, client: &Client, device: &DeviceCredential) {
    let due = agent
        .authority
        .read()
        .unwrap()
        .as_ref()
        .is_none_or(|a| a.not_after() - time::OffsetDateTime::now_utc() < RENEW_BEFORE);
    if !due {
        return;
    }
    match client.intermediate(device, &agent.keys.csr).await {
        Ok(response) => {
            install_intermediate(agent, &response.intermediate_pem, true);
        }
        Err(e) => tracing::warn!(error = %e, "intermediate renewal failed; will retry"),
    }
}

/// Makes `pem` the gateway's CA when it is valid for this Mac's gateway key.
fn install_intermediate(agent: &Agent, pem: &str, save: bool) -> bool {
    match Authority::new(agent.keys.gateway_pem(), pem) {
        Ok(authority) => {
            if save && let Err(e) = Intermediate::save(&agent.paths.data_dir, pem) {
                tracing::error!(error = %e, "could not persist the intermediate");
            }
            tracing::info!(not_after = %authority.not_after(), "gateway intermediate installed");
            *agent.authority.write().unwrap() = Some(Arc::new(authority));
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "unusable intermediate");
            false
        }
    }
}

/// Sends spooled reports whenever one is queued, and retries every minute while some remain.
pub async fn flush_reports(agent: Arc<Agent>) {
    loop {
        tokio::select! {
            _ = agent.reports_pending.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        let (device, url) = {
            let state = agent.state.read().unwrap();
            match (&state.enrollment, &state.settings) {
                (Some(e), Some(s)) if e.status == DeviceStatus::Active => (credential(&agent, e), s.api_url.clone()),
                _ => continue,
            }
        };
        let Ok(client) = Client::new(&url, agent.version) else { continue };
        for (path, report) in agent.spool.pending() {
            match client.report(&device, &report).await {
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
