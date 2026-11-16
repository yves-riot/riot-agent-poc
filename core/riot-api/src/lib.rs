//! Parrot's agent API (`/api/agent/*`, see `docs/parrot-agent-api.md`). The wire shapes reuse the
//! browser extension's where they exist: the same `SonarPolicy` (plus `desktop_apps` on each
//! service) and the same `SendSensitiveDataReportInput`, so one admin policy drives both.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

pub const MONITORING_POLICY_KIND: &str = "browser_extension_sensitive_data_monitoring";

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 401: the device token was revoked or the enrollment secret is wrong.
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("http {status}: {body}")]
    Status { status: u16, body: String },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, ApiError>;

// ---------- enrollment ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub workspace_id: String,
    pub hardware_uuid: String,
    pub serial_number: Option<String>,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub agent_version: String,
    /// From the MDM's per-device variable substitution; resolves the employee server-side.
    pub employee_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
    /// `SecretString` keeps the bearer token out of `{:?}` and zeroes it on drop.
    pub device_token: SecretString,
}

// ---------- config ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// `None` when the device is enrolled but no active employee matches it.
    pub employee: Option<Employee>,
    pub workspace: Option<WorkspaceInfo>,
    #[serde(default)]
    pub policies: Vec<SonarPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Employee {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub redactions_last_30_days: u32,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    pub id: String,
    pub branding_name: Option<String>,
    pub logo_url: Option<String>,
    pub portal_url: String,
    pub default_locale: Option<String>,
    pub bot_branding: BotBranding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotBranding {
    pub name: String,
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SonarPolicy {
    pub policy_kind: String,
    pub enabled: bool,
    #[serde(default)]
    pub allow_bypass_redaction: bool,
    #[serde(default)]
    pub data_types: Vec<DataTypeToggle>,
    #[serde(default)]
    pub services: Vec<MonitoredService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeToggle {
    pub data_type: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredService {
    pub service_id: String,
    pub display_name: String,
    #[serde(default)]
    pub authorized: bool,
    pub logo_url: Option<String>,
    /// The service's site (`claude.ai`), as in the extension's policy.
    #[serde(default)]
    pub domain: Option<String>,
    /// New for the agent: the native apps of this service, per platform.
    #[serde(default)]
    pub desktop_apps: Vec<DesktopApp>,
    /// New for the agent: the requests of this service the local proxy looks into (riot-proxy's
    /// `Rule`). Raw JSON, so that a rule kind this agent version does not know is skipped
    /// instead of failing the whole config.
    #[serde(default)]
    pub network_rules: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopApp {
    /// `macos` | `windows`
    pub platform: String,
    /// macOS bundle identifier, e.g. `com.anthropic.claudefordesktop`.
    pub bundle_id: Option<String>,
    /// Signing team, checked before trusting `bundle_id` for file blocking.
    pub team_id: Option<String>,
    /// Executable path prefixes the ES client watches (the app and its helpers).
    #[serde(default)]
    pub executable_prefixes: Vec<String>,
}

impl AgentConfig {
    /// The monitoring policy when present and enabled: the one source of truth for "is the
    /// agent active", as in the extension (`activeMonitoringPolicy`).
    pub fn active_policy(&self) -> Option<&SonarPolicy> {
        self.policies.iter().find(|p| p.policy_kind == MONITORING_POLICY_KIND && p.enabled)
    }
}

// ---------- heartbeat ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub agent_version: String,
    pub os_version: String,
    pub components: serde_json::Value,
}

// ---------- reports (the extension's SendSensitiveDataReportInput) ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveDataReport {
    pub session_id: uuid::Uuid,
    pub service_id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileSnapshot>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSnapshot {
    pub detections: Vec<SnapshotDetection>,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub key: String,
    pub format: String,
    pub detections: Vec<SnapshotDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDetection {
    #[serde(rename = "type")]
    pub kind: String,
    pub count: u32,
}

// ---------- client ----------

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    agent_version: String,
}

impl Client {
    /// `base` is the portal API root, e.g. `https://parrot.tryriot.dev/portal`.
    pub fn new(base: &str, agent_version: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("riot-agent/{agent_version}"))
            .build()?;
        Ok(Self { http, base: base.trim_end_matches('/').to_owned(), agent_version: agent_version.to_owned() })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/agent/{path}", self.base)
    }

    pub async fn enroll(&self, secret: &str, request: &EnrollRequest) -> Result<EnrollResponse> {
        let resp = self
            .http
            .post(self.url("enroll"))
            .bearer_auth(secret)
            .header("X-Workspace-Id", &request.workspace_id)
            .header("X-Agent-Version", &self.agent_version)
            .json(request)
            .send()
            .await?;
        decode(resp).await
    }

    pub async fn config(&self, device_token: &SecretString) -> Result<AgentConfig> {
        let resp = self.authed(self.http.get(self.url("config")), device_token).send().await?;
        decode(resp).await
    }

    pub async fn heartbeat(&self, device_token: &SecretString, heartbeat: &Heartbeat) -> Result<()> {
        let resp = self.authed(self.http.post(self.url("heartbeat")), device_token).json(heartbeat).send().await?;
        check(resp).await
    }

    pub async fn report(&self, device_token: &SecretString, report: &SensitiveDataReport) -> Result<()> {
        let resp =
            self.authed(self.http.post(self.url("sensitive_data_report")), device_token).json(report).send().await?;
        check(resp).await
    }

    /// The only place the device token leaves its `SecretString`.
    fn authed(&self, req: reqwest::RequestBuilder, device_token: &SecretString) -> reqwest::RequestBuilder {
        req.bearer_auth(device_token.expose_secret()).header("X-Agent-Version", &self.agent_version)
    }
}

async fn check(resp: reqwest::Response) -> Result<()> {
    let status = resp.status();
    if status.as_u16() == 401 {
        return Err(ApiError::Unauthenticated);
    }
    if !status.is_success() {
        return Err(ApiError::Status { status: status.as_u16(), body: resp.text().await.unwrap_or_default() });
    }
    Ok(())
}

async fn decode<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T> {
    let status = resp.status();
    if status.as_u16() == 401 {
        return Err(ApiError::Unauthenticated);
    }
    if !status.is_success() {
        return Err(ApiError::Status { status: status.as_u16(), body: resp.text().await.unwrap_or_default() });
    }
    Ok(resp.json().await?)
}
