//! Parrot's agent API (Portal API routes `/api/…_agent_…`, see `docs/parrot-agent-api.md`). The wire shapes reuse the
//! browser extension's where they exist: the same `SonarPolicy` (plus `desktop_apps` on each
//! service) and the same `SendSensitiveDataReportInput`, so one admin policy drives both.
//!
//! Auth: `enroll` takes the workspace's `rae_` enrollment key and a proof of the device key it
//! registers; every other call is authenticated by a proof alone ([`device_key`]). No bearer
//! token is ever stored on the Mac.

pub mod ca;
pub mod device_key;

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use device_key::DeviceKey;

pub const MONITORING_POLICY_KIND: &str = "browser_extension_sensitive_data_monitoring";

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 401: the device is unknown or revoked, or the enrollment key is wrong.
    #[error("unauthenticated")]
    Unauthenticated,
    /// The API URL is not `https` (plain `http` is allowed to loopback only, for the stub).
    #[error("insecure API URL {0}: https required")]
    InsecureUrl(String),
    #[error("http {status}: {body}")]
    Status { status: u16, body: String },
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, ApiError>;

// ---------- enrollment ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub hardware_uuid: String,
    pub serial_number: Option<String>,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
    pub agent_version: String,
    /// From the MDM's per-device variable substitution. Parrot treats it as a claim: the
    /// employee counts as verified only when the MDM's inventory assigns this Mac to them.
    pub employee_email: Option<String>,
    /// The device key's public half, as a JWK ([`DeviceKey::public_jwk`]).
    pub device_public_key: serde_json::Value,
    /// A CSR for the gateway's intermediate CA ([`ca::csr_pem`]).
    pub ca_csr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Active,
    /// This Mac is already enrolled with another key: an admin must approve the new one.
    PendingApproval,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub device_id: String,
    pub status: DeviceStatus,
    /// The intermediate CA signed for `ca_csr`; `None` while pending.
    pub intermediate_pem: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntermediateResponse {
    pub intermediate_pem: String,
}

/// What authenticates the device after enrollment: its id and its key.
#[derive(Debug, Clone)]
pub struct DeviceCredential {
    pub device_id: String,
    pub key: Arc<DeviceKey>,
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
    /// New for the agent: the native apps of this service, per platform.
    #[serde(default)]
    pub desktop_apps: Vec<DesktopApp>,
    /// New for the agent: the API hosts of this service that the local gateway redacts
    /// requests to, e.g. `api.anthropic.com`.
    #[serde(default)]
    pub api_hosts: Vec<String>,
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
    /// `base` is the portal API root, e.g. `https://parrot.tryriot.dev/portal`. Plain `http` is
    /// refused except to loopback (the development stub).
    pub fn new(base: &str, agent_version: &str) -> Result<Self> {
        let url = reqwest::Url::parse(base).map_err(|_| ApiError::InsecureUrl(base.into()))?;
        let loopback = match url.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err(ApiError::InsecureUrl(base.into()));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("riot-agent/{agent_version}"))
            .build()?;
        Ok(Self { http, base: base.trim_end_matches('/').to_owned(), agent_version: agent_version.to_owned() })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/{path}", self.base)
    }

    /// Enrolls with the workspace's enrollment key, registering `key` (proven by a proof whose
    /// subject is the hardware UUID).
    pub async fn enroll(&self, enrollment_key: &str, key: &DeviceKey, request: &EnrollRequest) -> Result<EnrollResponse> {
        let url = self.url("enroll_agent_device");
        let proof = key.proof(&request.hardware_uuid, "POST", &path_of(&url), now());
        let resp = self
            .http
            .post(url)
            .bearer_auth(enrollment_key)
            .header("X-Device-Proof", proof)
            .header("X-Agent-Version", &self.agent_version)
            .json(request)
            .send()
            .await?;
        decode(resp).await
    }

    pub async fn config(&self, device: &DeviceCredential) -> Result<AgentConfig> {
        decode(self.signed(reqwest::Method::GET, "get_agent_config", device).send().await?).await
    }

    pub async fn heartbeat(&self, device: &DeviceCredential, heartbeat: &Heartbeat) -> Result<()> {
        check(self.signed(reqwest::Method::POST, "send_agent_heartbeat", device).json(heartbeat).send().await?).await
    }

    pub async fn report(&self, device: &DeviceCredential, report: &SensitiveDataReport) -> Result<()> {
        check(self.signed(reqwest::Method::POST, "send_agent_sensitive_data_report", device).json(report).send().await?).await
    }

    /// A new intermediate for the gateway's key: before the current one expires.
    pub async fn intermediate(&self, device: &DeviceCredential, ca_csr: &str) -> Result<IntermediateResponse> {
        let body = serde_json::json!({ "ca_csr": ca_csr });
        decode(self.signed(reqwest::Method::POST, "renew_agent_intermediate_ca", device).json(&body).send().await?).await
    }

    /// A request carrying a fresh proof bound to its method and path.
    fn signed(&self, method: reqwest::Method, path: &str, device: &DeviceCredential) -> reqwest::RequestBuilder {
        let url = self.url(path);
        let proof = device.key.proof(&device.device_id, method.as_str(), &path_of(&url), now());
        self.http.request(method, url).bearer_auth(proof).header("X-Agent-Version", &self.agent_version)
    }
}

fn path_of(url: &str) -> String {
    reqwest::Url::parse(url).map(|u| u.path().to_owned()).unwrap_or_default()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_is_for_loopback_only() {
        for ok in ["https://parrot.example/portal", "http://127.0.0.1:7592/portal", "http://localhost:8787/portal", "http://[::1]:1/p"] {
            assert!(Client::new(ok, "0").is_ok(), "{ok}");
        }
        for refused in ["http://parrot.example/portal", "http://10.0.0.1/portal", "ftp://x", "not a url"] {
            assert!(matches!(Client::new(refused, "0"), Err(ApiError::InsecureUrl(_))), "{refused}");
        }
    }

    #[test]
    fn an_intermediate_signed_from_a_csr_is_for_the_requesting_key() {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let root = ca::root_params("Riot test root").self_signed(&root_key).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(root.der(), root_key).unwrap();
        let mac_key = rcgen::KeyPair::generate().unwrap();
        let pem = ca::sign_intermediate(&ca::csr_pem(&mac_key).unwrap(), "dev-1", &issuer).unwrap();
        let der = rustls_pki_der(&pem);
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert_eq!(cert.public_key().subject_public_key.data.as_ref(), mac_key.public_key_raw());
        assert!(cert.subject().to_string().contains("dev-1"));
        assert!(ca::sign_intermediate("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n", "d", &issuer).is_err());
    }

    fn rustls_pki_der(pem: &str) -> Vec<u8> {
        use base64::Engine as _;
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(body).unwrap()
    }
}
