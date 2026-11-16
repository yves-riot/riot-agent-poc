//! Where the daemon reads its settings: MDM managed preferences (domain `com.tryriot.agent`),
//! with environment overrides for development.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const MANAGED_PREFS: &str = "/Library/Managed Preferences/com.tryriot.agent.plist";
pub const DATA_DIR: &str = "/Library/Application Support/com.tryriot.agent";

/// The keys an admin sets in the MDM profile (see `mdm/riot-agent.mobileconfig`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ManagedSettings {
    pub api_url: String,
    pub workspace_id: String,
    pub enrollment_secret: String,
    /// Per-device MDM variable (e.g. `$EMAIL`); optional, resolves the employee server-side.
    pub employee_email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub settings: PathBuf,
    pub data_dir: PathBuf,
    pub socket: PathBuf,
    /// Where the proxy listens. `None` when it is switched off.
    pub proxy_addr: Option<SocketAddr>,
    /// Record mode: the proxy logs the shape of what the AI apps send (never the values).
    pub proxy_record: bool,
}

impl Paths {
    /// `RIOT_SETTINGS`, `RIOT_DATA_DIR` and `RIOT_SOCKET` override the system locations, so the
    /// daemon can run unprivileged during development. `RIOT_PROXY_ADDR` moves the proxy
    /// (`127.0.0.1:0` for any free port, `off` for none) and `RIOT_PROXY_RECORD=1` turns record
    /// mode on.
    pub fn from_env() -> Self {
        let var = |k: &str, default: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_else(|| default.into());
        Self {
            settings: var("RIOT_SETTINGS", MANAGED_PREFS),
            data_dir: var("RIOT_DATA_DIR", DATA_DIR),
            socket: var("RIOT_SOCKET", riot_ipc::DEFAULT_SOCKET),
            proxy_addr: proxy_addr(std::env::var("RIOT_PROXY_ADDR").ok().as_deref()),
            proxy_record: std::env::var("RIOT_PROXY_RECORD").is_ok_and(|v| v == "1"),
        }
    }

    /// The device CA of the proxy (`ca.pem`, `ca.key`).
    pub fn ca_dir(&self) -> PathBuf {
        self.data_dir.join("ca")
    }
}

fn proxy_addr(setting: Option<&str>) -> Option<SocketAddr> {
    match setting {
        None | Some("") => Some(SocketAddr::from(([127, 0, 0, 1], riot_ipc::DEFAULT_PROXY_PORT))),
        Some("off") => None,
        Some(addr) => addr
            .parse()
            .inspect_err(|e| tracing::error!(addr, error = %e, "RIOT_PROXY_ADDR is not an address; the proxy stays off"))
            .ok(),
    }
}

/// Reads a plist (the managed-preferences format) or, for development, a JSON file with the
/// same keys. `Ok(None)` when the file does not exist: the profile is not installed yet.
pub fn load_settings(path: &Path) -> anyhow::Result<Option<ManagedSettings>> {
    if !path.exists() {
        return Ok(None);
    }
    let settings: ManagedSettings = if path.extension().is_some_and(|e| e == "json") {
        serde_json::from_slice(&std::fs::read(path)?)?
    } else {
        plist::from_file(path)?
    };
    let email = settings.employee_email.filter(|e| !e.trim().is_empty() && !e.starts_with('$'));
    Ok(Some(ManagedSettings { employee_email: email, ..settings }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_managed_plist_and_drops_unsubstituted_variables() {
        let dir = std::env::temp_dir().join(format!("riot-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("com.tryriot.agent.plist");
        std::fs::write(
            &path,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>ApiUrl</key><string>https://parrot.example/portal</string>
  <key>WorkspaceId</key><string>ws-1</string>
  <key>EnrollmentSecret</key><string>rbx_abc</string>
  <key>EmployeeEmail</key><string>$EMAIL</string>
</dict></plist>"#,
        )
        .unwrap();
        let s = load_settings(&path).unwrap().unwrap();
        assert_eq!(s.workspace_id, "ws-1");
        assert_eq!(s.employee_email, None);
        assert!(load_settings(&dir.join("missing.plist")).unwrap().is_none());
    }

    #[test]
    fn the_proxy_listens_on_loopback_unless_told_otherwise() {
        assert_eq!(proxy_addr(None), Some("127.0.0.1:47610".parse().unwrap()));
        assert_eq!(proxy_addr(Some("127.0.0.1:0")), Some("127.0.0.1:0".parse().unwrap()));
        assert_eq!(proxy_addr(Some("off")), None);
        assert_eq!(proxy_addr(Some("nonsense")), None);
    }
}
