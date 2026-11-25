//! Where the daemon reads its settings: MDM managed preferences (domain `com.tryriot.agent`) on
//! macOS, policy values in the registry on Windows, with environment overrides for development.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[cfg(unix)]
pub const MANAGED_PREFS: &str = "/Library/Managed Preferences/com.tryriot.agent.plist";
/// Under `HKEY_LOCAL_MACHINE`: where Group Policy and MDMs (Intune's ADMX-backed policies) put
/// machine policy. Values: `ApiUrl`, `EnrollmentKey`, `EmployeeEmail` (`REG_SZ`).
#[cfg(windows)]
pub const POLICY_KEY: &str = r"SOFTWARE\Policies\Riot\Agent";

/// Production parrot's agent API. A profile names another (`ApiUrl`) only to reach staging or
/// a development server: in production the URL belongs to the app, which the MDM keeps up to
/// date, rather than to a profile, which nobody re-uploads. Parrot leaves it out of the
/// profiles it generates when it is this one (`Parrot.DesktopAgent.MDMProfile`).
pub const DEFAULT_API_URL: &str = "https://albert.tryriot.com/portal";

fn default_api_url() -> String {
    DEFAULT_API_URL.to_owned()
}

/// The keys of the MDM profile parrot generates (`priv/desktop_agent/riot-agent.mobileconfig.eex`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ManagedSettings {
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// The workspace's agent enrollment key, `rae_<id>_<secret>`: it only enrolls (parrot finds
    /// the workspace from `<id>`). Not the browser extension's `rbx_` secret.
    pub enrollment_key: String,
    /// Per-device MDM variable (e.g. `$EMAIL`); optional, resolves the employee server-side.
    pub employee_email: Option<String>,
}

/// Where the managed settings are.
#[derive(Debug, Clone)]
pub enum Settings {
    /// A plist (macOS managed preferences) or, for development, a JSON file with the same keys.
    File(PathBuf),
    /// String values under a registry key, named as the plist's keys.
    #[cfg(windows)]
    Registry { hive: crate::os::Hive, key: String },
}

impl Settings {
    fn system() -> Self {
        #[cfg(unix)]
        return Self::File(MANAGED_PREFS.into());
        #[cfg(windows)]
        return Self::Registry { hive: crate::os::Hive::LocalMachine, key: POLICY_KEY.into() };
    }
}

impl std::fmt::Display for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            #[cfg(windows)]
            Self::Registry { hive, key } => write!(f, r"{hive}\{key}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub settings: Settings,
    pub data_dir: PathBuf,
    /// The socket's path, or the pipe's name on Windows.
    pub socket: PathBuf,
}

impl Paths {
    /// `RIOT_SETTINGS` (a file), `RIOT_DATA_DIR` and `RIOT_SOCKET` override the system locations,
    /// so the daemon can run unprivileged during development.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
        Self {
            settings: var("RIOT_SETTINGS").map_or_else(Settings::system, Settings::File),
            data_dir: var("RIOT_DATA_DIR").unwrap_or_else(crate::os::default_data_dir),
            socket: var("RIOT_SOCKET").unwrap_or_else(|| riot_ipc::DEFAULT_SOCKET.into()),
        }
    }
}

/// The local API gateway's address (`RIOT_GATEWAY_ADDR` overrides it). Loopback only: it
/// forwards with the caller's own credentials and never needs to be reachable from elsewhere.
pub const GATEWAY_ADDR: &str = "127.0.0.1:7591";

pub fn gateway_addr() -> anyhow::Result<std::net::SocketAddr> {
    let addr: std::net::SocketAddr = std::env::var("RIOT_GATEWAY_ADDR").as_deref().unwrap_or(GATEWAY_ADDR).parse()?;
    anyhow::ensure!(addr.ip().is_loopback(), "the gateway listens on loopback only, not {addr}");
    Ok(addr)
}

/// `Ok(None)` when the file or the key does not exist: the profile or policy is not installed yet.
pub fn load_settings(source: &Settings) -> anyhow::Result<Option<ManagedSettings>> {
    let settings = match source {
        Settings::File(path) => load_file(path)?,
        #[cfg(windows)]
        Settings::Registry { hive, key } => load_registry(*hive, key)?,
    };
    Ok(settings.map(|settings| {
        let email = settings.employee_email.filter(|e| !e.trim().is_empty() && !e.starts_with('$'));
        ManagedSettings { employee_email: email, ..settings }
    }))
}

/// A plist (the managed-preferences format) or, for development, a JSON file with the same keys.
fn load_file(path: &Path) -> anyhow::Result<Option<ManagedSettings>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(if path.extension().is_some_and(|e| e == "json") {
        serde_json::from_slice(&std::fs::read(path)?)?
    } else {
        plist::from_file(path)?
    }))
}

#[cfg(windows)]
fn load_registry(hive: crate::os::Hive, key: &str) -> anyhow::Result<Option<ManagedSettings>> {
    use crate::os::{open_key, string_value};
    let Some(key) = open_key(hive, key)? else { return Ok(None) };
    let enrollment_key = string_value(&key, "EnrollmentKey")?.ok_or_else(|| anyhow::anyhow!("the policy has no EnrollmentKey"))?;
    Ok(Some(ManagedSettings {
        api_url: string_value(&key, "ApiUrl")?.filter(|u| !u.trim().is_empty()).unwrap_or_else(default_api_url),
        enrollment_key,
        employee_email: string_value(&key, "EmployeeEmail")?,
    }))
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
  <key>EnrollmentKey</key><string>rae_k1_abc</string>
  <key>EmployeeEmail</key><string>$EMAIL</string>
</dict></plist>"#,
        )
        .unwrap();
        let s = load_settings(&Settings::File(path.clone())).unwrap().unwrap();
        assert_eq!(s.enrollment_key, "rae_k1_abc");
        assert_eq!(s.employee_email, None);
        assert_eq!(s.api_url, "https://parrot.example/portal");
        assert!(load_settings(&Settings::File(dir.join("missing.plist"))).unwrap().is_none());

        // A production profile leaves the API URL to the app.
        std::fs::write(
            &path,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>EnrollmentKey</key><string>rae_k1_abc</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(load_settings(&Settings::File(path)).unwrap().unwrap().api_url, DEFAULT_API_URL);
    }

    /// The same keys as registry values. Written under HKCU, which a test may write; the daemon
    /// reads HKLM.
    #[cfg(windows)]
    #[test]
    fn reads_policy_values_from_the_registry() {
        use crate::os::Hive;
        let key = format!(r"Software\Riot-test-{}", std::process::id());
        let source = Settings::Registry { hive: Hive::CurrentUser, key: key.clone() };
        assert!(load_settings(&source).unwrap().is_none(), "no key, no policy");

        let set = |values: &[(&str, &str)]| {
            let created = windows_registry::CURRENT_USER.create(&key).unwrap();
            values.iter().for_each(|(name, value)| created.set_string(name, value).unwrap());
        };
        set(&[("EnrollmentKey", "rae_k1_abc"), ("EmployeeEmail", "$EMAIL")]);
        let s = load_settings(&source).unwrap().unwrap();
        assert_eq!((s.enrollment_key.as_str(), s.api_url.as_str(), s.employee_email), ("rae_k1_abc", DEFAULT_API_URL, None));

        set(&[("ApiUrl", "https://parrot.example/portal"), ("EmployeeEmail", "ana@example.com")]);
        let s = load_settings(&source).unwrap().unwrap();
        assert_eq!((s.api_url.as_str(), s.employee_email.as_deref()), ("https://parrot.example/portal", Some("ana@example.com")));
        windows_registry::CURRENT_USER.remove_tree(&key).unwrap();
    }
}
