//! What identifies this machine to parrot, and where its credential is kept.

use std::path::Path;
use std::process::Command;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct DeviceFacts {
    pub hardware_uuid: String,
    pub serial_number: Option<String>,
    pub hostname: String,
    pub os: String,
    pub os_version: String,
}

impl DeviceFacts {
    pub fn collect() -> Self {
        let ioreg = run("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).unwrap_or_default();
        let field = |key: &str| {
            ioreg.lines().find(|l| l.contains(&format!("\"{key}\""))).and_then(|l| l.split('"').nth(3)).map(str::to_owned)
        };
        Self {
            hardware_uuid: field("IOPlatformUUID").unwrap_or_else(|| "unknown".into()),
            serial_number: field("IOPlatformSerialNumber"),
            hostname: hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default(),
            os: std::env::consts::OS.into(),
            os_version: run("sw_vers", &["-productVersion"]).map(|v| v.trim().to_owned()).unwrap_or_default(),
        }
    }
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The enrollment result. POC: a 0600 file in the root-owned data directory.
/// Production: the System keychain (see the plan), so it survives a data-dir wipe and is not
/// readable from a backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub device_id: String,
    /// `SecretString` keeps the bearer token out of `{:?}` and zeroes it on drop.
    #[serde(serialize_with = "expose_for_storage")]
    pub device_token: SecretString,
    pub workspace_id: String,
    pub api_url: String,
}

/// `SecretString` refuses to serialize by design; the enrollment file is the one place it must.
fn expose_for_storage<S: serde::Serializer>(token: &SecretString, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(token.expose_secret())
}

impl Enrollment {
    const FILE: &str = "enrollment.json";

    pub fn load(data_dir: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(data_dir.join(Self::FILE)).ok()?).ok()
    }

    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(data_dir)?;
        let tmp = data_dir.join(format!("{}.tmp", Self::FILE));
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        std::io::Write::write_all(&mut f, &serde_json::to_vec(self)?)?;
        std::fs::rename(tmp, data_dir.join(Self::FILE))
    }

    pub fn remove(data_dir: &Path) {
        let _ = std::fs::remove_file(data_dir.join(Self::FILE));
    }
}

/// Whether an app is installed, by bundle id (Spotlight's index; cheap, refreshed on sync).
pub fn is_installed(bundle_id: &str) -> bool {
    run("mdfind", &[&format!("kMDItemCFBundleIdentifier == '{}'", bundle_id.replace('\'', ""))])
        .is_some_and(|out| out.lines().any(|l| l.ends_with(".app")))
}
