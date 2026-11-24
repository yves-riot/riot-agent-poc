//! What identifies this machine to parrot: its facts, its keys, its enrollment.

use std::path::Path;
use std::process::Command;

use std::sync::Arc;

use riot_api::{DeviceKey, DeviceStatus};
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

/// This Mac's two keys, generated on first start, root-only (`0600`) in the data directory.
/// POC: files; production: the Secure Enclave, so that not even root can copy them.
///
/// - The device key signs every request to parrot (`riot_api::device_key`): there is no bearer
///   token to steal.
/// - The gateway key is what parrot's intermediate CA is issued for (`riot_api::ca`): the
///   gateway signs its per-host certificates with it.
pub struct Keys {
    pub device: Arc<DeviceKey>,
    gateway_pem: SecretString,
    /// The CSR for the gateway key, sent at enrollment and at every renewal.
    pub csr: String,
}

impl Keys {
    const DEVICE_KEY_FILE: &str = "device-key.der";
    const GATEWAY_KEY_FILE: &str = "gateway-key.pem";
    /// A CA every Mac of a test fleet shared, installed by older packages: deleted on sight.
    const LEGACY_SHARED_CA: [&str; 2] = ["gateway-ca-key.pem", "gateway-ca.pem"];

    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        for legacy in Self::LEGACY_SHARED_CA {
            if std::fs::remove_file(data_dir.join(legacy)).is_ok() {
                tracing::warn!(file = legacy, "deleted the shared fleet CA left by an older package");
            }
        }
        let device_path = data_dir.join(Self::DEVICE_KEY_FILE);
        let gateway_path = data_dir.join(Self::GATEWAY_KEY_FILE);
        // Parrot binds a device to the gateway key of its first intermediate: a device key whose
        // gateway key is lost would never get another one. Both are created together, and a new
        // pair is a new device.
        let (device, gateway) = match (std::fs::read(&device_path), std::fs::read_to_string(&gateway_path)) {
            (Ok(der), Ok(pem)) => (DeviceKey::from_pkcs8(&der)?, rcgen::KeyPair::from_pem(&pem)?),
            _ => {
                let device = DeviceKey::generate()?;
                let gateway = rcgen::KeyPair::generate()?;
                write_private(&gateway_path, gateway.serialize_pem().as_bytes())?;
                write_private(&device_path, &device.to_pkcs8())?;
                tracing::info!(thumbprint = device.thumbprint(), "device and gateway keys created");
                (device, gateway)
            }
        };
        let csr = riot_api::ca::csr_pem(&gateway)?;
        Ok(Self { device: Arc::new(device), gateway_pem: gateway.serialize_pem().into(), csr })
    }

    pub fn gateway_pem(&self) -> &str {
        self.gateway_pem.expose_secret()
    }
}

/// The intermediate parrot last signed for the gateway key: a certificate, nothing secret.
pub struct Intermediate;

impl Intermediate {
    const FILE: &str = "gateway-intermediate.pem";

    pub fn load(data_dir: &Path) -> Option<String> {
        std::fs::read_to_string(data_dir.join(Self::FILE)).ok()
    }

    pub fn save(data_dir: &Path, pem: &str) -> std::io::Result<()> {
        let tmp = data_dir.join(format!("{}.tmp", Self::FILE));
        std::fs::write(&tmp, pem)?;
        std::fs::rename(tmp, data_dir.join(Self::FILE))
    }
}

/// The enrollment result: which device parrot knows this Mac as. Nothing in it authenticates:
/// the device key does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub device_id: String,
    pub status: DeviceStatus,
    /// SHA-256 of the `rae_` key it was enrolled with: another key (another workspace, or a
    /// rotated one) enrolls again.
    pub enrollment_key_sha256: String,
    /// The device key it registered: a new key (the file was lost) enrolls again.
    pub device_key_thumbprint: String,
    pub api_url: String,
}

impl Enrollment {
    const FILE: &str = "enrollment.json";

    /// `None` also for a file from before device keys (it held a bearer token): it is deleted,
    /// and the device enrolls again.
    pub fn load(data_dir: &Path) -> Option<Self> {
        let bytes = std::fs::read(data_dir.join(Self::FILE)).ok()?;
        let parsed = serde_json::from_slice(&bytes).ok();
        if parsed.is_none() {
            Self::remove(data_dir);
        }
        parsed
    }

    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let tmp = data_dir.join(format!("{}.tmp", Self::FILE));
        write_private(&tmp, &serde_json::to_vec(self)?)?;
        std::fs::rename(tmp, data_dir.join(Self::FILE))
    }

    pub fn remove(data_dir: &Path) {
        let _ = std::fs::remove_file(data_dir.join(Self::FILE));
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    std::io::Write::write_all(&mut f, bytes)
}

/// Whether an app is installed, by bundle id (Spotlight's index; cheap, refreshed on sync).
pub fn is_installed(bundle_id: &str) -> bool {
    run("mdfind", &[&format!("kMDItemCFBundleIdentifier == '{}'", bundle_id.replace('\'', ""))])
        .is_some_and(|out| out.lines().any(|l| l.ends_with(".app")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_kept_private_across_restarts_and_the_shared_fleet_ca_is_deleted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("riot-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gateway-ca-key.pem"), "shared").unwrap();
        let first = Keys::load_or_create(&dir).unwrap();
        let second = Keys::load_or_create(&dir).unwrap();
        assert_eq!(first.device.thumbprint(), second.device.thumbprint());
        assert_eq!(first.gateway_pem(), second.gateway_pem());
        for file in ["device-key.der", "gateway-key.pem"] {
            assert_eq!(std::fs::metadata(dir.join(file)).unwrap().permissions().mode() & 0o777, 0o600, "{file}");
        }
        assert!(!dir.join("gateway-ca-key.pem").exists());

        // Parrot would never sign for another gateway key on this device: a new pair, a new device.
        std::fs::remove_file(dir.join("gateway-key.pem")).unwrap();
        let third = Keys::load_or_create(&dir).unwrap();
        assert_ne!(third.device.thumbprint(), first.device.thumbprint());
        assert_ne!(third.gateway_pem(), first.gateway_pem());
    }

    #[test]
    fn an_enrollment_from_before_device_keys_is_dropped() {
        let dir = std::env::temp_dir().join(format!("riot-enrollment-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("enrollment.json"), r#"{"device_id":"d","device_token":"rad_x","secret_sha256":"","api_url":"u"}"#).unwrap();
        assert!(Enrollment::load(&dir).is_none());
        assert!(!dir.join("enrollment.json").exists(), "the old bearer token does not stay on disk");
    }
}
