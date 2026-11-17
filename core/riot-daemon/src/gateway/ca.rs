//! The certificate authority that lets the gateway terminate TLS for the AI hosts: a root kept
//! in the data directory, and short-lived leaf certificates issued in memory per host.
//!
//! The root is name-constrained to the AI domains (`PERMITTED_DOMAINS`): even with its key, no
//! certificate it signs is valid for any other site.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::OffsetDateTime;

/// The only domains (and their subdomains) the root may issue for.
pub const PERMITTED_DOMAINS: &[&str] = &["anthropic.com", "claude.ai", "openai.com", "chatgpt.com"];
const CA_CERT_FILE: &str = "gateway-ca.pem";
const CA_KEY_FILE: &str = "gateway-ca-key.pem";
const CA_DAYS: i64 = 365;
const LEAF_DAYS: i64 = 7;
/// Leaves are reissued well before they expire.
const LEAF_REUSE: Duration = Duration::from_secs(24 * 3600);

pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
    cert_path: PathBuf,
    /// One key for every leaf: only the certificate differs per host.
    leaf_key: KeyPair,
    leaves: Mutex<HashMap<String, (Arc<ServerConfig>, Instant)>>,
}

impl Authority {
    /// Loads the root from `dir`, or creates it (key readable by its owner only).
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let (cert_path, key_path) = (dir.join(CA_CERT_FILE), dir.join(CA_KEY_FILE));
        let (cert_pem, key) = if cert_path.exists() && key_path.exists() {
            (std::fs::read_to_string(&cert_path)?, KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?)
        } else {
            let key = KeyPair::generate()?;
            let cert = root_params()?.self_signed(&key)?;
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, cert.pem())?;
            (cert.pem(), key)
        };
        let root = CertificateDer::from(pem_der(&cert_pem)?);
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)?;
        Ok(Self { issuer, root, cert_path, leaf_key: KeyPair::generate()?, leaves: Mutex::default() })
    }

    /// The root certificate's file, to trust it (`NODE_EXTRA_CA_CERTS`, the keychain).
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    #[cfg(test)]
    pub fn root(&self) -> &CertificateDer<'static> {
        &self.root
    }

    pub fn permits(host: &str) -> bool {
        PERMITTED_DOMAINS.iter().any(|d| host == *d || host.strip_suffix(d).is_some_and(|rest| rest.ends_with('.')))
    }

    /// A TLS server configuration presenting a certificate for `host`, HTTP/1.1 only.
    pub fn server_config(&self, host: &str) -> anyhow::Result<Arc<ServerConfig>> {
        anyhow::ensure!(Self::permits(host), "the Riot CA does not issue for {host}");
        let mut leaves = self.leaves.lock().unwrap();
        if let Some((config, issued)) = leaves.get(host)
            && issued.elapsed() < LEAF_REUSE
        {
            return Ok(config.clone());
        }
        let config = Arc::new(self.issue(host)?);
        leaves.insert(host.to_owned(), (config.clone(), Instant::now()));
        Ok(config)
    }

    fn issue(&self, host: &str) -> anyhow::Result<ServerConfig> {
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(LEAF_DAYS);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf = params.signed_by(&self.leaf_key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.root.clone()], key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn root_params() -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::OrganizationName, "Riot");
    params.distinguished_name.push(DnType::CommonName, "Riot AI gateway (development)");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: PERMITTED_DOMAINS.iter().map(|d| GeneralSubtree::DnsName((*d).to_owned())).collect(),
        excluded_subtrees: vec![],
    });
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(CA_DAYS);
    Ok(params)
}

fn pem_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    Ok(CertificateDer::from_pem_slice(pem.as_bytes())?.to_vec())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_only_for_the_ai_domains() {
        for host in ["api.anthropic.com", "claude.ai", "chatgpt.com", "ws.chatgpt.com"] {
            assert!(Authority::permits(host), "{host}");
        }
        for host in ["example.com", "notanthropic.com", "anthropic.com.evil.test", "claude.ai.evil.test"] {
            assert!(!Authority::permits(host), "{host}");
        }
    }

    #[test]
    fn the_root_is_kept_across_restarts_and_its_key_is_private() {
        let dir = std::env::temp_dir().join(format!("riot-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = Authority::load_or_create(&dir).unwrap();
        let second = Authority::load_or_create(&dir).unwrap();
        assert_eq!(first.root(), second.root());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join(CA_KEY_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(second.server_config("api.anthropic.com").is_ok());
        assert!(second.server_config("example.com").is_err());
    }
}
