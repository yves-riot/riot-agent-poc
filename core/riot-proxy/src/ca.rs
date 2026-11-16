//! The device's own certificate authority. The proxy terminates TLS for the protected hosts
//! with leaf certificates signed by it, so the AI apps must trust it: its certificate goes into
//! the keychain (by hand in development, by the MDM profile in production).
//!
//! The key never leaves the device and is only readable by the daemon's user.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

use crate::Error;

const CERT_FILE: &str = "ca.pem";
const KEY_FILE: &str = "ca.key";
const CA_VALIDITY: Duration = Duration::days(5 * 365);
/// Under the 398 days Apple accepts for a TLS server certificate.
const LEAF_VALIDITY: Duration = Duration::days(365);
/// A cached leaf is reissued long before it expires, for a daemon that runs for months.
const LEAF_REISSUE: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);
/// Clocks differ: a certificate must not be "not yet valid" for the app that receives it.
const BACKDATE: Duration = Duration::days(1);

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_path: PathBuf,
    /// One key for every leaf: generating one per host would only cost time.
    leaf_key: KeyPair,
    leaf_signer: Arc<dyn rustls::sign::SigningKey>,
    leaves: Mutex<HashMap<String, (Arc<CertifiedKey>, Instant)>>,
}

impl Ca {
    /// Loads the CA in `dir`, creating it on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self, Error> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        let key = if cert_path.exists() && key_path.exists() {
            CertificateDer::from_pem_file(&cert_path).map_err(|e| Error::Ca(format!("{}: {e}", cert_path.display())))?;
            KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?
        } else {
            let key = KeyPair::generate()?;
            let cert = ca_params().self_signed(&key)?;
            create_dir(dir)?;
            write_private(&key_path, key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, cert.pem())?;
            tracing::info!(path = %cert_path.display(), "created the proxy's certificate authority");
            key
        };
        let leaf_key = KeyPair::generate()?;
        let leaf_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signer = rustls::crypto::aws_lc_rs::sign::any_supported_type(&leaf_der)?;
        Ok(Self {
            // The stored certificate was made from these same parameters, so leaves chain to it.
            issuer: Issuer::new(ca_params(), key),
            cert_path,
            leaf_key,
            leaf_signer,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate (PEM), the file the apps must trust.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    /// TLS for the app's side of an intercepted connection: a leaf for whatever name it asks.
    pub fn server_config(self: &Arc<Self>) -> Result<Arc<ServerConfig>, Error> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(self.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, Error> {
        let mut leaves = self.leaves.lock().unwrap();
        if let Some((leaf, issued)) = leaves.get(host)
            && issued.elapsed() < LEAF_REISSUE
        {
            return Ok(leaf.clone());
        }
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.not_before = now - BACKDATE;
        params.not_after = now + LEAF_VALIDITY;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        // Random and positive: two leaves of one issuer must not share a serial.
        let mut serial = *uuid::Uuid::new_v4().as_bytes();
        serial[0] &= 0x7f;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = params.signed_by(&self.leaf_key, &self.issuer)?;
        let leaf = Arc::new(CertifiedKey::new(vec![cert.der().clone()], self.leaf_signer.clone()));
        leaves.insert(host.to_owned(), (leaf.clone(), Instant::now()));
        Ok(leaf)
    }
}

impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca").field("cert_path", &self.cert_path).finish_non_exhaustive()
    }
}

impl ResolvesServerCert for Ca {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?;
        self.leaf(host).inspect_err(|e| tracing::error!(host, error = %e, "could not issue a leaf certificate")).ok()
    }
}

/// Everything about the CA except its dates: what `Issuer` needs to sign leaves that chain to
/// the stored certificate.
fn ca_params() -> CertificateParams {
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::OrganizationName, "Riot");
    params.distinguished_name.push(DnType::CommonName, "Riot Agent Local CA");
    params.not_before = now - BACKDATE;
    params.not_after = now + CA_VALIDITY;
    // It signs leaves and nothing else: no intermediate can be issued under it.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// World-readable: the certificate in it is what users and the MDM install. The key is not.
fn create_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)
}

fn write_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    file.write_all(content)
}
