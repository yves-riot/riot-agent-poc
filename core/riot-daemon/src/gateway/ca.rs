//! The certificate authority that lets the gateway terminate TLS for the AI hosts: the
//! intermediate CA parrot signed for this Mac's gateway key (`device::Keys`), and short-lived
//! leaf certificates issued in memory per host. The chain is described in `riot_api::ca`.
//!
//! Root and intermediate are name-constrained to the AI domains: even with the key, no
//! certificate it signs is valid for any other site.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use rcgen::CertificateParams;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

const LEAF_DAYS: i64 = 7;
/// Leaves are reissued well before they expire.
const LEAF_REUSE: Duration = Duration::from_secs(24 * 3600);

pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    intermediate: CertificateDer<'static>,
    not_after: OffsetDateTime,
    /// One key for every leaf: only the certificate differs per host.
    leaf_key: KeyPair,
    leaves: Mutex<HashMap<String, (Arc<ServerConfig>, Instant)>>,
}

impl Authority {
    /// The gateway key (PEM) and the intermediate parrot signed for it. Refuses an
    /// intermediate for another key, one that is not a CA, or one that has expired.
    pub fn new(key_pem: &str, intermediate_pem: &str) -> anyhow::Result<Self> {
        let der = pem_der(intermediate_pem)?;
        let key = KeyPair::from_pem(key_pem)?;
        let not_after = {
            let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("intermediate: {e}"))?;
            anyhow::ensure!(
                cert.public_key().subject_public_key.data.as_ref() == key.public_key_raw(),
                "the intermediate is for another key than this Mac's gateway key"
            );
            anyhow::ensure!(cert.is_ca(), "the intermediate is not a CA");
            cert.validity().not_after.to_datetime()
        };
        anyhow::ensure!(not_after > OffsetDateTime::now_utc(), "the intermediate expired on {not_after}");
        let intermediate = CertificateDer::from(der);
        let issuer = Issuer::from_ca_cert_der(&intermediate, key)?;
        Ok(Self { issuer, intermediate, not_after, leaf_key: KeyPair::generate()?, leaves: Mutex::default() })
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    pub fn permits(host: &str) -> bool {
        riot_api::ca::permits(host)
    }

    /// A TLS server configuration presenting a certificate for `host`, HTTP/1.1 only.
    pub fn server_config(&self, host: &str) -> anyhow::Result<Arc<ServerConfig>> {
        anyhow::ensure!(Self::permits(host), "the Riot CA does not issue for {host}");
        // Renewal failed for the intermediate's whole life: fail closed rather than serve a
        // chain every client refuses.
        anyhow::ensure!(self.not_after > OffsetDateTime::now_utc(), "the intermediate expired on {}", self.not_after);
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
        let leaf = self.issue_leaf(host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![leaf, self.intermediate.clone()], key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    fn issue_leaf(&self, host: &str) -> anyhow::Result<CertificateDer<'static>> {
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(LEAF_DAYS);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        Ok(params.signed_by(&self.leaf_key, &self.issuer)?.der().clone())
    }
}

fn pem_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    Ok(CertificateDer::from_pem_slice(pem.as_bytes())?.to_vec())
}

/// An organization root and an intermediate for a fresh gateway key, as parrot would sign it.
#[cfg(test)]
pub fn for_tests() -> (Authority, CertificateDer<'static>) {
    let root_key = KeyPair::generate().unwrap();
    let root = riot_api::ca::root_params("Riot test root").self_signed(&root_key).unwrap();
    let issuer = Issuer::from_ca_cert_der(root.der(), root_key).unwrap();
    let gateway_key = KeyPair::generate().unwrap();
    let csr = riot_api::ca::csr_pem(&gateway_key).unwrap();
    let intermediate = riot_api::ca::sign_intermediate(&csr, "dev-test", &issuer).unwrap();
    (Authority::new(&gateway_key.serialize_pem(), &intermediate).unwrap(), root.der().clone())
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
        let (authority, _) = for_tests();
        assert!(authority.server_config("api.anthropic.com").is_ok());
        assert!(authority.server_config("example.com").is_err());
    }

    #[test]
    fn an_intermediate_for_another_key_is_refused() {
        let root_key = KeyPair::generate().unwrap();
        let root = riot_api::ca::root_params("Riot test root").self_signed(&root_key).unwrap();
        let issuer = Issuer::from_ca_cert_der(root.der(), root_key).unwrap();
        let (mine, theirs) = (KeyPair::generate().unwrap(), KeyPair::generate().unwrap());
        let intermediate = riot_api::ca::sign_intermediate(&riot_api::ca::csr_pem(&theirs).unwrap(), "dev-2", &issuer).unwrap();
        assert!(Authority::new(&mine.serialize_pem(), &intermediate).is_err());
        assert!(Authority::new(&theirs.serialize_pem(), &intermediate).is_ok());
    }

    /// A leaf chains to the organization root through this Mac's intermediate, and the
    /// name constraints hold through the whole chain.
    #[test]
    fn a_leaf_validates_up_to_the_organization_root() {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        let (authority, root) = for_tests();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let leaf = authority.issue_leaf("api.anthropic.com").unwrap();
        let name = ServerName::try_from("api.anthropic.com").unwrap();
        verifier.verify_server_cert(&leaf, std::slice::from_ref(&authority.intermediate), &name, &[], UnixTime::now()).unwrap();
    }
}
