//! What the certificates of the gateway's chain contain, shared by the agent and the stub (parrot
//! issues the same):
//!
//! ```text
//! organization root    parrot, key in KMS; trusted by the MDM profile   pathlen 1, 10 years
//!   └ intermediate     one per Mac, key generated on the Mac            pathlen 0, 7 days
//!       └ leaf         one per AI host, issued by the daemon            7 days
//! ```
//!
//! Root and intermediate are name-constrained to [`PERMITTED_DOMAINS`]: even with their key,
//! nothing they sign is valid for another site. Every Mac of the organization trusts the root, so
//! one Mac's intermediate key, copied, signs certificates every other Mac accepts: the short life
//! of intermediates bounds it (docs/network-interception.md, "The CA in production").

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, GeneralSubtree, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, NameConstraints, SigningKey,
};
use time::OffsetDateTime;

/// The only domains (and their subdomains) the chain may issue for.
pub const PERMITTED_DOMAINS: &[&str] = &["anthropic.com", "claude.ai", "openai.com", "chatgpt.com"];
pub const ROOT_DAYS: i64 = 3650;
/// Short: a revoked Mac, or an intermediate copied off one, stops working within this. No
/// client checks revocation for a private root, so the lifetime is the revocation.
pub const INTERMEDIATE_DAYS: i64 = 7;

pub fn permits(host: &str) -> bool {
    PERMITTED_DOMAINS.iter().any(|d| host == *d || host.strip_suffix(d).is_some_and(|rest| rest.ends_with('.')))
}

/// An organization's root: parrot makes one per organization.
pub fn root_params(common_name: &str) -> CertificateParams {
    ca_params(common_name, 1, ROOT_DAYS)
}

/// One Mac's intermediate, named after its device.
pub fn intermediate_params(device_id: &str) -> CertificateParams {
    ca_params(&format!("Riot AI gateway {device_id}"), 0, INTERMEDIATE_DAYS)
}

fn ca_params(common_name: &str, path_len: u8, days: i64) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::OrganizationName, "Riot");
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: PERMITTED_DOMAINS.iter().map(|d| GeneralSubtree::DnsName((*d).to_owned())).collect(),
        excluded_subtrees: vec![],
    });
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(days);
    params
}

/// The request the daemon sends for its intermediate. Only the key matters: parrot decides
/// everything the certificate says.
pub fn csr_pem(key: &KeyPair) -> Result<String, rcgen::Error> {
    CertificateParams::default().serialize_request(key)?.pem()
}

/// The public key a CSR asks a certificate for (its subjectPublicKey bits), without checking the
/// request's signature: parrot binds a device to the key of its first intermediate.
pub fn csr_public_key(csr_pem: &str) -> Result<Vec<u8>, rcgen::Error> {
    use rcgen::PublicKeyData;
    Ok(CertificateSigningRequestParams::from_pem(csr_pem)?.public_key.der_bytes().to_vec())
}

/// What parrot does with a CSR: checks its signature (proof the requester holds the key) and
/// signs an intermediate for that key, ignoring whatever else the request asks for.
pub fn sign_intermediate(csr_pem: &str, device_id: &str, issuer: &Issuer<'_, impl SigningKey>) -> Result<String, rcgen::Error> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let request = CertificateSigningRequestParams { params: intermediate_params(device_id), public_key: csr.public_key };
    Ok(request.signed_by(issuer)?.pem())
}
