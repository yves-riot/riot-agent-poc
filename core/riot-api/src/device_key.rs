//! The device's own key: how the agent proves who it is to parrot, with no bearer token to steal.
//!
//! The daemon generates a P-256 key once and registers its public half at enrollment (as a JWK).
//! Every request then carries a short-lived ES256 JWT, a *proof*, signed with that key and bound
//! to the request's method and path; parrot checks it against the key it registered.
//!
//! Header `{"alg":"ES256","typ":"riot-agent+jwt"}`, claims:
//!
//! | Claim | Value |
//! |---|---|
//! | `sub` | the `device_id`, or the `hardware_uuid` on `enroll` (no id yet) |
//! | `htm`, `htu` | the request's method and path, e.g. `GET` `/portal/api/get_agent_config` |
//! | `iat`, `exp` | issued now, valid [`PROOF_TTL_SECS`] |
//! | `jti` | random; parrot refuses one it saw before `exp` |

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, UnparsedPublicKey,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PROOF_TYP: &str = "riot-agent+jwt";
pub const PROOF_TTL_SECS: i64 = 300;
/// Clock skew tolerated on `iat`.
const SKEW_SECS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid device key")]
    InvalidKey,
    #[error("invalid proof: {0}")]
    InvalidProof(&'static str),
}

pub struct DeviceKey(EcdsaKeyPair);

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DeviceKey").field(&self.thumbprint()).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofClaims {
    pub sub: String,
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

impl DeviceKey {
    pub fn generate() -> Result<Self, KeyError> {
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map(Self).map_err(|_| KeyError::InvalidKey)
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der).map(Self).map_err(|_| KeyError::InvalidKey)
    }

    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.0.to_pkcs8v1().expect("a P-256 key always serializes").as_ref().to_vec()
    }

    /// The public key as a JWK (`kty` `EC`, `crv` `P-256`), as `enroll` registers it.
    pub fn public_jwk(&self) -> Value {
        let point = self.0.public_key().as_ref();
        // Uncompressed SEC1: 0x04 ‖ x ‖ y.
        json!({ "kty": "EC", "crv": "P-256", "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]) })
    }

    /// RFC 7638 thumbprint of the public key: names it in logs without printing it.
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.public_jwk()).unwrap_or_default()
    }

    /// A proof for one request, valid [`PROOF_TTL_SECS`] from `now` (Unix seconds).
    pub fn proof(&self, sub: &str, method: &str, path: &str, now: i64) -> String {
        let claims = ProofClaims {
            sub: sub.into(),
            htm: method.into(),
            htu: path.into(),
            iat: now,
            exp: now + PROOF_TTL_SECS,
            jti: uuid::Uuid::new_v4().simple().to_string(),
        };
        let header = B64.encode(json!({ "alg": "ES256", "typ": PROOF_TYP }).to_string());
        let payload = B64.encode(serde_json::to_vec(&claims).expect("claims serialize"));
        let signing_input = format!("{header}.{payload}");
        let signature = self.0.sign(&SystemRandom::new(), signing_input.as_bytes()).expect("ECDSA signing does not fail");
        format!("{signing_input}.{}", B64.encode(signature.as_ref()))
    }
}

/// RFC 7638 thumbprint of a P-256 JWK.
pub fn thumbprint(jwk: &Value) -> Option<String> {
    let (x, y) = (jwk["x"].as_str()?, jwk["y"].as_str()?);
    // Required members only, in lexicographic order, no whitespace.
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Some(B64.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes())))
}

/// The claims a proof makes, without checking it: to find which device's key verifies it.
pub fn unverified_subject(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let claims: ProofClaims = serde_json::from_slice(&B64.decode(payload).ok()?).ok()?;
    Some(claims.sub)
}

/// Checks a proof's signature against `jwk`, its header, and its lifetime at `now`. The caller
/// still checks `sub`, `htm`, `htu`, and that `jti` is new.
pub fn verify_proof(jwk: &Value, token: &str, now: i64) -> Result<ProofClaims, KeyError> {
    let bad = KeyError::InvalidProof;
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad("not a JWT"));
    };
    let header: Value = B64.decode(header).ok().and_then(|h| serde_json::from_slice(&h).ok()).ok_or(bad("header"))?;
    if header["alg"] != "ES256" || header["typ"] != PROOF_TYP {
        return Err(bad("alg or typ"));
    }
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(bad("key type"));
    }
    let coordinate = |name: &str| jwk[name].as_str().and_then(|c| B64.decode(c).ok()).filter(|c| c.len() == 32);
    let (x, y) = coordinate("x").zip(coordinate("y")).ok_or(bad("key coordinates"))?;
    let point = [&[4u8][..], &x, &y].concat();
    let signature = B64.decode(signature).map_err(|_| bad("signature encoding"))?;
    let signing_input = token.rsplit_once('.').map_or("", |(input, _)| input);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| bad("signature"))?;
    let claims: ProofClaims = B64.decode(payload).ok().and_then(|p| serde_json::from_slice(&p).ok()).ok_or(bad("claims"))?;
    if claims.exp <= now || claims.iat > now + SKEW_SECS || claims.exp - claims.iat > PROOF_TTL_SECS {
        return Err(bad("expired or too long-lived"));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_verifies_against_its_key_only_and_only_while_fresh() {
        let key = DeviceKey::generate().unwrap();
        let now = 1_800_000_000;
        let proof = key.proof("dev-1", "GET", "/portal/api/get_agent_config", now);
        let claims = verify_proof(&key.public_jwk(), &proof, now + 10).unwrap();
        assert_eq!((claims.sub.as_str(), claims.htm.as_str(), claims.htu.as_str()), ("dev-1", "GET", "/portal/api/get_agent_config"));
        assert_eq!(unverified_subject(&proof).as_deref(), Some("dev-1"));

        let other = DeviceKey::generate().unwrap();
        assert!(verify_proof(&other.public_jwk(), &proof, now).is_err(), "another device's key");
        assert!(verify_proof(&key.public_jwk(), &proof, now + PROOF_TTL_SECS).is_err(), "expired");
        assert!(verify_proof(&key.public_jwk(), &key.proof("dev-1", "GET", "/", now + 3600), now).is_err(), "from the future");

        // A tampered payload breaks the signature.
        let mut parts: Vec<&str> = proof.split('.').collect();
        let forged = B64.encode(br#"{"sub":"dev-2","htm":"GET","htu":"/","iat":1800000000,"exp":1800000100,"jti":"x"}"#);
        parts[1] = &forged;
        assert!(verify_proof(&key.public_jwk(), &parts.join("."), now).is_err());
    }

    #[test]
    fn the_key_survives_a_round_trip_through_pkcs8() {
        let key = DeviceKey::generate().unwrap();
        let again = DeviceKey::from_pkcs8(&key.to_pkcs8()).unwrap();
        assert_eq!(key.public_jwk(), again.public_jwk());
        assert_eq!(key.thumbprint().len(), 43);
    }
}
