//! A stand-in for parrot's agent API (docs/parrot-agent-api.md), for local runs
//! (`dev/run-dev.sh`): it speaks the same protocol as parrot. It enrolls a device that presents
//! the enrollment key [`ENROLLMENT_KEY`] and a proof of its device key, authenticates every
//! other request by its proof alone, signs the gateway's intermediate CA with a development
//! root, and gives every device the same policy (`dev/stub-policy.json`). Devices are in memory:
//! after a restart, the daemon's next request is refused and it enrolls again.
//!
//! ```text
//! riot-stub-parrot [port] [--dev]        (default 7592; loopback only)
//! ```
//!
//! The root: with `STUB_CA_DIR`, kept there (`stub-root.pem` to trust, `stub-root-key.pem`),
//! so that it stays trusted across runs; otherwise a new one per run, in memory. Development
//! only: parrot keeps each organization's root key in KMS.
//!
//! Logs each request's method, path and status, never a body: they name the device and its user.
//! `--dev` also logs the bodies, keeps the last heartbeats and the reports, and serves them at
//! `GET /portal/_stub/state`; `POST /portal/_stub/approve/<device_id>` approves a pending device,
//! as an admin would in parrot.
//!
//! Env: `STUB_MONITORING=0` (policy disabled), `STUB_NO_EMPLOYEE=1`, `STUB_NO_BYPASS=1`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{Issuer, KeyPair};
use riot_api::device_key::{thumbprint, unverified_subject, verify_proof};
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

const DEFAULT_PORT: u16 = 7592;
/// The workspace its enrollment key names.
const WORKSPACE_ID: &str = "ws-dev";
/// `rae_<key id>_<secret>`, the only enrollment key the stub accepts (`dev/settings.json`).
const ENROLLMENT_KEY: &str = "rae_dev_stub";
const POLICY: &str = include_str!("../../../../dev/stub-policy.json");
const MAX_BODY_BYTES: usize = 1024 * 1024;
const KEPT_HEARTBEATS: usize = 5;
/// A Mac re-enrolling with a new key replaces its old one without approval only after the old
/// one has been silent this long.
const REPLACE_SILENT_AFTER_SECS: i64 = 30 * 24 * 3600;
/// The agent's routes, every one but enrollment authenticated by a device proof.
const AGENT_ROUTES: [&str; 4] =
    ["/portal/api/get_agent_config", "/portal/api/send_agent_heartbeat", "/portal/api/send_agent_sensitive_data_report", "/portal/api/renew_agent_intermediate_ca"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Active,
    PendingApproval,
    Revoked,
}

struct Device {
    id: String,
    hardware_uuid: String,
    public_key: Value,
    status: Status,
    last_seen: i64,
    employee_email: Option<String>,
    /// The gateway key of its first intermediate: every later one is for it alone, like parrot.
    gateway_key: Option<Vec<u8>>,
    /// Report sessions, and whether each was redacted (upserted, like parrot).
    reports: HashMap<String, bool>,
}

/// One request, as the routes see it.
struct Req<'a> {
    method: &'a Method,
    path: &'a str,
    /// `Authorization: Bearer …`: the enrollment key on `enroll`, a proof everywhere else.
    bearer: &'a str,
    /// `X-Device-Proof`, on `enroll`.
    device_proof: &'a str,
    body: &'a Value,
    now: i64,
}

struct Stub {
    policy: Value,
    no_employee: bool,
    /// What `--dev` keeps for `/portal/_stub/state`; `None` otherwise.
    dev: Option<Mutex<DevState>>,
    devices: Mutex<HashMap<String, Device>>,
    /// Proof ids seen, until they expire: a proof is used once.
    seen_proofs: Mutex<HashMap<String, i64>>,
    issuer: Issuer<'static, KeyPair>,
}

#[derive(Default)]
struct DevState {
    enrolled: Vec<Value>,
    heartbeats: Vec<Value>,
    /// By session, upserted like parrot.
    reports: HashMap<String, Value>,
}

type Reply = (StatusCode, Option<Value>);

fn unauthenticated() -> Reply {
    (StatusCode::UNAUTHORIZED, Some(json!({ "error": "unauthenticated" })))
}

fn invalid(what: &str) -> Reply {
    (StatusCode::UNPROCESSABLE_ENTITY, Some(json!({ "error": format!("invalid {what}") })))
}

impl Stub {
    fn new(dev: bool, issuer: Issuer<'static, KeyPair>) -> anyhow::Result<Self> {
        let set = |name: &str, value: &str| std::env::var(name).is_ok_and(|v| v == value);
        let mut policy: Value = serde_json::from_str(POLICY)?;
        policy["enabled"] = json!(!set("STUB_MONITORING", "0"));
        policy["allow_bypass_redaction"] = json!(!set("STUB_NO_BYPASS", "1"));
        Ok(Self {
            policy,
            no_employee: set("STUB_NO_EMPLOYEE", "1"),
            dev: dev.then(Mutex::default),
            devices: Mutex::default(),
            seen_proofs: Mutex::default(),
            issuer,
        })
    }

    fn route(&self, req: &Req) -> Reply {
        if let Some(dev) = &self.dev {
            if (req.method, req.path) == (&Method::GET, "/portal/_stub/state") {
                let dev = dev.lock().unwrap();
                let reports: Vec<&Value> = dev.reports.values().collect();
                return (StatusCode::OK, Some(json!({ "devices": dev.enrolled, "heartbeats": dev.heartbeats, "reports": reports })));
            }
            if let (&Method::POST, Some(id)) = (req.method, req.path.strip_prefix("/portal/_stub/approve/")) {
                return self.approve(id);
            }
        }
        if (req.method, req.path) == (&Method::POST, "/portal/api/enroll_agent_device") {
            return self.enroll(req);
        }
        if !AGENT_ROUTES.contains(&req.path) {
            return (StatusCode::NOT_FOUND, None);
        }
        let mut devices = self.devices.lock().unwrap();
        let Some(device) = self.authenticate(&mut devices, req) else {
            return unauthenticated();
        };
        match (req.method, req.path) {
            (&Method::GET, "/portal/api/get_agent_config") => (StatusCode::OK, Some(self.config(device))),
            (&Method::POST, "/portal/api/renew_agent_intermediate_ca") => match self.sign(req.body, device) {
                Ok(pem) => (StatusCode::OK, Some(json!({ "intermediate_pem": pem }))),
                Err(reply) => reply,
            },
            (&Method::POST, "/portal/api/send_agent_heartbeat") => {
                self.keep(|dev| {
                    dev.heartbeats.push(with_device(&device.id, req.body));
                    let excess = dev.heartbeats.len().saturating_sub(KEPT_HEARTBEATS);
                    dev.heartbeats.drain(..excess);
                });
                (StatusCode::NO_CONTENT, None)
            }
            (&Method::POST, "/portal/api/send_agent_sensitive_data_report") => {
                let body = req.body;
                let (Some(session), Some(_)) = (body["session_id"].as_str(), body["service_id"].as_str()) else {
                    return invalid("report");
                };
                device.reports.insert(session.to_owned(), body["text"]["redacted"].as_bool().unwrap_or(false));
                self.keep(|dev| drop(dev.reports.insert(session.to_owned(), with_device(&device.id, body))));
                (StatusCode::OK, Some(json!({ "recorded": true })))
            }
            _ => (StatusCode::NOT_FOUND, Some(json!({ "error": "not found" }))),
        }
    }

    /// The enrollment key, then a proof of the key being registered, bound to this request and
    /// to the hardware UUID. The same Mac with the same key gets its device back; the same Mac
    /// with a new key needs an admin, unless its old key has been silent for a month.
    fn enroll(&self, req: &Req) -> Reply {
        if req.bearer != ENROLLMENT_KEY {
            return unauthenticated();
        }
        let body = req.body;
        let (Some(hardware_uuid), public_key) = (body["hardware_uuid"].as_str(), &body["device_public_key"]) else {
            return invalid("hardware_uuid");
        };
        let Some(key_id) = thumbprint(public_key) else {
            return invalid("device_public_key");
        };
        if !self.fresh_proof(public_key, req.device_proof, hardware_uuid, req) {
            return unauthenticated();
        }
        let mut devices = self.devices.lock().unwrap();
        let same_mac = |d: &&mut Device| d.hardware_uuid == hardware_uuid && d.status != Status::Revoked;
        let known = devices.values_mut().filter(same_mac).find(|d| thumbprint(&d.public_key).as_deref() == Some(&key_id)).map(|d| d.id.clone());
        let id = match known {
            Some(id) => id,
            None => {
                let current = devices.values_mut().filter(same_mac).find(|d| d.status == Status::Active);
                let status = match current {
                    Some(old) if req.now - old.last_seen < REPLACE_SILENT_AFTER_SECS => Status::PendingApproval,
                    Some(old) => {
                        old.status = Status::Revoked;
                        Status::Active
                    }
                    None => Status::Active,
                };
                let id = uuid::Uuid::new_v4().to_string();
                let device = Device {
                    id: id.clone(),
                    hardware_uuid: hardware_uuid.to_owned(),
                    public_key: public_key.clone(),
                    status,
                    last_seen: req.now,
                    employee_email: None,
                    gateway_key: None,
                    reports: HashMap::new(),
                };
                devices.insert(id.clone(), device);
                self.keep(|dev| dev.enrolled.push(with_device(&id, body)));
                id
            }
        };
        let device = devices.get_mut(&id).expect("just found or inserted");
        device.employee_email = body["employee_email"].as_str().filter(|e| e.contains('@')).map(str::to_owned);
        device.last_seen = req.now;
        let (status, intermediate) = match device.status {
            Status::Active => match self.sign(body, device) {
                Ok(pem) => ("active", Some(pem)),
                Err(reply) => return reply,
            },
            _ => ("pending_approval", None),
        };
        (StatusCode::OK, Some(json!({ "device_id": id, "status": status, "intermediate_pem": intermediate })))
    }

    /// The active device whose key signed the request's proof.
    fn authenticate<'d>(&self, devices: &'d mut HashMap<String, Device>, req: &Req) -> Option<&'d mut Device> {
        let id = unverified_subject(req.bearer)?;
        let device = devices.get_mut(&id).filter(|d| d.status == Status::Active)?;
        if !self.fresh_proof(&device.public_key, req.bearer, &id, req) {
            return None;
        }
        device.last_seen = req.now;
        Some(device)
    }

    /// `proof` is signed by `key`, for `sub`, for this method and path, unexpired and unseen.
    fn fresh_proof(&self, key: &Value, proof: &str, sub: &str, req: &Req) -> bool {
        let Ok(claims) = verify_proof(key, proof, req.now) else { return false };
        if claims.sub != sub || claims.htm != req.method.as_str() || claims.htu != req.path {
            return false;
        }
        let mut seen = self.seen_proofs.lock().unwrap();
        seen.retain(|_, exp| *exp > req.now);
        seen.insert(claims.jti, claims.exp).is_none()
    }

    fn approve(&self, id: &str) -> Reply {
        let mut devices = self.devices.lock().unwrap();
        let Some(hardware_uuid) = devices.get(id).filter(|d| d.status == Status::PendingApproval).map(|d| d.hardware_uuid.clone()) else {
            return (StatusCode::NOT_FOUND, Some(json!({ "error": "no pending device" })));
        };
        for device in devices.values_mut().filter(|d| d.hardware_uuid == hardware_uuid) {
            device.status = if device.id == id { Status::Active } else { Status::Revoked };
        }
        (StatusCode::NO_CONTENT, None)
    }

    /// The device's intermediate, for the gateway key of its first one only. Unlike parrot, it
    /// signs a new one at every ask.
    fn sign(&self, body: &Value, device: &mut Device) -> Result<String, Reply> {
        let csr = body["ca_csr"].as_str().ok_or_else(|| invalid("ca_csr"))?;
        let key = riot_api::ca::csr_public_key(csr).map_err(|_| invalid("ca_csr"))?;
        if device.gateway_key.as_ref().is_some_and(|bound| *bound != key) {
            return Err(invalid("gateway key: not the one of the device's first intermediate"));
        }
        let pem = riot_api::ca::sign_intermediate(csr, &device.id, &self.issuer).map_err(|_| invalid("ca_csr"))?;
        device.gateway_key = Some(key);
        Ok(pem)
    }

    fn keep(&self, f: impl FnOnce(&mut DevState)) {
        if let Some(dev) = &self.dev {
            f(&mut dev.lock().unwrap());
        }
    }

    fn config(&self, device: &Device) -> Value {
        // The MDM's email variable, when it was substituted: the popup greets the user by its
        // local part.
        let employee = device.employee_email.as_ref().filter(|_| !self.no_employee).map(|email| {
            json!({
                "id": device.id,
                "name": email.split('@').next().unwrap_or(email),
                "emails": [email],
                "redactions_last_30_days": device.reports.values().filter(|&&redacted| redacted).count(),
                "locale": "fr",
            })
        });
        json!({
            "employee": employee,
            "workspace": {
                "id": WORKSPACE_ID,
                "branding_name": "Riot",
                "logo_url": null,
                "portal_url": "https://tryriot.com",
                "default_locale": "fr",
                "bot_branding": { "name": "Albert", "icon_url": "https://content.tryriot.com/Course/albert-avatar.png" },
            },
            "policies": [self.policy],
        })
    }
}

/// A request's body, stamped with the device it came from, as `/portal/_stub/state` lists it.
fn with_device(id: &str, body: &Value) -> Value {
    let mut kept = json!({ "device_id": id, "at": chrono::Utc::now().to_rfc3339() });
    if let (Some(kept), Some(body)) = (kept.as_object_mut(), body.as_object()) {
        kept.extend(body.clone());
    }
    kept
}

async fn handle(stub: Arc<Stub>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let bearer = header(AUTHORIZATION.as_str()).strip_prefix("Bearer ").unwrap_or("").to_owned();
    let device_proof = header("x-device-proof");
    let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(body) => serde_json::from_slice(&body.to_bytes()).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let request = Req {
        method: &parts.method,
        path: parts.uri.path(),
        bearer: &bearer,
        device_proof: &device_proof,
        body: &body,
        now: chrono::Utc::now().timestamp(),
    };
    let (status, reply) = stub.route(&request);
    if stub.dev.is_some() && !body.is_null() {
        tracing::info!(method = %parts.method, path = parts.uri.path(), status = status.as_u16(), %body);
    } else {
        tracing::info!(method = %parts.method, path = parts.uri.path(), status = status.as_u16());
    }
    let mut response = Response::new(Full::new(reply.map(|r| Bytes::from(r.to_string())).unwrap_or_default()));
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap());
    Ok(response)
}

/// The development root: kept in `dir` when given, so that it stays trusted across runs.
fn root(dir: Option<&Path>) -> anyhow::Result<Issuer<'static, KeyPair>> {
    let Some(dir) = dir else {
        let key = KeyPair::generate()?;
        let cert = riot_api::ca::root_params("Riot AI gateway (development root)").self_signed(&key)?;
        return Ok(Issuer::from_ca_cert_der(cert.der(), key)?);
    };
    let (cert_path, key_path) = (dir.join("stub-root.pem"), dir.join("stub-root-key.pem"));
    if !(cert_path.exists() && key_path.exists()) {
        std::fs::create_dir_all(dir)?;
        let key = KeyPair::generate()?;
        let cert = riot_api::ca::root_params("Riot AI gateway (development root)").self_signed(&key)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // On Windows, the development folder (under %TEMP%) is the user's own.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&key_path)?;
        std::io::Write::write_all(&mut f, key.serialize_pem().as_bytes())?;
        std::fs::write(&cert_path, cert.pem())?;
    }
    let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?;
    tracing::info!(root = %cert_path.display(), "development root (trust it to see the gateway's certificates as valid)");
    Ok(Issuer::from_ca_cert_pem(&std::fs::read_to_string(&cert_path)?, key)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let (flags, ports): (Vec<String>, Vec<String>) = std::env::args().skip(1).partition(|a| a.starts_with("--"));
    if let Some(unknown) = flags.iter().find(|f| *f != "--dev") {
        anyhow::bail!("unknown flag {unknown}; usage: riot-stub-parrot [port] [--dev]");
    }
    let port = ports.first().map(|p| p.parse()).transpose()?.unwrap_or(DEFAULT_PORT);
    let ca_dir = std::env::var_os("STUB_CA_DIR").map(std::path::PathBuf::from);
    let stub = Arc::new(Stub::new(!flags.is_empty(), root(ca_dir.as_deref())?)?);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    tracing::info!("stub parrot on http://127.0.0.1:{port}/portal");
    loop {
        let (stream, _) = listener.accept().await?;
        let stub = stub.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| handle(stub.clone(), req));
            if let Err(error) = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await {
                tracing::debug!(%error, "connection closed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use riot_api::DeviceKey;

    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn stub_with(dev: bool) -> Stub {
        Stub::new(dev, root(None).unwrap()).unwrap()
    }

    fn stub() -> Stub {
        stub_with(false)
    }

    /// A Mac: its device key and its gateway key.
    struct Mac {
        hardware_uuid: &'static str,
        key: DeviceKey,
        csr: String,
    }

    impl Mac {
        fn new(hardware_uuid: &'static str) -> Self {
            Self { hardware_uuid, key: DeviceKey::generate().unwrap(), csr: riot_api::ca::csr_pem(&KeyPair::generate().unwrap()).unwrap() }
        }

        fn enroll_with(&self, stub: &Stub, enrollment_key: &str, email: &str) -> Reply {
            let path = "/portal/api/enroll_agent_device";
            let body = json!({
                "hardware_uuid": self.hardware_uuid, "hostname": "mac", "employee_email": email,
                "device_public_key": self.key.public_jwk(), "ca_csr": self.csr,
            });
            let proof = self.key.proof(self.hardware_uuid, "POST", path, NOW);
            stub.route(&Req { method: &Method::POST, path, bearer: enrollment_key, device_proof: &proof, body: &body, now: NOW })
        }

        fn enroll(&self, stub: &Stub) -> Value {
            let (status, reply) = self.enroll_with(stub, ENROLLMENT_KEY, "camille@example.com");
            assert_eq!(status, StatusCode::OK);
            reply.unwrap()
        }

        fn call(&self, stub: &Stub, device_id: &str, method: Method, path: &str, body: Value) -> Reply {
            let proof = self.key.proof(device_id, method.as_str(), path, NOW);
            self.call_with(stub, &proof, method, path, body)
        }

        fn call_with(&self, stub: &Stub, proof: &str, method: Method, path: &str, body: Value) -> Reply {
            stub.route(&Req { method: &method, path, bearer: proof, device_proof: "", body: &body, now: NOW })
        }
    }

    #[test]
    fn a_device_enrolls_then_gets_its_intermediate_the_policy_and_reports() {
        let stub = stub();
        let mac = Mac::new("hw-1");
        let enrolled = mac.enroll(&stub);
        assert_eq!(enrolled["status"], "active");
        assert!(enrolled["intermediate_pem"].as_str().unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
        let id = enrolled["device_id"].as_str().unwrap();

        let report = json!({ "session_id": "s-1", "service_id": "anthropic", "text": { "redacted": true } });
        let (status, _) = mac.call(&stub, id, Method::POST, "/portal/api/send_agent_sensitive_data_report", report);
        assert_eq!(status, StatusCode::OK);
        let (status, config) = mac.call(&stub, id, Method::GET, "/portal/api/get_agent_config", Value::Null);
        assert_eq!(status, StatusCode::OK);
        let config: riot_api::AgentConfig = serde_json::from_value(config.unwrap()).unwrap();
        let employee = config.employee.unwrap();
        assert_eq!((employee.name.as_str(), employee.redactions_last_30_days), ("camille", 1));
        assert!(config.policies[0].services.iter().any(|s| s.api_hosts.contains(&"claude.ai".to_owned())));

        let renew = json!({ "ca_csr": mac.csr });
        let (status, reply) = mac.call(&stub, id, Method::POST, "/portal/api/renew_agent_intermediate_ca", renew);
        assert_eq!(status, StatusCode::OK);
        assert!(reply.unwrap()["intermediate_pem"].is_string());

        // A device key copied off the Mac gets no intermediate for the copier's own gateway key.
        let other_key = json!({ "ca_csr": Mac::new("hw-2").csr });
        let (status, _) = mac.call(&stub, id, Method::POST, "/portal/api/renew_agent_intermediate_ca", other_key);
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn the_browser_extension_secret_or_a_wrong_key_does_not_enroll() {
        let stub = stub();
        let mac = Mac::new("hw-1");
        for key in ["rbx_dev", "rae_dev_wrong", ""] {
            assert_eq!(mac.enroll_with(&stub, key, "").0, StatusCode::UNAUTHORIZED, "{key}");
        }
    }

    #[test]
    fn enrolling_needs_a_proof_of_the_key_it_registers() {
        let stub = stub();
        let (mac, impostor) = (Mac::new("hw-1"), Mac::new("hw-1"));
        let path = "/portal/api/enroll_agent_device";
        // The impostor registers the Mac's public key without holding its private half.
        let body = json!({ "hardware_uuid": "hw-1", "device_public_key": mac.key.public_jwk(), "ca_csr": mac.csr });
        let proof = impostor.key.proof("hw-1", "POST", path, NOW);
        let req = Req { method: &Method::POST, path, bearer: ENROLLMENT_KEY, device_proof: &proof, body: &body, now: NOW };
        assert_eq!(stub.route(&req).0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_proof_is_bound_to_its_device_its_request_and_used_once() {
        let stub = stub();
        let (mac, other) = (Mac::new("hw-1"), Mac::new("hw-2"));
        let id = mac.enroll(&stub)["device_id"].as_str().unwrap().to_owned();
        let config = "/portal/api/get_agent_config";

        let proof = mac.key.proof(&id, "GET", config, NOW);
        assert_eq!(mac.call_with(&stub, &proof, Method::GET, config, Value::Null).0, StatusCode::OK);
        assert_eq!(mac.call_with(&stub, &proof, Method::GET, config, Value::Null).0, StatusCode::UNAUTHORIZED, "replayed");

        let for_heartbeat = mac.key.proof(&id, "POST", "/portal/api/send_agent_heartbeat", NOW);
        assert_eq!(mac.call_with(&stub, &for_heartbeat, Method::GET, config, Value::Null).0, StatusCode::UNAUTHORIZED, "another path");

        let forged = other.key.proof(&id, "GET", config, NOW);
        assert_eq!(mac.call_with(&stub, &forged, Method::GET, config, Value::Null).0, StatusCode::UNAUTHORIZED, "another key");

        let expired = mac.key.proof(&id, "GET", config, NOW - 3600);
        assert_eq!(mac.call_with(&stub, &expired, Method::GET, config, Value::Null).0, StatusCode::UNAUTHORIZED, "expired");

        assert_eq!(mac.call_with(&stub, "rad_old_bearer", Method::GET, config, Value::Null).0, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn the_same_mac_with_the_same_key_gets_its_device_back() {
        let stub = stub();
        let mac = Mac::new("hw-1");
        let first = mac.enroll(&stub)["device_id"].clone();
        assert_eq!(mac.enroll(&stub)["device_id"], first);
    }

    #[test]
    fn a_new_key_for_an_active_mac_waits_for_an_admin() {
        let stub = stub_with(true);
        let (mac, newcomer) = (Mac::new("hw-1"), Mac::new("hw-1"));
        let old = mac.enroll(&stub)["device_id"].as_str().unwrap().to_owned();
        let pending = newcomer.enroll(&stub);
        assert_eq!(pending["status"], "pending_approval");
        assert!(pending["intermediate_pem"].is_null(), "no CA for an unapproved key");
        let new = pending["device_id"].as_str().unwrap().to_owned();
        assert_eq!(newcomer.call(&stub, &new, Method::GET, "/portal/api/get_agent_config", Value::Null).0, StatusCode::UNAUTHORIZED);
        assert_eq!(mac.call(&stub, &old, Method::GET, "/portal/api/get_agent_config", Value::Null).0, StatusCode::OK, "the Mac keeps working");

        let approve = Req { method: &Method::POST, path: &format!("/portal/_stub/approve/{new}"), bearer: "", device_proof: "", body: &Value::Null, now: NOW };
        assert_eq!(stub.route(&approve).0, StatusCode::NO_CONTENT);
        assert_eq!(newcomer.enroll(&stub)["status"], "active");
        assert_eq!(mac.call(&stub, &old, Method::GET, "/portal/api/get_agent_config", Value::Null).0, StatusCode::UNAUTHORIZED, "old key revoked");
    }

    #[test]
    fn an_unsubstituted_email_variable_is_no_employee() {
        let stub = stub();
        let mac = Mac::new("hw-1");
        let (_, reply) = mac.enroll_with(&stub, ENROLLMENT_KEY, "$EMAIL");
        let id = reply.unwrap()["device_id"].as_str().unwrap().to_owned();
        let (_, config) = mac.call(&stub, &id, Method::GET, "/portal/api/get_agent_config", Value::Null);
        assert_eq!(config.unwrap()["employee"], Value::Null);
    }

    #[test]
    fn only_dev_keeps_what_it_is_sent() {
        let report = json!({ "session_id": "s-1", "service_id": "anthropic", "text": { "redacted": true } });
        for (stub, kept) in [(stub(), false), (stub_with(true), true)] {
            let mac = Mac::new("hw-1");
            let id = mac.enroll(&stub)["device_id"].as_str().unwrap().to_owned();
            mac.call(&stub, &id, Method::POST, "/portal/api/send_agent_sensitive_data_report", report.clone());
            mac.call(&stub, &id, Method::POST, "/portal/api/send_agent_sensitive_data_report", report.clone());
            let state = Req { method: &Method::GET, path: "/portal/_stub/state", bearer: "", device_proof: "", body: &Value::Null, now: NOW };
            let (status, state) = stub.route(&state);
            if kept {
                let state = state.unwrap();
                assert_eq!(state["devices"][0]["hostname"], "mac");
                assert_eq!(state["reports"].as_array().unwrap().len(), 1, "upserted by session");
            } else {
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
        }
    }
}
