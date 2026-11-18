//! A stand-in for parrot's agent API (docs/parrot-agent-api.md) that runs next to the daemon on
//! each Mac of a test fleet, while parrot does not serve it. It enrolls any device that presents
//! its workspace secret and gives every device the same policy (`dev/stub-policy.json`, shared
//! with `dev/stub-parrot.mjs`). State is in memory: after a restart, the daemon's next request
//! is refused and it enrolls again.
//!
//! ```text
//! riot-stub-parrot [port]        (default 7592; loopback only)
//! ```
//!
//! Logs each request's method, path and status, never a body: they name the device and its user.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

const DEFAULT_PORT: u16 = 7592;
const WORKSPACE_ID: &str = "ws-dev";
const SECRET: &str = "rbx_dev";
const POLICY: &str = include_str!("../../../../dev/stub-policy.json");
const MAX_BODY_BYTES: usize = 1024 * 1024;

struct Device {
    id: String,
    employee_email: Option<String>,
    /// Report sessions, and whether each was redacted (upserted, like parrot).
    reports: HashMap<String, bool>,
}

struct Stub {
    policy: Value,
    devices: Mutex<HashMap<String, Device>>,
}

impl Stub {
    fn route(&self, method: &Method, path: &str, bearer: &str, workspace: &str, body: &Value) -> (StatusCode, Option<Value>) {
        let unauthenticated = (StatusCode::UNAUTHORIZED, Some(json!({ "error": "unauthenticated" })));
        let mut devices = self.devices.lock().unwrap();
        if (method, path) == (&Method::POST, "/portal/api/agent/enroll") {
            if bearer != SECRET || workspace != WORKSPACE_ID {
                return unauthenticated;
            }
            let id = uuid::Uuid::new_v4().to_string();
            let token = format!("rad_{}", uuid::Uuid::new_v4().simple());
            let employee_email = body["employee_email"].as_str().filter(|e| e.contains('@')).map(str::to_owned);
            devices.insert(token.clone(), Device { id: id.clone(), employee_email, reports: HashMap::new() });
            return (StatusCode::OK, Some(json!({ "device_id": id, "device_token": token })));
        }
        let Some(device) = devices.get_mut(bearer) else {
            return if path.starts_with("/portal/api/agent/") { unauthenticated } else { (StatusCode::NOT_FOUND, None) };
        };
        match (method, path) {
            (&Method::GET, "/portal/api/agent/config") => (StatusCode::OK, Some(self.config(device))),
            (&Method::POST, "/portal/api/agent/heartbeat") => (StatusCode::NO_CONTENT, None),
            (&Method::POST, "/portal/api/agent/sensitive_data_report") => {
                let (Some(session), Some(_)) = (body["session_id"].as_str(), body["service_id"].as_str()) else {
                    return (StatusCode::UNPROCESSABLE_ENTITY, Some(json!({ "error": "invalid" })));
                };
                device.reports.insert(session.to_owned(), body["text"]["redacted"].as_bool().unwrap_or(false));
                (StatusCode::OK, Some(json!({ "recorded": true })))
            }
            _ => (StatusCode::NOT_FOUND, Some(json!({ "error": "not found" }))),
        }
    }

    fn config(&self, device: &Device) -> Value {
        // The MDM's email variable, when it was substituted: the popup greets the user by its
        // local part.
        let employee = device.employee_email.as_ref().map(|email| {
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

async fn handle(stub: Arc<Stub>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let bearer = header(AUTHORIZATION.as_str()).strip_prefix("Bearer ").unwrap_or("").to_owned();
    let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(body) => serde_json::from_slice(&body.to_bytes()).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let (status, reply) = stub.route(&parts.method, parts.uri.path(), &bearer, &header("x-workspace-id"), &body);
    tracing::info!(method = %parts.method, path = parts.uri.path(), status = status.as_u16());
    let mut response = Response::new(Full::new(reply.map(|r| Bytes::from(r.to_string())).unwrap_or_default()));
    *response.status_mut() = status;
    response.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap());
    Ok(response)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let port = std::env::args().nth(1).map(|p| p.parse()).transpose()?.unwrap_or(DEFAULT_PORT);
    let stub = Arc::new(Stub { policy: serde_json::from_str(POLICY)?, devices: Mutex::default() });
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
    use super::*;

    fn stub() -> Stub {
        Stub { policy: serde_json::from_str(POLICY).unwrap(), devices: Mutex::default() }
    }

    #[test]
    fn a_device_enrolls_then_gets_the_policy_and_reports() {
        let stub = stub();
        let enroll = json!({ "hostname": "mac", "employee_email": "camille@example.com" });
        let (status, _) = stub.route(&Method::POST, "/portal/api/agent/enroll", "rbx_wrong", WORKSPACE_ID, &enroll);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, reply) = stub.route(&Method::POST, "/portal/api/agent/enroll", SECRET, WORKSPACE_ID, &enroll);
        assert_eq!(status, StatusCode::OK);
        let token = reply.unwrap()["device_token"].as_str().unwrap().to_owned();

        let report = json!({ "session_id": "s-1", "service_id": "anthropic", "text": { "redacted": true } });
        let (status, _) = stub.route(&Method::POST, "/portal/api/agent/sensitive_data_report", &token, "", &report);
        assert_eq!(status, StatusCode::OK);
        let (status, config) = stub.route(&Method::GET, "/portal/api/agent/config", &token, "", &Value::Null);
        assert_eq!(status, StatusCode::OK);
        let config: riot_api::AgentConfig = serde_json::from_value(config.unwrap()).unwrap();
        let employee = config.employee.unwrap();
        assert_eq!((employee.name.as_str(), employee.redactions_last_30_days), ("camille", 1));
        assert!(config.policies[0].services.iter().any(|s| s.api_hosts.contains(&"claude.ai".to_owned())));

        let (status, _) = stub.route(&Method::GET, "/portal/api/agent/config", "rad_unknown", "", &Value::Null);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "after a restart the daemon enrolls again");
    }

    #[test]
    fn an_unsubstituted_email_variable_is_no_employee() {
        let stub = stub();
        let enroll = json!({ "hostname": "mac", "employee_email": "$EMAIL" });
        let (_, reply) = stub.route(&Method::POST, "/portal/api/agent/enroll", SECRET, WORKSPACE_ID, &enroll);
        let token = reply.unwrap()["device_token"].as_str().unwrap().to_owned();
        let (_, config) = stub.route(&Method::GET, "/portal/api/agent/config", &token, "", &Value::Null);
        assert_eq!(config.unwrap()["employee"], Value::Null);
    }
}
