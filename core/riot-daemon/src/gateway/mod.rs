//! The local API gateway: AI API clients (Claude Code, SDKs) point their base URL at it, e.g.
//! `ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic`, and it forwards to the real API over
//! TLS. Requests to a host the policy lists (`api_hosts`) are redacted on the way out and their
//! answers detokenized on the way back; everything else passes through untouched.
//!
//! Two API formats are rewritten, by path: Anthropic Messages ([`anthropic`], JSON and SSE) and
//! OpenAI Responses ([`responses`], over a WebSocket ([`websocket`]) or SSE, as Codex and the
//! ChatGPT app use it).
//!
//! No certificate is involved: the client speaks plain HTTP to loopback. Bodies and headers are
//! never logged, they carry prompts and credentials.
//!
//! For development, the same port is also an `HTTPS_PROXY` (`RIOT_DEV_PROXY=1`): a CONNECT to a
//! host the policy lists is answered with a certificate from the Riot CA ([`ca`]) and its
//! requests take the same path as the base URL's; any other CONNECT is tunnelled untouched. It
//! stands in for the transparent proxy, which will hand the daemon the same TLS flows.

mod anthropic;
mod ca;
mod responses;
mod sse;
mod tokens;
mod websocket;

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use riot_detect::{Detection, Engine, Options};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};

use crate::agent::{Agent, Target};
use ca::Authority;

type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Path prefix → upstream host. The prefix keeps room for other APIs on the same port.
const UPSTREAMS: &[(&str, &str)] = &[("anthropic", "api.anthropic.com")];
/// Largest request body accepted (Messages requests carry the whole conversation).
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Largest single text redacted: the engine's ceiling for extracted file text. A longer text
/// is not known to be clean, so the request is refused.
const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Redacted texts remembered per scope. Clients resend the whole conversation on every turn:
/// only new texts reach the engine (and the report).
const CACHE_ENTRIES: usize = 4096;
const HOP_BY_HOP: &[&str] =
    &["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

pub struct Gateway {
    agent: Arc<Agent>,
    client: reqwest::Client,
    cache: Mutex<Cache>,
    upstreams: Upstreams,
    /// Set when the `HTTPS_PROXY` entry is on.
    authority: Option<Arc<Authority>>,
}

pub async fn serve(agent: Arc<Agent>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let upstreams = Upstreams::from_env()?;
    let authority = match std::env::var_os("RIOT_DEV_PROXY").is_some_and(|v| v == "1") {
        true => Some(Arc::new(Authority::load_or_create(&agent.paths.data_dir)?)),
        false => None,
    };
    tracing::info!(
        %addr,
        upstream = %upstreams,
        proxy_ca = authority.as_ref().map(|a| a.cert_path().display().to_string()),
        "gateway listening"
    );
    Gateway::new(agent, upstreams, authority)?.run(listener).await
}

/// Where requests for an API host go instead of `https://<host>`: a local server in tests, or
/// an inspecting proxy between the gateway and the API (`RIOT_GATEWAY_UPSTREAM`).
#[derive(Debug, Default)]
struct Upstreams {
    /// For every host.
    any: Option<String>,
    by_host: HashMap<String, String>,
}

impl Upstreams {
    #[cfg(test)]
    fn any(base: String) -> Self {
        Self { any: Some(base), by_host: HashMap::new() }
    }

    /// `RIOT_GATEWAY_UPSTREAM`, for development: comma-separated `host=url` entries, one per
    /// mitmproxy reverse mode (`api.anthropic.com=http://127.0.0.1:18081,chatgpt.com=…:18082`);
    /// a bare URL applies to every host. Loopback only: the gateway forwards the client's
    /// credentials, and they must not be sent anywhere else.
    fn from_env() -> anyhow::Result<Self> {
        let Ok(value) = std::env::var("RIOT_GATEWAY_UPSTREAM") else { return Ok(Self::default()) };
        Self::parse(&value)
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        let mut out = Self::default();
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (host, base) = match entry.split_once('=') {
                Some((host, base)) => (Some(host.trim().to_ascii_lowercase()), base.trim()),
                None => (None, entry),
            };
            let url = reqwest::Url::parse(base)?;
            let name = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']');
            let loopback = name == "localhost" || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
            anyhow::ensure!(loopback, "RIOT_GATEWAY_UPSTREAM must hold loopback URLs, not {base}");
            let base = base.trim_end_matches('/').to_owned();
            match host {
                Some(host) => out.by_host.insert(host, base),
                None => out.any.replace(base),
            };
        }
        Ok(out)
    }

    fn base(&self, host: &str) -> String {
        let host = host.to_ascii_lowercase();
        self.by_host.get(&host).or(self.any.as_ref()).cloned().unwrap_or_else(|| format!("https://{host}"))
    }
}

impl std::fmt::Display for Upstreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entries: Vec<String> = self.by_host.iter().map(|(h, b)| format!("{h}={b}")).collect();
        entries.sort();
        entries.push(format!("*={}", self.any.as_deref().unwrap_or("https://<host>")));
        f.write_str(&entries.join(","))
    }
}

impl Gateway {
    fn new(agent: Arc<Agent>, upstreams: Upstreams, authority: Option<Arc<Authority>>) -> anyhow::Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Arc::new(Self { agent, client, cache: Mutex::new(Cache::default()), upstreams, authority }))
    }

    async fn run(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let gateway = self.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    let gateway = gateway.clone();
                    async move { Ok::<_, Infallible>(gateway.handle(req).await) }
                });
                let io = TokioIo::new(stream);
                if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, service).with_upgrades().await {
                    tracing::debug!(error = %e, "gateway connection ended");
                }
            });
        }
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<Body> {
        match req.method() {
            &Method::CONNECT => self.connect(req).await.unwrap_or_else(GatewayError::response),
            _ => self.handle_request(req, None).await,
        }
    }

    /// `origin` is the host a decrypted CONNECT tunnel leads to; `None` on the base URL entry.
    async fn handle_request(self: Arc<Self>, req: Request<Incoming>, origin: Option<Arc<str>>) -> Response<Body> {
        let (method, path) = (req.method().clone(), req.uri().path().to_owned());
        let started = Instant::now();
        let result = match &origin {
            Some(host) => self.relay(req, host, &path).await,
            None => self.forward(req).await,
        };
        let response = result.unwrap_or_else(GatewayError::response);
        let host = origin.as_deref().unwrap_or_default();
        tracing::info!(%method, host, path, status = response.status().as_u16(), ms = started.elapsed().as_millis() as u64, "gateway");
        response
    }

    /// The `HTTPS_PROXY` entry: TLS is terminated only for a host the policy lists, with a
    /// certificate from the Riot CA; anything else is tunnelled as is.
    async fn connect(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, GatewayError> {
        let authority = self.authority.clone().ok_or_else(|| GatewayError::BadRequest("the proxy entry is off (RIOT_DEV_PROXY)".into()))?;
        let target = req.uri().authority().ok_or_else(|| GatewayError::BadRequest("CONNECT needs host:port".into()))?;
        let (host, port) = (target.host().to_ascii_lowercase(), target.port_u16().unwrap_or(443));
        let intercept = port == 443 && self.agent.api_target(&host).is_some();
        tracing::info!(host, port, intercept, "gateway connect");
        let next = if intercept {
            // A host to protect that the CA cannot cover is refused, not tunnelled unchecked.
            Next::Tls(authority.server_config(&host).map_err(|e| GatewayError::Blocked(e.to_string()))?)
        } else {
            Next::Tunnel(TcpStream::connect((host.as_str(), port)).await.map_err(|e| GatewayError::Upstream(e.to_string()))?)
        };
        tokio::spawn(async move {
            let client = match hyper::upgrade::on(req).await {
                Ok(upgraded) => TokioIo::new(upgraded),
                Err(e) => return tracing::debug!(error = %e, "gateway connect upgrade failed"),
            };
            let ended = match next {
                Next::Tls(config) => self.serve_tls(client, config, host.into()).await,
                Next::Tunnel(mut server) => {
                    let mut client = client;
                    tokio::io::copy_bidirectional(&mut client, &mut server).await.map(drop).map_err(Into::into)
                }
            };
            if let Err(e) = ended {
                tracing::debug!(error = %e, "gateway tunnel ended");
            }
        });
        Ok(Response::new(full(Bytes::new())))
    }

    async fn serve_tls(self: Arc<Self>, client: TokioIo<Upgraded>, config: Arc<rustls::ServerConfig>, host: Arc<str>) -> anyhow::Result<()> {
        let tls = tokio_rustls::TlsAcceptor::from(config).accept(client).await?;
        let service = hyper::service::service_fn(move |req| {
            let (gateway, host) = (self.clone(), host.clone());
            async move { Ok::<_, Infallible>(gateway.handle_request(req, Some(host)).await) }
        });
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).with_upgrades().await?;
        Ok(())
    }

    /// The base URL entry: `/anthropic/v1/messages` → `api.anthropic.com`, `/v1/messages`.
    async fn forward(self: &Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, GatewayError> {
        let (prefix, rest) = req.uri().path().trim_start_matches('/').split_once('/').ok_or(GatewayError::NotFound)?;
        let host = UPSTREAMS.iter().find(|(p, _)| *p == prefix).map(|(_, h)| *h).ok_or(GatewayError::NotFound)?;
        let api_path = format!("/{rest}");
        self.relay(req, host, &api_path).await
    }

    /// Sends a request on to `host`, redacting it on the way out and detokenizing the answer
    /// when the policy protects that host.
    async fn relay(self: &Arc<Self>, req: Request<Incoming>, host: &str, api_path: &str) -> Result<Response<Body>, GatewayError> {
        let base = self.upstreams.base(host);
        let url = match req.uri().query() {
            Some(q) => format!("{base}{api_path}?{q}"),
            None => format!("{base}{api_path}"),
        };
        let target = self.agent.api_target(host);
        let api = Api::for_path(api_path);
        if websocket::is_upgrade(&req) {
            let hooks = match (target, api) {
                (Some(target), Some(Api::Responses)) => {
                    let scope = scope(&target.service_id, req.headers());
                    self.responses_hooks(target, scope)
                }
                _ => websocket::Hooks::passthrough(),
            };
            return websocket::relay(req, &url, hooks).await;
        }

        let rewrite = target.is_some() && req.method() == Method::POST && api.is_some();
        let api = api.unwrap_or(Api::Messages);
        let method = req.method().clone();
        let mut headers = forwarded_headers(req.headers());
        let scope = target.as_ref().map(|t| scope(&t.service_id, req.headers()));

        let body = Limited::new(req.into_body(), MAX_REQUEST_BYTES)
            .collect()
            .await
            .map_err(|e| GatewayError::BadRequest(format!("could not read the request body: {e}")))?
            .to_bytes();

        let body = match (&target, &scope) {
            (Some(target), Some(scope)) if rewrite => {
                // Sent on uncompressed; responses must come back uncompressed to be detokenized.
                let body = decoded(headers.remove(header::CONTENT_ENCODING), body)?;
                headers.remove(header::ACCEPT_ENCODING);
                self.redact(body, api, target, scope).await?
            }
            _ => body,
        };

        let upstream = self
            .client
            .request(method, &url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))?;

        let status = upstream.status();
        let mut response_headers = forwarded_headers(upstream.headers());
        let content_type = upstream.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let encoded = upstream.headers().get(header::CONTENT_ENCODING).is_some_and(|v| v != "identity");

        let body: Body = match scope {
            // `chatgpt.com/backend-api/codex/responses` streams SSE with no content type at all.
            Some(scope) if rewrite && !encoded && (content_type.starts_with("text/event-stream") || content_type.is_empty()) => {
                response_headers.remove(header::CONTENT_LENGTH);
                self.detokenize_stream(upstream, api.sse_rewriter(), scope)
            }
            Some(scope) if rewrite && !encoded && content_type.starts_with("application/json") => {
                response_headers.remove(header::CONTENT_LENGTH);
                let bytes = upstream.bytes().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
                full(self.detokenize_json(bytes, api, scope).await)
            }
            _ => StreamBody::new(upstream.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other)).boxed_unsync(),
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        Ok(response)
    }

    /// Redacts a request body; reports what it redacted for the first time.
    async fn redact(&self, body: Bytes, api: Api, target: &Target, scope: &str) -> Result<Bytes, GatewayError> {
        let mut json: Value =
            serde_json::from_slice(&body).map_err(|e| GatewayError::BadRequest(format!("the request is not JSON: {e}")))?;
        // The engine call blocks on the JS thread.
        tokio::task::block_in_place(|| self.redact_json(&mut json, api, target, scope, body.len()))?;
        Ok(serde_json::to_vec(&json).map_err(|e| GatewayError::Blocked(e.to_string()))?.into())
    }

    /// Blocking: calls the engine for every text not seen before in this scope.
    fn redact_json(&self, json: &mut Value, api: Api, target: &Target, scope: &str, bytes: usize) -> Result<(), GatewayError> {
        let options = Options { max_bytes: Some(MAX_TEXT_BYTES), ..target.options.clone() };
        let started = Instant::now();
        let mut detections = vec![];
        let mut redact = |text: &str| redact_cached(&self.agent.engine, &self.cache, scope, &options, text, &mut detections);
        match api {
            Api::Messages => anthropic::redact_request(json, &mut redact)?,
            Api::Responses => responses::redact_request(json, &mut redact)?,
        }
        let ms = started.elapsed().as_millis() as u64;
        tracing::info!(?api, ms, bytes, new_detections = detections.len(), "gateway redaction");
        if !detections.is_empty() {
            self.agent.report_api_redaction(target, &detections);
        }
        Ok(())
    }

    /// A Responses WebSocket: each `response.create` is redacted (or refused, and the client
    /// gets an `error` event instead), each event detokenized.
    fn responses_hooks(self: &Arc<Self>, target: Target, scope: String) -> websocket::Hooks {
        let gateway = self.clone();
        let engine = self.agent.engine.clone();
        let down_scope = scope.clone();
        let mut events = responses::EventRewriter::default();
        websocket::Hooks {
            up: Box::new(move |text| {
                let refuse = |e: GatewayError| e.error_event();
                let mut json: Value =
                    serde_json::from_str(text).map_err(|e| refuse(GatewayError::Blocked(format!("a message is not JSON: {e}"))))?;
                if json.get("type").and_then(Value::as_str) != Some("response.create") {
                    return Ok(text.to_owned());
                }
                gateway.redact_json(&mut json, Api::Responses, &target, &scope, text.len()).map_err(refuse)?;
                Ok(json.to_string())
            }),
            down: Box::new(move |text| match serde_json::from_str::<Value>(text) {
                Ok(event) => events.event(event, &mut resolver(&engine, &down_scope)).iter().map(Value::to_string).collect(),
                Err(_) => vec![text.to_owned()],
            }),
            allow_binary_up: false,
        }
    }

    fn detokenize_stream(&self, upstream: reqwest::Response, rewriter: Box<dyn sse::Rewrite>, scope: String) -> Body {
        let engine = self.agent.engine.clone();
        let state = (upstream.bytes_stream(), rewriter);
        let stream = futures_util::stream::unfold(Some(state), move |state| {
            let (engine, scope) = (engine.clone(), scope.clone());
            async move {
                let (mut upstream, mut rewriter) = state?;
                loop {
                    match upstream.next().await {
                        Some(Ok(chunk)) => {
                            let out = tokio::task::block_in_place(|| rewriter.push(&chunk, &mut resolver(&engine, &scope)));
                            if !out.is_empty() {
                                return Some((Ok(Frame::data(Bytes::from(out))), Some((upstream, rewriter))));
                            }
                        }
                        Some(Err(e)) => return Some((Err(std::io::Error::other(e)), None)),
                        None => {
                            let rest = rewriter.finish();
                            return (!rest.is_empty()).then(|| (Ok(Frame::data(Bytes::from(rest))), None));
                        }
                    }
                }
            }
        });
        StreamBody::new(stream).boxed_unsync()
    }

    async fn detokenize_json(&self, bytes: Bytes, api: Api, scope: String) -> Bytes {
        let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) else { return bytes };
        let engine = self.agent.engine.clone();
        tokio::task::block_in_place(|| {
            let mut resolve = resolver(&engine, &scope);
            match api {
                Api::Messages => anthropic::detokenize_response(&mut json, &mut resolve),
                Api::Responses => responses::detokenize_value(&mut json, &mut resolve),
            }
        });
        serde_json::to_vec(&json).map(Bytes::from).unwrap_or(bytes)
    }
}

/// The API formats the gateway rewrites, by request path.
#[derive(Debug, Clone, Copy)]
enum Api {
    /// Anthropic Messages (`/v1/messages`).
    Messages,
    /// OpenAI Responses (`/backend-api/codex/responses`, `/v1/responses`).
    Responses,
}

impl Api {
    fn for_path(path: &str) -> Option<Self> {
        if anthropic::is_messages_path(path) {
            Some(Self::Messages)
        } else if responses::is_responses_path(path) {
            Some(Self::Responses)
        } else {
            None
        }
    }

    fn sse_rewriter(self) -> Box<dyn sse::Rewrite> {
        match self {
            Self::Messages => Box::new(anthropic::SseRewriter::default()),
            Self::Responses => Box::new(responses::SseRewriter::default()),
        }
    }
}

/// A request body as the client encoded it (Codex compresses with zstd when it falls back from
/// its WebSocket to HTTPS). Another encoding cannot be checked: the request is refused.
fn decoded(encoding: Option<HeaderValue>, body: Bytes) -> Result<Bytes, GatewayError> {
    use std::io::Read;
    let encoding = encoding.as_ref().and_then(|v| v.to_str().ok()).map(str::to_ascii_lowercase);
    match encoding.as_deref() {
        None | Some("identity") => Ok(body),
        Some("zstd") => {
            let mut out = vec![];
            zstd::stream::read::Decoder::new(&body[..])
                .and_then(|d| d.take(MAX_REQUEST_BYTES as u64 + 1).read_to_end(&mut out))
                .map_err(|e| GatewayError::Blocked(format!("the zstd request body could not be read: {e}")))?;
            if out.len() > MAX_REQUEST_BYTES {
                return Err(GatewayError::Blocked(format!("the request is over {} MiB", MAX_REQUEST_BYTES / 1_048_576)));
            }
            Ok(out.into())
        }
        Some(other) => Err(GatewayError::Blocked(format!("{other}-compressed request bodies cannot be checked"))),
    }
}

/// Token memory is per credential: the gateway cannot tell which local user a TCP connection
/// comes from, but it can tell credentials apart, and a value only resolves for requests
/// carrying the one that redacted it.
fn scope(service_id: &str, headers: &HeaderMap) -> String {
    let credential = headers.get("x-api-key").or_else(|| headers.get(header::AUTHORIZATION)).map(HeaderValue::as_bytes);
    let digest = Sha256::digest(credential.unwrap_or_default());
    format!("api:{service_id}:{}", &hex::encode(digest)[..16])
}

fn resolver<'a>(engine: &'a Engine, scope: &'a str) -> impl FnMut(&str) -> Option<String> + 'a {
    move |token| engine.detokenize(token, scope).ok().filter(|d| d.replaced > 0).map(|d| d.text)
}

fn redact_cached(
    engine: &Engine,
    cache: &Mutex<Cache>,
    scope: &str,
    options: &Options,
    text: &str,
    detections: &mut Vec<Detection>,
) -> Result<String, GatewayError> {
    if text.trim().is_empty() {
        return Ok(text.to_owned());
    }
    let key: [u8; 32] = Sha256::new().chain_update(scope).chain_update([0]).chain_update(text).finalize().into();
    if let Some(hit) = cache.lock().unwrap().get(&key) {
        return Ok(hit);
    }
    let out = engine.redact(text, scope, options).map_err(|e| GatewayError::Blocked(format!("the detection engine failed: {e}")))?;
    if out.oversized {
        return Err(GatewayError::Blocked(format!("a text in the request is over {} MiB", MAX_TEXT_BYTES / 1_048_576)));
    }
    detections.extend(out.detections);
    cache.lock().unwrap().put(key, out.text.clone());
    Ok(out.text)
}

#[derive(Default)]
struct Cache {
    entries: HashMap<[u8; 32], String>,
    order: VecDeque<[u8; 32]>,
}

impl Cache {
    fn get(&self, key: &[u8; 32]) -> Option<String> {
        self.entries.get(key).cloned()
    }

    fn put(&mut self, key: [u8; 32], value: String) {
        if self.entries.insert(key, value).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > CACHE_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }
}

enum Next {
    Tls(Arc<rustls::ServerConfig>),
    Tunnel(TcpStream),
}

fn forwarded_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = headers.clone();
    for name in HOP_BY_HOP.iter().chain(&["host", "content-length"]) {
        out.remove(HeaderName::from_static(name));
    }
    out
}

fn full(bytes: Bytes) -> Body {
    Full::new(bytes).map_err(|never| match never {}).boxed_unsync()
}

#[derive(Debug)]
enum GatewayError {
    NotFound,
    BadRequest(String),
    /// The request could not be checked: not sent (fail closed, as for files).
    Blocked(String),
    Upstream(String),
}

impl GatewayError {
    fn parts(self) -> (StatusCode, &'static str, String) {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found_error", "unknown API prefix (use /anthropic)".to_owned()),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request_error", m),
            Self::Blocked(m) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Riot could not check this request for sensitive data, so it was not sent: {m}"),
            ),
            Self::Upstream(m) => (StatusCode::BAD_GATEWAY, "api_error", format!("Riot gateway could not reach the API: {m}")),
        }
    }

    /// The same refusal as a WebSocket `error` event with an HTTP status, which Codex reports
    /// as a final error (a `response.failed` reads as a broken stream: it retries, then falls
    /// back to HTTPS). The request is not sent.
    fn error_event(self) -> String {
        let (status, kind, message) = self.parts();
        tracing::warn!(status = status.as_u16(), message, "gateway refused a request");
        let error = serde_json::json!({ "type": kind, "code": "riot_blocked", "message": message });
        serde_json::json!({ "type": "error", "status": status.as_u16(), "error": error }).to_string()
    }

    /// An error in the Messages API's shape, so the client shows the message.
    fn response(self) -> Response<Body> {
        let (status, kind, message) = self.parts();
        tracing::warn!(status = status.as_u16(), message, "gateway refused a request");
        let body = serde_json::json!({ "type": "error", "error": { "type": kind, "message": message } });
        let mut response = Response::new(full(body.to_string().into()));
        *response.status_mut() = status;
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use riot_detect::EngineConfig;
    use serde_json::json;

    const MAIL: &str = "jean.dupont@example.com";
    const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";

    fn agent(name: &str, api_hosts: &[&str]) -> Arc<Agent> {
        let dir = std::env::temp_dir().join(format!("riot-gateway-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths { settings: dir.join("settings.json"), data_dir: dir.clone(), socket: dir.join("agent.sock") };
        let agent = Agent::new(paths, Engine::start(EngineConfig::default()).unwrap()).unwrap();
        agent.state.write().unwrap().config = Some(
            serde_json::from_value(json!({
                "employee": null, "workspace": null,
                "policies": [{
                    "policy_kind": riot_api::MONITORING_POLICY_KIND, "enabled": true, "allow_bypass_redaction": true,
                    "services": [{ "service_id": "anthropic", "display_name": "Claude", "api_hosts": api_hosts }]
                }]
            }))
            .unwrap(),
        );
        Arc::new(agent)
    }

    /// A Messages API stand-in: records each request body and streams back the last user
    /// text, three bytes per event, as the model would repeat it.
    async fn fake_api() -> (String, Arc<Mutex<Vec<Value>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let recorded = recorded.clone();
                        async move {
                            let body: Value = serde_json::from_slice(&req.into_body().collect().await.unwrap().to_bytes()).unwrap();
                            let echo = body["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap().to_owned();
                            recorded.lock().unwrap().push(body);
                            let mut sse = String::from("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n");
                            for piece in echo.as_bytes().chunks(3) {
                                let delta = json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": String::from_utf8_lossy(piece) } });
                                sse.push_str(&format!("event: content_block_delta\ndata: {delta}\n\n"));
                            }
                            sse.push_str("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
                            let mut response = Response::new(full(sse.into()));
                            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
                });
            }
        });
        (base, seen)
    }

    async fn gateway(agent: Arc<Agent>, upstream: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/anthropic", listener.local_addr().unwrap());
        tokio::spawn(Gateway::new(agent, Upstreams::any(upstream), None).unwrap().run(listener));
        url
    }

    /// The gateway with its `HTTPS_PROXY` entry on, and the root its certificates chain to.
    async fn proxy(agent: Arc<Agent>, upstream: String) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        let authority = Arc::new(Authority::load_or_create(&agent.paths.data_dir).unwrap());
        let root = authority.root().clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Gateway::new(agent, Upstreams::any(upstream), Some(authority)).unwrap().run(listener));
        (addr, root)
    }

    /// Sends a raw CONNECT; returns the stream and the response's status line.
    async fn raw_connect(proxy: SocketAddr, target: &str) -> (TcpStream, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = vec![];
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        (stream, head.lines().next().unwrap_or_default().to_owned())
    }

    /// What the client reads: the streamed text, rebuilt.
    async fn ask(url: &str, text: &str) -> String {
        ask_with(&reqwest::Client::new(), url, text).await
    }

    async fn ask_with(client: &reqwest::Client, url: &str, text: &str) -> String {
        let body = json!({ "model": "m", "stream": true, "messages": [{ "role": "user", "content": text }] });
        let sse = client
            .post(format!("{url}/v1/messages"))
            .header("x-api-key", "sk-test")
            .json(&body)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        sse.split("\n\n")
            .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
            .filter_map(|d| serde_json::from_str::<Value>(d).ok())
            .filter_map(|d| d.pointer("/delta/text").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    #[test]
    fn upstreams_are_chosen_per_host() {
        let upstreams = Upstreams::parse("api.anthropic.com=http://127.0.0.1:18081, ChatGPT.com=http://localhost:18082/").unwrap();
        assert_eq!(upstreams.base("api.anthropic.com"), "http://127.0.0.1:18081");
        assert_eq!(upstreams.base("chatgpt.com"), "http://localhost:18082");
        assert_eq!(upstreams.base("claude.ai"), "https://claude.ai");
        assert_eq!(Upstreams::parse("http://[::1]:9").unwrap().base("chatgpt.com"), "http://[::1]:9");
        assert!(Upstreams::parse("chatgpt.com=https://evil.example").is_err(), "credentials stay on this machine");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn values_never_reach_the_api_and_come_back_to_the_client() {
        let agent = agent("roundtrip", &["api.anthropic.com"]);
        let (upstream, seen) = fake_api().await;
        let url = gateway(agent.clone(), upstream).await;
        let text = format!("Mail {MAIL}, IBAN {IBAN}.");

        assert_eq!(ask(&url, &text).await, text, "the answer is detokenized, split tokens included");
        let sent = seen.lock().unwrap()[0].to_string();
        assert!(!sent.contains(MAIL) && !sent.contains("3000 6000"), "upstream saw: {sent}");
        assert!(sent.contains("[EMAIL") && sent.contains("[IBAN"), "upstream saw: {sent}");
        assert_eq!(agent.spool.len(), 1);

        // The client resends the conversation: same tokens, nothing new to report.
        assert_eq!(ask(&url, &text).await, text);
        assert_eq!(seen.lock().unwrap()[1].to_string(), sent, "stable tokens keep the prompt cache prefix");
        assert_eq!(agent.spool.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_outside_the_policy_passes_through() {
        let agent = agent("passthrough", &[]);
        let (upstream, seen) = fake_api().await;
        let url = gateway(agent.clone(), upstream).await;
        let text = format!("Mail {MAIL}");
        assert_eq!(ask(&url, &text).await, text);
        assert!(seen.lock().unwrap()[0].to_string().contains(MAIL));
        assert_eq!(agent.spool.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_proxy_decrypts_a_policy_host_with_the_riot_ca() {
        let agent = agent("proxy", &["api.anthropic.com"]);
        let (upstream, seen) = fake_api().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        // The client trusts the Riot root and nothing else, and checks the name: the
        // certificate must be valid for api.anthropic.com under the root's name constraints.
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{proxy}")).unwrap())
            .tls_certs_only([reqwest::Certificate::from_der(&root).unwrap()])
            .build()
            .unwrap();
        let text = format!("Mail {MAIL}, IBAN {IBAN}.");

        assert_eq!(ask_with(&client, "https://api.anthropic.com", &text).await, text);
        let sent = seen.lock().unwrap()[0].to_string();
        assert!(!sent.contains(MAIL) && sent.contains("[EMAIL"), "upstream saw: {sent}");
        assert_eq!(agent.spool.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_proxy_tunnels_other_hosts_untouched() {
        let agent = agent("tunnel", &["api.anthropic.com"]);
        let (upstream, seen) = fake_api().await;
        let (proxy, _) = proxy(agent.clone(), upstream.clone()).await;
        let target = upstream.trim_start_matches("http://");
        let (stream, status) = raw_connect(proxy, target).await;
        assert!(status.contains(" 200 "), "{status}");

        // Plain HTTP inside the tunnel reaches the server as sent.
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let body = json!({ "model": "m", "messages": [{ "role": "user", "content": format!("Mail {MAIL}") }] });
        let req = Request::post("/v1/messages").header(header::HOST, target).body(full(body.to_string().into())).unwrap();
        assert_eq!(sender.send_request(req).await.unwrap().status(), StatusCode::OK);
        assert!(seen.lock().unwrap()[0].to_string().contains(MAIL));
        assert_eq!(agent.spool.len(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_policy_host_the_ca_cannot_cover_is_refused() {
        let agent = agent("refused", &["example.com"]);
        let (upstream, _) = fake_api().await;
        let (proxy, _) = proxy(agent, upstream).await;
        let (_, status) = raw_connect(proxy, "example.com:443").await;
        assert!(status.contains(" 400 "), "{status}");
    }

    /// A Responses WebSocket stand-in: records each `response.create` and answers with its last
    /// input text, three bytes per delta, then the closing events.
    async fn fake_responses_ws() -> (String, Arc<Mutex<Vec<Value>>>) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let seen = Arc::new(Mutex::new(vec![]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                    while let Some(Ok(Message::Text(message))) = ws.next().await {
                        let body: Value = serde_json::from_str(message.as_str()).unwrap();
                        let text = body["input"].as_array().unwrap().last().unwrap()["content"][0]["text"].as_str().unwrap().to_owned();
                        recorded.lock().unwrap().push(body);
                        let mut events: Vec<Value> = text
                            .as_bytes()
                            .chunks(3)
                            .map(|p| json!({ "type": "response.output_text.delta", "item_id": "m", "content_index": 0, "delta": String::from_utf8_lossy(p) }))
                            .collect();
                        events.push(json!({ "type": "response.output_text.done", "item_id": "m", "content_index": 0, "text": text }));
                        let item = json!({ "type": "message", "id": "m", "content": [{ "type": "output_text", "text": text }] });
                        events.push(json!({ "type": "response.completed", "response": { "output": [item] } }));
                        for event in events {
                            ws.send(Message::text(event.to_string())).await.unwrap();
                        }
                    }
                });
            }
        });
        (base, seen)
    }

    /// A WebSocket to `wss://chatgpt.com/backend-api/codex/responses` through the proxy, trusting
    /// the Riot root only.
    async fn responses_ws(
        proxy: SocketAddr,
        root: rustls::pki_types::CertificateDer<'static>,
    ) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let (tcp, status) = raw_connect(proxy, "chatgpt.com:443").await;
        assert!(status.contains(" 200 "), "{status}");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("chatgpt.com").unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
        let mut request = "wss://chatgpt.com/backend-api/codex/responses".into_client_request().unwrap();
        request.headers_mut().insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer test"));
        tokio_tungstenite::client_async(request, tls).await.unwrap().0
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_responses_websocket_is_redacted_and_detokenized() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let agent = agent("ws", &["chatgpt.com"]);
        let (upstream, seen) = fake_responses_ws().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        let mut ws = responses_ws(proxy, root).await;
        let text = format!("Mail {MAIL}, IBAN {IBAN}.");
        let create = json!({ "type": "response.create", "input": [{ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": text }] }] });
        ws.send(Message::text(create.to_string())).await.unwrap();

        let mut deltas = String::new();
        let completed = loop {
            let event: Value = serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
            match event["type"].as_str().unwrap() {
                "response.output_text.delta" => deltas.push_str(event["delta"].as_str().unwrap()),
                "response.completed" => break event,
                _ => {}
            }
        };
        assert_eq!(deltas, text, "the streamed answer is detokenized, split tokens included");
        assert_eq!(completed["response"]["output"][0]["content"][0]["text"], text);
        let sent = seen.lock().unwrap()[0].to_string();
        assert!(!sent.contains(MAIL) && !sent.contains("3000 6000"), "upstream saw: {sent}");
        assert!(sent.contains("[EMAIL") && sent.contains("[IBAN"), "upstream saw: {sent}");
        assert_eq!(agent.spool.len(), 1);

        // A message that cannot be checked is not sent: the client gets a failure instead.
        ws.send(Message::text("not json")).await.unwrap();
        let refusal: Value = serde_json::from_str(ws.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
        assert_eq!(refusal["type"], "error");
        assert_eq!(refusal["status"], 400);
        assert_eq!(refusal["error"]["code"], "riot_blocked");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    /// A Responses HTTP stand-in: records the request body (and its encoding), answers with its
    /// last input text as SSE deltas of three bytes.
    async fn fake_responses_sse() -> (String, Arc<Mutex<Vec<(Option<String>, Value)>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let recorded = recorded.clone();
                        async move {
                            let encoding = req.headers().get(header::CONTENT_ENCODING).map(|v| v.to_str().unwrap().to_owned());
                            let body: Value = serde_json::from_slice(&req.into_body().collect().await.unwrap().to_bytes()).unwrap();
                            let text = body["input"][0]["content"][0]["text"].as_str().unwrap().to_owned();
                            recorded.lock().unwrap().push((encoding, body));
                            let sse: String = text
                                .as_bytes()
                                .chunks(3)
                                .map(|p| json!({ "type": "response.output_text.delta", "item_id": "m", "content_index": 0, "delta": String::from_utf8_lossy(p) }))
                                .map(|e| format!("event: response.output_text.delta\ndata: {e}\n\n"))
                                .collect();
                            // No content type, as chatgpt.com sends it.
                            Ok::<_, Infallible>(Response::new(full(sse.into())))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                });
            }
        });
        (base, seen)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_zstd_responses_request_over_https_is_redacted() {
        let agent = agent("zstd", &["chatgpt.com"]);
        let (upstream, seen) = fake_responses_sse().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{proxy}")).unwrap())
            .tls_certs_only([reqwest::Certificate::from_der(&root).unwrap()])
            .build()
            .unwrap();
        let text = format!("Mail {MAIL}, IBAN {IBAN}.");
        let create = json!({ "model": "m", "stream": true, "input": [{ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": text }] }] });
        let sse = client
            .post("https://chatgpt.com/backend-api/codex/responses")
            .header("authorization", "Bearer test")
            .header(header::CONTENT_ENCODING, "zstd")
            .body(zstd::encode_all(create.to_string().as_bytes(), 3).unwrap())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let answer: String = sse
            .split("\n\n")
            .filter_map(|e| e.lines().find_map(|l| l.strip_prefix("data: ")))
            .map(|d| serde_json::from_str::<Value>(d).unwrap()["delta"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(answer, text);
        let (encoding, sent) = seen.lock().unwrap()[0].clone();
        assert_eq!(encoding, None, "sent on uncompressed");
        let sent = sent.to_string();
        assert!(!sent.contains(MAIL) && sent.contains("[EMAIL"), "upstream saw: {sent}");

        // An encoding the gateway cannot read is refused, not passed on.
        let refused = client
            .post("https://chatgpt.com/backend-api/codex/responses")
            .header(header::CONTENT_ENCODING, "br")
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
