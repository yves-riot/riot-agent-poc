//! The local API gateway: AI API clients (Claude Code, SDKs) point their base URL at it, e.g.
//! `ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic`, and it forwards to the real API over
//! TLS. Requests to a host the policy lists (`api_hosts`) are redacted on the way out and their
//! answers detokenized on the way back; everything else passes through untouched.
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
mod tokens;

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
    /// Replaces `https://<host>`: a local server in tests, or `RIOT_GATEWAY_UPSTREAM` to put an
    /// inspecting proxy between the gateway and the API.
    upstream_base: Option<String>,
    /// Set when the `HTTPS_PROXY` entry is on.
    authority: Option<Arc<Authority>>,
}

pub async fn serve(agent: Arc<Agent>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let upstream = upstream_override()?;
    let authority = match std::env::var_os("RIOT_DEV_PROXY").is_some_and(|v| v == "1") {
        true => Some(Arc::new(Authority::load_or_create(&agent.paths.data_dir)?)),
        false => None,
    };
    tracing::info!(
        %addr,
        upstream = upstream.as_deref().unwrap_or("https://<api host>"),
        proxy_ca = authority.as_ref().map(|a| a.cert_path().display().to_string()),
        "gateway listening"
    );
    Gateway::new(agent, upstream, authority)?.run(listener).await
}

/// `RIOT_GATEWAY_UPSTREAM`, for development: e.g. `http://127.0.0.1:18081`, a mitmproxy in
/// reverse mode, to see exactly what leaves the gateway. Loopback only: the gateway forwards the
/// client's credentials, and they must not be sent anywhere else.
fn upstream_override() -> anyhow::Result<Option<String>> {
    let Ok(base) = std::env::var("RIOT_GATEWAY_UPSTREAM") else { return Ok(None) };
    let url = reqwest::Url::parse(&base)?;
    let host = url.host_str().unwrap_or_default().trim_start_matches('[').trim_end_matches(']');
    let loopback = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    anyhow::ensure!(loopback, "RIOT_GATEWAY_UPSTREAM must be a loopback URL, not {base}");
    Ok(Some(base.trim_end_matches('/').to_owned()))
}

impl Gateway {
    fn new(agent: Arc<Agent>, upstream_base: Option<String>, authority: Option<Arc<Authority>>) -> anyhow::Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Arc::new(Self { agent, client, cache: Mutex::new(Cache::default()), upstream_base, authority }))
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
    async fn handle_request(&self, req: Request<Incoming>, origin: Option<Arc<str>>) -> Response<Body> {
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
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await?;
        Ok(())
    }

    /// The base URL entry: `/anthropic/v1/messages` → `api.anthropic.com`, `/v1/messages`.
    async fn forward(&self, req: Request<Incoming>) -> Result<Response<Body>, GatewayError> {
        let (prefix, rest) = req.uri().path().trim_start_matches('/').split_once('/').ok_or(GatewayError::NotFound)?;
        let host = UPSTREAMS.iter().find(|(p, _)| *p == prefix).map(|(_, h)| *h).ok_or(GatewayError::NotFound)?;
        let api_path = format!("/{rest}");
        self.relay(req, host, &api_path).await
    }

    /// Sends a request on to `host`, redacting it on the way out and detokenizing the answer
    /// when the policy protects that host.
    async fn relay(&self, req: Request<Incoming>, host: &str, api_path: &str) -> Result<Response<Body>, GatewayError> {
        let base = self.upstream_base.clone().unwrap_or_else(|| format!("https://{host}"));
        let url = match req.uri().query() {
            Some(q) => format!("{base}{api_path}?{q}"),
            None => format!("{base}{api_path}"),
        };

        let target = self.agent.api_target(host);
        let rewrite = target.is_some() && req.method() == Method::POST && anthropic::is_messages_path(api_path);
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
                if headers.get(header::CONTENT_ENCODING).is_some_and(|v| v != "identity") {
                    return Err(GatewayError::Blocked("compressed request bodies cannot be checked".into()));
                }
                // Responses must come back uncompressed to be detokenized.
                headers.remove(header::ACCEPT_ENCODING);
                self.redact(body, target, scope).await?
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
            Some(scope) if rewrite && !encoded && content_type.starts_with("text/event-stream") => {
                response_headers.remove(header::CONTENT_LENGTH);
                self.detokenize_stream(upstream, scope)
            }
            Some(scope) if rewrite && !encoded && content_type.starts_with("application/json") => {
                response_headers.remove(header::CONTENT_LENGTH);
                let bytes = upstream.bytes().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
                full(self.detokenize_json(bytes, scope).await)
            }
            _ => StreamBody::new(upstream.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other)).boxed_unsync(),
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        Ok(response)
    }

    /// Redacts a Messages request; reports what it redacted for the first time.
    async fn redact(&self, body: Bytes, target: &Target, scope: &str) -> Result<Bytes, GatewayError> {
        let mut json: Value =
            serde_json::from_slice(&body).map_err(|e| GatewayError::BadRequest(format!("the request is not JSON: {e}")))?;
        let engine = self.agent.engine.clone();
        let options = Options { max_bytes: Some(MAX_TEXT_BYTES), ..target.options.clone() };
        let scope = scope.to_owned();
        let started = Instant::now();
        // The engine call blocks on the JS thread.
        let (json, detections) = tokio::task::block_in_place(|| {
            let mut detections = vec![];
            let mut redact =
                |text: &str| redact_cached(&engine, &self.cache, &scope, &options, text, &mut detections);
            anthropic::redact_request(&mut json, &mut redact).map(|()| (json, detections))
        })?;
        let ms = started.elapsed().as_millis() as u64;
        tracing::info!(ms, bytes = body.len(), new_detections = detections.len(), "gateway redaction");
        if !detections.is_empty() {
            self.agent.report_api_redaction(target, &detections);
        }
        Ok(serde_json::to_vec(&json).map_err(|e| GatewayError::Blocked(e.to_string()))?.into())
    }

    fn detokenize_stream(&self, upstream: reqwest::Response, scope: String) -> Body {
        let engine = self.agent.engine.clone();
        let state = (upstream.bytes_stream(), anthropic::SseRewriter::default());
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

    async fn detokenize_json(&self, bytes: Bytes, scope: String) -> Bytes {
        let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) else { return bytes };
        let engine = self.agent.engine.clone();
        tokio::task::block_in_place(|| anthropic::detokenize_response(&mut json, &mut resolver(&engine, &scope)));
        serde_json::to_vec(&json).map(Bytes::from).unwrap_or(bytes)
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
    /// An error in the Messages API's shape, so the client shows the message.
    fn response(self) -> Response<Body> {
        let (status, kind, message) = match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found_error", "unknown API prefix (use /anthropic)".to_owned()),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request_error", m),
            Self::Blocked(m) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Riot could not check this request for sensitive data, so it was not sent: {m}"),
            ),
            Self::Upstream(m) => (StatusCode::BAD_GATEWAY, "api_error", format!("Riot gateway could not reach the API: {m}")),
        };
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
        tokio::spawn(Gateway::new(agent, Some(upstream), None).unwrap().run(listener));
        url
    }

    /// The gateway with its `HTTPS_PROXY` entry on, and the root its certificates chain to.
    async fn proxy(agent: Arc<Agent>, upstream: String) -> (SocketAddr, reqwest::Certificate) {
        let authority = Arc::new(Authority::load_or_create(&agent.paths.data_dir).unwrap());
        let root = reqwest::Certificate::from_der(authority.root()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Gateway::new(agent, Some(upstream), Some(authority)).unwrap().run(listener));
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
            .tls_certs_only([root])
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
}
