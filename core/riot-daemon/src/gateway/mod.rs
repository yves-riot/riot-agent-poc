//! The local API gateway: AI API clients (Claude Code, SDKs) point their base URL at it, e.g.
//! `ANTHROPIC_BASE_URL=http://127.0.0.1:7591/anthropic`, and it forwards to the real API over
//! TLS. Requests to a host the policy lists (`api_hosts`) are redacted on the way out and their
//! answers detokenized on the way back; everything else passes through untouched.
//!
//! Three API formats are rewritten, by path: Anthropic Messages ([`anthropic`], JSON and SSE),
//! OpenAI Responses ([`responses`], over a WebSocket ([`websocket`]) or SSE, as Codex and the
//! ChatGPT app use it), and Claude Desktop's conversation service ([`claude_rpc`], protobuf over
//! Connect RPC).
//!
//! No certificate is involved: the client speaks plain HTTP to loopback. Bodies and headers are
//! never logged, they carry prompts and credentials.
//!
//! TLS flows reach it as CONNECTs: from the network extension over a Unix socket next to the
//! daemon's (`flows.sock`, root or the daemon's user only), and for development from any client
//! with `HTTPS_PROXY` on the same TCP port (`RIOT_DEV_PROXY=1`). The route is chosen from the
//! ClientHello's server name: a host the policy lists gets a certificate from the Riot CA
//! ([`ca`]) and its requests take the same path as the base URL's; anything else is tunnelled
//! untouched, the bytes read to decide replayed first.

mod anthropic;
pub mod ca;
mod claude_rpc;
mod connect;
#[cfg(feature = "debug-redaction")]
mod debug_redaction;
mod protobuf;
mod recording;
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
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use riot_detect::{Detection, Engine, Options};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};

use crate::agent::{Agent, Target};
use recording::Recording;

type Body = UnsyncBoxBody<Bytes, std::io::Error>;

/// Path prefix → upstream host. The prefix keeps room for other APIs on the same port.
const UPSTREAMS: &[(&str, &str)] = &[("anthropic", "api.anthropic.com")];
/// Largest request body accepted (Messages requests carry the whole conversation).
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Largest single text redacted: the engine's ceiling for extracted file text. A longer text
/// is not known to be clean, so the request is refused.
const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Connect's per-message compression of a stream, asked for and given.
const CONNECT_ACCEPT_ENCODING: &str = "connect-accept-encoding";
const CONNECT_CONTENT_ENCODING: &str = "connect-content-encoding";
/// How long a client may take to send its ClientHello once its CONNECT is answered.
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
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
    /// Whether the TCP port answers CONNECT (`RIOT_DEV_PROXY=1`).
    tcp_connect: bool,
}

/// Where a request came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// The loopback TCP port: base URL, and CONNECT for development.
    Tcp,
    /// `flows.sock`: the network extension's flows, as CONNECTs.
    Flows,
}

pub async fn serve(agent: Arc<Agent>, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let upstreams = Upstreams::from_env()?;
    let tcp_connect = std::env::var_os("RIOT_DEV_PROXY").is_some_and(|v| v == "1");
    let flows_path = agent.paths.socket.with_file_name("flows.sock");
    let flows = match bind_flows(&flows_path) {
        Ok(listener) => Some(listener),
        Err(e) => {
            tracing::warn!(path = %flows_path.display(), error = %e, "no flow socket: the network extension cannot hand flows over");
            None
        }
    };
    tracing::info!(
        %addr,
        upstream = %upstreams,
        flows = flows.is_some().then(|| flows_path.display().to_string()),
        tcp_connect,
        "gateway listening"
    );
    #[cfg(feature = "debug-redaction")]
    debug_redaction::warn_enabled();
    let gateway = Gateway::new(agent, upstreams, tcp_connect)?;
    if let Some(flows) = flows {
        tokio::spawn(gateway.clone().run_flows(flows));
    }
    gateway.run(listener).await
}

/// Only root (the network extension) and the daemon's own user may hand flows over: the socket
/// is `0600`, and each peer's uid is checked.
fn bind_flows(path: &std::path::Path) -> anyhow::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    // The gateway may start before the server has made the sockets' folder.
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn peer_allowed(stream: &tokio::net::UnixStream) -> bool {
    let uid = stream.peer_cred().map(|c| c.uid());
    // SAFETY: geteuid has no preconditions.
    uid.is_ok_and(|uid| uid == 0 || uid == unsafe { libc::geteuid() })
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
    fn new(agent: Arc<Agent>, upstreams: Upstreams, tcp_connect: bool) -> anyhow::Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Arc::new(Self { agent, client, cache: Mutex::new(Cache::default()), upstreams, tcp_connect }))
    }

    async fn run(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let gateway = self.clone();
            tokio::spawn(async move {
                gateway.serve_entry(TokioIo::new(stream), Entry::Tcp).await;
            });
        }
    }

    async fn run_flows(self: Arc<Self>, listener: UnixListener) {
        loop {
            let stream = match listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => return tracing::error!(error = %e, "flow socket closed"),
            };
            if !peer_allowed(&stream) {
                tracing::warn!("flow socket: a peer that is neither root nor the daemon's user was refused");
                continue;
            }
            let gateway = self.clone();
            tokio::spawn(async move { gateway.serve_entry(TokioIo::new(stream), Entry::Flows).await });
        }
    }

    async fn serve_entry<S>(self: Arc<Self>, io: TokioIo<S>, entry: Entry)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = hyper::service::service_fn(move |req| {
            let gateway = self.clone();
            async move { Ok::<_, Infallible>(gateway.handle(req, entry).await) }
        });
        if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, service).with_upgrades().await {
            tracing::debug!(error = %e, "gateway connection ended");
        }
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>, entry: Entry) -> Response<Body> {
        match (req.method(), entry) {
            (&Method::CONNECT, _) => self.connect(req, entry).await.unwrap_or_else(GatewayError::response),
            (_, Entry::Tcp) => self.handle_request(req, None).await,
            (_, Entry::Flows) => GatewayError::BadRequest("the flow socket only takes CONNECT".into()).response(),
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

    /// A CONNECT, answered at once: the route is chosen from what the client sends next.
    /// `Riot-App` (set by the network extension) names the process, for the log.
    async fn connect(self: Arc<Self>, req: Request<Incoming>, entry: Entry) -> Result<Response<Body>, GatewayError> {
        if entry == Entry::Tcp && !self.tcp_connect {
            return Err(GatewayError::BadRequest("the proxy entry is off (RIOT_DEV_PROXY)".into()));
        }
        let target = req.uri().authority().ok_or_else(|| GatewayError::BadRequest("CONNECT needs host:port".into()))?;
        let (host, port) = (target.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase(), target.port_u16().unwrap_or(443));
        let app = req.headers().get("riot-app").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        tokio::spawn(async move {
            let client = match hyper::upgrade::on(req).await {
                Ok(upgraded) => TokioIo::new(upgraded),
                Err(e) => return tracing::debug!(error = %e, "gateway connect upgrade failed"),
            };
            if let Err(e) = self.route(client, host, port, app).await {
                tracing::debug!(error = %e, "gateway flow ended");
            }
        });
        Ok(Response::new(full(Bytes::new())))
    }

    /// Port 443: the ClientHello's server name (or the CONNECT host without one) decides. A
    /// host the policy lists is decrypted; one the CA cannot cover, or non-TLS traffic to it,
    /// is dropped (fail closed), as it is while parrot has not signed this Mac's intermediate.
    /// Anything else is tunnelled to the CONNECT target.
    async fn route<S>(self: Arc<Self>, client: S, host: String, port: u16, app: String) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if port != 443 {
            tracing::info!(host, port, app, intercept = false, "gateway connect");
            return tunnel(client, &host, port, &[]).await;
        }
        let mut lazy = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), Recording::new(client));
        let hello = tokio::time::timeout(HELLO_TIMEOUT, &mut lazy).await;
        let mut start = match hello {
            Ok(Ok(start)) => start,
            Ok(Err(_)) => {
                anyhow::ensure!(self.agent.api_target(&host).is_none(), "non-TLS traffic to {host}:443 dropped");
                let mut io = lazy.take_io().ok_or_else(|| anyhow::anyhow!("connection lost"))?;
                let sent = io.stop();
                tracing::info!(host, port, app, intercept = false, tls = false, "gateway connect");
                return tunnel(io, &host, port, &sent).await;
            }
            Err(_) => anyhow::bail!("no ClientHello from the client"),
        };
        let name = start.client_hello().server_name().map(str::to_ascii_lowercase).unwrap_or_else(|| host.clone());
        let intercept = self.agent.api_target(&name).is_some();
        tracing::info!(host, name, port, app, intercept, "gateway connect");
        let sent = start.io.stop();
        if !intercept {
            return tunnel(start.io, &host, port, &sent).await;
        }
        let authority = self.agent.authority.read().unwrap().clone();
        let authority = authority.ok_or_else(|| anyhow::anyhow!("no intermediate CA yet: {name} dropped"))?;
        let config = authority.server_config(&name)?;
        let tls = start.into_stream(config).await?;
        self.serve_tls(tls, name.into()).await
    }

    async fn serve_tls<S>(self: Arc<Self>, tls: S, host: Arc<str>) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
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
                #[cfg(feature = "debug-redaction")]
                (Some(target), _) => websocket::Hooks {
                    up: debug_redaction::watched_up(self.agent.engine.clone(), target.options, host, api_path),
                    ..websocket::Hooks::passthrough()
                },
                _ => websocket::Hooks::passthrough(),
            };
            return websocket::relay(req, &url, hooks).await;
        }
        if let (Some(target), Some(rpc)) = (&target, claude_rpc::method(api_path)) {
            let scope = scope(&target.service_id, req.headers());
            return self.claude_rpc(req, &url, host, api_path, rpc, target, scope).await;
        }
        if let Some(target) = target.as_ref().filter(|_| req.method() == Method::GET && claude_rpc::is_file_contents(api_path)) {
            let scope = scope(&target.service_id, req.headers());
            return self.claude_file(req, &url, scope).await;
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
            _ => {
                #[cfg(feature = "debug-redaction")]
                if let Some(target) = &target {
                    let encoding = headers.get(header::CONTENT_ENCODING).cloned();
                    debug_redaction::forwarded_body(&self.agent.engine, &target.options, host, api_path, encoding, body.clone());
                }
                body
            }
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

    /// Claude Desktop's conversation service (`claude_rpc`): the text a `PerformAction` sends
    /// is redacted, every protobuf response detokenized, unary or streamed.
    #[allow(clippy::too_many_arguments)]
    async fn claude_rpc(
        self: &Arc<Self>,
        req: Request<Incoming>,
        url: &str,
        host: &str,
        api_path: &str,
        rpc: &str,
        target: &Target,
        scope: String,
    ) -> Result<Response<Body>, GatewayError> {
        let method = req.method().clone();
        let mut headers = forwarded_headers(req.headers());
        // Responses must come back uncompressed to be detokenized (Connect compresses each
        // message of a stream on its own).
        headers.remove(header::ACCEPT_ENCODING);
        headers.remove(CONNECT_ACCEPT_ENCODING);
        let body = Limited::new(req.into_body(), MAX_REQUEST_BYTES)
            .collect()
            .await
            .map_err(|e| GatewayError::BadRequest(format!("could not read the request body: {e}")))?
            .to_bytes();
        let body = if claude_rpc::sends_text(rpc) {
            let body = decoded(headers.remove(header::CONTENT_ENCODING), body)?;
            self.redact_claude_rpc(body, target, &scope)?
        } else {
            #[cfg(feature = "debug-redaction")]
            debug_redaction::forwarded_body(&self.agent.engine, &target.options, host, api_path, headers.get(header::CONTENT_ENCODING).cloned(), body.clone());
            #[cfg(not(feature = "debug-redaction"))]
            let _ = (host, api_path);
            body
        };

        let upstream = self.client.request(method, url).headers(headers).body(body).send().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
        let status = upstream.status();
        let mut response_headers = forwarded_headers(upstream.headers());
        let content_type = upstream.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let body = if content_type.starts_with("application/connect+proto") {
            let gzip = upstream.headers().get(CONNECT_CONTENT_ENCODING).is_some_and(|v| v == "gzip");
            response_headers.remove(header::CONTENT_LENGTH);
            self.detokenize_connect_stream(upstream, gzip, scope)
        } else if content_type.starts_with("application/proto") {
            let encoding = upstream.headers().get(header::CONTENT_ENCODING).cloned();
            let bytes = upstream.bytes().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
            let engine = self.agent.engine.clone();
            let detokenized = decoded(encoding, bytes.clone())
                .ok()
                .and_then(|plain| tokio::task::block_in_place(|| claude_rpc::detokenize_message(&plain, &mut resolver(&engine, &scope))));
            match detokenized {
                Some(out) => {
                    response_headers.remove(header::CONTENT_ENCODING);
                    response_headers.remove(header::CONTENT_LENGTH);
                    full(Bytes::from(out))
                }
                None => full(bytes),
            }
        } else {
            StreamBody::new(upstream.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other)).boxed_unsync()
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        Ok(response)
    }

    /// An attached file's content, as Claude Desktop previews it: asked for whole and
    /// uncompressed, detokenized when it is text (`text/*`, or no content type and UTF-8).
    /// Anything else passes as it is.
    async fn claude_file(self: &Arc<Self>, req: Request<Incoming>, url: &str, scope: String) -> Result<Response<Body>, GatewayError> {
        let mut headers = forwarded_headers(req.headers());
        // A range of a detokenized file would not match the bytes the server meant.
        for name in [header::RANGE, header::IF_RANGE, header::ACCEPT_ENCODING] {
            headers.remove(name);
        }
        let upstream = self.client.get(url).headers(headers).send().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
        let status = upstream.status();
        let mut response_headers = forwarded_headers(upstream.headers());
        // claude.ai sends a `.txt` with no content type: read as text when it decodes as UTF-8.
        let is_text = upstream.headers().get(header::CONTENT_TYPE).is_none_or(|v| v.to_str().is_ok_and(|t| t.starts_with("text/")));
        let plain = upstream.headers().get(header::CONTENT_ENCODING).is_none();
        let small = upstream.content_length().is_some_and(|n| n <= MAX_TEXT_BYTES as u64);
        let body = if status == StatusCode::OK && is_text && plain && small {
            let bytes = upstream.bytes().await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
            let engine = self.agent.engine.clone();
            let detokenized = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| tokio::task::block_in_place(|| claude_rpc::detokenize_text(text, &mut resolver(&engine, &scope))));
            match detokenized {
                Some(text) => {
                    for name in [header::CONTENT_LENGTH, header::ETAG, header::ACCEPT_RANGES] {
                        response_headers.remove(name);
                    }
                    full(Bytes::from(text))
                }
                None => full(bytes),
            }
        } else {
            StreamBody::new(upstream.bytes_stream().map_ok(Frame::data).map_err(std::io::Error::other)).boxed_unsync()
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        Ok(response)
    }

    /// Redacts a `PerformAction`; reports what it redacted for the first time.
    fn redact_claude_rpc(&self, body: Bytes, target: &Target, scope: &str) -> Result<Bytes, GatewayError> {
        let options = Options { max_bytes: Some(MAX_TEXT_BYTES), ..target.options.clone() };
        let started = Instant::now();
        let mut detections = vec![];
        let out = tokio::task::block_in_place(|| {
            claude_rpc::redact_request(&body, &mut |text| redact_cached(&self.agent.engine, &self.cache, scope, &options, text, &mut detections))
        })?;
        let ms = started.elapsed().as_millis() as u64;
        tracing::info!(api = "ClaudeRpc", ms, bytes = body.len(), new_detections = detections.len(), "gateway redaction");
        if !claude_rpc::has_sent_text(&body) {
            // Content-free: where the strings are, and how long, to find a text the app moved.
            let strings: Vec<String> = protobuf::utf8_paths(&body).iter().take(80).map(|(path, len)| format!("{path}:{len}")).collect();
            tracing::info!(strings = %strings.join(" "), "PerformAction without text at the known paths (path:bytes)");
        }
        if !detections.is_empty() {
            self.agent.report_api_redaction(target, &detections);
        }
        Ok(out.map(Bytes::from).unwrap_or(body))
    }

    /// A Connect stream (`StreamTimeline`), each message detokenized.
    fn detokenize_connect_stream(&self, upstream: reqwest::Response, gzip: bool, scope: String) -> Body {
        let engine = self.agent.engine.clone();
        let state = (upstream.bytes_stream(), connect::EnvelopeRewriter::new(gzip), claude_rpc::TimelineDetokenizer::default());
        let stream = futures_util::stream::unfold(Some(state), move |state| {
            let (engine, scope) = (engine.clone(), scope.clone());
            async move {
                let (mut upstream, mut rewriter, mut timeline) = state?;
                loop {
                    match upstream.next().await {
                        Some(Ok(chunk)) => {
                            let out = tokio::task::block_in_place(|| {
                                let mut resolve = resolver(&engine, &scope);
                                rewriter.push(&chunk, &mut |message| timeline.message(message, &mut resolve))
                            });
                            if !out.is_empty() {
                                return Some((Ok(Frame::data(Bytes::from(out))), Some((upstream, rewriter, timeline))));
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
/// its WebSocket to HTTPS, Claude Code some requests with gzip). Another encoding cannot be
/// checked: the request is refused.
fn decoded(encoding: Option<HeaderValue>, body: Bytes) -> Result<Bytes, GatewayError> {
    use std::io::Read;
    let encoding = encoding.as_ref().and_then(|v| v.to_str().ok()).map(str::to_ascii_lowercase);
    let decoder: Box<dyn Read + '_> = match encoding.as_deref() {
        None | Some("identity") => return Ok(body),
        Some("zstd") => Box::new(zstd::stream::read::Decoder::new(&body[..]).map_err(|e| GatewayError::Blocked(format!("the zstd request body could not be read: {e}")))?),
        Some("gzip" | "x-gzip") => Box::new(flate2::read::GzDecoder::new(&body[..])),
        Some(other) => return Err(GatewayError::Blocked(format!("{other}-compressed request bodies cannot be checked"))),
    };
    let mut out = vec![];
    decoder
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| GatewayError::Blocked(format!("the compressed request body could not be read: {e}")))?;
    if out.len() > MAX_REQUEST_BYTES {
        return Err(GatewayError::Blocked(format!("the request is over {} MiB", MAX_REQUEST_BYTES / 1_048_576)));
    }
    Ok(out.into())
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
    move |token| {
        let value = engine.detokenize(token, scope).ok().filter(|d| d.replaced > 0).map(|d| d.text);
        #[cfg(feature = "debug-redaction")]
        debug_redaction::restored(token, value.as_deref());
        value
    }
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
    #[cfg(feature = "debug-redaction")]
    debug_redaction::sent(engine, scope, &out);
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

/// Connects to the CONNECT target, sends what the client already sent, then pipes both ways.
async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, host: &str, port: u16, sent: &[u8]) -> anyhow::Result<()> {
    let mut server = TcpStream::connect((host, port)).await?;
    server.write_all(sent).await?;
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
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

impl From<protobuf::Malformed> for GatewayError {
    fn from(_: protobuf::Malformed) -> Self {
        Self::Blocked("the request is not the protobuf message expected".into())
    }
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

    #[test]
    fn the_network_extension_learns_the_api_hosts() {
        let agent = agent("hosts", &["API.anthropic.com", "api.anthropic.com", "claude.ai"]);
        assert_eq!(agent.es_config().api_hosts, ["api.anthropic.com", "claude.ai"]);
    }

    #[test]
    fn a_paused_agent_applies_no_policy() {
        let agent = agent("paused", &["api.anthropic.com"]);
        agent.pause(None);
        let config = agent.es_config();
        assert!(config.api_hosts.is_empty() && config.watched.is_empty());
        assert!(agent.api_target("api.anthropic.com").is_none());
        agent.resume();
        assert!(agent.api_target("api.anthropic.com").is_some());
    }

    #[tokio::test]
    async fn a_pause_ends_with_the_process_it_lasts_for() {
        let agent = agent("paused-for", &["api.anthropic.com"]);
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        agent.pause(Some(child.id()));
        tokio::spawn(agent.clone().watch_pause());
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(agent.api_target("api.anthropic.com").is_none(), "paused while the process runs");
        child.kill().unwrap();
        child.wait().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(agent.api_target("api.anthropic.com").is_some(), "resumed once it is gone");
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
        tokio::spawn(Gateway::new(agent, Upstreams::any(upstream), false).unwrap().run(listener));
        url
    }

    /// The gateway with its `HTTPS_PROXY` entry on, and the root its certificates chain to.
    async fn proxy(agent: Arc<Agent>, upstream: String) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>) {
        let (authority, root) = ca::for_tests();
        *agent.authority.write().unwrap() = Some(Arc::new(authority));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(Gateway::new(agent, Upstreams::any(upstream), true).unwrap().run(listener));
        (addr, root)
    }

    /// Sends a raw CONNECT; returns the stream and the response's status line.
    async fn raw_connect(proxy: SocketAddr, target: &str) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let status = send_connect(&mut stream, target).await;
        (stream, status)
    }

    async fn send_connect<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, target: &str) -> String {
        use tokio::io::AsyncReadExt;
        stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nRiot-App: test\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = vec![];
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        head.lines().next().unwrap_or_default().to_owned()
    }

    /// A TLS client that trusts the Riot root only.
    async fn tls_to<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        root: rustls::pki_types::CertificateDer<'static>,
        name: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<S>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await
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
        let (proxy, root) = proxy(agent, upstream).await;
        let (stream, status) = raw_connect(proxy, "example.com:443").await;
        assert!(status.contains(" 200 "), "{status}");
        // No certificate, and no tunnel either: the connection is dropped at the ClientHello.
        assert!(tls_to(stream, root, "example.com").await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_flow_to_an_address_is_routed_by_its_server_name() {
        let agent = agent("flows", &["api.anthropic.com"]);
        let (upstream, seen) = fake_api().await;
        let (authority, root) = ca::for_tests();
        *agent.authority.write().unwrap() = Some(Arc::new(authority));
        let path = agent.paths.data_dir.join("flows.sock");
        let listener = bind_flows(&path).unwrap();
        tokio::spawn(Gateway::new(agent.clone(), Upstreams::any(upstream), false).unwrap().run_flows(listener));

        // The extension knows the destination address, not always its name.
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let status = send_connect(&mut stream, "192.0.2.1:443").await;
        assert!(status.contains(" 200 "), "{status}");
        let tls = tls_to(stream, root, "api.anthropic.com").await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        let body = json!({ "model": "m", "stream": true, "messages": [{ "role": "user", "content": format!("Mail {MAIL}") }] });
        let req = Request::post("/v1/messages")
            .header(header::HOST, "api.anthropic.com")
            .header("x-api-key", "sk-test")
            .body(full(body.to_string().into()))
            .unwrap();
        let response = sender.send_request(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let sse = String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(sse.contains("jea") && !sse.contains("[EMA"), "the answer is detokenized: {sse}");
        let sent = seen.lock().unwrap()[0].to_string();
        assert!(!sent.contains(MAIL) && sent.contains("[EMAIL"), "upstream saw: {sent}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_an_intermediate_the_ai_hosts_are_dropped() {
        let agent = agent("no-intermediate", &["api.anthropic.com"]);
        let (upstream, seen) = fake_api().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        // Not enrolled yet, or waiting for an admin's approval.
        *agent.authority.write().unwrap() = None;
        let (stream, status) = raw_connect(proxy, "api.anthropic.com:443").await;
        assert!(status.contains(" 200 "), "{status}");
        assert!(tls_to(stream, root, "api.anthropic.com").await.is_err());
        assert!(seen.lock().unwrap().is_empty(), "nothing went upstream");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_flow_socket_takes_only_connect() {
        let agent = agent("flows-only", &[]);
        let path = agent.paths.data_dir.join("flows.sock");
        let listener = bind_flows(&path).unwrap();
        tokio::spawn(Gateway::new(agent, Upstreams::default(), false).unwrap().run_flows(listener));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get("/anthropic/v1/models").header(header::HOST, "x").body(full(Bytes::new())).unwrap();
        assert_eq!(sender.send_request(req).await.unwrap().status(), StatusCode::BAD_REQUEST);
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
        let tls = tls_to(tcp, root, "chatgpt.com").await.unwrap();
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
    async fn a_compressed_responses_request_over_https_is_redacted() {
        use std::io::Write;
        let agent = agent("compressed", &["chatgpt.com"]);
        let (upstream, seen) = fake_responses_sse().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{proxy}")).unwrap())
            .tls_certs_only([reqwest::Certificate::from_der(&root).unwrap()])
            .build()
            .unwrap();
        let text = format!("Mail {MAIL}, IBAN {IBAN}.");
        let create = json!({ "model": "m", "stream": true, "input": [{ "type": "message", "role": "user", "content": [{ "type": "input_text", "text": text }] }] });
        let plain = create.to_string();
        let mut gzip = flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
        gzip.write_all(plain.as_bytes()).unwrap();
        for (i, (encoding, body)) in [("zstd", zstd::encode_all(plain.as_bytes(), 3).unwrap()), ("gzip", gzip.finish().unwrap())].into_iter().enumerate() {
            let sse = client
                .post("https://chatgpt.com/backend-api/codex/responses")
                .header("authorization", "Bearer test")
                .header(header::CONTENT_ENCODING, encoding)
                .body(body)
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
            assert_eq!(answer, text, "{encoding}");
            let (sent_encoding, sent) = seen.lock().unwrap()[i].clone();
            assert_eq!(sent_encoding, None, "{encoding}: sent on uncompressed");
            let sent = sent.to_string();
            assert!(!sent.contains(MAIL) && sent.contains("[EMAIL"), "{encoding}: upstream saw: {sent}");
        }

        // An encoding the gateway cannot read is refused, not passed on.
        let refused = client
            .post("https://chatgpt.com/backend-api/codex/responses")
            .header(header::CONTENT_ENCODING, "br")
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    /// A fake `claude.ai` conversation service: records each request, answers `PerformAction`
    /// with an empty message and `StreamTimeline` with the last sent text's token, once plain
    /// and once gzip-compressed.
    async fn fake_claude_rpc() -> (String, Arc<Mutex<Vec<(String, HeaderMap, Bytes)>>>) {
        use connect::tests::{envelope, gzip};
        use protobuf::tests::len_field;
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
                            let path = req.uri().path().to_owned();
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let mut seen = recorded.lock().unwrap();
                            seen.push((path.clone(), headers, body));
                            let mut response = if path.ends_with("/StreamTimeline") {
                                let sent = seen.iter().rev().find(|(p, ..)| p.ends_with("/PerformAction")).map(|(.., b)| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
                                let token = sent.find("[EMAIL_").map(|i| &sent[i..=i + sent[i..].find(']').unwrap()]).unwrap_or("none").to_owned();
                                let text = format!("Ton email : {token}");
                                let block = len_field(1, &len_field(5, &len_field(9, text.as_bytes())));
                                let title = len_field(1, &len_field(2, &len_field(2, format!("Email {token}").as_bytes())));
                                let stream = [envelope(0, &title), envelope(1, &gzip(&block)), envelope(2, b"{}")].concat();
                                let mut response = Response::new(full(stream.into()));
                                response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/connect+proto"));
                                response.headers_mut().insert(CONNECT_CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                                response
                            } else {
                                let mut response = Response::new(full(Bytes::from_static(b"\x30\x01")));
                                response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/proto"));
                                response
                            };
                            *response.status_mut() = StatusCode::OK;
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
                });
            }
        });
        (base, seen)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_claude_desktop_message_is_redacted_and_its_timeline_restored() {
        use protobuf::tests::len_field;
        let agent = agent("claude-rpc", &["claude.ai"]);
        let (upstream, seen) = fake_claude_rpc().await;
        let (proxy, root) = proxy(agent.clone(), upstream).await;
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::https(format!("http://{proxy}")).unwrap())
            .tls_certs_only([reqwest::Certificate::from_der(&root).unwrap()])
            .build()
            .unwrap();
        let rpc = |method: &str| format!("https://claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/{method}");
        let text = format!("Mon email est {MAIL}");
        let attestation = len_field(17, &len_field(1, &[len_field(2, b"user"), len_field(3, &[0xab; 32])].concat()));
        let action = [len_field(1, &attestation), len_field(2, &[len_field(1, b"message-uuid"), len_field(3, text.as_bytes())].concat())].concat();

        let sent = client.post(rpc("PerformAction")).header(header::CONTENT_TYPE, "application/proto").body(action.clone()).send().await.unwrap();
        assert_eq!(sent.status(), StatusCode::OK);
        let upstream_body = seen.lock().unwrap()[0].2.clone();
        let upstream_text = String::from_utf8_lossy(&upstream_body);
        assert!(!upstream_text.contains(MAIL) && upstream_text.contains("Mon email est [EMAIL_"), "upstream saw: {upstream_text}");
        assert!(upstream_body.starts_with(&len_field(1, &attestation)), "the attestation is sent as it was");

        let timeline = client
            .post(rpc("StreamTimeline"))
            .header(header::CONTENT_TYPE, "application/connect+proto")
            .header(CONNECT_ACCEPT_ENCODING, "gzip")
            .body(Vec::new())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert!(seen.lock().unwrap()[1].1.get(CONNECT_ACCEPT_ENCODING).is_none(), "messages are asked for uncompressed");
        let (mut at, mut messages) = (0, vec![]);
        while at < timeline.len() {
            let len = u32::from_be_bytes(timeline[at + 1..at + 5].try_into().unwrap()) as usize;
            messages.push((timeline[at], String::from_utf8_lossy(&timeline[at + 5..at + 5 + len]).into_owned()));
            at += 5 + len;
        }
        assert_eq!(messages.len(), 3);
        assert!(messages[0].1.contains(&format!("Email {MAIL}")), "title: {:?}", messages[0]);
        assert_eq!(messages[1].0, 0, "the restored message is sent on uncompressed");
        assert!(messages[1].1.contains(&format!("Ton email : {MAIL}")), "text: {:?}", messages[1]);
        assert_eq!(messages[2], (2, "{}".to_owned()));

        // A PerformAction that is not protobuf is refused, not passed on.
        let refused = client.post(rpc("PerformAction")).header(header::CONTENT_TYPE, "application/proto").body("not protobuf").send().await.unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
