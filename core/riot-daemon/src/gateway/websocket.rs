//! WebSocket upgrades on a connection the gateway handles. The handshake is relayed to the
//! upstream nearly as is, so the upstream's `Sec-WebSocket-Accept` answers the client's own key;
//! only `Sec-WebSocket-Extensions` is dropped, so no compression is negotiated and every message
//! can be read. Messages are then pumped both ways through `Hooks`.
//!
//! Ping and pong stay on their own side: each end's pings are answered by the gateway.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

use super::{Body, GatewayError, forwarded_headers, full};

/// Largest handshake error body relayed back to the client.
const MAX_ERROR_BYTES: usize = 64 * 1024;
/// Largest message: a request carries the whole conversation.
const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

/// Client → API: the message to send, or `Err` with a message for the client instead.
pub type UpHook = Box<dyn FnMut(&str) -> Result<String, String> + Send>;
/// API → client: the messages to send in place of one.
pub type DownHook = Box<dyn FnMut(&str) -> Vec<String> + Send>;

/// What happens to each text message. `up` returns the message to send to the API, or `Err`
/// with a message for the client instead: the request is not sent (fail closed). `down` returns
/// the messages to send to the client in place of one from the API.
pub struct Hooks {
    pub up: UpHook,
    pub down: DownHook,
    /// Whether binary messages from the client may pass: they cannot be checked.
    pub allow_binary_up: bool,
}

impl Hooks {
    pub fn passthrough() -> Self {
        Self { up: Box::new(|m| Ok(m.to_owned())), down: Box::new(|m| vec![m.to_owned()]), allow_binary_up: true }
    }
}

pub fn is_upgrade(req: &Request<Incoming>) -> bool {
    let has = |name: header::HeaderName, token: &str| {
        req.headers().get_all(name).iter().filter_map(|v| v.to_str().ok()).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    has(header::UPGRADE, "websocket") && has(header::CONNECTION, "upgrade")
}

/// Opens the upstream WebSocket at `url` (`http(s)://host[:port]/path?query`) with the client's
/// handshake, then answers the client with the upstream's answer. A refused handshake (`401`,
/// `426`…) is relayed as is.
pub async fn relay(req: Request<Incoming>, url: &str, hooks: Hooks) -> Result<Response<Body>, GatewayError> {
    let url = reqwest::Url::parse(url).map_err(|e| GatewayError::BadRequest(e.to_string()))?;
    let host = url.host_str().ok_or_else(|| GatewayError::BadRequest("no upstream host".into()))?.to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };

    let mut headers = forwarded_headers(req.headers());
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    let authority = if url.port().is_some() { format!("{host}:{port}") } else { host.clone() };
    headers.insert(header::HOST, HeaderValue::from_str(&authority).map_err(|e| GatewayError::BadRequest(e.to_string()))?);
    let mut upstream_req = Request::get(path).body(Empty::<bytes::Bytes>::new()).map_err(|e| GatewayError::BadRequest(e.to_string()))?;
    *upstream_req.headers_mut() = headers;

    let mut upstream = send(upstream_req, &host, port, url.scheme() == "https").await.map_err(|e| GatewayError::Upstream(e.to_string()))?;
    if upstream.status() != StatusCode::SWITCHING_PROTOCOLS {
        let status = upstream.status();
        let headers = forwarded_headers(upstream.headers());
        let body = Limited::new(upstream.into_body(), MAX_ERROR_BYTES).collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        let mut response = Response::new(full(body));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }

    let mut answer = Response::new(full(bytes::Bytes::new()));
    *answer.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *answer.headers_mut() = handshake_headers(upstream.headers());
    let upstream_upgrade = hyper::upgrade::on(&mut upstream);
    let client_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let (client, server) = match tokio::try_join!(client_upgrade, upstream_upgrade) {
            Ok(pair) => pair,
            Err(e) => return tracing::debug!(error = %e, "websocket upgrade failed"),
        };
        let config = Some(WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_BYTES)));
        let client = WebSocketStream::from_raw_socket(TokioIo::new(client), Role::Server, config).await;
        let server = WebSocketStream::from_raw_socket(TokioIo::new(server), Role::Client, config).await;
        if let Err(e) = pump(client, server, hooks).await {
            tracing::debug!(error = %e, "websocket ended");
        }
    });
    Ok(answer)
}

/// The upstream's 101 headers, for the client: the hop-by-hop ones the handshake needs are
/// put back.
fn handshake_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut headers = forwarded_headers(upstream);
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers
}

async fn send(req: Request<Empty<bytes::Bytes>>, host: &str, port: u16, tls: bool) -> anyhow::Result<Response<Incoming>> {
    let tcp = TcpStream::connect((host, port)).await?;
    if !tls {
        return handshake(TokioIo::new(tcp), req).await;
    }
    use rustls_platform_verifier::ConfigVerifierExt;
    let mut config = rustls::ClientConfig::with_platform_verifier()?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await?;
    handshake(TokioIo::new(stream), req).await
}

async fn handshake<T>(io: TokioIo<T>, req: Request<Empty<bytes::Bytes>>) -> anyhow::Result<Response<Incoming>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "websocket upstream connection ended");
        }
    });
    Ok(sender.send_request(req).await?)
}

async fn pump<C, S>(client: WebSocketStream<C>, server: WebSocketStream<S>, mut hooks: Hooks) -> anyhow::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut to_client, mut from_client) = client.split();
    let (mut to_server, mut from_server) = server.split();
    loop {
        tokio::select! {
            message = from_client.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    // The hooks may call the engine, which blocks.
                    match tokio::task::block_in_place(|| (hooks.up)(text.as_str())) {
                        Ok(out) => to_server.send(Message::text(out)).await?,
                        Err(refusal) => to_client.send(Message::text(refusal)).await?,
                    }
                }
                Some(Ok(Message::Binary(data))) if hooks.allow_binary_up => to_server.send(Message::Binary(data)).await?,
                Some(Ok(Message::Binary(_))) => tracing::warn!("websocket binary message from the client dropped: it cannot be checked"),
                Some(Ok(Message::Close(frame))) => {
                    let _ = to_server.send(Message::Close(frame)).await;
                    return Ok(());
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            },
            message = from_server.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    for out in tokio::task::block_in_place(|| (hooks.down)(text.as_str())) {
                        to_client.send(Message::text(out)).await?;
                    }
                }
                Some(Ok(Message::Binary(data))) => to_client.send(Message::Binary(data)).await?,
                Some(Ok(Message::Close(frame))) => {
                    let _ = to_client.send(Message::Close(frame)).await;
                    return Ok(());
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            },
        }
    }
}
