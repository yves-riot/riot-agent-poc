//! An intercepted connection: TLS ends here, each request is matched against the rules, and
//! everything else goes on to the real host as it came. Responses are streamed back untouched.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, BodyStream, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;

use crate::rules::RuleKind;
use crate::{FileVerdict, Flow, Inspector, Shared, Upload, record, rewrite};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;

/// What the largest API accepts in one request: a body that repeats its conversation, with the
/// files read along the way, grows that far. Beyond it the body is forwarded unread.
const TEXT_CAP: usize = 32 * 1024 * 1024;
/// Above the engine's own 25 MiB limit, so that it is the one to call a file oversized.
const FILE_CAP: usize = 32 * 1024 * 1024;
/// How much of an unmatched body record mode reads to describe it.
const RECORD_CAP: usize = 1024 * 1024;

/// How long a refused upload is still read, so that its sender gets the refusal.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const BLOCKED: &str = r#"{"error":{"type":"blocked_by_riot","message":"Riot blocked this upload."}}"#;

pub(crate) async fn serve<I, S>(shared: Arc<Shared<I>>, flow: Arc<Flow>, io: S)
where
    I: Inspector,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls = match TlsAcceptor::from(shared.tls.clone()).accept(io).await {
        Ok(tls) => tls,
        Err(e) => {
            // Most often the app does not trust the proxy's CA. Nothing was sent either way.
            shared.stats.handshake_failures.fetch_add(1, Relaxed);
            tracing::warn!(host = %flow.host, bundle_id = ?flow.bundle_id, error = %e, "TLS handshake with the app failed");
            return;
        }
    };
    let host = flow.host.clone();
    let service = service_fn(move |req| {
        let (shared, flow) = (shared.clone(), flow.clone());
        async move {
            let response = forward(&shared, &flow, req).await.unwrap_or_else(|e| {
                tracing::warn!(host = %flow.host, error = %e, "could not forward a request");
                full(StatusCode::BAD_GATEWAY, "text/plain", "Riot could not reach the service.")
            });
            Ok::<_, Infallible>(response)
        }
    });
    let served = auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(tls), service).await;
    if let Err(e) = served {
        tracing::debug!(%host, error = %e, "intercepted connection ended");
    }
}

async fn forward<I: Inspector>(shared: &Shared<I>, flow: &Flow, mut req: Request<Incoming>) -> Result<Response<Body>, BoxError> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let url = format!("https://{}:{}{}", flow.host, flow.port, req.uri().path_and_query().map_or("/", |p| p.as_str()));
    let websocket = req.headers().get(header::UPGRADE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let mut headers = request_headers(parts.headers, websocket);

    // As sent: a multipart boundary is case-sensitive. Only the media type is not.
    let content_type = header_str(&headers, header::CONTENT_TYPE).to_owned();
    let mime = content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let declared = header_str(&headers, header::CONTENT_LENGTH).parse::<u64>().ok();
    let encoded = headers.get(header::CONTENT_ENCODING).is_some_and(|v| v != "identity");

    let rules = shared.inspector.rules(flow);
    let rule = rules.as_deref().and_then(|rules| rules.iter().find(|r| r.matches(&flow.host, method.as_str(), &path)));
    let mut shape = None;

    let outgoing = match rule.map(|r| &r.kind) {
        Some(RuleKind::JsonText { .. } | RuleKind::ProtoText { .. }) if encoded => {
            tracing::warn!(host = %flow.host, %path, "compressed request body: forwarded unread");
            reqwest::Body::wrap(body)
        }
        Some(RuleKind::JsonText { text_pointers, file_pointers, history }) => match buffer(body, declared, TEXT_CAP).await? {
            Buffered::Complete(bytes) => {
                if shared.record {
                    shape = record::json_shape(&bytes); // to check the rule's pointers against
                }
                let pointers = rewrite::Pointers { text: text_pointers, files: file_pointers };
                match rewrite::json(&*shared.inspector, flow, pointers, *history, &bytes).await {
                    rewrite::Json::Redacted(redacted) => {
                        shared.stats.rewritten.fetch_add(1, Relaxed);
                        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(redacted.len()));
                        redacted.into()
                    }
                    rewrite::Json::Unchanged => bytes.into(),
                    rewrite::Json::Denied => {
                        shared.stats.blocked.fetch_add(1, Relaxed);
                        if shared.record {
                            tracing::info!(target: "riot_proxy::record", host = %flow.host, %method, %path, shape = shape.as_deref().unwrap_or("-"), "embedded file blocked");
                        }
                        return Ok(full(StatusCode::FORBIDDEN, "application/json", BLOCKED));
                    }
                }
            }
            Buffered::TooLarge(body) => {
                tracing::warn!(host = %flow.host, %path, "request body over the text limit: forwarded unread");
                body
            }
        },
        Some(RuleKind::ProtoText { text_fields }) => match buffer(body, declared, TEXT_CAP).await? {
            Buffered::Complete(bytes) => {
                if shared.record {
                    shape = record::proto_shape(&bytes);
                }
                match rewrite::proto_text(&*shared.inspector, flow, text_fields, &bytes).await {
                    Some(redacted) => {
                        shared.stats.rewritten.fetch_add(1, Relaxed);
                        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(redacted.len()));
                        redacted.into()
                    }
                    None => bytes.into(),
                }
            }
            Buffered::TooLarge(body) => {
                tracing::warn!(host = %flow.host, %path, "request body over the text limit: forwarded unread");
                body
            }
        },
        Some(kind @ (RuleKind::MultipartFile | RuleKind::RawFile)) => {
            // What cannot be read here (compressed, over the limit) is not known to be clean.
            let unreadable = Upload { name: String::new(), mime: mime.clone(), bytes: None };
            let (verdict, body) = match buffer(body, declared, FILE_CAP).await? {
                Buffered::Complete(_) if encoded => (shared.inspector.file(flow, unreadable).await, None),
                Buffered::Complete(bytes) if matches!(kind, RuleKind::MultipartFile) => {
                    (rewrite::multipart_files(&*shared.inspector, flow, &content_type, bytes.clone()).await, Some(bytes))
                }
                Buffered::Complete(bytes) => {
                    let upload = Upload { name: rewrite::raw_file_name(&path, &mime), mime, bytes: Some(bytes.clone()) };
                    (shared.inspector.file(flow, upload).await, Some(bytes))
                }
                Buffered::TooLarge(rest) => {
                    let verdict = shared.inspector.file(flow, unreadable).await;
                    drain(rest).await;
                    (verdict, None)
                }
            };
            match (verdict, body) {
                (FileVerdict::Allow, Some(bytes)) => bytes.into(),
                _ => {
                    shared.stats.blocked.fetch_add(1, Relaxed);
                    if shared.record {
                        tracing::info!(target: "riot_proxy::record", host = %flow.host, %method, %path, %content_type, "upload blocked");
                    }
                    return Ok(full(StatusCode::FORBIDDEN, "application/json", BLOCKED));
                }
            }
        }
        None if shared.record && !websocket && !encoded => {
            // A protobuf body may be a stream that never ends: read only one of a declared size.
            let proto = matches!(mime.as_str(), "application/proto" | "application/connect+proto") && declared.is_some();
            let cap = match mime.as_str() {
                "multipart/form-data" => FILE_CAP,
                "application/json" | "text/plain" => RECORD_CAP,
                _ if proto => RECORD_CAP,
                _ => 0,
            };
            match buffer(body, declared, cap).await? {
                Buffered::Complete(bytes) => {
                    shape = match mime.as_str() {
                        "multipart/form-data" => {
                            rewrite::multipart_parts(&content_type, bytes.clone()).await.ok().map(|parts| record::multipart_shape(&parts))
                        }
                        "application/proto" => record::proto_shape(&bytes),
                        "application/connect+proto" => record::connect_shape(&bytes),
                        _ => record::json_shape(&bytes),
                    };
                    bytes.into()
                }
                Buffered::TooLarge(body) => body,
            }
        }
        None => reqwest::Body::wrap(body),
    };

    let client = if websocket { &shared.http1 } else { &shared.http };
    let upstream = client.request(method.clone(), &url).headers(headers).body(outgoing).send().await?;
    if shared.record {
        tracing::info!(
            target: "riot_proxy::record",
            host = %flow.host,
            %method,
            %path,
            %content_type,
            bytes = declared,
            shape = shape.as_deref().unwrap_or("-"),
            rule = rule.is_some(),
            status = upstream.status().as_u16(),
            response_type = header_str(upstream.headers(), header::CONTENT_TYPE),
            websocket,
        );
    }

    if let Some(client_upgrade) = client_upgrade
        && upstream.status() == StatusCode::SWITCHING_PROTOCOLS
    {
        let mut response = Response::new(empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *response.headers_mut() = upstream.headers().clone();
        tokio::spawn(tunnel(client_upgrade, upstream));
        return Ok(response);
    }

    let mut response: Response<reqwest::Body> = upstream.into();
    *response.version_mut() = Version::HTTP_11;
    for name in [header::CONNECTION, header::TRANSFER_ENCODING, KEEP_ALIVE] {
        response.headers_mut().remove(name);
    }
    // No HTTP/3 advert: QUIC would take the app's next requests around the proxy.
    response.headers_mut().remove(header::ALT_SVC);
    Ok(response.map(|body| body.map_err(BoxError::from).boxed_unsync()))
}

/// A WebSocket (or any upgraded connection): bytes both ways, unread.
async fn tunnel(client: OnUpgrade, upstream: reqwest::Response) {
    let (Ok(client), Ok(mut upstream)) = (client.await, upstream.upgrade().await) else { return };
    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut upstream).await;
}

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

/// The app's headers, minus what belongs to its connection with the proxy.
fn request_headers(mut headers: HeaderMap, websocket: bool) -> HeaderMap {
    // The client writes Host from the URL, and frames the body itself.
    for name in [header::HOST, header::TRANSFER_ENCODING, KEEP_ALIVE, PROXY_CONNECTION] {
        headers.remove(name);
    }
    if !websocket {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
    // HTTP/2 sends one header per cookie; HTTP/1.1 wants them in one.
    let cookies: Vec<&[u8]> = headers.get_all(header::COOKIE).iter().map(HeaderValue::as_bytes).collect();
    if cookies.len() > 1
        && let Ok(joined) = HeaderValue::from_bytes(&cookies.join(&b"; "[..]))
    {
        headers.insert(header::COOKIE, joined);
    }
    headers
}

fn header_str(headers: &HeaderMap, name: HeaderName) -> &str {
    headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default()
}

enum Buffered {
    Complete(Bytes),
    /// More than the cap: what was read followed by the rest, to forward as a stream.
    TooLarge(reqwest::Body),
}

/// Reads and drops the rest of a request about to be refused. A client still writing its body
/// when the connection closes sees a broken pipe, and never the answer.
async fn drain(mut body: reqwest::Body) {
    let rest = async { while let Some(Ok(_)) = body.frame().await {} };
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, rest).await;
}

/// Reads a whole request body when it fits in `cap` bytes.
async fn buffer(mut body: Incoming, declared: Option<u64>, cap: usize) -> Result<Buffered, hyper::Error> {
    if declared.is_some_and(|len| len > cap as u64) {
        return Ok(Buffered::TooLarge(reqwest::Body::wrap(body)));
    }
    let mut read = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let Ok(data) = frame?.into_data() else { continue }; // trailers: none on a request we read
        read.extend_from_slice(&data);
        if read.len() > cap {
            let head = stream::iter([Ok(Frame::data(read.freeze()))]);
            return Ok(Buffered::TooLarge(reqwest::Body::wrap(StreamBody::new(head.chain(BodyStream::new(body))))));
        }
    }
    Ok(Buffered::Complete(read.freeze()))
}

fn empty() -> Body {
    Full::new(Bytes::new()).map_err(|never| match never {}).boxed_unsync()
}

fn full(status: StatusCode, content_type: &'static str, body: &'static str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())).map_err(|never| match never {}).boxed_unsync());
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
