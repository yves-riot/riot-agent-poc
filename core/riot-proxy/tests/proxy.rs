//! The proxy end to end: an HTTP client that trusts the proxy's CA, the proxy, and a local TLS
//! server standing in for the AI service, which echoes what reached it.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use http::{Request, Response, StatusCode, header};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use riot_proxy::{FileVerdict, Flow, Inspector, Proxy, ProxyConfig, Rule, Upload, Upstream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const AI: &str = "ai.test";

// ---------- the service ----------

struct Service {
    addr: SocketAddr,
    /// Its self-signed certificate (DER), also the root that vouches for it.
    cert: Vec<u8>,
    hits: Arc<AtomicUsize>,
}

async fn service(host: &str) -> Service {
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![host.to_owned()]).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, hits) = (acceptor.clone(), counter.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let service = service_fn(move |req| echo(req, hits.clone()));
                let _ = auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(TokioIo::new(tls), service).await;
            });
        }
    });
    Service { addr, cert: cert.der().to_vec(), hits }
}

type Body = UnsyncBoxBody<Bytes, Infallible>;

async fn echo(mut req: Request<Incoming>, hits: Arc<AtomicUsize>) -> Result<Response<Body>, Infallible> {
    hits.fetch_add(1, SeqCst);
    match req.uri().path() {
        // Two chunks, the second one late: a proxy that buffers delivers them together.
        "/sse" => {
            let chunks = stream::iter(["one\n", "two\n"]).then(|chunk| async move {
                if chunk == "two\n" {
                    tokio::time::sleep(Duration::from_millis(600)).await;
                }
                Ok::<_, Infallible>(Frame::data(Bytes::from(chunk)))
            });
            let mut response = Response::new(StreamBody::new(chunks).boxed_unsync());
            response.headers_mut().insert(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
            Ok(response)
        }
        // An upgraded connection that sends back what it receives.
        "/ws" => {
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let mut io = TokioIo::new(upgrade.await.unwrap());
                let mut buf = [0u8; 64];
                while let Ok(read) = io.read(&mut buf).await {
                    if read == 0 || io.write_all(&buf[..read]).await.is_err() {
                        break;
                    }
                }
            });
            let mut response = Response::new(Full::new(Bytes::new()).boxed_unsync());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            response.headers_mut().insert(header::CONNECTION, "upgrade".parse().unwrap());
            response.headers_mut().insert(header::UPGRADE, "websocket".parse().unwrap());
            Ok(response)
        }
        _ => {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            let header = |name: header::HeaderName| parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
            let seen = json!({
                "method": parts.method.as_str(),
                "path": parts.uri.path(),
                "query": parts.uri.query(),
                "version": format!("{:?}", parts.version),
                "host": header(header::HOST).or_else(|| parts.uri.authority().map(|a| a.to_string())),
                "content_length": header(header::CONTENT_LENGTH),
                "content_type": header(header::CONTENT_TYPE),
                "cookie": header(header::COOKIE),
                "custom": header(header::HeaderName::from_static("x-custom")),
                "body": String::from_utf8_lossy(&body),
                "bytes": body.len(),
            });
            let mut response = Response::new(Full::new(Bytes::from(seen.to_string())).boxed_unsync());
            response.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
            response.headers_mut().insert(header::ALT_SVC, "h3=\":443\"; ma=86400".parse().unwrap());
            Ok(response)
        }
    }
}

// ---------- the daemon's side ----------

/// Protects `ai.test`: `SECRET` becomes `[X_1]` in text, and a file holding it is denied.
struct Fake {
    rules: Arc<[Rule]>,
    allow_files: AtomicBool,
    uploads: Mutex<Vec<(String, String, Option<usize>)>>,
    flows: Mutex<Vec<Flow>>,
}

impl Fake {
    fn new() -> Arc<Self> {
        let rules: Vec<Rule> = serde_json::from_value(json!([
            { "host": AI, "method": "POST", "path": "/chat/*/completion", "kind": "json_text", "text_pointers": ["/prompt"] },
            { "host": AI, "method": "POST", "path": "/rpc/Send", "kind": "proto_text", "text_fields": ["2.3"] },
            { "host": AI, "method": "POST", "path": "/upload", "kind": "multipart_file" },
            { "host": AI, "method": "PUT", "path": "/blob/**", "kind": "raw_file" },
        ]))
        .unwrap();
        Arc::new(Self { rules: rules.into(), allow_files: AtomicBool::new(false), uploads: Mutex::default(), flows: Mutex::default() })
    }
}

impl Inspector for Fake {
    fn rules(&self, flow: &Flow) -> Option<Arc<[Rule]>> {
        self.flows.lock().unwrap().push(flow.clone());
        (flow.host == AI).then(|| self.rules.clone())
    }

    async fn text(&self, _: &Flow, texts: Vec<String>, _: bool) -> Vec<Option<String>> {
        texts.into_iter().map(|t| t.contains("SECRET").then(|| t.replace("SECRET", "[X_1]"))).collect()
    }

    async fn file(&self, _: &Flow, upload: Upload) -> FileVerdict {
        let sensitive = upload.bytes.as_ref().is_none_or(|b| b.windows(6).any(|w| w == b"SECRET"));
        self.uploads.lock().unwrap().push((upload.name, upload.mime, upload.bytes.map(|b| b.len())));
        if sensitive && !self.allow_files.load(SeqCst) { FileVerdict::Deny } else { FileVerdict::Allow }
    }
}

// ---------- the app's side ----------

struct Bench {
    proxy: Proxy<Fake>,
    fake: Arc<Fake>,
    service: Service,
}

async fn bench(record: bool) -> Bench {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let ca_dir = std::env::temp_dir().join(format!("riot-proxy-{}-{}", std::process::id(), NEXT.fetch_add(1, SeqCst)));
    let _ = std::fs::remove_dir_all(&ca_dir);
    let service = service(AI).await;
    let fake = Fake::new();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ca_dir,
        record,
        upstream: Upstream { resolve: vec![(AI.into(), service.addr)], roots: vec![service.cert.clone()] },
    };
    let proxy = Proxy::start(config, fake.clone()).await.unwrap();
    Bench { proxy, fake, service }
}

impl Bench {
    /// A client that goes through the proxy and trusts its CA, as a configured app does.
    fn client(&self, http1_only: bool) -> reqwest::Client {
        let ca = reqwest::Certificate::from_pem(&std::fs::read(self.proxy.ca_cert()).unwrap()).unwrap();
        let mut builder = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy.addr())).unwrap())
            .tls_certs_only([ca]);
        if http1_only {
            builder = builder.http1_only();
        }
        builder.build().unwrap()
    }

    fn url(&self, path: &str) -> String {
        format!("https://{AI}:{}{path}", self.service.addr.port())
    }
}

async fn seen(response: reqwest::Response) -> Value {
    assert_eq!(response.status(), 200);
    response.json().await.unwrap()
}

// ---------- tests ----------

#[tokio::test]
async fn redacts_the_text_of_a_matched_request_over_http1_and_http2() {
    let bench = bench(false).await;
    for (http1_only, version) in [(true, http::Version::HTTP_11), (false, http::Version::HTTP_2)] {
        let response = bench
            .client(http1_only)
            .post(bench.url("/chat/c-1/completion?stream=1"))
            .header("x-custom", "kept")
            .json(&json!({ "prompt": "my SECRET", "id": "SECRET-id", "n": 1 }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.version(), version);
        assert!(response.headers().get(header::ALT_SVC).is_none(), "HTTP/3 must not be advertised");
        let seen = seen(response).await;
        assert_eq!(seen["body"], r#"{"prompt":"my [X_1]","id":"SECRET-id","n":1}"#);
        assert_eq!(seen["content_length"], seen["bytes"].to_string());
        assert_eq!(seen["query"], "stream=1");
        assert_eq!(seen["custom"], "kept");
        assert_eq!(seen["host"], format!("{AI}:{}", bench.service.addr.port()));
        assert_eq!(seen["version"], "HTTP/2.0", "the proxy speaks HTTP/2 to a host that offers it");
    }
    let stats = bench.proxy.stats();
    assert_eq!((stats.intercepted, stats.rewritten, stats.relayed, stats.blocked), (2, 2, 0, 0));
}

#[tokio::test]
async fn redacts_the_text_of_a_protobuf_request() {
    let bench = bench(true).await;
    // { 1: "c-1", 2: { 3: <text> } }
    let message = |text: &str| {
        let inner = [&[0x1a, text.len() as u8], text.as_bytes()].concat();
        [&[0x0a, 3], &b"c-1"[..], &[0x12, inner.len() as u8], &inner].concat()
    };
    let response = bench
        .client(false)
        .post(bench.url("/rpc/Send"))
        .header(header::CONTENT_TYPE, "application/proto")
        .body(message("my SECRET"))
        .send()
        .await
        .unwrap();
    let seen = seen(response).await;
    assert_eq!(seen["body"].as_str().unwrap().as_bytes(), message("my [X_1]"));
    assert_eq!(seen["content_length"], seen["bytes"].to_string());
    assert_eq!(bench.proxy.stats().rewritten, 1);
}

#[tokio::test]
async fn forwards_as_it_is_what_no_rule_matches() {
    let bench = bench(true).await; // record mode reads these bodies to describe them
    let client = bench.client(false);

    let body = r#"{"prompt": "my SECRET",  "spaced": true}"#;
    let request = client.post(bench.url("/other")).header(header::CONTENT_TYPE, "application/json").body(body);
    let seen_post = seen(request.send().await.unwrap()).await;
    assert_eq!(seen_post["body"], body, "byte for byte");

    // A matched request with nothing to redact keeps its bytes too.
    let body = r#"{ "prompt": "nothing" }"#;
    let request = client.post(bench.url("/chat/c-1/completion")).header(header::CONTENT_TYPE, "application/json").body(body);
    assert_eq!(seen(request.send().await.unwrap()).await["body"], body);

    let request = client.get(bench.url("/history?page=2")).header(header::COOKIE, "a=1; b=2");
    let seen_get = seen(request.send().await.unwrap()).await;
    assert_eq!((&seen_get["method"], &seen_get["query"], &seen_get["cookie"]), (&json!("GET"), &json!("page=2"), &json!("a=1; b=2")));
    assert_eq!(bench.proxy.stats().rewritten, 0);
}

#[tokio::test]
async fn gates_uploads() {
    let bench = bench(false).await;
    let client = bench.client(false);
    let form = |content: &'static str| {
        let file = reqwest::multipart::Part::bytes(content.as_bytes()).file_name("notes.txt").mime_str("text/plain").unwrap();
        reqwest::multipart::Form::new().text("purpose", "SECRET purpose").part("file", file)
    };

    let denied = client.post(bench.url("/upload")).multipart(form("a SECRET inside")).send().await.unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(denied.json::<Value>().await.unwrap()["error"]["type"], "blocked_by_riot");
    assert_eq!(bench.service.hits.load(SeqCst), 0, "a denied upload never reaches the service");
    // Only the file part was scanned, not the form's text field.
    assert_eq!(*bench.fake.uploads.lock().unwrap(), [("notes.txt".to_owned(), "text/plain".to_owned(), Some(15))]);

    let clean = seen(client.post(bench.url("/upload")).multipart(form("nothing inside")).send().await.unwrap()).await;
    assert!(clean["body"].as_str().unwrap().contains("nothing inside"));

    let raw = client.put(bench.url("/blob/1f/report.txt")).header(header::CONTENT_TYPE, "text/plain").body("SECRET").send().await.unwrap();
    assert_eq!(raw.status(), 403);
    assert_eq!(bench.fake.uploads.lock().unwrap().last().unwrap().0, "report.txt");

    // A boundary with capitals, as curl and browsers write them.
    let body = "--AbC123\r\nContent-Disposition: form-data; name=\"file\"; filename=\"iban.txt\"\r\n\r\nSECRET\r\n--AbC123--\r\n";
    let request = client.post(bench.url("/upload")).header(header::CONTENT_TYPE, "Multipart/Form-Data; boundary=AbC123").body(body);
    assert_eq!(request.send().await.unwrap().status(), 403);
    assert_eq!(bench.fake.uploads.lock().unwrap().last().unwrap().0, "iban.txt", "read, not denied as unreadable");

    // The user's "send anyway": the same upload now goes through, whole.
    bench.fake.allow_files.store(true, SeqCst);
    let allowed = seen(client.post(bench.url("/upload")).multipart(form("a SECRET inside")).send().await.unwrap()).await;
    assert!(allowed["body"].as_str().unwrap().contains("a SECRET inside"));
    assert!(allowed["content_type"].as_str().unwrap().starts_with("multipart/form-data; boundary="));
    assert_eq!(bench.proxy.stats().blocked, 3);
}

#[tokio::test]
async fn an_upload_too_large_to_read_is_denied() {
    let bench = bench(false).await;
    bench.fake.allow_files.store(false, SeqCst);
    let big = vec![b'a'; 33 * 1024 * 1024];
    let response = bench.client(true).put(bench.url("/blob/big.txt")).body(big).send().await.unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(bench.fake.uploads.lock().unwrap().last().unwrap().2, None);
    assert_eq!(bench.service.hits.load(SeqCst), 0);
}

#[tokio::test]
async fn streams_responses_without_buffering_them() {
    let bench = bench(false).await;
    for http1_only in [true, false] {
        let mut response = bench.client(http1_only).get(bench.url("/sse")).send().await.unwrap();
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/event-stream");
        assert_eq!(response.chunk().await.unwrap().unwrap(), "one\n");
        let first = Instant::now();
        assert_eq!(response.chunk().await.unwrap().unwrap(), "two\n");
        assert!(first.elapsed() > Duration::from_millis(300), "the first chunk waited for the second");
    }
}

#[tokio::test]
async fn tunnels_upgraded_connections() {
    let bench = bench(false).await;
    let request = bench.client(true).get(bench.url("/ws")).header(header::CONNECTION, "upgrade").header(header::UPGRADE, "websocket");
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut socket = response.upgrade().await.unwrap();
    socket.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
}

/// A raw `CONNECT`, as the network extension sends it: destination by address, source named.
async fn connect(proxy: SocketAddr, to: SocketAddr, bundle_id: &str) -> TcpStream {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {to} HTTP/1.1\r\nX-Riot-Bundle-Id: {bundle_id}\r\nX-Riot-Uid: 501\r\n\r\n").as_bytes()).await.unwrap();
    let mut reply = [0u8; 39];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..], b"HTTP/1.1 200 Connection Established\r\n\r\n");
    tcp
}

fn connector(root: &[u8]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn relays_other_hosts_without_decrypting_them() {
    let bench = bench(false).await;
    let other = service("other.test").await;
    let tcp = connect(bench.proxy.addr(), other.addr, "com.example.app").await;
    // Trusting only the service's own certificate: the handshake succeeds only if the proxy
    // did not put itself in the middle.
    let mut tls = connector(&other.cert).connect("other.test".try_into().unwrap(), tcp).await.unwrap();
    tls.write_all(b"GET /hello HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200") && response.contains(r#""path":"/hello""#), "{response}");

    let stats = bench.proxy.stats();
    assert_eq!((stats.relayed, stats.intercepted), (1, 0));
    let flows = bench.fake.flows.lock().unwrap();
    assert_eq!(
        *flows,
        [Flow { host: "other.test".into(), port: other.addr.port(), bundle_id: Some("com.example.app".into()), uid: Some(501), pid: None }]
    );
}

#[tokio::test]
async fn an_app_that_does_not_trust_the_ca_sends_nothing() {
    let bench = bench(false).await;
    let tcp = connect(bench.proxy.addr(), bench.service.addr, "com.example.app").await;
    // The app expects the service's certificate and gets the proxy's leaf.
    assert!(connector(&bench.service.cert).connect(AI.try_into().unwrap(), tcp).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(bench.proxy.stats().handshake_failures, 1);
    assert_eq!(bench.service.hits.load(SeqCst), 0);
}
