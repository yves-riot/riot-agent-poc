//! The Riot agent's local proxy: what the AI apps send is checked where it leaves the machine.
//!
//! ```text
//! AI app ──▶ network extension ──CONNECT──▶ riot-proxy
//!                                              ├─ other host      relayed, still encrypted
//!                                              └─ protected host  TLS ends here (device CA)
//!                                                    ├─ a rule matches  text redacted / upload gated
//!                                                    └─ anything else   forwarded as it is
//! ```
//!
//! The proxy holds no policy: an [`Inspector`] (the daemon) says which hosts are protected,
//! which requests to look into ([`Rule`]), and what to do with their text and files.

mod ca;
mod listener;
mod mitm;
mod proto;
mod record;
mod rewrite;
mod rules;
mod sni;

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

pub use bytes::Bytes;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub use ca::Ca;
pub use rules::{Rule, RuleKind, host_matches};

/// One connection of an app to a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// The TLS server name the app asked for.
    pub host: String,
    pub port: u16,
    /// The app, as the network extension names it. Absent for a connection that came straight
    /// to the proxy.
    pub bundle_id: Option<String>,
    pub uid: Option<u32>,
    pub pid: Option<u32>,
}

/// A file on its way to an AI service.
#[derive(Debug, Clone)]
pub struct Upload {
    pub name: String,
    pub mime: String,
    /// `None` when the proxy could not read it (too large, compressed, broken envelope).
    pub bytes: Option<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileVerdict {
    Allow,
    /// The upload is answered with a 403 and never reaches the service.
    Deny,
}

/// The decisions the proxy asks for. Implemented by the daemon; calls come from many
/// connections at once.
pub trait Inspector: Send + Sync + 'static {
    /// The rules for this flow's host. `None` when the flow is not protected: it is then
    /// relayed without being decrypted. An empty list still intercepts (and, in record mode,
    /// describes what goes through).
    fn rules(&self, flow: &Flow) -> Option<Arc<[Rule]>>;

    /// The text of one request. Returns, for each string, its redacted form, or `None` to
    /// leave it as it is. `history` is the rule's: the request repeats earlier ones.
    fn text(&self, flow: &Flow, texts: Vec<String>, history: bool) -> impl Future<Output = Vec<Option<String>>> + Send;

    fn file(&self, flow: &Flow, upload: Upload) -> impl Future<Output = FileVerdict> + Send;
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Loopback address to listen on; port 0 picks a free one.
    pub listen: SocketAddr,
    /// Where the device CA lives (`ca.pem`, `ca.key`).
    pub ca_dir: PathBuf,
    /// Log the shape of every request to a protected host (see `record.rs`).
    pub record: bool,
    pub upstream: Upstream,
}

/// How the proxy reaches the real hosts. The defaults are the system's DNS and trust store;
/// tests point a host at a local server.
#[derive(Debug, Clone, Default)]
pub struct Upstream {
    pub resolve: Vec<(String, SocketAddr)>,
    /// DER certificates to trust instead of the system's roots.
    pub roots: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("certificate authority: {0}")]
    Ca(String),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Client(#[from] reqwest::Error),
}

impl From<rcgen::Error> for Error {
    fn from(e: rcgen::Error) -> Self {
        Error::Ca(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Connections whose TLS ended at the proxy.
    pub intercepted: u64,
    /// Connections relayed without being decrypted.
    pub relayed: u64,
    /// Requests whose text was redacted.
    pub rewritten: u64,
    /// Uploads refused.
    pub blocked: u64,
    /// Intercepted connections the app gave up on, typically for not trusting the CA.
    pub handshake_failures: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    intercepted: AtomicU64,
    relayed: AtomicU64,
    rewritten: AtomicU64,
    blocked: AtomicU64,
    handshake_failures: AtomicU64,
}

pub(crate) struct Shared<I> {
    inspector: Arc<I>,
    record: bool,
    tls: Arc<rustls::ServerConfig>,
    /// Negotiates HTTP/2 or HTTP/1.1 with the host, as the app would.
    http: reqwest::Client,
    /// For WebSocket handshakes, which are HTTP/1.1 upgrades.
    http1: reqwest::Client,
    stats: Arc<Counters>,
}

/// The proxy's counters, readable without holding the proxy itself.
#[derive(Clone)]
pub struct StatsHandle(Arc<Counters>);

impl StatsHandle {
    pub fn get(&self) -> Stats {
        let c = &self.0;
        Stats {
            intercepted: c.intercepted.load(Relaxed),
            relayed: c.relayed.load(Relaxed),
            rewritten: c.rewritten.load(Relaxed),
            blocked: c.blocked.load(Relaxed),
            handshake_failures: c.handshake_failures.load(Relaxed),
        }
    }
}

/// A running proxy. Dropping it stops the listener; connections in flight end on their own.
pub struct Proxy<I> {
    addr: SocketAddr,
    ca_cert: PathBuf,
    shared: Arc<Shared<I>>,
    task: JoinHandle<()>,
}

impl<I: Inspector> Proxy<I> {
    pub async fn start(config: ProxyConfig, inspector: Arc<I>) -> Result<Self, Error> {
        let ca = Arc::new(Ca::load_or_create(&config.ca_dir)?);
        let shared = Arc::new(Shared {
            inspector,
            record: config.record,
            tls: ca.server_config()?,
            http: client(&config.upstream, false)?,
            http1: client(&config.upstream, true)?,
            stats: Arc::default(),
        });
        let listener = TcpListener::bind(config.listen).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(listener::run(shared.clone(), listener));
        tracing::info!(%addr, ca = %ca.cert_path().display(), record = config.record, "proxy listening");
        Ok(Self { addr, ca_cert: ca.cert_path().to_owned(), shared, task })
    }
}

impl<I> Proxy<I> {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The CA certificate the apps must trust (PEM).
    pub fn ca_cert(&self) -> &Path {
        &self.ca_cert
    }

    pub fn stats(&self) -> Stats {
        self.stats_handle().get()
    }

    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle(self.shared.stats.clone())
    }
}

impl<I> Drop for Proxy<I> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The client for the real hosts. It adds nothing of its own: no proxy from the environment,
/// no redirect followed, no decompression, so the service sees the app's request.
fn client(upstream: &Upstream, http1_only: bool) -> Result<reqwest::Client, Error> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .connect_timeout(Duration::from_secs(15));
    if http1_only {
        builder = builder.http1_only();
    }
    for (host, addr) in &upstream.resolve {
        builder = builder.resolve(host, *addr);
    }
    if !upstream.roots.is_empty() {
        let roots = upstream.roots.iter().map(|der| reqwest::Certificate::from_der(der)).collect::<Result<Vec<_>, _>>()?;
        builder = builder.tls_certs_only(roots);
    }
    Ok(builder.build()?)
}
