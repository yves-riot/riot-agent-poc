//! The daemon's state and the decisions it makes for its clients. Every policy decision lives
//! here: the menu bar app, the system extensions and the proxy only ask and apply.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use riot_api::{AgentConfig, FileSnapshot, MonitoredService, SensitiveDataReport, SnapshotDetection, TextSnapshot};
use riot_detect::{Detection, Engine, FileScan, Options};
use riot_ipc::{
    DetokenizeResult, EsConfig, Event, IpcError, NetApp, NetConfig, PopupState, PopupView, ProxyStatus, RecentEvent, RedactTextResult,
    ReportPasteResult, ScanFileResult, Status, TargetApp, TypeCount, WatchedApp,
};
use riot_proxy::{FileVerdict, Flow, Inspector, Rule, StatsHandle, Upload, host_matches};
use sha2::Digest;
use tokio::sync::{Notify, broadcast};
use uuid::Uuid;

use crate::config::{ManagedSettings, Paths};
use crate::device::Enrollment;
use crate::reports::Spool;

const PLATFORM: &str = "macos";
const BYPASS_TTL: Duration = Duration::from_secs(60);
/// An upload waits for its scan, but not forever: past this the file goes through, as for the
/// ES extension's deadline. An AI app must stay usable.
const UPLOAD_SCAN_DEADLINE: Duration = Duration::from_secs(20);
/// One upload attempt opens the same file several times; notify the user once.
const BLOCK_NOTIFY_DEBOUNCE: Duration = Duration::from_secs(5);
const RECENT_EVENTS: usize = 20;
const SCAN_CACHE: usize = 512;
/// Max entries in `State::redactions`, one per redacted clipboard, kept so `report_paste`
/// can report each paste of it.
const MAX_REDACTIONS: usize = 200;
/// Max entries in `State::pastes`, one per reported paste, kept so `report_override` can
/// re-report it as "paste the original".
const MAX_PASTES: usize = 200;
/// Max entries in `TextMemo`: a long conversation holds a few thousand strings.
const TEXT_MEMO: usize = 8192;

#[derive(Default)]
pub struct State {
    pub settings: Option<ManagedSettings>,
    pub enrollment: Option<Enrollment>,
    pub config: Option<AgentConfig>,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub installed: HashMap<String, bool>,
    recent: VecDeque<RecentEvent>,
    redactions: HashMap<String, Redaction>,
    /// Paste id (the report's session) → its `redactions` key.
    pastes: HashMap<String, (String, DateTime<Utc>)>,
    blocked_files: HashMap<String, FileIdentity>,
    bypasses: Vec<(FileIdentity, Instant)>,
    /// "Allow my next message": token scope (user and app) → until when.
    text_bypasses: HashMap<String, Instant>,
    scan_cache: HashMap<FileIdentity, (ScanFileResult, Instant)>,
}

struct Redaction {
    /// Whose text it was, and in which app (see `scope`).
    scope: String,
    service_id: String,
    occurred_at: DateTime<Utc>,
    counts: Vec<SnapshotDetection>,
    app_name: String,
    types: Vec<TypeCount>,
}

/// What was decided for the texts of requests that repeat their conversation (a rule with
/// `history`): each later request carries them again, and must get the same answer without
/// another scan, event or report. Keyed by `memo_key`; the oldest entries go first.
#[derive(Default)]
struct TextMemo {
    /// The redacted text, or `None` for a text that goes out as written.
    decisions: HashMap<[u8; 32], Option<String>>,
    order: VecDeque<[u8; 32]>,
}

impl TextMemo {
    fn insert(&mut self, key: [u8; 32], decision: Option<String>) {
        if self.decisions.insert(key, decision).is_none() {
            self.order.push_back(key);
        }
        if self.order.len() > TEXT_MEMO
            && let Some(oldest) = self.order.pop_front()
        {
            self.decisions.remove(&oldest);
        }
    }
}

/// A text under a token scope and a policy: a decision does not outlive a change of either.
fn memo_key(scope: &str, options: &Options, text: &str) -> [u8; 32] {
    let mut hash = sha2::Sha256::new();
    for part in [scope, &serde_json::to_string(options).unwrap_or_default()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.update(text);
    hash.finalize().into()
}

/// Same file, same content: the scan cache and the "send anyway" grant are keyed on this.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum FileIdentity {
    /// A file on disk, as the ES extension sees it opened.
    OnDisk { dev: u64, ino: u64, mtime_ns: i128, size: u64 },
    /// An upload seen by the proxy: it has no path, its content names it.
    Upload { sha256: [u8; 32] },
}

impl FileIdentity {
    fn of(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path)?;
        Ok(Self::OnDisk { dev: m.dev(), ino: m.ino(), mtime_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128, size: m.size() })
    }

    fn of_upload(bytes: &[u8]) -> Self {
        Self::Upload { sha256: sha2::Sha256::digest(bytes).into() }
    }
}

/// A file about to reach an AI app, from either path.
struct Candidate {
    identity: FileIdentity,
    name: String,
    /// The extension's `fileKey`, for the report.
    key: String,
    bundle_id: String,
}

/// The running proxy, as `status` and the network extension need it.
pub struct ProxyInfo {
    pub addr: SocketAddr,
    pub ca_cert: PathBuf,
    pub record: bool,
    pub stats: StatsHandle,
}

pub struct Agent {
    pub paths: Paths,
    pub engine: Engine,
    pub spool: Spool,
    pub state: RwLock<State>,
    pub events: broadcast::Sender<Event>,
    pub refresh: Notify,
    pub reports_pending: Notify,
    pub version: &'static str,
    /// Set once the proxy listens (`main`).
    pub proxy: OnceLock<ProxyInfo>,
    /// Serialises scans so concurrent opens of one file are scanned once.
    scan_lock: tokio::sync::Mutex<()>,
    last_block_notice: Mutex<HashMap<FileIdentity, Instant>>,
    /// One request's text at a time: a client sends a new message in several requests at
    /// once, and the later ones must find the first one's decisions in `text_memo`.
    text_lock: tokio::sync::Mutex<()>,
    text_memo: Mutex<TextMemo>,
}

struct Target {
    service_id: String,
    app_name: String,
    options: Options,
    allow_bypass: bool,
}

pub fn bad_request(message: impl Into<String>) -> IpcError {
    IpcError { code: "badRequest".into(), message: message.into() }
}

pub fn internal(message: impl ToString) -> IpcError {
    IpcError { code: "internal".into(), message: message.to_string() }
}

impl Agent {
    pub fn new(paths: Paths, engine: Engine) -> anyhow::Result<Self> {
        let spool = Spool::new(&paths.data_dir)?;
        Ok(Self {
            paths,
            engine,
            spool,
            state: RwLock::new(State::default()),
            events: broadcast::channel(64).0,
            refresh: Notify::new(),
            reports_pending: Notify::new(),
            version: env!("CARGO_PKG_VERSION"),
            proxy: OnceLock::new(),
            scan_lock: tokio::sync::Mutex::new(()),
            last_block_notice: Mutex::new(HashMap::new()),
            text_lock: tokio::sync::Mutex::new(()),
            text_memo: Mutex::default(),
        }
        .loaded())
    }

    fn loaded(self) -> Self {
        self.state.write().unwrap().enrollment = Enrollment::load(&self.paths.data_dir);
        self
    }

    /// The service a frontmost app belongs to, with the policy that applies, when the agent is
    /// active and the app is one of the policy's desktop apps.
    fn target(&self, bundle_id: &str) -> Option<Target> {
        let state = self.state.read().unwrap();
        let policy = state.config.as_ref()?.active_policy()?;
        let service = policy.services.iter().find(|s| {
            s.desktop_apps.iter().any(|a| a.platform == PLATFORM && a.bundle_id.as_deref() == Some(bundle_id))
        })?;
        let categories: BTreeMap<String, bool> =
            policy.data_types.iter().map(|d| (d.data_type.clone(), d.enabled)).collect();
        Some(Target {
            service_id: service.service_id.clone(),
            app_name: service.display_name.clone(),
            options: Options { categories: Some(categories), max_bytes: None },
            allow_bypass: policy.allow_bypass_redaction,
        })
    }

    pub fn target_apps(&self) -> Vec<TargetApp> {
        let state = self.state.read().unwrap();
        let Some(policy) = state.config.as_ref().and_then(|c| c.active_policy()) else { return vec![] };
        policy
            .services
            .iter()
            .flat_map(|s| {
                s.desktop_apps.iter().filter(|a| a.platform == PLATFORM).filter_map(|a| {
                    let bundle_id = a.bundle_id.clone()?;
                    Some(TargetApp {
                        service_id: s.service_id.clone(),
                        display_name: s.display_name.clone(),
                        installed: state.installed.get(&bundle_id).copied().unwrap_or(false),
                        bundle_id,
                    })
                })
            })
            .collect()
    }

    pub fn es_config(&self) -> EsConfig {
        let state = self.state.read().unwrap();
        let watched = state
            .config
            .as_ref()
            .and_then(|c| c.active_policy())
            .into_iter()
            .flat_map(|p| p.services.iter())
            .flat_map(|s| s.desktop_apps.iter())
            .filter(|a| a.platform == PLATFORM && !a.executable_prefixes.is_empty())
            .filter_map(|a| {
                Some(WatchedApp {
                    bundle_id: a.bundle_id.clone()?,
                    team_id: a.team_id.clone(),
                    executable_prefixes: a.executable_prefixes.clone(),
                })
            })
            .collect();
        // The formats `scanFile` understands (riot-detect / sonar-detection extractors).
        let extensions = ["pdf", "docx", "xlsx", "csv", "txt"].map(String::from).to_vec();
        EsConfig { watched, extensions }
    }

    // ---------- text ----------

    pub async fn redact_text(&self, uid: u32, text: String, bundle_id: String) -> Result<RedactTextResult, IpcError> {
        let skipped = |allow_bypass| RedactTextResult {
            action: "skipped".into(),
            text: None,
            types: vec![],
            event_id: None,
            allow_bypass,
        };
        let Some(target) = self.target(&bundle_id) else { return Ok(skipped(false)) };

        let engine = self.engine.clone();
        let scope = scope(uid, &bundle_id);
        let options = target.options.clone();
        let redact_scope = scope.clone();
        let outcome = tokio::task::spawn_blocking(move || engine.redact(&text, &redact_scope, &options)).await;
        let outcome = match outcome {
            Ok(Ok(outcome)) => outcome,
            // As the extension does for a paste: an engine failure leaves the text as it is.
            Ok(Err(e)) => {
                tracing::error!(error = %e, "redaction failed; clipboard left untouched");
                return Ok(RedactTextResult { action: "error".into(), ..skipped(target.allow_bypass) });
            }
            Err(e) => return Err(internal(e)),
        };
        if outcome.detections.is_empty() {
            return Ok(RedactTextResult { action: "clean".into(), ..skipped(target.allow_bypass) });
        }

        // Not reported yet: the clipboard is read ahead of a paste that may never come.
        // `report_paste` reports when the redacted text is actually pasted.
        let types = type_counts(&outcome.detections);
        let event_id = Uuid::new_v4();
        {
            let mut state = self.state.write().unwrap();
            state.redactions.insert(
                event_id.to_string(),
                Redaction {
                    scope,
                    service_id: target.service_id,
                    occurred_at: Utc::now(),
                    counts: snapshot_counts(&outcome.counts),
                    app_name: target.app_name.clone(),
                    types: types.clone(),
                },
            );
            trim_redactions(&mut state);
        }
        Ok(RedactTextResult {
            action: "redacted".into(),
            text: Some(outcome.text),
            types,
            event_id: Some(event_id.to_string()),
            allow_bypass: target.allow_bypass,
        })
    }

    pub async fn detokenize(&self, uid: u32, text: String, bundle_id: String) -> Result<DetokenizeResult, IpcError> {
        let engine = self.engine.clone();
        let scope = scope(uid, &bundle_id);
        let out = tokio::task::spawn_blocking(move || engine.detokenize(&text, &scope))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        Ok(DetokenizeResult { text: out.text, replaced: out.replaced })
    }

    /// The redacted text of `event_id` was pasted: one report per paste, as the extension's
    /// paste handler, each with its own session.
    pub fn report_paste(&self, event_id: &str) -> Result<ReportPasteResult, IpcError> {
        let paste_id = Uuid::new_v4();
        let now = Utc::now();
        let mut state = self.state.write().unwrap();
        let event = state.redactions.get(event_id).ok_or_else(|| bad_request("unknown event"))?;
        let report = text_report(paste_id, &event.service_id, now, event.counts.clone(), true);
        let (app, types) = (event.app_name.clone(), event.types.clone());
        state.pastes.insert(paste_id.to_string(), (event_id.to_owned(), now));
        if state.pastes.len() > MAX_PASTES {
            let oldest = state.pastes.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| k.clone());
            oldest.map(|k| state.pastes.remove(&k));
        }
        push_recent(&mut state, paste_id.to_string(), "textRedacted", &app, &types);
        drop(state);
        self.queue_report(report);
        let _ = self.events.send(Event::StateChanged);
        Ok(ReportPasteResult { paste_id: paste_id.to_string() })
    }

    /// "Paste the original": the paste's report again, now `redacted: false` (parrot upserts).
    pub fn report_override(&self, paste_id: &str) -> Result<(), IpcError> {
        let mut state = self.state.write().unwrap();
        if !state.config.as_ref().and_then(|c| c.active_policy()).is_some_and(|p| p.allow_bypass_redaction) {
            return Err(IpcError { code: "forbidden".into(), message: "bypass not allowed by policy".into() });
        }
        let (event_id, pasted_at) = state.pastes.get(paste_id).cloned().ok_or_else(|| bad_request("unknown paste"))?;
        let event = state.redactions.get(&event_id).ok_or_else(|| bad_request("unknown event"))?;
        let session = paste_id.parse().map_err(|_| bad_request("bad paste id"))?;
        let report = text_report(session, &event.service_id, pasted_at, event.counts.clone(), false);
        let (app, types) = (event.app_name.clone(), event.types.clone());
        push_recent(&mut state, paste_id.to_owned(), "originalPasted", &app, &types);
        drop(state);
        self.queue_report(report);
        let _ = self.events.send(Event::StateChanged);
        Ok(())
    }

    // ---------- files ----------

    /// A file one of `bundle_id`'s processes is opening (ES extension).
    pub async fn scan_file(&self, path: String, bundle_id: String, deadline_ms: Option<u64>) -> ScanFileResult {
        let Some(target) = self.target(&bundle_id) else { return allow("notTarget") };
        let on_disk = Path::new(&path);
        let Ok(identity) = FileIdentity::of(on_disk) else { return allow("unsupported") };
        let FileIdentity::OnDisk { mtime_ns, size, .. } = identity else { unreachable!() };
        let name = on_disk.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let key = file_key(&name, size, (mtime_ns / 1_000_000) as i64, "");
        let deadline = deadline_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let file = Candidate { identity, name, key, bundle_id };
        self.decide_file(target, file, move |engine, options| engine.scan_path(Path::new(&path), options, deadline)).await
    }

    /// A file in a request one of `bundle_id`'s processes is sending (proxy).
    async fn scan_upload(&self, bundle_id: String, upload: Upload) -> ScanFileResult {
        let Some(target) = self.target(&bundle_id) else { return allow("notTarget") };
        let Upload { name, mime, bytes } = upload;
        let Some(bytes) = bytes else {
            // The proxy could not read it. Fail closed, as for a file the engine cannot read.
            let file = Candidate { identity: FileIdentity::of_upload(name.as_bytes()), name, key: String::new(), bundle_id };
            let result = deny("error");
            self.notify_blocked(&file, &target, &result);
            return result;
        };
        let key = file_key(&name, bytes.len() as u64, 0, &mime);
        let file = Candidate { identity: FileIdentity::of_upload(&bytes), name: name.clone(), key, bundle_id };
        let deadline = Some(Instant::now() + UPLOAD_SCAN_DEADLINE);
        self.decide_file(target, file, move |engine, options| engine.scan_bytes(&name, &mime, bytes.to_vec(), options, deadline)).await
    }

    /// The verdict on a file, whichever way it travels: a standing "send anyway", a cached
    /// verdict, or a scan. A denial is reported and shown to the user.
    async fn decide_file<F>(&self, target: Target, file: Candidate, scan: F) -> ScanFileResult
    where
        F: FnOnce(&Engine, &Options) -> riot_detect::Result<FileScan> + Send + 'static,
    {
        if self.bypassed(&file.identity) {
            return allow("bypass");
        }
        let _guard = self.scan_lock.lock().await;
        // Its own statement: an `if let` would hold this read guard through the block, and
        // `notify_blocked` takes the write lock (a deadlock on every cached deny).
        let cached = self.state.read().unwrap().scan_cache.get(&file.identity).cloned();
        if let Some((cached, _)) = cached {
            if cached.decision == "deny" {
                self.notify_blocked(&file, &target, &cached);
            }
            return cached;
        }

        let engine = self.engine.clone();
        let options = target.options.clone();
        let scanned = tokio::task::spawn_blocking(move || scan(&engine, &options)).await;

        let result = match scanned {
            Ok(Ok(FileScan::Scanned { detections, format, counts })) if !detections.is_empty() => {
                let event_id = Uuid::new_v4();
                let types = type_counts(&detections);
                self.queue_report(SensitiveDataReport {
                    session_id: event_id,
                    service_id: target.service_id.clone(),
                    occurred_at: Utc::now(),
                    authorization_status: None,
                    text: None,
                    files: Some(vec![FileSnapshot { key: file.key.clone(), format, detections: snapshot_counts(&counts) }]),
                });
                ScanFileResult { decision: "deny".into(), reason: "detections".into(), types, event_id: Some(event_id.to_string()) }
            }
            Ok(Ok(FileScan::Scanned { .. })) => allow("clean"),
            Ok(Ok(FileScan::Unsupported { .. })) => allow("unsupported"),
            // Fail closed, as the extension: what could not be read is not known to be clean.
            Ok(Ok(FileScan::Oversized { .. })) | Ok(Ok(FileScan::Error { .. })) => deny("error"),
            // Out of time: never make the AI app unusable; the file goes through.
            Ok(Err(riot_detect::Error::Timeout)) => return allow("timeout"),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "file scan failed");
                deny("error")
            }
            Err(e) => {
                tracing::error!(error = %e, "file scan task failed");
                return allow("timeout");
            }
        };

        {
            let mut state = self.state.write().unwrap();
            if state.scan_cache.len() >= SCAN_CACHE {
                let oldest = state.scan_cache.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k);
                oldest.map(|k| state.scan_cache.remove(&k));
            }
            state.scan_cache.insert(file.identity, (result.clone(), Instant::now()));
        }
        if result.decision == "deny" {
            self.notify_blocked(&file, &target, &result);
        }
        result
    }

    fn notify_blocked(&self, file: &Candidate, target: &Target, result: &ScanFileResult) {
        {
            let mut notices = self.last_block_notice.lock().unwrap();
            if notices.get(&file.identity).is_some_and(|at| at.elapsed() < BLOCK_NOTIFY_DEBOUNCE) {
                return;
            }
            notices.insert(file.identity, Instant::now());
        }
        let Some(event_id) = result.event_id.clone() else { return };
        {
            let mut state = self.state.write().unwrap();
            state.blocked_files.insert(event_id.clone(), file.identity);
            push_recent(&mut state, event_id.clone(), "fileBlocked", &target.app_name, &result.types);
        }
        let _ = self.events.send(Event::FileBlocked {
            event_id,
            file_name: file.name.clone(),
            bundle_id: file.bundle_id.clone(),
            app_name: target.app_name.clone(),
            types: result.types.clone(),
            // An unreadable file is never bypassable: there is nothing to vouch for.
            allow_bypass: target.allow_bypass && result.reason == "detections",
        });
    }

    fn bypassed(&self, identity: &FileIdentity) -> bool {
        let mut state = self.state.write().unwrap();
        state.bypasses.retain(|(_, until)| *until > Instant::now());
        state.bypasses.iter().any(|(id, _)| id == identity)
    }

    pub fn grant_file_bypass(&self, event_id: &str) -> Result<(), IpcError> {
        let mut state = self.state.write().unwrap();
        if !state.config.as_ref().and_then(|c| c.active_policy()).is_some_and(|p| p.allow_bypass_redaction) {
            return Err(IpcError { code: "forbidden".into(), message: "bypass not allowed by policy".into() });
        }
        let identity = *state.blocked_files.get(event_id).ok_or_else(|| bad_request("unknown event"))?;
        state.bypasses.push((identity, Instant::now() + BYPASS_TTL));
        let recent = state.recent.iter().find(|e| e.event_id == event_id).cloned();
        if let Some(e) = recent {
            push_recent(&mut state, event_id.to_owned(), "fileAllowedByUser", &e.app_name, &e.types);
        }
        Ok(())
    }

    // ---------- network (the proxy's Inspector, below) ----------

    /// The app a flow belongs to and the rules for its host, when both are protected.
    fn protected(&self, flow: &Flow) -> Option<(String, Arc<[Rule]>)> {
        let state = self.state.read().unwrap();
        let policy = state.config.as_ref()?.active_policy()?;
        let (service, rules) = policy.services.iter().find_map(|service| {
            let rules = network_rules(service);
            let owned = service.domain.as_deref().is_some_and(|d| host_matches(d, &flow.host))
                || rules.iter().any(|r| host_matches(&r.host, &flow.host));
            owned.then_some((service, rules))
        })?;
        let app_of = |s: &MonitoredService| s.desktop_apps.iter().filter(|a| a.platform == PLATFORM).find_map(|a| a.bundle_id.clone());
        let bundle_id = match &flow.bundle_id {
            // Named by the network extension: a protected app, or one of its helpers
            // (`com.anthropic.claudefordesktop.helper`).
            Some(source) => policy.services.iter().filter_map(app_of).find(|id| {
                source == id || source.strip_prefix(id.as_str()).is_some_and(|rest| rest.starts_with('.'))
            })?,
            // Straight to the proxy (development): the desktop app of the host's service.
            None => app_of(service)?,
        };
        Some((bundle_id, rules.into()))
    }

    pub fn net_config(&self) -> NetConfig {
        let state = self.state.read().unwrap();
        let apps = state
            .config
            .as_ref()
            .and_then(|c| c.active_policy())
            .into_iter()
            .flat_map(|p| p.services.iter())
            .flat_map(|s| s.desktop_apps.iter())
            .filter(|a| a.platform == PLATFORM)
            .filter_map(|a| Some(NetApp { bundle_id: a.bundle_id.clone()?, team_id: a.team_id.clone() }))
            .collect();
        NetConfig { proxy_port: self.proxy.get().map(|p| p.addr.port()), apps }
    }

    /// The text of one outgoing request. Unlike a clipboard read, this is a message being
    /// sent: it is reported at once. With `history` the request repeats earlier ones: only the
    /// texts not seen before are scanned and reported, the others get their earlier decision.
    async fn redact_request(&self, flow: &Flow, texts: Vec<String>, history: bool) -> Vec<Option<String>> {
        let unchanged = vec![None; texts.len()];
        let Some((bundle_id, _)) = self.protected(flow) else { return unchanged };
        let Some(target) = self.target(&bundle_id) else { return unchanged };
        // SAFETY: getuid cannot fail.
        let scope = scope(flow.uid.unwrap_or_else(|| unsafe { libc::getuid() }), &bundle_id);
        let _turn = self.text_lock.lock().await;
        let bypass = self.state.read().unwrap().text_bypasses.get(&scope).is_some_and(|until| *until > Instant::now());

        let keys: Vec<Option<[u8; 32]>> = texts.iter().map(|t| history.then(|| memo_key(&scope, &target.options, t))).collect();
        let mut replacements = unchanged;
        let mut fresh = vec![];
        {
            let memo = self.text_memo.lock().unwrap();
            for (i, text) in texts.into_iter().enumerate() {
                match keys[i].and_then(|key| memo.decisions.get(&key)) {
                    Some(decision) => replacements[i] = decision.clone(),
                    None => fresh.push((i, text)),
                }
            }
        }
        if fresh.is_empty() {
            return replacements;
        }

        let engine = self.engine.clone();
        let (options, redact_scope) = (target.options.clone(), scope.clone());
        let work = tokio::task::spawn_blocking(move || {
            let (mut decisions, mut detections, mut counts) = (vec![], vec![], vec![]);
            for (i, text) in &fresh {
                // With a bypass the text goes out as written, but what it held is still reported.
                let outcome = if bypass {
                    engine.detect(text, &options).map(|o| (None, o.detections, o.counts))
                } else {
                    engine.redact(text, &redact_scope, &options).map(|o| (Some(o.text), o.detections, o.counts))
                };
                match outcome {
                    Ok((text, found, count)) => {
                        decisions.push((*i, text.filter(|_| !found.is_empty())));
                        detections.extend(found);
                        counts.extend(count);
                    }
                    // As for a paste: an engine failure leaves the text as it is. It is not
                    // remembered, so the next request tries again.
                    Err(e) => tracing::error!(error = %e, "redaction failed; request text left untouched"),
                }
            }
            (decisions, detections, counts)
        });
        // The texts already decided keep their decision even if this scan is lost.
        let Ok((decisions, detections, counts)) = work.await else { return replacements };
        {
            let mut memo = self.text_memo.lock().unwrap();
            for (i, decision) in decisions {
                if let Some(key) = keys[i] {
                    memo.insert(key, decision.clone());
                }
                replacements[i] = decision;
            }
        }
        if detections.is_empty() {
            return replacements;
        }

        let event_id = Uuid::new_v4();
        let types = type_counts(&detections);
        let counts = merged_counts(&counts);
        let now = Utc::now();
        {
            let mut state = self.state.write().unwrap();
            if bypass {
                state.text_bypasses.remove(&scope); // one message, not one minute of them
                push_recent(&mut state, event_id.to_string(), "originalSent", &target.app_name, &types);
            } else {
                push_recent(&mut state, event_id.to_string(), "messageRedacted", &target.app_name, &types);
                let redaction = Redaction {
                    scope,
                    service_id: target.service_id.clone(),
                    occurred_at: now,
                    counts: counts.clone(),
                    app_name: target.app_name.clone(),
                    types: types.clone(),
                };
                state.redactions.insert(event_id.to_string(), redaction);
                trim_redactions(&mut state);
            }
        }
        self.queue_report(text_report(event_id, &target.service_id, now, counts, !bypass));
        if !bypass {
            let _ = self.events.send(Event::TextRedacted {
                event_id: event_id.to_string(),
                bundle_id,
                app_name: target.app_name,
                types,
                allow_bypass: target.allow_bypass,
            });
        }
        let _ = self.events.send(Event::StateChanged);
        replacements
    }

    /// "Allow my next message": the next message with sensitive data from the same user and app
    /// goes out as written, if it leaves within the TTL.
    pub fn grant_text_bypass(&self, event_id: &str) -> Result<(), IpcError> {
        let mut state = self.state.write().unwrap();
        if !state.config.as_ref().and_then(|c| c.active_policy()).is_some_and(|p| p.allow_bypass_redaction) {
            return Err(IpcError { code: "forbidden".into(), message: "bypass not allowed by policy".into() });
        }
        let scope = state.redactions.get(event_id).ok_or_else(|| bad_request("unknown event"))?.scope.clone();
        state.text_bypasses.retain(|_, until| *until > Instant::now());
        state.text_bypasses.insert(scope, Instant::now() + BYPASS_TTL);
        Ok(())
    }

    // ---------- reports ----------

    fn queue_report(&self, report: SensitiveDataReport) {
        if let Err(e) = self.spool.push(&report) {
            tracing::error!(error = %e, "could not spool report");
        }
        self.reports_pending.notify_one();
    }

    // ---------- views ----------

    pub fn popup_state(&self) -> PopupState {
        let protected_apps = self.target_apps();
        let state = self.state.read().unwrap();
        let workspace = state.config.as_ref().and_then(|c| c.workspace.as_ref());
        let policy = state.config.as_ref().and_then(|c| c.active_policy());
        let view = if state.settings.is_none() {
            PopupView::NotConfigured
        } else if state.config.is_none() {
            match &state.last_error {
                Some(message) => PopupView::Error { message: message.clone() },
                None => PopupView::Loading,
            }
        } else if policy.is_none() {
            PopupView::Standby
        } else {
            match state.config.as_ref().and_then(|c| c.employee.as_ref()) {
                Some(e) => PopupView::SignedIn { name: e.name.clone(), redactions: e.redactions_last_30_days },
                None => PopupView::Reconnect,
            }
        };
        PopupState {
            view,
            bot_name: workspace.map(|w| w.bot_branding.name.clone()).unwrap_or_else(|| "Albert".into()),
            bot_icon_url: workspace.and_then(|w| w.bot_branding.icon_url.clone()),
            company: workspace.and_then(|w| w.branding_name.clone()),
            portal_url: workspace.map(|w| w.portal_url.clone()),
            allow_bypass: policy.is_some_and(|p| p.allow_bypass_redaction),
            protected_apps,
            recent_events: state.recent.iter().cloned().collect(),
        }
    }

    pub async fn status(&self) -> Status {
        let engine = self.engine.clone();
        let heap = tokio::task::spawn_blocking(move || engine.heap_stats()).await.ok().and_then(Result::ok);
        let target_apps = self.target_apps();
        let state = self.state.read().unwrap();
        Status {
            version: self.version.into(),
            configured: state.settings.is_some(),
            device_id: state.enrollment.as_ref().map(|e| e.device_id.clone()),
            monitoring: state.config.as_ref().and_then(|c| c.active_policy()).is_some(),
            last_sync: state.last_sync.map(|t| t.to_rfc3339()),
            last_error: state.last_error.clone(),
            engine_heap_mib: heap.map_or(0.0, |h| h.malloc_size as f64 / 1_048_576.0),
            target_apps,
            pending_reports: self.spool.len(),
            proxy: self.proxy.get().map(|p| {
                let stats = p.stats.get();
                ProxyStatus {
                    addr: p.addr.to_string(),
                    ca_cert: p.ca_cert.display().to_string(),
                    record: p.record,
                    intercepted: stats.intercepted,
                    relayed: stats.relayed,
                    rewritten: stats.rewritten,
                    blocked: stats.blocked,
                    handshake_failures: stats.handshake_failures,
                }
            }),
        }
    }
}

impl Inspector for Agent {
    fn rules(&self, flow: &Flow) -> Option<Arc<[Rule]>> {
        self.protected(flow).map(|(_, rules)| rules)
    }

    async fn text(&self, flow: &Flow, texts: Vec<String>, history: bool) -> Vec<Option<String>> {
        self.redact_request(flow, texts, history).await
    }

    async fn file(&self, flow: &Flow, upload: Upload) -> FileVerdict {
        let Some((bundle_id, _)) = self.protected(flow) else { return FileVerdict::Allow };
        match self.scan_upload(bundle_id, upload).await.decision.as_str() {
            "deny" => FileVerdict::Deny,
            _ => FileVerdict::Allow,
        }
    }
}

fn allow(reason: &str) -> ScanFileResult {
    ScanFileResult { decision: "allow".into(), reason: reason.into(), types: vec![], event_id: None }
}

/// A denial with nothing found: the file could not be read. It still gets an event, to tell
/// the user why the upload failed.
fn deny(reason: &str) -> ScanFileResult {
    ScanFileResult { decision: "deny".into(), reason: reason.into(), types: vec![], event_id: Some(Uuid::new_v4().to_string()) }
}

/// A service's rules for the proxy. One this version cannot read is skipped.
fn network_rules(service: &MonitoredService) -> Vec<Rule> {
    service
        .network_rules
        .iter()
        .filter_map(|raw| {
            serde_json::from_value(raw.clone())
                .inspect_err(|e| tracing::debug!(service = %service.service_id, error = %e, "network rule skipped"))
                .ok()
        })
        .collect()
}

fn text_report(session_id: Uuid, service_id: &str, occurred_at: DateTime<Utc>, detections: Vec<SnapshotDetection>, redacted: bool) -> SensitiveDataReport {
    SensitiveDataReport {
        session_id,
        service_id: service_id.to_owned(),
        occurred_at,
        authorization_status: None,
        text: Some(TextSnapshot { detections, redacted }),
        files: None,
    }
}

fn trim_redactions(state: &mut State) {
    if state.redactions.len() > MAX_REDACTIONS {
        let oldest = state.redactions.iter().min_by_key(|(_, e)| e.occurred_at).map(|(k, _)| k.clone());
        oldest.map(|k| state.redactions.remove(&k));
    }
}

/// The counts of several strings of one message, as one snapshot.
fn merged_counts(counts: &[riot_detect::TypeCount]) -> Vec<SnapshotDetection> {
    let mut merged: Vec<SnapshotDetection> = vec![];
    for c in counts {
        match merged.iter_mut().find(|m| m.kind == c.kind) {
            Some(m) => m.count += c.count,
            None => merged.push(SnapshotDetection { kind: c.kind.clone(), count: c.count }),
        }
    }
    merged
}

/// Token memory is per user and per app: one user's tokens never resolve in another's session.
fn scope(uid: u32, bundle_id: &str) -> String {
    format!("{uid}:{bundle_id}")
}

fn push_recent(state: &mut State, event_id: String, kind: &str, app_name: &str, types: &[TypeCount]) {
    state.recent.push_front(RecentEvent {
        event_id,
        at: Utc::now().to_rfc3339(),
        kind: kind.into(),
        app_name: app_name.into(),
        types: types.to_vec(),
    });
    state.recent.truncate(RECENT_EVENTS);
}

/// Distinct values per flag, with the catalog label, most frequent first.
fn type_counts(detections: &[Detection]) -> Vec<TypeCount> {
    let mut by_flag: Vec<(String, String, Vec<&str>)> = vec![];
    for d in detections {
        match by_flag.iter_mut().find(|(f, _, _)| *f == d.flag) {
            Some((_, _, values)) if !values.contains(&d.value.as_str()) => values.push(&d.value),
            Some(_) => {}
            None => by_flag.push((d.flag.clone(), d.label.clone(), vec![&d.value])),
        }
    }
    let mut out: Vec<TypeCount> =
        by_flag.into_iter().map(|(flag, label, v)| TypeCount { flag, label, count: v.len() as u32 }).collect();
    out.sort_by_key(|t| std::cmp::Reverse(t.count));
    out
}

fn snapshot_counts(counts: &[riot_detect::TypeCount]) -> Vec<SnapshotDetection> {
    counts.iter().map(|c| SnapshotDetection { kind: c.kind.clone(), count: c.count }).collect()
}

/// The extension's `fileKey`: sha-256 over `[name, size, lastModified, type]`, content-free.
/// An upload has no modification time (0); a file on disk has no declared type.
fn file_key(name: &str, size: u64, last_modified_ms: i64, mime: &str) -> String {
    let serialized = serde_json::to_string(&(name, size, last_modified_ms, mime)).unwrap_or_default();
    hex::encode(sha2::Sha256::digest(serialized.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use riot_detect::EngineConfig;

    const APP: &str = "com.apple.TextEdit";
    const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";

    fn agent(name: &str) -> Agent {
        let dir = std::env::temp_dir().join(format!("riot-agent-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths {
            settings: dir.join("settings.json"),
            data_dir: dir.clone(),
            socket: dir.join("agent.sock"),
            proxy_addr: None,
            proxy_record: false,
        };
        let agent = Agent::new(paths, Engine::start(EngineConfig::default()).unwrap()).unwrap();
        let config: AgentConfig = serde_json::from_value(serde_json::json!({
            "employee": null,
            "workspace": null,
            "policies": [{
                "policy_kind": riot_api::MONITORING_POLICY_KIND,
                "enabled": true,
                "allow_bypass_redaction": true,
                "services": [{
                    "service_id": "demo",
                    "display_name": "TextEdit",
                    "domain": "ai.test",
                    "desktop_apps": [{ "platform": "macos", "bundle_id": APP, "team_id": null }],
                    "network_rules": [
                        { "host": "ai.test", "method": "POST", "path": "/chat", "kind": "json_text", "text_pointers": ["/prompt"] },
                        { "host": "files.ai.test", "path": "/**", "kind": "raw_file" },
                        { "host": "ai.test", "path": "/later", "kind": "a_kind_from_a_newer_parrot" }
                    ]
                }]
            }]
        }))
        .unwrap();
        agent.state.write().unwrap().config = Some(config);
        agent
    }

    async fn redact(agent: &Agent) -> String {
        let result = agent.redact_text(501, format!("Mon IBAN {IBAN}"), APP.into()).await.unwrap();
        assert_eq!(result.action, "redacted");
        result.event_id.unwrap()
    }

    #[tokio::test]
    async fn redacting_alone_reports_nothing() {
        let agent = agent("redact");
        redact(&agent).await;
        assert_eq!(agent.spool.len(), 0);
        assert!(agent.popup_state().recent_events.is_empty());
    }

    #[tokio::test]
    async fn each_paste_is_its_own_report_and_can_be_overridden() {
        let agent = agent("paste");
        let event = redact(&agent).await;
        let first = agent.report_paste(&event).unwrap().paste_id;
        let second = agent.report_paste(&event).unwrap().paste_id;
        assert_ne!(first, second);
        let reports = agent.spool.pending();
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|(_, r)| r.text.as_ref().is_some_and(|t| t.redacted)));

        agent.report_override(&second).unwrap();
        let reports = agent.spool.pending();
        assert_eq!(reports.len(), 2, "the override upserts the paste's report");
        let overridden = reports.iter().find(|(_, r)| r.session_id.to_string() == second).unwrap();
        assert!(!overridden.1.text.as_ref().unwrap().redacted);
        assert!(agent.report_override(&event).is_err(), "overrides name a paste, not the redaction");
        assert!(agent.report_paste("nope").is_err());
    }

    /// A blocked file opened again once the notice debounce is over is answered from the cache,
    /// and notified again: that must not wait on the state lock the cache lookup holds.
    #[test]
    fn a_blocked_file_opened_again_is_denied_from_the_cache() {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let decisions = runtime.block_on(async {
                let agent = agent("rescan");
                let path = agent.paths.data_dir.join("sensible.txt");
                std::fs::write(&path, format!("Mon IBAN {IBAN}")).unwrap();
                let path = path.to_string_lossy().into_owned();
                let first = agent.scan_file(path.clone(), APP.into(), None).await;
                agent.last_block_notice.lock().unwrap().clear(); // as if the debounce were over
                let again = agent.scan_file(path, APP.into(), None).await;
                let blocked = agent.popup_state().recent_events.iter().filter(|e| e.kind == "fileBlocked").count();
                (first.decision, again.decision, blocked)
            });
            let _ = done.send(decisions);
        });
        let (first, again, blocked) =
            finished.recv_timeout(Duration::from_secs(20)).expect("the second scan never returned: deadlock");
        assert_eq!((first.as_str(), again.as_str()), ("deny", "deny"));
        assert_eq!(blocked, 2, "each notice past the debounce is a recent event");
    }

    // ---------- network ----------

    fn flow(host: &str, bundle_id: Option<&str>) -> Flow {
        Flow { host: host.into(), port: 443, bundle_id: bundle_id.map(str::to_owned), uid: Some(501), pid: None }
    }

    fn next_event(events: &mut broadcast::Receiver<Event>, wanted: fn(&Event) -> bool) -> Event {
        loop {
            let event = events.try_recv().expect("an event");
            if wanted(&event) {
                return event;
            }
        }
    }

    #[tokio::test]
    async fn only_the_protected_apps_flows_to_the_services_hosts_are_intercepted() {
        let agent = agent("flows");
        let rules = agent.rules(&flow("ai.test", None)).unwrap();
        assert_eq!(rules.len(), 2, "the rule of an unknown kind is skipped");
        assert!(agent.rules(&flow("files.ai.test", Some(APP))).is_some(), "a host only the rules name");
        assert!(agent.rules(&flow("ai.test", Some("com.apple.TextEdit.helper"))).is_some());
        assert!(agent.rules(&flow("ai.test", Some("com.apple.TextEditor"))).is_none(), "another app");
        assert!(agent.rules(&flow("example.com", Some(APP))).is_none(), "another host");
        assert_eq!(agent.net_config(), NetConfig { proxy_port: None, apps: vec![NetApp { bundle_id: APP.into(), team_id: None }] });

        agent.state.write().unwrap().config.as_mut().unwrap().policies[0].enabled = false;
        assert!(agent.rules(&flow("ai.test", Some(APP))).is_none(), "monitoring off");
        assert!(agent.net_config().apps.is_empty());
    }

    #[tokio::test]
    async fn a_sent_message_is_redacted_reported_and_can_be_allowed_once() {
        let agent = agent("message");
        let mut events = agent.events.subscribe();
        let flow = flow("ai.test", Some(APP));
        let message = || vec!["hello there".to_owned(), format!("Mon IBAN {IBAN}")];

        let sent = agent.text(&flow, message(), false).await;
        assert_eq!(sent[0], None);
        assert_eq!(sent[1].as_deref(), Some("Mon IBAN [IBAN_1]"));
        let Event::TextRedacted { event_id, bundle_id, allow_bypass, types, .. } =
            next_event(&mut events, |e| matches!(e, Event::TextRedacted { .. }))
        else {
            unreachable!()
        };
        assert_eq!((bundle_id.as_str(), allow_bypass, types[0].count), (APP, true, 1));
        // Sent, so reported at once; and the tokens are the clipboard guard's.
        let reports = agent.spool.pending();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].1.text.as_ref().unwrap().redacted);
        assert_eq!(agent.detokenize(501, "[IBAN_1]".into(), APP.into()).await.unwrap().text, IBAN);

        assert!(agent.text(&flow, vec!["nothing to see".into()], false).await.iter().all(Option::is_none));
        assert_eq!(agent.spool.len(), 1, "a clean message reports nothing");

        // "Allow my next message": a clean request does not use it up, the next sensitive one
        // does, and the one after is redacted again.
        agent.grant_text_bypass(&event_id).unwrap();
        assert!(agent.text(&flow, vec!["nothing to see".into()], false).await.iter().all(Option::is_none));
        assert!(agent.text(&flow, message(), false).await.iter().all(Option::is_none), "goes out as written");
        let reports = agent.spool.pending();
        assert_eq!(reports.len(), 2);
        assert_eq!(reports.iter().filter(|(_, r)| !r.text.as_ref().unwrap().redacted).count(), 1);
        assert!(agent.text(&flow, message(), false).await[1].is_some());

        let kinds: Vec<String> = agent.popup_state().recent_events.into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["messageRedacted", "originalSent", "messageRedacted"]);
        assert!(agent.grant_text_bypass("nope").is_err());
    }

    /// Claude Code's API keeps no state: every request carries the conversation again.
    #[tokio::test]
    async fn a_conversation_sent_again_is_redacted_the_same_way_and_reported_once() {
        let agent = agent("history");
        let flow = flow("ai.test", Some(APP));
        let first = format!("Mon IBAN {IBAN}");
        let second = "Et mon numéro de carte 4242 4242 4242 4242".to_owned();
        let redacted = |sent: &[Option<String>]| sent.iter().map(|s| s.is_some()).collect::<Vec<_>>();

        let sent = agent.text(&flow, vec![first.clone()], true).await;
        assert_eq!(sent[0].as_deref(), Some("Mon IBAN [IBAN_1]"));
        assert_eq!(agent.spool.len(), 1);

        // The next turn: the first message again, an answer, a new message.
        let turn = vec![first.clone(), "Bien noté.".to_owned(), second.clone()];
        let again = agent.text(&flow, turn.clone(), true).await;
        assert_eq!(again[0], sent[0], "the same tokens, or the service's cache of the conversation is lost");
        assert_eq!(redacted(&again), [true, false, true]);
        assert_eq!(agent.spool.len(), 2, "only the new message is reported");
        agent.text(&flow, turn.clone(), true).await;
        assert_eq!(agent.spool.len(), 2, "nothing new, nothing reported");
        assert_eq!(agent.popup_state().recent_events.len(), 2);

        // A message the user allowed stays as written in the turns that follow.
        let event_id = agent.state.read().unwrap().redactions.keys().next().unwrap().clone();
        agent.grant_text_bypass(&event_id).unwrap();
        let third = "Mon autre IBAN DE89 3704 0044 0532 0130 00".to_owned();
        let turn: Vec<String> = turn.into_iter().chain([third]).collect();
        assert_eq!(redacted(&agent.text(&flow, turn.clone(), true).await), [true, false, true, false]);
        assert_eq!(redacted(&agent.text(&flow, turn.clone(), true).await), [true, false, true, false]);
        assert_eq!(agent.spool.len(), 3);

        // A change of policy starts over.
        agent.state.write().unwrap().config.as_mut().unwrap().policies[0].data_types =
            serde_json::from_value(serde_json::json!([{ "data_type": "financial_data", "enabled": false }])).unwrap();
        assert_eq!(redacted(&agent.text(&flow, turn, true).await), [false, false, false, false]);
    }

    #[tokio::test]
    async fn an_upload_is_denied_until_the_user_sends_it_anyway() {
        let agent = agent("upload");
        let mut events = agent.events.subscribe();
        let flow = flow("files.ai.test", Some(APP));
        let upload = |content: &str| Upload { name: "notes.txt".into(), mime: "text/plain".into(), bytes: Some(content.to_owned().into()) };
        let sensitive = format!("Mon IBAN {IBAN}");

        assert_eq!(agent.file(&flow, upload("nothing to see")).await, FileVerdict::Allow);
        assert_eq!(agent.file(&flow, upload(&sensitive)).await, FileVerdict::Deny);
        let Event::FileBlocked { event_id, file_name, allow_bypass, .. } = next_event(&mut events, |e| matches!(e, Event::FileBlocked { .. }))
        else {
            unreachable!()
        };
        assert_eq!((file_name.as_str(), allow_bypass), ("notes.txt", true));
        assert_eq!(agent.spool.pending()[0].1.files.as_ref().unwrap()[0].format, "txt");

        agent.grant_file_bypass(&event_id).unwrap();
        assert_eq!(agent.file(&flow, upload(&sensitive)).await, FileVerdict::Allow, "the same content, sent anyway");
        assert_eq!(agent.file(&flow, upload(&format!("{sensitive} et autre chose"))).await, FileVerdict::Deny, "another file");

        // What the proxy could not read is denied, and cannot be sent anyway.
        let unreadable = Upload { name: String::new(), mime: String::new(), bytes: None };
        assert_eq!(agent.file(&flow, unreadable).await, FileVerdict::Deny);
        let unreadable = next_event(&mut events, |e| matches!(e, Event::FileBlocked { file_name, .. } if file_name.is_empty()));
        assert!(matches!(unreadable, Event::FileBlocked { allow_bypass: false, .. }));
    }
}
