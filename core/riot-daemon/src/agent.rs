//! The daemon's state and the decisions it makes for its clients. Every policy decision lives
//! here: the menu bar app and the ES extension only ask and apply.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use riot_api::{AgentConfig, FileSnapshot, SensitiveDataReport, SnapshotDetection, TextSnapshot};
use riot_detect::{Detection, Engine, FileScan, Options};
use riot_ipc::{
    DetokenizeResult, EsConfig, Event, IpcError, PopupState, PopupView, RecentEvent, RedactTextResult, ReportPasteResult, ScanFileResult,
    Status, TargetApp, TypeCount, WatchedApp,
};
use sha2::Digest;
use tokio::sync::{Notify, broadcast};
use uuid::Uuid;

use crate::config::{ManagedSettings, Paths};
use crate::device::{Enrollment, Keys};
use crate::gateway::ca::Authority;
use crate::reports::Spool;

const PLATFORM: &str = "macos";
const BYPASS_TTL: Duration = Duration::from_secs(60);
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
    scan_cache: HashMap<FileIdentity, (ScanFileResult, Instant)>,
    /// Set by root (`riotctl pause`, as `dev/run-dev.sh` does on a Mac where the agent is
    /// installed): no policy applies until `resume` or the daemon's next start.
    pub paused: bool,
    /// The process the pause lasts for, if any (`dev/run-dev.sh`): `watch_pause` resumes once
    /// it is gone, however it ended.
    pause_owner: Option<u32>,
}

impl State {
    /// The policy that applies: the active one, unless paused.
    pub fn policy(&self) -> Option<&riot_api::SonarPolicy> {
        if self.paused {
            return None;
        }
        self.config.as_ref()?.active_policy()
    }
}

struct Redaction {
    service_id: String,
    occurred_at: DateTime<Utc>,
    counts: Vec<SnapshotDetection>,
    app_name: String,
    types: Vec<TypeCount>,
}

/// Same file, same content: the ES cache and the "send anyway" grant are keyed on this.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FileIdentity {
    dev: u64,
    ino: u64,
    mtime_ns: i128,
    size: u64,
}

impl FileIdentity {
    fn of(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path)?;
        Ok(Self { dev: m.dev(), ino: m.ino(), mtime_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128, size: m.size() })
    }
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
    pub keys: Keys,
    /// The gateway's CA: `None` until parrot signs an intermediate for this Mac, and the hosts
    /// to decrypt are then refused (fail closed). Replaced on each renewal.
    pub authority: RwLock<Option<Arc<Authority>>>,
    /// Serialises scans so concurrent opens of one file are scanned once.
    scan_lock: tokio::sync::Mutex<()>,
    last_block_notice: Mutex<HashMap<FileIdentity, Instant>>,
}

pub(crate) struct Target {
    pub(crate) service_id: String,
    app_name: String,
    pub(crate) options: Options,
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
        let keys = Keys::load_or_create(&paths.data_dir)?;
        Ok(Self {
            paths,
            engine,
            spool,
            state: RwLock::new(State::default()),
            events: broadcast::channel(64).0,
            refresh: Notify::new(),
            reports_pending: Notify::new(),
            version: env!("CARGO_PKG_VERSION"),
            keys,
            authority: RwLock::new(None),
            scan_lock: tokio::sync::Mutex::new(()),
            last_block_notice: Mutex::new(HashMap::new()),
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
        self.target_where(|s| {
            s.desktop_apps.iter().any(|a| a.platform == PLATFORM && a.bundle_id.as_deref() == Some(bundle_id))
        })
    }

    /// The service an API host belongs to, for the local gateway.
    pub(crate) fn api_target(&self, host: &str) -> Option<Target> {
        self.target_where(|s| s.api_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)))
    }

    fn target_where(&self, matches: impl Fn(&riot_api::MonitoredService) -> bool) -> Option<Target> {
        let state = self.state.read().unwrap();
        let policy = state.policy()?;
        let service = policy.services.iter().find(|s| matches(s))?;
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
        let Some(policy) = state.policy() else { return vec![] };
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
        let services = || state.policy().into_iter().flat_map(|p| p.services.iter());
        let watched = services()
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
        let mut api_hosts: Vec<String> = services().flat_map(|s| s.api_hosts.iter()).map(|h| h.to_ascii_lowercase()).collect();
        api_hosts.sort();
        api_hosts.dedup();
        EsConfig { watched, extensions, api_hosts }
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
        let outcome = tokio::task::spawn_blocking(move || engine.redact(&text, &scope, &options)).await;
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
                    service_id: target.service_id,
                    occurred_at: Utc::now(),
                    counts: snapshot_counts(&outcome.counts),
                    app_name: target.app_name.clone(),
                    types: types.clone(),
                },
            );
            if state.redactions.len() > MAX_REDACTIONS {
                let oldest = state.redactions.iter().min_by_key(|(_, e)| e.occurred_at).map(|(k, _)| k.clone());
                oldest.map(|k| state.redactions.remove(&k));
            }
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
        let report = SensitiveDataReport {
            session_id: paste_id,
            service_id: event.service_id.clone(),
            occurred_at: now,
            authorization_status: None,
            text: Some(TextSnapshot { detections: event.counts.clone(), redacted: true }),
            files: None,
        };
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
        if !state.policy().is_some_and(|p| p.allow_bypass_redaction) {
            return Err(IpcError { code: "forbidden".into(), message: "bypass not allowed by policy".into() });
        }
        let (event_id, pasted_at) = state.pastes.get(paste_id).cloned().ok_or_else(|| bad_request("unknown paste"))?;
        let event = state.redactions.get(&event_id).ok_or_else(|| bad_request("unknown event"))?;
        let report = SensitiveDataReport {
            session_id: paste_id.parse().map_err(|_| bad_request("bad paste id"))?,
            service_id: event.service_id.clone(),
            occurred_at: pasted_at,
            authorization_status: None,
            text: Some(TextSnapshot { detections: event.counts.clone(), redacted: false }),
            files: None,
        };
        let (app, types) = (event.app_name.clone(), event.types.clone());
        push_recent(&mut state, paste_id.to_owned(), "originalPasted", &app, &types);
        drop(state);
        self.queue_report(report);
        let _ = self.events.send(Event::StateChanged);
        Ok(())
    }

    /// The local gateway redacted values out of a request: reported at once, the request is
    /// on its way. `detections` holds only what this request redacted for the first time.
    pub(crate) fn report_api_redaction(&self, target: &Target, detections: &[Detection]) {
        let event_id = Uuid::new_v4();
        let types = type_counts(detections);
        let counts = types.iter().map(|t| SnapshotDetection { kind: t.flag.clone(), count: t.count }).collect();
        self.queue_report(SensitiveDataReport {
            session_id: event_id,
            service_id: target.service_id.clone(),
            occurred_at: Utc::now(),
            authorization_status: None,
            text: Some(TextSnapshot { detections: counts, redacted: true }),
            files: None,
        });
        push_recent(&mut self.state.write().unwrap(), event_id.to_string(), "textRedacted", &target.app_name, &types);
        let _ = self.events.send(Event::StateChanged);
    }

    // ---------- files ----------

    pub async fn scan_file(&self, path: String, bundle_id: String, deadline_ms: Option<u64>) -> ScanFileResult {
        let allow = |reason: &str| ScanFileResult { decision: "allow".into(), reason: reason.into(), types: vec![], event_id: None };
        let Some(target) = self.target(&bundle_id) else { return allow("notTarget") };
        let path_ref = Path::new(&path);
        let Ok(identity) = FileIdentity::of(path_ref) else { return allow("unsupported") };

        if self.bypassed(&identity) {
            return allow("bypass");
        }
        let _guard = self.scan_lock.lock().await;
        // Its own statement: an `if let` would hold this read guard through the block, and
        // `notify_blocked` takes the write lock (a deadlock on every cached deny).
        let cached = self.state.read().unwrap().scan_cache.get(&identity).cloned();
        if let Some((cached, _)) = cached {
            if cached.decision == "deny" {
                self.notify_blocked(&identity, &path, &bundle_id, &target, &cached);
            }
            return cached;
        }

        let deadline = deadline_ms.map(|ms| Instant::now() + Duration::from_millis(ms));
        let engine = self.engine.clone();
        let options = target.options.clone();
        let scan_path = path.clone();
        let scanned = tokio::task::spawn_blocking(move || engine.scan_path(Path::new(&scan_path), &options, deadline)).await;

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
                    files: Some(vec![FileSnapshot {
                        key: file_key(path_ref, &identity),
                        format,
                        detections: snapshot_counts(&counts),
                    }]),
                });
                ScanFileResult { decision: "deny".into(), reason: "detections".into(), types, event_id: Some(event_id.to_string()) }
            }
            Ok(Ok(FileScan::Scanned { .. })) => allow("clean"),
            Ok(Ok(FileScan::Unsupported { .. })) => allow("unsupported"),
            // Fail closed, as the extension: what could not be read is not known to be clean.
            Ok(Ok(FileScan::Oversized { .. })) | Ok(Ok(FileScan::Error { .. })) => ScanFileResult {
                decision: "deny".into(),
                reason: "error".into(),
                types: vec![],
                event_id: Some(Uuid::new_v4().to_string()),
            },
            // Out of time: never make the AI app unusable; the ES client allows.
            Ok(Err(riot_detect::Error::Timeout)) => return allow("timeout"),
            Ok(Err(e)) => {
                tracing::error!(error = %e, "file scan failed");
                ScanFileResult { decision: "deny".into(), reason: "error".into(), types: vec![], event_id: Some(Uuid::new_v4().to_string()) }
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
            state.scan_cache.insert(identity, (result.clone(), Instant::now()));
        }
        if result.decision == "deny" {
            self.notify_blocked(&identity, &path, &bundle_id, &target, &result);
        }
        result
    }

    fn notify_blocked(&self, identity: &FileIdentity, path: &str, bundle_id: &str, target: &Target, result: &ScanFileResult) {
        {
            let mut notices = self.last_block_notice.lock().unwrap();
            if notices.get(identity).is_some_and(|at| at.elapsed() < BLOCK_NOTIFY_DEBOUNCE) {
                return;
            }
            notices.insert(*identity, Instant::now());
        }
        let Some(event_id) = result.event_id.clone() else { return };
        {
            let mut state = self.state.write().unwrap();
            state.blocked_files.insert(event_id.clone(), *identity);
            push_recent(&mut state, event_id.clone(), "fileBlocked", &target.app_name, &result.types);
        }
        let file_name = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let _ = self.events.send(Event::FileBlocked {
            event_id,
            file_name,
            bundle_id: bundle_id.to_owned(),
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
        if !state.policy().is_some_and(|p| p.allow_bypass_redaction) {
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
        let policy = state.policy();
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

    /// Root only (the server checks): stops applying the policy, until `resume`, or until
    /// `while_pid` is gone.
    pub fn pause(&self, while_pid: Option<u32>) {
        let mut state = self.state.write().unwrap();
        state.pause_owner = while_pid;
        if !std::mem::replace(&mut state.paused, true) {
            tracing::warn!(while_pid, "policy paused by root");
            let _ = self.events.send(Event::StateChanged);
        }
    }

    pub fn resume(&self) {
        let mut state = self.state.write().unwrap();
        state.pause_owner = None;
        if std::mem::replace(&mut state.paused, false) {
            tracing::warn!("policy resumed");
            let _ = self.events.send(Event::StateChanged);
        }
    }

    /// Resumes once the process a pause lasts for is gone.
    pub async fn watch_pause(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let owner = self.state.read().unwrap().pause_owner;
            if let Some(pid) = owner
                && !process_exists(pid)
                && self.state.read().unwrap().pause_owner == Some(pid)
            {
                tracing::info!(pid, "the process the pause lasted for is gone");
                self.resume();
            }
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
            monitoring: state.policy().is_some(),
            paused: state.paused,
            last_sync: state.last_sync.map(|t| t.to_rfc3339()),
            last_error: state.last_error.clone(),
            engine_heap_mib: heap.map_or(0.0, |h| h.malloc_size as f64 / 1_048_576.0),
            target_apps,
            pending_reports: self.spool.len(),
        }
    }
}

fn process_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
    // Signal 0 checks without sending: EPERM still means the process exists.
    (unsafe { libc::kill(pid, 0) == 0 }) || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
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
fn file_key(path: &Path, identity: &FileIdentity) -> String {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let last_modified_ms = (identity.mtime_ns / 1_000_000) as i64;
    let serialized = serde_json::to_string(&(name, identity.size, last_modified_ms, "")).unwrap_or_default();
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
        let paths = Paths { settings: dir.join("settings.json"), data_dir: dir.clone(), socket: dir.join("agent.sock") };
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
                    "desktop_apps": [{ "platform": "macos", "bundle_id": APP, "team_id": null }]
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
}
