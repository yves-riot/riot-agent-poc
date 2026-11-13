//! The daemon's local protocol: one JSON object per line over a Unix socket.
//!
//! ```text
//! → {"id":1,"method":"redactText","params":{"text":"…","bundleId":"com.openai.codex"}}
//! ← {"id":1,"ok":{"action":"redacted","text":"[IBAN_1]",…}}
//! ← {"id":2,"error":{"code":"badRequest","message":"…"}}
//! → {"id":3,"method":"subscribe"}            (the connection then also receives events)
//! ← {"event":"fileBlocked","data":{…}}
//! ```
//!
//! Keys are camelCase so Swift's and C#'s default JSON coders read them as is. Clients are thin
//! by design: the menu bar app and the ES extension hold no detection or policy logic.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_SOCKET: &str = "/var/run/com.tryriot.agent/agent.sock";

// ---------- requests ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "camelCase")]
pub enum Request {
    Status,
    PopupState,
    /// Clipboard text read while `bundle_id` was frontmost.
    #[serde(rename_all = "camelCase")]
    RedactText { text: String, bundle_id: String },
    /// Text copied out of `bundle_id`: put back the values of its tokens.
    #[serde(rename_all = "camelCase")]
    Detokenize { text: String, bundle_id: String },
    /// From the ES extension, for an AUTH_OPEN by a process of `bundle_id`.
    #[serde(rename_all = "camelCase")]
    ScanFile { path: String, bundle_id: String, deadline_ms: Option<u64> },
    /// "Send anyway": the next open of this file (same inode and mtime) within the TTL is allowed.
    #[serde(rename_all = "camelCase")]
    GrantFileBypass { event_id: String },
    /// The redacted text of a `redactText` event was pasted: report it now (one report per
    /// paste). Nothing is reported at `redactText` time, when the user may never paste.
    #[serde(rename_all = "camelCase")]
    ReportPaste { event_id: String },
    /// The user chose to paste the original: re-report that paste as not redacted.
    #[serde(rename_all = "camelCase")]
    ReportOverride { paste_id: String },
    /// What the ES extension watches: the protected apps' executables and the scanned extensions.
    EsConfig,
    /// Keep this connection open for pushed [`Event`]s.
    Subscribe,
    /// Refetch config and policies now.
    Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

// ---------- responses ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseEnvelope {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{code}: {message}")]
pub struct IpcError {
    /// `badRequest` | `forbidden` | `unavailable` | `internal`
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetApp {
    pub service_id: String,
    pub display_name: String,
    pub bundle_id: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    /// Managed preferences found (workspace, API URL, enrollment secret).
    pub configured: bool,
    pub device_id: Option<String>,
    pub monitoring: bool,
    pub last_sync: Option<String>,
    pub last_error: Option<String>,
    pub engine_heap_mib: f64,
    pub target_apps: Vec<TargetApp>,
    pub pending_reports: usize,
}

/// The menu bar popup, derived like the extension's `App.vue` view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PopupView {
    Loading,
    /// No managed preferences: the MDM profile is missing.
    NotConfigured,
    /// Monitoring disabled (or no policy) for this workspace.
    Standby,
    #[serde(rename_all = "camelCase")]
    SignedIn { name: String, redactions: u32 },
    /// Enrolled, but no active employee matches this device.
    Reconnect,
    #[serde(rename_all = "camelCase")]
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PopupState {
    pub view: PopupView,
    pub bot_name: String,
    pub bot_icon_url: Option<String>,
    pub company: Option<String>,
    pub portal_url: Option<String>,
    pub allow_bypass: bool,
    pub protected_apps: Vec<TargetApp>,
    /// Content-free: what happened, never what was in it.
    pub recent_events: Vec<RecentEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentEvent {
    pub event_id: String,
    pub at: String,
    /// `textRedacted` | `fileBlocked` | `fileAllowedByUser` | `originalPasted`
    pub kind: String,
    pub app_name: String,
    pub types: Vec<TypeCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TypeCount {
    pub flag: String,
    pub label: String,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactTextResult {
    /// `redacted` (write `text` to the clipboard) | `clean` | `skipped` (not a target app or
    /// monitoring off) | `error` (engine failure: the clipboard is left as is, as the
    /// extension does for a paste)
    pub action: String,
    pub text: Option<String>,
    pub types: Vec<TypeCount>,
    pub event_id: Option<String>,
    pub allow_bypass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportPasteResult {
    pub paste_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetokenizeResult {
    pub text: String,
    pub replaced: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EsConfig {
    /// Empty when monitoring is off: the extension then watches nothing.
    pub watched: Vec<WatchedApp>,
    /// Lower-case file extensions the engine scans (`pdf`, `docx`, …).
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchedApp {
    pub bundle_id: String,
    pub team_id: Option<String>,
    /// Executable path prefixes: the app and its helpers (`/Applications/Claude.app/`).
    pub executable_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFileResult {
    /// `allow` | `deny`
    pub decision: String,
    /// `clean` | `detections` | `bypass` | `unsupported` | `notTarget` | `disabled` | `error` | `timeout`
    pub reason: String,
    pub types: Vec<TypeCount>,
    pub event_id: Option<String>,
}

// ---------- events ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
pub enum Event {
    #[serde(rename_all = "camelCase")]
    FileBlocked {
        event_id: String,
        file_name: String,
        bundle_id: String,
        app_name: String,
        types: Vec<TypeCount>,
        allow_bypass: bool,
    },
    StateChanged,
}

// ---------- blocking client (CLI, tests; the Swift app has its own) ----------

pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl Client {
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self { reader: BufReader::new(stream.try_clone()?), writer: stream, next_id: 1 })
    }

    pub fn call_raw(&mut self, request: &Request) -> Result<serde_json::Value, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_string(&RequestEnvelope { id, request: request.clone() })?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        loop {
            let mut buf = String::new();
            if self.reader.read_line(&mut buf)? == 0 {
                return Err(ClientError::Closed);
            }
            let value: serde_json::Value = serde_json::from_str(&buf)?;
            if value.get("event").is_some() {
                continue; // events interleave with replies on a subscribed connection
            }
            let resp: ResponseEnvelope = serde_json::from_value(value)?;
            if resp.id != id {
                continue;
            }
            return match (resp.ok, resp.error) {
                (_, Some(e)) => Err(ClientError::Remote(e)),
                (Some(v), None) => Ok(v),
                (None, None) => Ok(serde_json::Value::Null),
            };
        }
    }

    pub fn call<T: for<'de> Deserialize<'de>>(&mut self, request: &Request) -> Result<T, ClientError> {
        Ok(serde_json::from_value(self.call_raw(request)?)?)
    }

    /// Next pushed event (after a `Subscribe`). Blocks up to the read timeout.
    pub fn next_event(&mut self) -> Result<Event, ClientError> {
        loop {
            let mut buf = String::new();
            if self.reader.read_line(&mut buf)? == 0 {
                return Err(ClientError::Closed);
            }
            let value: serde_json::Value = serde_json::from_str(&buf)?;
            if value.get("event").is_some() {
                return Ok(serde_json::from_value(value)?);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("daemon error: {0}")]
    Remote(IpcError),
    #[error("connection closed")]
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_shapes() {
        let req = RequestEnvelope { id: 7, request: Request::RedactText { text: "x".into(), bundle_id: "b".into() } };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"id":7,"method":"redactText","params":{"text":"x","bundleId":"b"}}"#
        );
        let unit: RequestEnvelope = serde_json::from_str(r#"{"id":1,"method":"status"}"#).unwrap();
        assert!(matches!(unit.request, Request::Status));
        let view = serde_json::to_string(&PopupView::SignedIn { name: "Ana".into(), redactions: 3 }).unwrap();
        assert_eq!(view, r#"{"kind":"signedIn","name":"Ana","redactions":3}"#);
        let ev = serde_json::to_string(&Event::StateChanged).unwrap();
        assert_eq!(ev, r#"{"event":"stateChanged"}"#);
    }
}
