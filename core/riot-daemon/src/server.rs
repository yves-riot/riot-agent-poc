//! The local socket. Any local user may connect (each request is scoped to the caller's uid);
//! `scanFile` is reserved to root, i.e. the ES extension, because the daemon reads files the
//! caller may not be able to read and the verdict would leak something about their content.
//!
//! Production hardening (plan §2): also verify the peer's code signature from its audit token
//! (`LOCAL_PEERTOKEN` + `SecCodeCheckValidity` against the team id).

use std::os::fd::AsRawFd;
use std::sync::Arc;

use riot_ipc::{IpcError, Request, RequestEnvelope, ResponseEnvelope};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::agent::{Agent, bad_request};

pub async fn serve(agent: Arc<Agent>) -> anyhow::Result<()> {
    let path = agent.paths.socket.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    }
    tracing::info!(socket = %path.display(), "listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(agent, stream).await {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: valid fd for the stream's lifetime; out-params are plain integers.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

async fn connection(agent: Arc<Agent>, stream: UnixStream) -> anyhow::Result<()> {
    let uid = peer_uid(&stream)?;
    let (read, mut write) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<String>(64);
    let writer = tokio::spawn(async move {
        while let Some(mut line) = out_rx.recv().await {
            line.push('\n');
            if write.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        let envelope: RequestEnvelope = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                let id = serde_json::from_str::<serde_json::Value>(&line).ok().and_then(|v| v["id"].as_u64()).unwrap_or(0);
                let _ = out_tx.send(reply(id, Err(bad_request(e.to_string())))).await;
                continue;
            }
        };
        let id = envelope.id;
        if let Request::Subscribe = envelope.request {
            let mut events = agent.events.subscribe();
            let tx = out_tx.clone();
            tokio::spawn(async move {
                loop {
                    match events.recv().await {
                        Ok(event) => {
                            let Ok(line) = serde_json::to_string(&event) else { continue };
                            if tx.send(line).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
            });
            let _ = out_tx.send(reply(id, Ok(serde_json::Value::Null))).await;
            continue;
        }
        // Requests run concurrently: a slow file scan must not hold up a quick status call.
        let agent = agent.clone();
        let tx = out_tx.clone();
        tokio::spawn(async move {
            let result = handle(&agent, uid, envelope.request).await;
            let _ = tx.send(reply(id, result)).await;
        });
    }
    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

fn reply(id: u64, result: Result<serde_json::Value, IpcError>) -> String {
    let envelope = match result {
        Ok(v) => ResponseEnvelope { id, ok: Some(v), error: None },
        Err(e) => ResponseEnvelope { id, ok: None, error: Some(e) },
    };
    serde_json::to_string(&envelope).unwrap_or_default()
}

fn json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, IpcError> {
    serde_json::to_value(v).map_err(crate::agent::internal)
}

async fn handle(agent: &Agent, uid: u32, request: Request) -> Result<serde_json::Value, IpcError> {
    match request {
        Request::Status => json(agent.status().await),
        Request::PopupState => json(agent.popup_state()),
        Request::RedactText { text, bundle_id } => json(agent.redact_text(uid, text, bundle_id).await?),
        Request::Detokenize { text, bundle_id } => json(agent.detokenize(uid, text, bundle_id).await?),
        Request::ScanFile { path, bundle_id, deadline_ms } => {
            if uid != 0 && std::env::var_os("RIOT_DEV_ALLOW_SCAN").is_none() {
                return Err(IpcError { code: "forbidden".into(), message: "scanFile is reserved to the ES extension".into() });
            }
            json(agent.scan_file(path, bundle_id, deadline_ms).await)
        }
        Request::GrantFileBypass { event_id } => json(agent.grant_file_bypass(&event_id)?),
        Request::ReportOverride { event_id } => json(agent.report_override(&event_id)?),
        Request::EsConfig => json(agent.es_config()),
        Request::Refresh => {
            agent.refresh.notify_one();
            Ok(serde_json::Value::Null)
        }
        Request::Subscribe => Ok(serde_json::Value::Null), // handled by the connection loop
    }
}
