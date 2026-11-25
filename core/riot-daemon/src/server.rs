//! The local socket (a named pipe on Windows). Any local user may connect (each request is
//! scoped to the caller's user); `scanFile` is reserved to root (LocalSystem or an elevated
//! administrator on Windows), i.e. the file guard, because the daemon reads files the caller may
//! not be able to read and the verdict would leak something about their content.
//!
//! Production hardening (plan §2): also verify the peer's code signature, from its audit token
//! on macOS (`LOCAL_PEERTOKEN` + `SecCodeCheckValidity` against the team id), from its process's
//! Authenticode signature on Windows.

use std::sync::Arc;

use riot_ipc::{IpcError, Request, RequestEnvelope, ResponseEnvelope};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use crate::agent::{Agent, bad_request};
use crate::os::Peer;

#[cfg(unix)]
pub async fn serve(agent: Arc<Agent>) -> anyhow::Result<()> {
    let path = agent.paths.socket.clone();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    }
    tracing::info!(socket = %path.display(), "listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let agent = agent.clone();
        tokio::spawn(async move {
            let result = match crate::os::peer(&stream) {
                Ok(peer) => {
                    let (read, write) = stream.into_split();
                    connection(agent, peer, read, write).await
                }
                Err(e) => Err(e.into()),
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

/// One pipe instance per client: the next one is created as soon as a client takes the
/// current one. The first instance must be the daemon's own: a pipe of that name created by
/// anyone else first is refused, not joined.
#[cfg(windows)]
pub async fn serve(agent: Arc<Agent>) -> anyhow::Result<()> {
    use anyhow::Context;

    let name = agent.paths.socket.clone();
    let create = |first| crate::os::create_pipe(&name, first);
    let mut server = create(true).with_context(|| format!("cannot create {}: is another daemon running?", name.display()))?;
    tracing::info!(pipe = %name.display(), "listening");
    loop {
        if let Err(e) = server.connect().await {
            tracing::debug!(error = %e, "a client left before it was accepted");
            server = create(false)?;
            continue;
        }
        let client = std::mem::replace(&mut server, create(false)?);
        let agent = agent.clone();
        tokio::spawn(async move {
            let result = match crate::os::pipe_peer(&client) {
                Ok(peer) => {
                    let (read, write) = tokio::io::split(client);
                    connection(agent, peer, read, write).await
                }
                Err(e) => Err(anyhow::Error::from(e).context("the client's user could not be identified")),
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

async fn connection<R, W>(agent: Arc<Agent>, peer: Peer, read: R, mut write: W) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
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
        let peer = peer.clone();
        tokio::spawn(async move {
            let result = handle(&agent, &peer, envelope.request).await;
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

async fn handle(agent: &Agent, peer: &Peer, request: Request) -> Result<serde_json::Value, IpcError> {
    match request {
        Request::Status => json(agent.status().await),
        Request::PopupState => json(agent.popup_state()),
        Request::RedactText { text, bundle_id } => json(agent.redact_text(&peer.user, text, bundle_id).await?),
        Request::Detokenize { text, bundle_id } => json(agent.detokenize(&peer.user, text, bundle_id).await?),
        Request::ScanFile { path, bundle_id, deadline_ms } => {
            if !peer.privileged && std::env::var_os("RIOT_DEV_ALLOW_SCAN").is_none() {
                return Err(IpcError { code: "forbidden".into(), message: "scanFile is reserved to the file guard".into() });
            }
            json(agent.scan_file(path, bundle_id, deadline_ms).await)
        }
        Request::GrantFileBypass { event_id } => json(agent.grant_file_bypass(&event_id)?),
        Request::ReportPaste { event_id } => json(agent.report_paste(&event_id)?),
        Request::ReportOverride { paste_id } => json(agent.report_override(&paste_id)?),
        Request::EsConfig => json(agent.es_config()),
        Request::Refresh => {
            agent.refresh.notify_one();
            Ok(serde_json::Value::Null)
        }
        Request::Pause { .. } | Request::Resume => {
            if !peer.privileged {
                return Err(IpcError { code: "forbidden".into(), message: "pausing the agent is reserved to root (an elevated administrator on Windows)".into() });
            }
            match request {
                Request::Pause { while_pid } => agent.pause(while_pid),
                _ => agent.resume(),
            }
            Ok(serde_json::Value::Null)
        }
        Request::Subscribe => Ok(serde_json::Value::Null), // handled by the connection loop
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use riot_detect::{Engine, EngineConfig};
    use riot_ipc::{Client, ClientError, Status};

    use super::*;
    use crate::config::{Paths, Settings};

    fn agent(name: &str) -> Arc<Agent> {
        let dir = std::env::temp_dir().join(format!("riot-server-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        #[cfg(unix)]
        let socket = dir.join("agent.sock");
        #[cfg(windows)]
        let socket = format!(r"\\.\pipe\riot-test-{name}-{}", std::process::id()).into();
        let paths = Paths { settings: Settings::File(dir.join("settings.json")), data_dir: dir, socket };
        Arc::new(Agent::new(paths, Engine::start(EngineConfig::default()).unwrap()).unwrap())
    }

    fn connect(agent: &Agent) -> Client {
        let started = Instant::now();
        loop {
            match Client::connect(&agent.paths.socket) {
                Ok(client) => return client,
                Err(_) if started.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("cannot connect to {}: {e}", agent.paths.socket.display()),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_local_client_is_served_and_root_requests_need_root() {
        let agent = agent("serve");
        tokio::spawn(serve(agent.clone()));
        let client_agent = agent.clone();
        let (status, pause) = tokio::task::spawn_blocking(move || {
            let mut client = connect(&client_agent);
            let status: Status = client.call(&Request::Status).unwrap();
            // Several clients at once: each gets its own instance.
            let mut other = connect(&client_agent);
            let _: Status = other.call(&Request::Status).unwrap();
            (status, client.call_raw(&Request::Pause { while_pid: None }))
        })
        .await
        .unwrap();
        assert!(!status.configured);
        if !crate::os::current_peer().unwrap().privileged {
            assert!(matches!(pause, Err(ClientError::Remote(e)) if e.code == "forbidden"));
            assert!(!agent.state.read().unwrap().paused);
        }
    }

    /// A pipe of the daemon's name that someone else created first is not joined: clients could
    /// not tell which server answers them.
    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pipe_name_already_taken_is_refused() {
        let agent = agent("taken");
        tokio::spawn(serve(agent.clone()));
        let probe = agent.clone();
        tokio::task::spawn_blocking(move || drop(connect(&probe))).await.unwrap();
        let second = tokio::time::timeout(Duration::from_secs(5), serve(agent)).await.expect("the second server returns at once");
        assert!(second.is_err());
    }
}
