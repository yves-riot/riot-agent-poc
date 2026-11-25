//! Talk to a running daemon from a terminal.
//!
//! ```text
//! riotctl status | popup | refresh | watch | es-config
//! riotctl redact <bundle-id> <text>
//! riotctl detok <bundle-id> <text>
//! riotctl scan <bundle-id> <path>          (root, or daemon started with RIOT_DEV_ALLOW_SCAN=1)
//! riotctl paste <event-id>                (report a paste of a redactText event)
//! riotctl pause [pid] | resume            (root: stop or restart applying the policy; with a pid,
//!                                          until that process is gone)
//! riotctl bypass <event-id> | override <paste-id>
//! ```
//!
//! Every command and its output: docs/riotctl.md.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use riot_ipc::{Client, Request};

fn main() {
    let socket = std::env::var_os("RIOT_SOCKET").map(PathBuf::from).unwrap_or_else(|| riot_ipc::DEFAULT_SOCKET.into());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_else(|| usage());
    let request = match args.first().map(String::as_str) {
        Some("status") => Request::Status,
        Some("popup") => Request::PopupState,
        Some("refresh") => Request::Refresh,
        Some("pause") => Request::Pause { while_pid: args.get(1).map(|p| p.parse().unwrap_or_else(|_| usage())) },
        Some("resume") => Request::Resume,
        Some("watch") => Request::Subscribe,
        Some("es-config") => Request::EsConfig,
        Some("redact") => Request::RedactText { bundle_id: arg(1), text: arg(2) },
        Some("detok") => Request::Detokenize { bundle_id: arg(1), text: arg(2) },
        Some("scan") => Request::ScanFile { bundle_id: arg(1), path: arg(2), deadline_ms: Some(10_000) },
        Some("bypass") => Request::GrantFileBypass { event_id: arg(1) },
        Some("paste") => Request::ReportPaste { event_id: arg(1) },
        Some("override") => Request::ReportOverride { paste_id: arg(1) },
        _ => usage(),
    };
    let mut client = Client::connect(&socket).unwrap_or_else(|e| {
        eprintln!("cannot connect to {}: {e}", socket.display());
        std::process::exit(1)
    });
    match client.call_raw(&request) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
    if matches!(request, Request::Subscribe) {
        loop {
            match client.next_event() {
                Ok(event) => println!("{}", serde_json::to_string(&event).unwrap()),
                Err(riot_ipc::ClientError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    eprintln!("{e}");
                    break;
                }
            }
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: riotctl status|popup|refresh|watch|es-config|redact <bundle> <text>|detok <bundle> <text>|scan <bundle> <path>|paste <event>|bypass <event>|override <paste>|pause [pid]|resume");
    std::process::exit(2)
}
