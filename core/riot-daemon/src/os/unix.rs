//! macOS: Unix socket peers, `0600` files, IOKit's platform UUID, Spotlight.
//!
//! No `unsafe` code: the system calls std does not wrap go through tokio and rustix.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::Peer;

pub const DATA_DIR: &str = "/Library/Application Support/com.tryriot.agent";

pub fn default_data_dir() -> PathBuf {
    DATA_DIR.into()
}

/// Root owns the folder (the daemon runs as root); the secrets in it are `0600`.
pub fn prepare_data_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// The client's effective uid (`getpeereid`), as the kernel recorded it at connection.
pub fn peer(stream: &tokio::net::UnixStream) -> std::io::Result<Peer> {
    let uid = stream.peer_cred()?.uid();
    Ok(Peer { user: uid.to_string(), privileged: uid == 0 })
}

/// Readable and writable by the daemon's user only (`0600`).
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    std::io::Write::write_all(&mut f, bytes)
}

pub fn process_exists(pid: u32) -> bool {
    // 0 and values past i32 name no single process.
    let Some(pid) = i32::try_from(pid).ok().and_then(rustix::process::Pid::from_raw) else { return false };
    // `kill(pid, 0)` checks without sending: EPERM still means the process exists.
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(e) => e == rustix::io::Errno::PERM,
    }
}

/// The platform UUID and serial number (IOKit's `IOPlatformExpertDevice`).
pub fn machine_ids() -> (Option<String>, Option<String>) {
    let ioreg = run("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).unwrap_or_default();
    let field = |key: &str| {
        ioreg.lines().find(|l| l.contains(&format!("\"{key}\""))).and_then(|l| l.split('"').nth(3)).map(str::to_owned)
    };
    (field("IOPlatformUUID"), field("IOPlatformSerialNumber"))
}

pub fn os_version() -> String {
    run("sw_vers", &["-productVersion"]).map(|v| v.trim().to_owned()).unwrap_or_default()
}

/// Whether an app is installed, by bundle id (Spotlight's index; cheap, refreshed on sync).
pub fn is_installed(bundle_id: &str) -> bool {
    run("mdfind", &[&format!("kMDItemCFBundleIdentifier == '{}'", bundle_id.replace('\'', ""))])
        .is_some_and(|out| out.lines().any(|l| l.ends_with(".app")))
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// This process, as a client of its own daemon would be seen.
#[cfg(test)]
pub fn current_peer() -> std::io::Result<Peer> {
    let uid = current_uid();
    Ok(Peer { user: uid.to_string(), privileged: uid == 0 })
}

/// The daemon's effective uid.
pub fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
