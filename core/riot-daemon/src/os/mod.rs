//! What differs between macOS and Windows below the daemon's logic: who a local client is,
//! files only the daemon may read, file identity, process liveness, this machine's facts, and
//! the data folder. Both modules expose the same functions; the rest of the daemon is shared.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

/// A client of the local socket or pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// What token memory is scoped to: the uid on macOS, the user's SID on Windows.
    pub user: String,
    /// root on macOS; LocalSystem or an elevated administrator on Windows (`sudo`'s equivalent).
    pub privileged: bool,
}
