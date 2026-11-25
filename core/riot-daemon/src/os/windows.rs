//! Windows: the named pipe and its clients' identity, files only the daemon's user may read
//! (DACLs), the protected data folder, process liveness, the registry, and SMBIOS.
//!
//! LocalSystem plays root's part: the service runs as it, and what is "root only" on macOS is
//! LocalSystem or an elevated administrator here.
//!
//! The daemon's only `unsafe` code is here (`#![deny(unsafe_code)]` elsewhere): the Win32 calls
//! that no maintained crate wraps safely. The registry goes through
//! `windows-registry` and file identity through `file-id`, which are safe to call.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_SUCCESS, HANDLE, LocalFree, STILL_ACTIVE, WIN32_ERROR};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

use super::Peer;

/// LocalSystem, the account the service runs as.
pub const LOCAL_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators: the default owner of what LocalSystem creates.
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// Folder and files: LocalSystem and elevated administrators only, inherited by what is
/// created inside. Unlike `/Library/Application Support`, `%ProgramData%` lets every user
/// create files in new folders: its inherited permissions must not apply.
const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Win32's "not found" (`ERROR_FILE_NOT_FOUND`) as the HRESULT `windows-registry` returns.
const HRESULT_NOT_FOUND: i32 = 0x8007_0002_u32 as i32;

/// `%ProgramData%\Riot`.
pub fn default_data_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into()).join("Riot")
}

/// As LocalSystem (the service), the folder is created with its own permissions, never
/// `%ProgramData%`'s; an existing one must belong to LocalSystem or the administrators (any
/// user may create a folder there first, keys included), and gets its permissions back.
/// Unprivileged (development), it is an ordinary folder.
pub fn prepare_data_dir(dir: &Path) -> io::Result<()> {
    if !is_local_system() {
        return std::fs::create_dir_all(dir);
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let descriptor = Descriptor::parse(DATA_DIR_SDDL)?;
    let attributes = descriptor.attributes();
    // SAFETY: valid NUL-terminated path; the attributes outlive the call.
    if unsafe { CreateDirectoryW(wide(dir).as_ptr(), &attributes) } != 0 {
        return Ok(());
    }
    let created = io::Error::last_os_error();
    if !dir.is_dir() {
        return Err(created);
    }
    let owner = owner_sid(dir)?;
    if owner != LOCAL_SYSTEM && owner != ADMINISTRATORS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} belongs to {owner}, not to LocalSystem or the administrators: refusing to keep keys in it", dir.display()),
        ));
    }
    set_dacl(dir, &descriptor)
}

// ---------- the pipe ----------

/// An instance of the daemon's pipe. Full control for LocalSystem and the daemon's own user (who
/// creates every instance); for authenticated users read and write without
/// `FILE_CREATE_PIPE_INSTANCE` (0x12019b): they can connect, not serve the pipe in the daemon's
/// place. `first`: the first instance must be the daemon's own, a pipe of that name created by
/// anyone else first is refused rather than joined.
pub fn create_pipe(name: &Path, first: bool) -> io::Result<NamedPipeServer> {
    let me = current_user_sid()?;
    let descriptor = Descriptor::parse(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{me})(A;;0x12019b;;;AU)"))?;
    let mut attributes = descriptor.attributes();
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: valid attributes for the call; the pipe keeps its own copy of the descriptor.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}

/// Who is at the other end of a connected pipe instance: the user of the client process's token.
pub fn pipe_peer(pipe: &NamedPipeServer) -> io::Result<Peer> {
    let mut pid = 0;
    // SAFETY: a valid pipe handle for the call; `pid` is a plain out-param.
    check(unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) })?;
    Token::of_process(pid)?.peer()
}

// ---------- files and processes ----------

/// Readable and writable by LocalSystem and the daemon's user only (`0600`'s equivalent),
/// whatever the folder lets others do. The permissions are set before anything is written.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
    set_dacl(path, &Descriptor::parse(&private_sddl()?)?)?;
    io::Write::write_all(&mut f, bytes)
}

pub(crate) fn private_sddl() -> io::Result<String> {
    let me = current_user_sid()?;
    Ok(if me == LOCAL_SYSTEM { "D:P(A;;FA;;;SY)".into() } else { format!("D:P(A;;FA;;;SY)(A;;FA;;;{me})") })
}

pub fn process_exists(pid: u32) -> bool {
    match Handle::process(pid) {
        Ok(process) => {
            let mut code = 0;
            // SAFETY: a valid process handle; `code` is a plain out-param.
            (unsafe { GetExitCodeProcess(process.0, &mut code) }) != 0 && code == STILL_ACTIVE as u32
        }
        // Another user's process may not be opened, but it exists.
        Err(e) => e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32),
    }
}

// ---------- machine facts ----------

/// The SMBIOS system UUID and serial number (structure type 1), as `Win32_ComputerSystemProduct`
/// shows them: the hardware UUID, like macOS's `IOPlatformUUID`.
pub fn machine_ids() -> (Option<String>, Option<String>) {
    // SAFETY: a null buffer of size 0 asks for the size.
    let size = unsafe { GetSystemFirmwareTable(RSMB, 0, null_mut(), 0) };
    let mut raw = vec![0u8; size as usize];
    // SAFETY: the buffer holds `size` bytes.
    if size == 0 || unsafe { GetSystemFirmwareTable(RSMB, 0, raw.as_mut_ptr(), size) } != size {
        return (None, None);
    }
    parse_smbios(&raw)
}

/// `RawSMBIOSData`: four version bytes, the table's length, then the structures, each a
/// formatted area followed by its strings and a double NUL.
fn parse_smbios(raw: &[u8]) -> (Option<String>, Option<String>) {
    let Some(len) = raw.get(4..8).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) else { return (None, None) };
    let table = &raw[8..raw.len().min(8 + len)];
    let mut at = 0;
    while at + 4 <= table.len() {
        let (kind, length) = (table[at], usize::from(table[at + 1]));
        if length < 4 || at + length > table.len() {
            break;
        }
        let formatted = &table[at..at + length];
        let mut end = at + length;
        while end + 1 < table.len() && !(table[end] == 0 && table[end + 1] == 0) {
            end += 1;
        }
        if kind == 1 {
            let strings: Vec<&[u8]> = table[at + length..end].split(|&b| b == 0).collect();
            let serial = formatted
                .get(7)
                .and_then(|&i| strings.get(usize::from(i).checked_sub(1)?))
                .map(|s| String::from_utf8_lossy(s).trim().to_owned())
                .filter(|s| !s.is_empty());
            // 0 means "not set", all 0xFF "not present".
            let uuid = formatted.get(8..24).filter(|u| u.iter().any(|&b| b != 0) && u.iter().any(|&b| b != 0xff)).map(|u| {
                // The first three fields are little-endian (SMBIOS 2.6 and later).
                format!(
                    "{:08X}-{:04X}-{:04X}-{}-{}",
                    u32::from_le_bytes([u[0], u[1], u[2], u[3]]),
                    u16::from_le_bytes([u[4], u[5]]),
                    u16::from_le_bytes([u[6], u[7]]),
                    hex::encode_upper(&u[8..10]),
                    hex::encode_upper(&u[10..16]),
                )
            });
            return (uuid, serial);
        }
        if kind == 127 {
            break; // end of table
        }
        at = end + 2;
    }
    (None, None)
}

/// `10.0.26100.7171`: major, minor, build and update revision.
pub fn os_version() -> String {
    let Ok(Some(key)) = open_key(Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") else { return String::new() };
    let number = |name| key.get_u32(name).ok().map(|v| v.to_string());
    let parts = [number("CurrentMajorVersionNumber"), number("CurrentMinorVersionNumber"), key.get_string("CurrentBuildNumber").ok(), number("UBR")];
    parts.into_iter().map_while(|p| p).collect::<Vec<_>>().join(".")
}

/// Not known on Windows yet: how a protected app is identified there (executable, package
/// family, signer) is decided with the clipboard guard.
pub fn is_installed(_app_id: &str) -> bool {
    false
}

// ---------- registry ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    LocalMachine,
    /// For tests, which may not write `HKEY_LOCAL_MACHINE`.
    #[cfg_attr(not(test), allow(dead_code))]
    CurrentUser,
}

impl Hive {
    pub fn key(self) -> &'static windows_registry::Key {
        match self {
            Self::LocalMachine => windows_registry::LOCAL_MACHINE,
            Self::CurrentUser => windows_registry::CURRENT_USER,
        }
    }
}

impl std::fmt::Display for Hive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LocalMachine => "HKLM",
            Self::CurrentUser => "HKCU",
        })
    }
}

/// A key, read-only, in the 64-bit view whatever the process; `None` when it does not exist.
pub fn open_key(hive: Hive, path: &str) -> io::Result<Option<windows_registry::Key>> {
    optional(hive.key().options().read().wow64_64().open(path))
}

/// A string value; `None` when it does not exist.
pub fn string_value(key: &windows_registry::Key, name: &str) -> io::Result<Option<String>> {
    optional(key.get_string(name))
}

fn optional<T>(result: windows_registry::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.code().0 == HRESULT_NOT_FOUND => Ok(None),
        Err(e) => Err(io::Error::other(e)),
    }
}

// ---------- tokens and security descriptors ----------

pub fn current_user_sid() -> io::Result<String> {
    Token::of_process(std::process::id())?.user_sid()
}

pub fn is_local_system() -> bool {
    current_user_sid().is_ok_and(|sid| sid == LOCAL_SYSTEM)
}

/// This process, as a client of its own daemon would be seen.
#[cfg(test)]
pub fn current_peer() -> io::Result<Peer> {
    Token::of_process(std::process::id())?.peer()
}

struct Token(Handle);

impl Token {
    fn of_process(pid: u32) -> io::Result<Self> {
        let process = Handle::process(pid)?;
        let mut token = null_mut();
        // SAFETY: a valid process handle; `token` is a plain out-param.
        check(unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) })?;
        Ok(Self(Handle(token)))
    }

    fn peer(&self) -> io::Result<Peer> {
        let user = self.user_sid()?;
        let privileged = user == LOCAL_SYSTEM || self.elevated()?;
        Ok(Peer { user, privileged })
    }

    fn user_sid(&self) -> io::Result<String> {
        // TOKEN_USER is followed by the SID it points to: a buffer aligned for it, sized by Windows.
        let mut len = 0;
        // SAFETY: a null buffer of size 0 asks for the size (the call fails, by design).
        unsafe { GetTokenInformation(self.0.0, TokenUser, null_mut(), 0, &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: the buffer holds at least `len` bytes, aligned for TOKEN_USER.
        check(unsafe { GetTokenInformation(self.0.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) })?;
        // SAFETY: `TokenUser` filled a TOKEN_USER whose SID points into `buf`, alive here.
        sid_string(unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })
    }

    fn elevated(&self) -> io::Result<bool> {
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0;
        let size = size_of::<TOKEN_ELEVATION>() as u32;
        // SAFETY: the out-param is a TOKEN_ELEVATION of the size given.
        check(unsafe { GetTokenInformation(self.0.0, TokenElevation, (&raw mut elevation).cast(), size, &mut len) })?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut out = null_mut();
    // SAFETY: a valid SID; Windows allocates `out`, freed by `Local`.
    check(unsafe { ConvertSidToStringSidW(sid, &mut out) })?;
    Local(out.cast()).wide_string()
}

fn owner_sid(path: &Path) -> io::Result<String> {
    let (mut owner, mut descriptor): (PSID, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut());
    let path = wide(path);
    // SAFETY: valid path; Windows allocates the descriptor (freed by `Local`), `owner` points into it.
    ok(unsafe {
        GetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, null_mut(), null_mut(), null_mut(), &mut descriptor)
    })?;
    let _descriptor = Local(descriptor);
    sid_string(owner)
}

/// A security descriptor parsed from SDDL.
struct Descriptor(Local);

impl Descriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let mut descriptor = null_mut();
        // SAFETY: valid NUL-terminated SDDL; Windows allocates the descriptor, freed by `Local`.
        check(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut()) })?;
        Ok(Self(Local(descriptor)))
    }

    /// Valid while `self` lives.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: self.0.0, bInheritHandle: 0 }
    }

    /// Points into `self`.
    fn dacl(&self) -> io::Result<*const ACL> {
        let (mut present, mut dacl, mut defaulted) = (0, null_mut(), 0);
        // SAFETY: a valid descriptor; `dacl` points into it.
        check(unsafe { GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) })?;
        Ok(dacl)
    }
}

/// Replaces the DACL, not inheriting the parent's (`P`), and propagates it to what inherits.
fn set_dacl(path: &Path, descriptor: &Descriptor) -> io::Result<()> {
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let (path, dacl) = (wide(path), descriptor.dacl()?);
    // SAFETY: valid path and ACL (alive in `descriptor`) for the call.
    ok(unsafe { SetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, info, null_mut(), null_mut(), dacl, null()) })
}

/// A file's DACL as SDDL, for tests.
#[cfg(test)]
pub(crate) fn dacl_sddl(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let path = wide(path);
    // SAFETY: valid path; Windows allocates the descriptor, freed by `Local`.
    ok(unsafe {
        GetNamedSecurityInfoW(path.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), null_mut(), null_mut(), &mut descriptor)
    })?;
    let descriptor = Local(descriptor);
    let mut out = null_mut();
    // SAFETY: a valid descriptor; Windows allocates `out`, freed by `Local`.
    check(unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor.0, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut out, null_mut()) })?;
    Local(out.cast()).wide_string()
}

// ---------- owned handles and memory ----------

struct Handle(HANDLE);

impl Handle {
    fn process(pid: u32) -> io::Result<Self> {
        // SAFETY: no pointer arguments.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(handle)) }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: owned handle, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Memory Windows allocated with `LocalAlloc`.
struct Local(*mut c_void);

impl Local {
    /// The NUL-terminated UTF-16 string it holds.
    fn wide_string(&self) -> io::Result<String> {
        let p = self.0.cast::<u16>();
        // SAFETY: Windows returned a NUL-terminated string; `len` units precede the NUL.
        let units = unsafe { std::slice::from_raw_parts(p, (0..).take_while(|&i| *p.add(i) != 0).count()) };
        String::from_utf16(units).map_err(io::Error::other)
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by Windows for us, freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn check(result: windows_sys::core::BOOL) -> io::Result<()> {
    if result != 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

fn ok(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(status as i32)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smbios_system_structure_gives_the_uuid_and_serial() {
        // A BIOS structure (type 0) with one string, then the system structure (type 1).
        let mut table = vec![0u8, 4, 0, 0];
        table.extend(b"bios\0\0");
        let mut system = vec![1u8, 0x1b, 1, 0, 1, 2, 0, 3];
        system.extend([0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        system.extend([0, 0, 0]);
        table.extend(system);
        table.extend(b"Maker\0Model\0  SN-42 \0\0");
        table.extend([127, 4, 0, 0, 0, 0]);
        let mut raw = vec![0, 3, 4, 0];
        raw.extend((table.len() as u32).to_le_bytes());
        raw.extend(table);
        let (uuid, serial) = parse_smbios(&raw);
        assert_eq!(uuid.as_deref(), Some("00112233-4455-6677-8899-AABBCCDDEEFF"));
        assert_eq!(serial.as_deref(), Some("SN-42"));
        assert_eq!(parse_smbios(&raw[..6]), (None, None));
    }

    #[test]
    fn this_machine_has_facts_and_a_live_process() {
        let (uuid, _) = machine_ids();
        assert!(uuid.is_some_and(|u| u.len() == 36));
        assert!(os_version().starts_with("10.0."));
        assert!(process_exists(std::process::id()));
        assert!(!process_exists(u32::MAX - 1));
        assert!(current_user_sid().unwrap().starts_with("S-1-5-"));
    }

    #[test]
    fn a_missing_key_or_value_is_none() {
        assert!(open_key(Hive::CurrentUser, r"Software\Riot-test-never-created").unwrap().is_none());
        let key = open_key(Hive::LocalMachine, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").unwrap().unwrap();
        assert!(string_value(&key, "CurrentBuildNumber").unwrap().is_some());
        assert!(string_value(&key, "Riot-no-such-value").unwrap().is_none());
    }
}
