//! Where things live on this machine and how a client reaches `vaultd`: a
//! Unix socket, or on Windows a named pipe whose server must run as the same
//! user (so another account cannot squat the name and collect passwords).

use std::io;
use std::path::PathBuf;

#[cfg(unix)]
fn home(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| home(fallback))
        .join("vault")
}

/// `~/Library/Application Support/vault`, unless an XDG variable says
/// otherwise (for people who keep dotfiles the Linux way).
#[cfg(target_os = "macos")]
fn xdg(var: &str, _fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| home("Library/Application Support"))
        .join("vault")
}

#[cfg(windows)]
fn win(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("USERPROFILE").unwrap_or_default()).join(fallback)
        })
        .join("vault")
}

/// Client settings and pairing tokens.
pub fn config_dir() -> PathBuf {
    #[cfg(unix)]
    return xdg("XDG_CONFIG_HOME", ".config");
    #[cfg(windows)]
    return win("APPDATA", r"AppData\Roaming");
}

/// The vault file's directory.
pub fn data_dir() -> PathBuf {
    #[cfg(unix)]
    return xdg("XDG_DATA_HOME", ".local/share");
    #[cfg(windows)]
    return win("LOCALAPPDATA", r"AppData\Local");
}

/// The daemon's own state (lock file, client list, generation).
pub fn state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    if std::env::var_os("XDG_STATE_HOME").is_none() {
        return data_dir().join("state");
    }
    #[cfg(unix)]
    return xdg("XDG_STATE_HOME", ".local/state");
    #[cfg(windows)]
    return win("LOCALAPPDATA", r"AppData\Local").join("state");
}

/// Where `vaultd` listens: `VAULT_SOCKET`, else a socket in the runtime
/// directory, or on Windows `\\.\pipe\vaultd-<user SID>`.
pub fn endpoint() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os("VAULT_SOCKET") {
        return Ok(p.into());
    }
    #[cfg(unix)]
    return Ok(match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("vault/vaultd.sock"),
        None => state_dir().join("vaultd.sock"),
    });
    #[cfg(windows)]
    {
        let sid = crate::win::sid_string(&crate::win::current_user()?)?;
        Ok(PathBuf::from(format!(r"\\.\pipe\vaultd-{sid}")))
    }
}

/// Where `vaultd` serves the ssh-agent protocol (point `SSH_AUTH_SOCK`
/// here): a socket next to the daemon's, or on Windows
/// `\\.\pipe\vaultd-ssh-<user SID>`.
pub fn ssh_agent_endpoint() -> io::Result<PathBuf> {
    #[cfg(unix)]
    return Ok(match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("vault/ssh-agent.sock"),
        None => state_dir().join("ssh-agent.sock"),
    });
    #[cfg(windows)]
    {
        let sid = crate::win::sid_string(&crate::win::current_user()?)?;
        Ok(PathBuf::from(format!(r"\\.\pipe\vaultd-ssh-{sid}")))
    }
}

/// A connection to the daemon.
#[cfg(unix)]
pub type Stream = std::os::unix::net::UnixStream;
/// A connection to the daemon.
#[cfg(windows)]
pub type Stream = std::fs::File;

/// Connect to the daemon at `path`.
#[cfg(unix)]
pub fn connect(path: &std::path::Path) -> io::Result<Stream> {
    Stream::connect(path)
}

/// Connect to the daemon at `path`, refusing a pipe served by another user.
#[cfg(windows)]
pub fn connect(path: &std::path::Path) -> io::Result<Stream> {
    use std::os::windows::fs::OpenOptionsExt;
    // Identification only: the server may learn who we are, not act as us.
    const SECURITY_IDENTIFICATION: u32 = 1 << 16;
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut tries = 0;
    let f = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)
        {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            r => break r?,
        }
    };
    let server = crate::win::process_user(crate::win::pipe_server_pid(&f)?)?;
    if server != crate::win::current_user()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the vaultd pipe is served by another user",
        ));
    }
    Ok(f)
}

/// Write a file only this user can read: mode 0600 on Unix. On Windows the
/// per-user profile directories already carry that ACL.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).truncate(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)?.write_all(bytes)
}
