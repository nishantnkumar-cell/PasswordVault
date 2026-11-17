//! Where things live on this machine and how a client reaches `vaultd`: a
//! Unix socket, or on Windows a named pipe whose server must run as the same
//! user (so another account cannot squat the name and collect passwords).

use std::io;
use std::path::{Path, PathBuf};

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

/// Where clients connect: [`endpoint`], except that on Linux, with
/// `VAULT_SOCKET` unset and no daemon of your own at the default place, the
/// system service's socket `/run/vault/<your login>/vaultd.sock` is used
/// when it exists. So programs find `vaultd@you` (installed by the .deb, the
/// Arch package or `get.sh`) without any setting. Only root can make folders
/// in `/run/vault`, so nobody else can put a socket there for you.
pub fn client_endpoint() -> io::Result<PathBuf> {
    let own = endpoint()?;
    #[cfg(target_os = "linux")]
    if std::env::var_os("VAULT_SOCKET").is_none()
        && !own.exists()
        && let Some(sys) = system_service_dir().map(|d| d.join("vaultd.sock"))
        && sys.exists()
    {
        return Ok(sys);
    }
    Ok(own)
}

/// [`ssh_agent_endpoint`] for clients, with the same fallback to the
/// system service as [`client_endpoint`].
pub fn client_ssh_agent_endpoint() -> io::Result<PathBuf> {
    let own = ssh_agent_endpoint()?;
    #[cfg(target_os = "linux")]
    if std::env::var_os("VAULT_SOCKET").is_none()
        && std::env::var_os("VAULT_SSH_AGENT").is_none()
        && !endpoint()?.exists()
        && let Some(dir) = system_service_dir()
        && dir.join("vaultd.sock").exists()
    {
        return Ok(dir.join("ssh-agent.sock"));
    }
    Ok(own)
}

/// `/run/vault/<login>`, the system service's runtime folder for this user.
#[cfg(target_os = "linux")]
fn system_service_dir() -> Option<PathBuf> {
    let name = login_name()?;
    // A login name is one path component; anything else is not ours.
    if name.is_empty() || name.contains('/') || name.starts_with('.') {
        return None;
    }
    Some(PathBuf::from("/run/vault").join(name))
}

/// This process's login name: from /etc/passwd by its real UID, else `$USER`.
#[cfg(target_os = "linux")]
fn login_name() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .to_owned();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    passwd_name(&passwd, &uid).or_else(|| std::env::var("USER").ok())
}

/// The name of `uid` in a passwd file's text.
#[cfg(any(target_os = "linux", test))]
fn passwd_name(passwd: &str, uid: &str) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let (name, _, id) = (f.next()?, f.next()?, f.next()?);
        (id == uid).then(|| name.to_owned())
    })
}

/// Where `vaultd` serves the ssh-agent protocol (point `SSH_AUTH_SOCK`
/// here): `VAULT_SSH_AGENT` if set; else, with `VAULT_SOCKET` set, next to
/// that socket (`ssh-agent.sock` in its folder, or `<pipe>-ssh` on
/// Windows), so a second vaultd on its own socket never shares an agent
/// with the first; else a socket next to the daemon's default one, or on
/// Windows `\\.\pipe\vaultd-ssh-<user SID>`. vaultd and `vault ssh agent`
/// both use this, so they agree.
pub fn ssh_agent_endpoint() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os("VAULT_SSH_AGENT") {
        return Ok(p.into());
    }
    if let Some(p) = std::env::var_os("VAULT_SOCKET") {
        return Ok(ssh_agent_for(Path::new(&p)));
    }
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

/// The agent endpoint that goes with a daemon endpoint other than the
/// default one.
pub fn ssh_agent_for(socket: &Path) -> PathBuf {
    #[cfg(unix)]
    return socket
        .parent()
        .unwrap_or(Path::new("."))
        .join("ssh-agent.sock");
    #[cfg(windows)]
    {
        let mut s = socket.as_os_str().to_owned();
        s.push("-ssh");
        PathBuf::from(s)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn agent_sits_next_to_a_custom_socket() {
        assert_eq!(
            ssh_agent_for(Path::new("/tmp/scratch/run/vaultd.sock")),
            PathBuf::from("/tmp/scratch/run/ssh-agent.sock")
        );
    }

    #[test]
    fn login_name_from_passwd() {
        let passwd = "root:x:0:0::/root:/bin/sh\nalex:x:1000:1000:Alex Example:/home/alex:/bin/bash\n\
                      vault-alex:x:998:998:Secret Vault daemon for alex:/var/lib/vault/alex:/usr/sbin/nologin\n";
        assert_eq!(passwd_name(passwd, "1000").as_deref(), Some("alex"));
        assert_eq!(passwd_name(passwd, "998").as_deref(), Some("vault-alex"));
        assert_eq!(passwd_name(passwd, "5"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clients_use_their_own_socket_when_set() {
        // VAULT_SOCKET wins over the system service fallback.
        if std::env::var_os("VAULT_SOCKET").is_some() {
            assert_eq!(client_endpoint().unwrap(), endpoint().unwrap());
        }
        assert!(system_service_dir().is_some_and(|d| d.starts_with("/run/vault/")));
    }
}
