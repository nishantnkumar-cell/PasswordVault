//! The Unix socket server: one thread per connection, every request checked
//! against the socket peer's UID before it reaches the daemon.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use vault_ipc::{Envelope, Response, read_frame, write_frame};

use crate::daemon::Daemon;

pub type Shared = Arc<Mutex<Daemon>>;

/// Bind the socket, replacing a stale one. A daemon serving its own user
/// makes the socket 0600 in a 0700 directory. A daemon running as a separate
/// system user (`shared`) must let the owner reach it, so the socket is 0666
/// in a 0755 directory and the peer-UID check in [`serve`] is the gate.
pub fn bind(path: &Path, shared: bool) -> io::Result<UnixListener> {
    let (dir_mode, sock_mode) = if shared {
        (0o755, 0o666)
    } else {
        (0o700, 0o600)
    };
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(io::Error::other(
                "another vaultd is listening on this socket",
            ));
        }
        std::fs::remove_file(path)?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode))?;
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(sock_mode))?;
    Ok(l)
}

/// Accept connections forever.
pub fn serve(listener: UnixListener, daemon: Shared, owner_uid: u32) {
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let d = daemon.clone();
        std::thread::spawn(move || {
            let _ = connection(conn, &d, owner_uid);
        });
    }
}

fn connection(mut s: UnixStream, daemon: &Shared, owner_uid: u32) -> io::Result<()> {
    let cred = getsockopt(&s, PeerCredentials).map_err(io::Error::from)?;
    if cred.uid() != owner_uid {
        return write_frame(
            &mut s,
            &Response::Error("this vault belongs to another user".into()),
        );
    }
    s.set_read_timeout(Some(Duration::from_secs(600)))?;
    loop {
        let env: Envelope = match read_frame(&mut s) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => {
                let _ = write_frame(&mut s, &Response::Error(format!("bad request: {e}")));
                return Err(e);
            }
        };
        let resp = daemon.lock().unwrap_or_else(|p| p.into_inner()).handle(env);
        write_frame(&mut s, &resp)?;
    }
}

/// Lock the vault when idle. Runs on its own thread.
pub fn idle_locker(daemon: Shared) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        daemon.lock().unwrap_or_else(|p| p.into_inner()).tick();
    }
}
