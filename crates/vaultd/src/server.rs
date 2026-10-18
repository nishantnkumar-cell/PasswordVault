//! The socket server: one thread per connection, every connection checked
//! against the peer's user before it reaches the daemon. A Unix socket
//! (peer UID) or, on Windows, a named pipe (peer token's user SID).

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vault_ipc::{Envelope, Response, read_frame, write_frame};

use crate::daemon::Daemon;

pub type Shared = Arc<Mutex<Daemon>>;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

fn refuse(s: &mut impl Write) -> io::Result<()> {
    write_frame(
        s,
        &Response::Error("this vault belongs to another user".into()),
    )
}

fn connection(mut s: impl Read + Write, daemon: &Shared) -> io::Result<()> {
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

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    use super::*;

    /// Who may connect: a UID.
    pub type Owner = u32;
    pub type Listener = UnixListener;

    /// The user running this process.
    pub fn current_user() -> Owner {
        nix::unistd::getuid().as_raw()
    }

    /// Bind the socket, replacing a stale one. A daemon serving its own user
    /// makes the socket 0600 in a 0700 directory. A daemon running as a
    /// separate system user (`shared`) must let the owner reach it, so the
    /// socket is 0666 in a 0755 directory and the peer-UID check in [`serve`]
    /// is the gate.
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
    pub fn serve(listener: UnixListener, daemon: Shared, owner: Owner) {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let d = daemon.clone();
            std::thread::spawn(move || {
                let Ok(cred) = getsockopt(&conn, PeerCredentials) else {
                    return;
                };
                if cred.uid() != owner {
                    let _ = refuse(&mut conn);
                    return;
                }
                let _ = conn.set_read_timeout(Some(Duration::from_secs(600)));
                let _ = connection(conn, &d);
            });
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
    use std::ptr::null_mut;

    use vault_ipc::win;
    use windows_sys::Win32::Foundation::{
        ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    use super::*;

    /// Who may connect: a user SID.
    pub type Owner = Vec<u8>;

    /// The user running this process.
    pub fn current_user() -> Owner {
        win::current_user().expect("reading this process's token")
    }

    /// A named pipe whose ACL admits only the owner, local clients only.
    pub struct Listener {
        name: Vec<u16>,
        sd: PSECURITY_DESCRIPTOR,
        first: Option<OwnedHandle>,
    }

    // The security descriptor is only read, from the accept loop.
    unsafe impl Send for Listener {}

    impl Drop for Listener {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.sd) };
        }
    }

    impl Listener {
        fn instance(&self, first: bool) -> io::Result<OwnedHandle> {
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.sd,
                bInheritHandle: 0,
            };
            let flags = PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                };
            // SAFETY: `name` is NUL-terminated and `sa` outlives the call.
            let h = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    flags,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    64 * 1024,
                    64 * 1024,
                    0,
                    &sa,
                )
            };
            if h == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a new handle we own.
            Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) })
        }
    }

    /// Create the pipe. Fails if the name is taken: another vaultd, or
    /// someone squatting it. `shared` (a separate system user) is Unix-only.
    pub fn bind(path: &Path, shared: bool) -> io::Result<Listener> {
        if shared {
            return Err(io::Error::other(
                "serving another user is not supported on Windows",
            ));
        }
        let sid = win::sid_string(&win::current_user()?)?;
        // Protected DACL: full access for this user, nobody else.
        let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut l = Listener {
            name: path.as_os_str().encode_wide().chain([0]).collect(),
            sd,
            first: None,
        };
        l.first = Some(l.instance(true).map_err(|e| {
            io::Error::other(format!(
                "cannot create the pipe (another vaultd may be running): {e}"
            ))
        })?);
        Ok(l)
    }

    /// Accept connections forever.
    pub fn serve(mut listener: Listener, daemon: Shared, owner: Owner) {
        loop {
            let h = match listener.first.take() {
                Some(h) => h,
                None => match listener.instance(false) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("vaultd: cannot create a pipe instance: {e}");
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                },
            };
            use std::os::windows::io::AsRawHandle;
            // SAFETY: `h` is a pipe instance we own; blocks until a client connects.
            let ok = unsafe { ConnectNamedPipe(h.as_raw_handle() as _, null_mut()) };
            if ok == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
                continue;
            }
            let mut conn = File::from(h);
            let d = daemon.clone();
            let owner = owner.clone();
            std::thread::spawn(move || {
                let peer = win::pipe_client_pid(&conn).and_then(win::process_user);
                if peer.ok().as_ref() != Some(&owner) {
                    let _ = refuse(&mut conn);
                    return;
                }
                let _ = connection(conn, &d);
            });
        }
    }
}
