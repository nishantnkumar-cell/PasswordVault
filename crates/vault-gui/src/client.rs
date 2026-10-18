//! Talking to `vaultd` off the UI thread, and where the pairing token lives.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};

use vault_ipc::{ClientToken, Envelope, Request, Response, read_frame, write_frame};
use zeroize::Zeroizing;

/// Socket and token file locations.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `vaultd`'s socket.
    pub socket: PathBuf,
    /// This app's pairing token.
    pub token: PathBuf,
}

fn home(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

impl Paths {
    /// The same defaults as the `vault` CLI, with the app's own token file
    /// so it can be revoked separately.
    pub fn from_env() -> Paths {
        let socket = match (
            std::env::var_os("VAULT_SOCKET"),
            std::env::var_os("XDG_RUNTIME_DIR"),
        ) {
            (Some(p), _) => p.into(),
            (None, Some(d)) => PathBuf::from(d).join("vault/vaultd.sock"),
            (None, None) => std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home(".local/state"))
                .join("vault/vaultd.sock"),
        };
        let token = match std::env::var_os("VAULT_DESKTOP_TOKEN_FILE") {
            Some(p) => p.into(),
            None => std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home(".config"))
                .join("vault/desktop-token"),
        };
        Paths { socket, token }
    }

    /// The stored token, if any.
    pub fn load_token(&self) -> Option<ClientToken> {
        let bytes = Zeroizing::new(std::fs::read(&self.token).ok()?);
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(Zeroizing::new(arr))
    }

    /// Store a token, readable only by this user.
    pub fn save_token(&self, t: &ClientToken) -> Result<(), String> {
        let err = |e: std::io::Error| format!("{}: {e}", self.token.display());
        if let Some(d) = self.token.parent() {
            std::fs::create_dir_all(d).map_err(err)?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&self.token)
            .and_then(|mut f| f.write_all(&t[..]))
            .map_err(err)
    }

    /// Delete a token the daemon no longer knows.
    pub fn forget_token(&self) {
        let _ = std::fs::remove_file(&self.token);
    }
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// No daemon at the socket, or the connection dropped.
    Unreachable(String),
    /// The daemon refused, with a message safe to show.
    Daemon(String),
}

/// One call to the daemon. `op` says what the answer is for.
pub struct Job<Op> {
    pub op: Op,
    pub token: Option<ClientToken>,
    pub request: Request,
}

/// A worker thread that owns the connection, so slow calls (Argon2, a
/// security key waiting for a touch) never freeze the window.
pub struct Backend<Op> {
    jobs: Sender<Job<Op>>,
    results: Receiver<(Op, Result<Response, Failure>)>,
    in_flight: usize,
}

impl<Op: Send + 'static> Backend<Op> {
    /// Start the worker. `wake` is called after each answer (to repaint).
    pub fn start(socket: PathBuf, wake: impl Fn() + Send + 'static) -> Backend<Op> {
        let (jobs, job_rx) = channel::<Job<Op>>();
        let (result_tx, results) = channel();
        std::thread::spawn(move || {
            let mut stream: Option<UnixStream> = None;
            for job in job_rx {
                let r = call(&socket, &mut stream, job.token, job.request);
                if r.is_err() {
                    stream = None;
                }
                if result_tx.send((job.op, r)).is_err() {
                    return;
                }
                wake();
            }
        });
        Backend {
            jobs,
            results,
            in_flight: 0,
        }
    }

    /// Queue a call.
    pub fn send(&mut self, op: Op, token: Option<ClientToken>, request: Request) {
        if self.jobs.send(Job { op, token, request }).is_ok() {
            self.in_flight += 1;
        }
    }

    /// Answers that have arrived.
    pub fn poll(&mut self) -> Vec<(Op, Result<Response, Failure>)> {
        let out: Vec<_> = self.results.try_iter().collect();
        self.in_flight -= out.len();
        out
    }

    /// Calls still waiting for an answer.
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }
}

fn call(
    socket: &PathBuf,
    stream: &mut Option<UnixStream>,
    token: Option<ClientToken>,
    request: Request,
) -> Result<Response, Failure> {
    let unreachable = |e: std::io::Error| {
        Failure::Unreachable(format!(
            "Can't reach vaultd at {}: {e}. Is it running?",
            socket.display()
        ))
    };
    if stream.is_none() {
        *stream = Some(UnixStream::connect(socket).map_err(unreachable)?);
    }
    let s = stream.as_mut().expect("connected above");
    write_frame(s, &Envelope { token, request }).map_err(unreachable)?;
    match read_frame(s).map_err(unreachable)? {
        Response::Error(m) => Err(Failure::Daemon(m)),
        r => Ok(r),
    }
}
