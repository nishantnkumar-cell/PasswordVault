//! Talking to `vaultd` off the UI thread, and where the pairing token lives.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use vault_core::{HwKey, OsRandom, SecureRandom};
use vault_hw::HwResult;
use vault_hw::phone::{self, Enrolled, PasskeyCred, PhoneEvent};
use vault_ipc::{
    ClientScope, ClientToken, Envelope, Request, Response, Secret, local, read_frame, write_frame,
};
use zeroize::Zeroizing;

/// Socket and token file locations.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `vaultd`'s socket.
    pub socket: PathBuf,
    /// This app's pairing token.
    pub token: PathBuf,
}

impl Paths {
    /// The same daemon as the `vault` CLI, with the app's own token file so
    /// it can be revoked separately.
    pub fn from_env() -> Paths {
        let socket = local::endpoint().unwrap_or_default();
        let token = match std::env::var_os("VAULT_DESKTOP_TOKEN_FILE") {
            Some(p) => p.into(),
            None => local::config_dir().join("desktop-token"),
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
        local::write_private(&self.token, &t[..])
            .map_err(|e| format!("{}: {e}", self.token.display()))
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

/// The phone side of a phone passkey (`vault_hw::phone`), behind a trait
/// so tests can stand in for a phone.
pub trait Phone: Send + Sync {
    /// Create a passkey, see [`phone::enroll`].
    fn enroll(
        &self,
        rp_id: &str,
        prf_input: &[u8; 32],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<Enrolled>;
    /// Ask for a PRF output, see [`phone::prf`].
    fn prf(
        &self,
        rp_id: &str,
        creds: &[PasskeyCred],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<(Vec<u8>, HwKey)>;
}

/// The phone, over Bluetooth and the QR code (Linux) or Windows' own window.
pub struct SystemPhone;

impl Phone for SystemPhone {
    fn enroll(
        &self,
        rp_id: &str,
        prf_input: &[u8; 32],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<Enrolled> {
        phone::check_available()?;
        phone::enroll(rp_id, prf_input, events)
    }
    fn prf(
        &self,
        rp_id: &str,
        creds: &[PasskeyCred],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<(Vec<u8>, HwKey)> {
        phone::check_available()?;
        phone::prf(rp_id, creds, events)
    }
}

/// What the phone ceremony asks the window to show while it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneView {
    /// A `FIDO:/` URI to show as a QR code (Linux).
    pub qr: Option<String>,
    /// The latest progress line.
    pub status: Option<String>,
}

/// What the worker does for a job.
// Like `Request`, a job lives for one round trip; boxing buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum Work {
    /// Send this request.
    Call(Request),
    /// Ask the phone for its passkey's PRF output, then unlock with it, or
    /// pair this app with `pair` (name and scope) if given.
    PhoneUnlock {
        password: Secret,
        pair: Option<(String, ClientScope)>,
    },
    /// Create a passkey on the phone and enroll it as a slot.
    PhoneEnroll { password: Secret, label: String },
}

/// One call to the daemon. `op` says what the answer is for.
pub struct Job<Op> {
    pub op: Op,
    pub token: Option<ClientToken>,
    pub work: Work,
}

/// A worker thread that owns the connection, so slow calls (Argon2, a
/// security key waiting for a touch) never freeze the window.
pub struct Backend<Op> {
    jobs: Sender<Job<Op>>,
    results: Receiver<(Op, Result<Response, Failure>)>,
    in_flight: usize,
    /// What a running phone ceremony wants shown.
    pub phone: Arc<Mutex<PhoneView>>,
}

impl<Op: Send + 'static> Backend<Op> {
    /// Start the worker. `wake` is called after each answer (to repaint).
    pub fn start(
        socket: PathBuf,
        wake: impl Fn() + Send + 'static,
        phone: Arc<dyn Phone>,
    ) -> Backend<Op> {
        let (jobs, job_rx) = channel::<Job<Op>>();
        let (result_tx, results) = channel();
        let view = Arc::new(Mutex::new(PhoneView::default()));
        let shown = view.clone();
        std::thread::spawn(move || {
            let mut stream: Option<local::Stream> = None;
            for job in job_rx {
                let r = match job.work {
                    Work::Call(request) => call(&socket, &mut stream, job.token, request),
                    work => {
                        let w = &wake;
                        let events = |e: PhoneEvent| {
                            if let Ok(mut v) = shown.lock() {
                                match e {
                                    PhoneEvent::Qr(q) => v.qr = Some(q),
                                    PhoneEvent::Status(s) => v.status = Some(s),
                                }
                            }
                            w();
                        };
                        let r = with_phone(&socket, &mut stream, job.token, work, &*phone, &events);
                        if let Ok(mut v) = shown.lock() {
                            *v = PhoneView::default();
                        }
                        r
                    }
                };
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
            phone: view,
        }
    }

    /// Queue a call.
    pub fn send(&mut self, op: Op, token: Option<ClientToken>, request: Request) {
        self.send_work(op, token, Work::Call(request));
    }

    /// Queue a call or a phone ceremony.
    pub fn send_work(&mut self, op: Op, token: Option<ClientToken>, work: Work) {
        if self.jobs.send(Job { op, token, work }).is_ok() {
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
    socket: &std::path::Path,
    stream: &mut Option<local::Stream>,
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
        *stream = Some(local::connect(socket).map_err(unreachable)?);
    }
    let s = stream.as_mut().expect("connected above");
    write_frame(s, &Envelope { token, request }).map_err(unreachable)?;
    match read_frame(s).map_err(unreachable)? {
        Response::Error(m) => Err(Failure::Daemon(m)),
        r => Ok(r),
    }
}

const NO_PHONE_SLOT: &str = "No phone is set up for this vault. Unlock another way, then add \
     your phone under Unlock methods.";

/// Run a phone job: the phone first, then the daemon call built from its answer.
fn with_phone(
    socket: &std::path::Path,
    stream: &mut Option<local::Stream>,
    token: Option<ClientToken>,
    work: Work,
    phone: &dyn Phone,
    events: &dyn Fn(PhoneEvent),
) -> Result<Response, Failure> {
    let rp = vault_hw::RP_ID;
    let fail = Failure::Daemon;
    let out = |k: HwKey| Zeroizing::new(k.expose().to_vec());
    let request = match work {
        Work::Call(r) => r,
        Work::PhoneUnlock { password, pair } => {
            let Response::PasskeySlots(slots) = call(socket, stream, None, Request::PasskeySlots)?
            else {
                return Err(fail("unexpected answer from vaultd".into()));
            };
            let creds: Vec<PasskeyCred> = slots
                .into_iter()
                .filter(|s| s.rp_id == rp)
                .map(|s| PasskeyCred {
                    credential_id: s.credential_id,
                    prf_input: s.prf_input,
                })
                .collect();
            if creds.is_empty() {
                return Err(fail(NO_PHONE_SLOT.into()));
            }
            let (credential_id, key) = phone.prf(rp, &creds, events).map_err(fail)?;
            let method = vault_ipc::UnlockMethod::Passkey {
                password,
                credential_id,
                prf_output: out(key),
            };
            match pair {
                Some((client_name, scope)) => Request::Pair {
                    client_name,
                    scope,
                    method: Some(method),
                },
                None => Request::Unlock { method },
            }
        }
        Work::PhoneEnroll { password, label } => {
            // Check the vault is open before the phone is asked.
            call(socket, stream, token.clone(), Request::ListSlots)?;
            let mut prf_input = [0u8; 32];
            OsRandom
                .fill(&mut prf_input)
                .map_err(|e| fail(e.to_string()))?;
            let made = phone.enroll(rp, &prf_input, events).map_err(fail)?;
            let key = match made.prf {
                Some(k) => k,
                None => {
                    events(PhoneEvent::Status(
                        "Passkey created. Confirm it once more on your phone so the vault can \
                         test it."
                            .into(),
                    ));
                    let cred = PasskeyCred {
                        credential_id: made.credential_id.clone(),
                        prf_input,
                    };
                    phone.prf(rp, &[cred], events).map_err(fail)?.1
                }
            };
            Request::AddPasskeySlot {
                password,
                credential_id: made.credential_id,
                prf_input,
                prf_output: out(key),
                label,
            }
        }
    };
    call(socket, stream, token, request)
}
