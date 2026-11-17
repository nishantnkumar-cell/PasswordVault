//! `vault-sync`: mirrors this device's cloud mailbox to the `cloud` folder
//! next to the vault file, which `vaultd` keeps in sync like any synced
//! folder (docs/cloud-sync.md). It holds only the encrypted file and this
//! device's access token, never a key, so `vaultd` keeps its no-network
//! sandbox.
//!
//! Usage: vault-sync [--dir DIR] [--once]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use vault_cloud::{Fetched, Mailbox, Saved, digest};
use vault_ipc::{CLOUD_COPY_FILE, CLOUD_DEVICE_FILE, CloudDevice};

/// How often the local copy is checked for a change `vaultd` wrote.
const LOCAL_CHECK: Duration = Duration::from_secs(1);
/// How often the server is asked even without a change notice.
const REMOTE_CHECK_WATCHING: Duration = Duration::from_secs(15 * 60);
const REMOTE_CHECK_POLLING: Duration = Duration::from_secs(30);

fn log(msg: &str) {
    let _ = writeln!(io::stderr(), "vault-sync: {msg}");
}

fn usage() -> ! {
    eprintln!(
        "usage: vault-sync [--dir DIR] [--once]\n\n\
         Mirrors this device's cloud sync mailbox to DIR (default: the `cloud`\n\
         folder next to the vault file). Set it up with `vault cloud setup` or\n\
         `vault cloud join`; see docs/user-guide/15-cloud-sync.md."
    );
    std::process::exit(2)
}

fn main() {
    let mut dir = vault_ipc::local::data_dir().join("cloud");
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dir" => dir = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--once" => once = true,
            "-h" | "--help" => usage(),
            "--version" => {
                println!("vault-sync {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => usage(),
        }
    }
    if once {
        let Some(device) = read_device(&dir) else {
            log(&format!("no {CLOUD_DEVICE_FILE} in {}", dir.display()));
            std::process::exit(1);
        };
        let mut m = match Mirror::new(&dir, device) {
            Ok(m) => m,
            Err(e) => {
                log(&e);
                std::process::exit(1)
            }
        };
        if let Err(e) = m.step(true) {
            log(&e);
            std::process::exit(1);
        }
        return;
    }
    run(&dir);
}

fn read_device(dir: &Path) -> Option<CloudDevice> {
    let text = zeroize::Zeroizing::new(fs::read_to_string(dir.join(CLOUD_DEVICE_FILE)).ok()?);
    CloudDevice::from_text(&text)
}

/// Write `bytes` to `path` so `vaultd` never reads half a file. The temporary
/// name must not look like a conflict copy (`vault*.svault`) or `vaultd`'s
/// own temporary file (`vault.tmp`).
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_file_name(".vault-sync.part");
    {
        let mut o = fs::OpenOptions::new();
        o.create(true).write(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// The two sides being kept equal.
struct Mirror {
    copy: PathBuf,
    mailbox: Mailbox,
    /// The server version the local copy was last made equal to.
    version: Option<u64>,
    /// The local copy's digest at that point.
    synced: Option<[u8; 32]>,
    /// The local copy's modified time and size when last read.
    seen: Option<(SystemTime, u64)>,
}

impl Mirror {
    fn new(dir: &Path, device: CloudDevice) -> Result<Mirror, String> {
        Ok(Mirror {
            copy: dir.join(CLOUD_COPY_FILE),
            mailbox: Mailbox::from_device(&device).map_err(|e| e.to_string())?,
            version: None,
            synced: None,
            seen: None,
        })
    }

    fn local_changed(&mut self) -> bool {
        let now = fs::metadata(&self.copy)
            .ok()
            .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
        let changed = now != self.seen;
        self.seen = now;
        changed
    }

    /// One round: upload what `vaultd` wrote, then take in what other
    /// devices saved. `remote` asks the server even without a notice.
    fn step(&mut self, remote: bool) -> Result<(), String> {
        if self.version.is_none() {
            self.pull()?;
        }
        self.push()?;
        if remote {
            self.pull()?;
        }
        Ok(())
    }

    fn push(&mut self) -> Result<(), String> {
        let local = match fs::read(&self.copy) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", self.copy.display())),
        };
        let d = digest(&local);
        if Some(d) == self.synced {
            return Ok(());
        }
        match self
            .mailbox
            .put(self.version.unwrap_or(0), &local)
            .map_err(|e| e.to_string())?
        {
            Saved::Saved(v) => {
                self.version = Some(v);
                self.synced = Some(d);
            }
            // Another device saved first: take its file. vaultd merges it
            // with this device's edits and writes the copy again, which the
            // next round uploads.
            Saved::Conflict(_) => self.pull()?,
        }
        Ok(())
    }

    fn pull(&mut self) -> Result<(), String> {
        match self.mailbox.get(self.version).map_err(|e| e.to_string())? {
            Fetched::Unchanged => {}
            Fetched::Empty(v) => self.version = Some(v),
            Fetched::File(v, bytes) => {
                let d = digest(&bytes);
                let local = fs::read(&self.copy).ok().map(|b| digest(&b));
                if local != Some(d) {
                    write_atomic(&self.copy, &bytes).map_err(|e| {
                        let hint = if e.kind() == io::ErrorKind::ReadOnlyFilesystem
                            || e.kind() == io::ErrorKind::PermissionDenied
                        {
                            " (if the service started before cloud sync was set up, restart it)"
                        } else {
                            ""
                        };
                        format!("{}: {e}{hint}", self.copy.display())
                    })?;
                    self.local_changed();
                }
                self.version = Some(v);
                self.synced = Some(d);
            }
        }
        Ok(())
    }
}

/// What the watcher thread reports.
enum Notice {
    Connected,
    Changed,
    Lost,
}

/// Listens on the mailbox's WebSocket and reports changes, reconnecting
/// with growing waits. Stops when `stop` is dropped.
fn watch(mailbox: &Mailbox, tx: Sender<Notice>) {
    let Ok(req) = mailbox.watch_request() else {
        return;
    };
    thread::spawn(move || {
        let mut wait = Duration::from_secs(5);
        loop {
            match tungstenite::connect(req.clone()) {
                Ok((mut ws, _)) => {
                    wait = Duration::from_secs(5);
                    if let tungstenite::stream::MaybeTlsStream::Rustls(s) = ws.get_mut() {
                        let _ = s.sock.set_read_timeout(Some(Duration::from_secs(50)));
                    }
                    if tx.send(Notice::Connected).is_err() {
                        return;
                    }
                    loop {
                        match ws.read() {
                            Ok(tungstenite::Message::Text(t)) if t.as_str() != "pong" => {
                                if tx.send(Notice::Changed).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(tungstenite::Error::Io(e))
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) =>
                            {
                                // Keeps the connection open through proxies;
                                // the server answers without waking up.
                                if ws.send(tungstenite::Message::text("ping")).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => log(&format!(
                    "cannot watch for changes ({e}); asking every 30 seconds instead"
                )),
            }
            if tx.send(Notice::Lost).is_err() {
                return;
            }
            thread::sleep(wait);
            wait = (wait * 2).min(Duration::from_secs(300));
        }
    });
}

fn run(dir: &Path) {
    let mut waiting_said = false;
    loop {
        let Some(device) = read_device(dir) else {
            if !waiting_said {
                log(&format!(
                    "waiting for {} (run `vault cloud setup` or `vault cloud join`)",
                    dir.join(CLOUD_DEVICE_FILE).display()
                ));
                waiting_said = true;
            }
            thread::sleep(Duration::from_secs(5));
            continue;
        };
        waiting_said = false;
        log(&format!("syncing {} with {}", dir.display(), device.server));
        serve(dir, &device);
    }
}

/// Mirrors one device's mailbox until its device file changes.
fn serve(dir: &Path, device: &CloudDevice) {
    let mut m = match Mirror::new(dir, device.clone()) {
        Ok(m) => m,
        Err(e) => {
            log(&e);
            thread::sleep(Duration::from_secs(60));
            return;
        }
    };
    let (tx, rx): (Sender<Notice>, Receiver<Notice>) = mpsc::channel();
    watch(&m.mailbox, tx);
    let mut watching = false;
    let mut last_remote = Instant::now() - REMOTE_CHECK_WATCHING;
    let mut failures = 0u32;
    let mut last_error = String::new();
    loop {
        if read_device(dir).as_ref() != Some(device) {
            log("this device's cloud sync access changed; starting again");
            return;
        }
        let every = if watching {
            REMOTE_CHECK_WATCHING
        } else {
            REMOTE_CHECK_POLLING
        };
        let mut remote = last_remote.elapsed() >= every;
        match rx.recv_timeout(LOCAL_CHECK) {
            Ok(Notice::Changed) | Ok(Notice::Connected) => {
                watching = true;
                remote = true;
            }
            Ok(Notice::Lost) => watching = false,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => watching = false,
        }
        let local = m.local_changed();
        if !(local || remote || failures > 0) {
            continue;
        }
        match m.step(remote) {
            Ok(()) => {
                if failures > 0 {
                    log("back in sync");
                }
                failures = 0;
                last_error.clear();
                if remote {
                    last_remote = Instant::now();
                }
            }
            Err(e) => {
                if e != last_error {
                    log(&e);
                    last_error = e;
                }
                failures += 1;
                // Back off: 2 s, 4 s ... up to 5 minutes.
                thread::sleep(
                    Duration::from_secs(1u64 << failures.min(8)).min(Duration::from_secs(300)),
                );
            }
        }
    }
}
