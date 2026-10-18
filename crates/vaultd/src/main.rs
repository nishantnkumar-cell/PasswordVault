//! vaultd entry point. See `vaultd --help`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vault_core::KdfCost;
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::server;
use vaultd::store::Store;

const HELP: &str = "vaultd: the vault daemon

USAGE: vaultd [OPTIONS]

OPTIONS:
  --vault PATH       vault file      [default: $XDG_DATA_HOME/vault/vault.svault]
  --state-dir PATH   daemon state    [default: $XDG_STATE_HOME/vault]
  --socket PATH      Unix socket     [default: $XDG_RUNTIME_DIR/vault/vaultd.sock]
  --owner-uid UID    the only UID allowed to connect [default: this process's UID]
  --owner-user NAME  same, by user name (for a system unit running as its own user)
  --idle-secs N      lock after N idle seconds [default: 900]
  --fast-kdf         minimum Argon2id cost for new slots (testing only)
  -h, --help         this text";

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").expect("HOME is not set")).join(fallback)
    })
}

/// No core dumps, no ptrace attach from same-UID processes, and keys kept
/// out of swap (threat model A3 and section 6).
fn harden() {
    use nix::sys::resource::{Resource, getrlimit, setrlimit};
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        eprintln!("vaultd: warning: could not clear the dumpable flag: {e}");
    }
    // Lock all memory, including future Argon2id buffers (up to 4 GiB), but
    // only when the limit allows it: past the limit, allocations would fail.
    const NEEDED: u64 = 5 << 30;
    match getrlimit(Resource::RLIMIT_MEMLOCK) {
        Ok((soft, _)) if soft == nix::sys::resource::RLIM_INFINITY || soft >= NEEDED => {
            use nix::sys::mman::{MlockAllFlags, mlockall};
            if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
                eprintln!("vaultd: warning: could not lock memory, keys may reach swap: {e}");
            }
        }
        _ => eprintln!(
            "vaultd: warning: RLIMIT_MEMLOCK is too low to lock memory, keys may reach swap (set LimitMEMLOCK=infinity)"
        ),
    }
}

fn main() {
    harden();
    let mut vault = env_dir("XDG_DATA_HOME", ".local/share").join("vault/vault.svault");
    let mut state = env_dir("XDG_STATE_HOME", ".local/state").join("vault");
    let mut socket = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("vault/vaultd.sock"))
        .unwrap_or_else(|| state.join("vaultd.sock"));
    let mut owner = nix::unistd::getuid().as_raw();
    let mut idle = 900u64;
    let mut cost = KdfCost::DEFAULT;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || {
            args.next()
                .unwrap_or_else(|| die(&format!("{a} needs a value")))
        };
        match a.as_str() {
            "--vault" => vault = val().into(),
            "--state-dir" => state = val().into(),
            "--socket" => socket = val().into(),
            "--owner-user" => {
                let name = val();
                owner = match nix::unistd::User::from_name(&name) {
                    Ok(Some(u)) => u.uid.as_raw(),
                    _ => die(&format!("no such user {name}")),
                }
            }
            "--owner-uid" => {
                owner = val()
                    .parse()
                    .unwrap_or_else(|_| die("--owner-uid must be a number"))
            }
            "--idle-secs" => {
                idle = val()
                    .parse()
                    .unwrap_or_else(|_| die("--idle-secs must be a number"))
            }
            "--fast-kdf" => cost = KdfCost::MINIMUM,
            "-h" | "--help" => {
                println!("{HELP}");
                return;
            }
            _ => die(&format!("unknown option {a}; see --help")),
        }
    }

    let store = Store::open(vault, state).unwrap_or_else(|e| die(&e.to_string()));
    let daemon = Arc::new(Mutex::new(Daemon::new(
        store,
        Hardware::system(),
        cost,
        Duration::from_secs(idle),
    )));
    let listener = server::bind(&socket, owner != nix::unistd::getuid().as_raw())
        .unwrap_or_else(|e| die(&format!("{}: {e}", socket.display())));

    // Lock and exit cleanly on SIGTERM / SIGINT / SIGHUP.
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])
    .unwrap_or_else(|e| die(&e.to_string()));
    {
        let d = daemon.clone();
        let sock = socket.clone();
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                d.lock().unwrap_or_else(|p| p.into_inner()).lock();
                let _ = std::fs::remove_file(&sock);
                std::process::exit(0);
            }
        });
    }
    {
        let d = daemon.clone();
        std::thread::spawn(move || server::idle_locker(d));
    }
    #[cfg(all(feature = "logind", target_os = "linux"))]
    {
        let d = daemon.clone();
        std::thread::spawn(move || vaultd::logind::run(d));
    }
    eprintln!("vaultd: listening on {}", socket.display());
    server::serve(listener, daemon, owner);
}

fn die(msg: &str) -> ! {
    eprintln!("vaultd: {msg}");
    std::process::exit(2)
}
