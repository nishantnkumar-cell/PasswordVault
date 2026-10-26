//! vaultd entry point. See `vaultd --help`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vault_core::KdfCost;
use vault_ipc::local;
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::server;
use vaultd::store::Store;

const HELP: &str = "vaultd: the vault daemon

USAGE: vaultd [OPTIONS]

OPTIONS:
  --vault PATH       vault file      [default: DATA/vault.svault]
  --state-dir PATH   daemon state    [default: STATE]
  --socket PATH      Unix socket or Windows pipe [default: see docs/vaultd.md]
  --ssh-agent PATH   ssh-agent socket or pipe for SSH_AUTH_SOCK [default: see docs/ssh.md]
  --no-ssh-agent     do not serve the ssh-agent protocol
  --owner-uid UID    the only UID allowed to connect [default: this process's UID] (Unix)
  --owner-user NAME  same, by user name (for a system unit running as its own user) (Unix)
  --idle-secs N      lock after N idle seconds [default: 900]
  --fast-kdf         minimum Argon2id cost for new slots (testing only)
  --no-prompt        never show the pairing approval window (pairing then needs
                     an unlock method); VAULT_PROMPT names the window program
                     [default: vault-prompt next to vaultd]
  -V, --version      print the version
  -h, --help         this text";

/// No core dumps, no ptrace attach from same-UID processes, and keys kept
/// out of swap (threat model A3 and section 6). Not yet on Windows.
#[cfg(unix)]
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
    if matches!(std::env::args().nth(1).as_deref(), Some("-V" | "--version")) {
        println!("vaultd {}", vault_ipc::VERSION);
        return;
    }
    #[cfg(unix)]
    harden();
    let mut vault = local::data_dir().join("vault.svault");
    let mut state: PathBuf = local::state_dir();
    let mut socket = local::endpoint().unwrap_or_else(|e| die(&e.to_string()));
    #[cfg_attr(windows, allow(unused_mut))]
    let mut owner = server::current_user();
    let mut idle = 900u64;
    let mut cost = KdfCost::DEFAULT;
    let mut prompt = true;
    let mut agent = Some(local::ssh_agent_endpoint().unwrap_or_else(|e| die(&e.to_string())));

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
            "--ssh-agent" => agent = Some(val().into()),
            "--no-ssh-agent" => agent = None,
            #[cfg(unix)]
            "--owner-user" => {
                let name = val();
                owner = match nix::unistd::User::from_name(&name) {
                    Ok(Some(u)) => u.uid.as_raw(),
                    _ => die(&format!("no such user {name}")),
                }
            }
            #[cfg(unix)]
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
            "--no-prompt" => prompt = false,
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
    // A daemon running as its own system user has no desktop to draw on.
    if prompt && owner == server::current_user() {
        match vaultd::approve::Helper::find() {
            Some(h) => daemon
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .set_approver(Arc::new(h)),
            None => eprintln!(
                "vaultd: no vault-prompt next to vaultd; pairing will need an unlock method"
            ),
        }
    }
    let shared = owner != server::current_user();
    let listener = server::bind(&socket, shared)
        .unwrap_or_else(|e| die(&format!("{}: {e}", socket.display())));
    let agent_listener = agent
        .as_ref()
        .map(|p| server::bind(p, shared).unwrap_or_else(|e| die(&format!("{}: {e}", p.display()))));

    // Lock and exit cleanly on SIGTERM / SIGINT / SIGHUP.
    #[cfg(unix)]
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGHUP,
    ])
    .unwrap_or_else(|e| die(&e.to_string()));
    #[cfg(unix)]
    {
        let d = daemon.clone();
        let sock = socket.clone();
        let agent_sock = agent.clone();
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                d.lock().unwrap_or_else(|p| p.into_inner()).lock();
                let _ = std::fs::remove_file(&sock);
                if let Some(a) = &agent_sock {
                    let _ = std::fs::remove_file(a);
                }
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
    #[cfg(windows)]
    {
        let d = daemon.clone();
        std::thread::spawn(move || vaultd::winsession::run(d));
    }
    if let (Some(l), Some(p)) = (agent_listener, &agent) {
        let d = daemon.clone();
        #[cfg_attr(unix, allow(clippy::clone_on_copy))]
        let o = owner.clone();
        eprintln!("vaultd: ssh-agent on {}", p.display());
        std::thread::spawn(move || {
            server::serve(l, o, move |c, pid| {
                let _ = vaultd::ssh::connection(c, &d, pid);
            })
        });
    }
    eprintln!("vaultd: listening on {}", socket.display());
    let d = daemon.clone();
    server::serve(listener, owner, move |c, pid| {
        let _ = server::connection(c, &d, pid);
    });
}

fn die(msg: &str) -> ! {
    eprintln!("vaultd: {msg}");
    std::process::exit(2)
}
