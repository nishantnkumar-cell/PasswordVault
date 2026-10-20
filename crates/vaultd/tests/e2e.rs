//! End-to-end: a real daemon on a real Unix socket or named pipe, with software stand-ins
//! for the FIDO2 key and the TPM.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vault_core::KdfCost;
use vault_core::item::{ItemData, UrlEntry};
use vault_core::origin::MatchMode;
use vault_core::totp::TotpConfig;
use vault_ipc::{
    ClientScope, ClientToken, Envelope, GenerateOptions, ImportFormat, Request, Response, Secret,
    SlotId, UnlockMethod, read_frame, write_frame,
};
use vaultd::approve::PairPrompt;
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::hw::soft::{SoftFido2, SoftTpm};
use vaultd::server;
use vaultd::store::Store;
use zeroize::Zeroizing;

const PW: &str = "correct horse battery";

fn s(x: &str) -> Secret {
    Zeroizing::new(x.to_owned())
}

fn soft_hw() -> Hardware {
    Hardware {
        fido2: Some(Box::new(SoftFido2 {
            device_secret: [9; 32],
            pin: "4321".into(),
            counter: Mutex::new(0),
        })),
        tpm: Some(Box::new(SoftTpm {
            device_key: [5; 32],
        })),
    }
}

/// A socket in the test's directory, or a uniquely named pipe on Windows.
fn endpoint(dir: &Path) -> std::path::PathBuf {
    #[cfg(unix)]
    return dir.join("run/vaultd.sock");
    #[cfg(windows)]
    {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let _ = dir;
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!(r"\\.\pipe\vaultd-test-{}-{n}", std::process::id()).into()
    }
}

/// Some user other than the one running the tests.
fn other_user() -> server::Owner {
    #[cfg(unix)]
    return server::current_user() + 1;
    // LocalSystem, S-1-5-18.
    #[cfg(windows)]
    return vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
}

fn start(dir: &Path, owner: server::Owner, idle: Duration) -> std::path::PathBuf {
    start_daemon(dir, owner, idle).0
}

fn start_daemon(
    dir: &Path,
    owner: server::Owner,
    idle: Duration,
) -> (std::path::PathBuf, server::Shared) {
    let store = Store::open(dir.join("data/vault.svault"), dir.join("state")).unwrap();
    let d = Arc::new(Mutex::new(Daemon::new(
        store,
        soft_hw(),
        KdfCost::MINIMUM,
        idle,
    )));
    let sock = endpoint(dir);
    let l = server::bind(&sock, false).unwrap();
    let d2 = d.clone();
    std::thread::spawn(move || {
        server::serve(l, owner, move |c, pid| {
            let _ = server::connection(c, &d2, pid);
        })
    });
    let d3 = d.clone();
    std::thread::spawn(move || server::idle_locker(d3));
    (sock, d)
}

struct C {
    s: vault_ipc::local::Stream,
    token: Option<ClientToken>,
}

impl C {
    fn new(sock: &Path) -> C {
        C {
            s: vault_ipc::local::connect(sock).unwrap(),
            token: None,
        }
    }
    fn call(&mut self, request: Request) -> Response {
        write_frame(
            &mut self.s,
            &Envelope {
                token: self.token.clone(),
                request,
            },
        )
        .unwrap();
        read_frame(&mut self.s).unwrap()
    }
    fn ok(&mut self, request: Request) -> Response {
        match self.call(request) {
            Response::Error(m) => panic!("unexpected error: {m}"),
            r => r,
        }
    }
    fn err(&mut self, request: Request) -> String {
        match self.call(request) {
            Response::Error(m) => m,
            _ => panic!("expected an error"),
        }
    }
}

fn pw() -> UnlockMethod {
    UnlockMethod::Password { password: s(PW) }
}

fn login(title: &str, url: &str) -> ItemData {
    let mut it = ItemData::default();
    it.title = title.into();
    it.username = "test-user".into();
    it.password = "x".repeat(18);
    it.urls = vec![UrlEntry {
        url: url.into(),
        mode: MatchMode::Origin,
        allow_http: false,
    }];
    it.totp = Some(TotpConfig::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap());
    it
}

fn status(c: &mut C) -> vault_ipc::StatusInfo {
    match c.ok(Request::Status) {
        Response::Status(s) => s,
        _ => unreachable!(),
    }
}

#[test]
fn full_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let sock = start(dir.path(), server::current_user(), Duration::from_secs(600));
    let mut c = C::new(&sock);

    // Init: password + recovery, returns a token, leaves the vault unlocked.
    assert!(!status(&mut c).initialized);
    assert!(
        c.err(Request::Init {
            password: s("short"),
            client_name: "t".into()
        })
        .contains("8 characters")
    );
    let Response::Initialized {
        recovery_code,
        token,
    } = c.ok(Request::Init {
        password: s(PW),
        client_name: "cli".into(),
    })
    else {
        panic!()
    };
    assert!(
        c.err(Request::Init {
            password: s(PW),
            client_name: "t".into()
        })
        .contains("already exists")
    );
    assert!(c.err(Request::ListItems).contains("not paired"));
    c.token = Some(token.clone());
    assert!(status(&mut c).unlocked);

    // Items.
    let Response::ItemSaved { id } = c.ok(Request::PutItem {
        id: None,
        item: login("Example", "https://example.com"),
    }) else {
        panic!()
    };
    c.ok(Request::PutItem {
        id: None,
        item: login("Other", "https://other.org"),
    });
    let Response::Items(all) = c.ok(Request::ListItems) else {
        panic!()
    };
    assert_eq!(
        all.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
        ["Example", "Other"]
    );
    let Response::Item { item, .. } = c.ok(Request::GetItem { id }) else {
        panic!()
    };
    assert_eq!(item.password, "x".repeat(18));
    assert!(item.created > 0);
    let Response::Items(found) = c.ok(Request::FindForOrigin {
        origin: "https://example.com".into(),
    }) else {
        panic!()
    };
    assert_eq!(found.len(), 1);
    let Response::Items(found) = c.ok(Request::FindForOrigin {
        origin: "https://example.com.evil.net".into(),
    }) else {
        panic!()
    };
    assert!(found.is_empty());
    let Response::Totp { code, .. } = c.ok(Request::Totp { id }) else {
        panic!()
    };
    assert_eq!(code.len(), 6);
    let Response::Generated(g) = c.ok(Request::Generate {
        options: GenerateOptions {
            length: 30,
            symbols: false,
            avoid_ambiguous: true,
        },
    }) else {
        panic!()
    };
    assert_eq!(g.chars().count(), 30);

    // Hardware slots.
    let Response::SlotAdded { id: fido_slot, .. } = c.ok(Request::AddFido2Slot {
        password: s(PW),
        pin: Some(s("4321")),
        require_uv: true,
        label: "blue key".into(),
    }) else {
        panic!()
    };
    let Response::SlotAdded { id: tpm_slot, .. } = c.ok(Request::AddTpmSlot {
        password: s(PW),
        pin: Some(s("2468")),
        bind_pcr7: false,
        label: "laptop".into(),
    }) else {
        panic!()
    };
    let Response::Slots(slots) = c.ok(Request::ListSlots) else {
        panic!()
    };
    let kinds: Vec<_> = slots.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["password", "recovery", "fido2", "tpm"]);
    assert_eq!(slots[2].label, "blue key");

    // Lock, then unlock with each factor.
    c.ok(Request::Lock);
    assert!(c.err(Request::ListItems).contains("locked"));
    assert!(
        c.err(Request::Unlock {
            method: UnlockMethod::Password {
                password: s("wrong password")
            }
        })
        .contains("wrong")
    );
    c.ok(Request::Unlock { method: pw() });
    c.ok(Request::Lock);
    assert!(
        c.err(Request::Unlock {
            method: UnlockMethod::Fido2 {
                password: s(PW),
                pin: Some(s("0000"))
            }
        })
        .contains("PIN")
    );
    c.ok(Request::Unlock {
        method: UnlockMethod::Fido2 {
            password: s(PW),
            pin: Some(s("4321")),
        },
    });
    c.ok(Request::Lock);
    assert!(
        c.err(Request::Unlock {
            method: UnlockMethod::Tpm {
                password: s(PW),
                pin: Some(s("1111"))
            }
        })
        .contains("TPM")
    );
    c.ok(Request::Unlock {
        method: UnlockMethod::Tpm {
            password: s(PW),
            pin: Some(s("2468")),
        },
    });
    c.ok(Request::Lock);
    c.ok(Request::Unlock {
        method: UnlockMethod::Recovery {
            code: s(&recovery_code.to_lowercase()),
        },
    });

    // An autofill client can fill only matching sites and cannot list or export.
    let mut a = C::new(&sock);
    let Response::Paired { token: at } = a.ok(Request::Pair {
        client_name: "browser".into(),
        scope: ClientScope::Autofill,
        method: Some(pw()),
    }) else {
        panic!()
    };
    a.token = Some(at);
    assert!(a.err(Request::ListItems).contains("autofill"));
    assert!(a.err(Request::GetItem { id }).contains("autofill"));
    assert!(
        a.err(Request::GetForFill {
            id,
            origin: "https://evil.example".into()
        })
        .contains("not bound")
    );
    assert!(
        a.err(Request::GetForFill {
            id,
            origin: "http://example.com".into()
        })
        .contains("not bound")
    );
    let Response::Item { item, .. } = a.ok(Request::GetForFill {
        id,
        origin: "https://example.com".into(),
    }) else {
        panic!()
    };
    assert_eq!(item.username, "test-user");
    a.ok(Request::TotpForFill {
        id,
        origin: "https://example.com".into(),
    });

    // Import.
    let csv = "name,url,username,password\nGitHub,https://github.com,me,pw1\n,https://news.ycombinator.com,me,pw2\n";
    let Response::Imported(n) = c.ok(Request::Import {
        format: ImportFormat::BrowserCsv,
        data: s(csv),
    }) else {
        panic!()
    };
    assert_eq!(n, 2);

    // Revoke: keep password + FIDO2; TPM and recovery go, and recovery no longer unlocks.
    let pw_slot: SlotId = slots[0].id;
    let keep = vec![
        (pw_slot, pw()),
        (
            fido_slot,
            UnlockMethod::Fido2 {
                password: s(PW),
                pin: Some(s("4321")),
            },
        ),
    ];
    let Response::Revoked { removed } = c.ok(Request::Revoke { keep }) else {
        panic!()
    };
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&tpm_slot));
    c.ok(Request::Lock);
    assert!(
        c.err(Request::Unlock {
            method: UnlockMethod::Recovery {
                code: recovery_code.clone()
            }
        })
        .contains("no slot")
    );
    c.ok(Request::Unlock { method: pw() });
    let Response::Items(all) = c.ok(Request::ListItems) else {
        panic!()
    };
    assert_eq!(all.len(), 4);

    // Rollback: restore an older file; unlocking works but writes are refused.
    let file = dir.path().join("data/vault.svault");
    let old = std::fs::read(&file).unwrap();
    c.ok(Request::DeleteItem { id });
    std::fs::write(&file, &old).unwrap();
    c.ok(Request::Lock);
    c.ok(Request::Unlock { method: pw() });
    assert!(status(&mut c).rollback_detected);
    assert!(c.err(Request::DeleteItem { id }).contains("rollback"));
}

#[test]
fn rate_limits_failed_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let sock = start(dir.path(), server::current_user(), Duration::from_secs(600));
    let mut c = C::new(&sock);
    let Response::Initialized { token, .. } = c.ok(Request::Init {
        password: s(PW),
        client_name: "cli".into(),
    }) else {
        panic!()
    };
    c.token = Some(token);
    let bad = || Request::Unlock {
        method: UnlockMethod::Password {
            password: s("not the password"),
        },
    };
    for _ in 0..4 {
        assert!(c.err(bad()).contains("wrong"));
    }
    assert!(c.err(Request::Unlock { method: pw() }).contains("too many"));
}

#[test]
fn locks_when_idle() {
    let dir = tempfile::tempdir().unwrap();
    let sock = start(dir.path(), server::current_user(), Duration::from_secs(1));
    let mut c = C::new(&sock);
    let Response::Initialized { token, .. } = c.ok(Request::Init {
        password: s(PW),
        client_name: "cli".into(),
    }) else {
        panic!()
    };
    c.token = Some(token);
    assert!(status(&mut c).unlocked);
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!status(&mut c).unlocked);
}

#[test]
fn refuses_other_users() {
    let dir = tempfile::tempdir().unwrap();
    let sock = start(dir.path(), other_user(), Duration::from_secs(600));
    assert!(C::new(&sock).err(Request::Status).contains("another user"));
}

#[test]
fn one_daemon_per_state_dir() {
    let dir = tempfile::tempdir().unwrap();
    let _a = Store::open(dir.path().join("v"), dir.path().join("state")).unwrap();
    assert!(Store::open(dir.path().join("v"), dir.path().join("state")).is_err());
}

fn pair_request(name: &str) -> Request {
    Request::Pair {
        client_name: name.into(),
        scope: ClientScope::Autofill,
        method: None,
    }
}

#[test]
fn pairs_through_the_daemons_own_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, d) = start_daemon(dir.path(), server::current_user(), Duration::from_secs(600));
    let mut c = C::new(&sock);
    assert!(c.err(pair_request("early")).contains("no vault"));
    let Response::Initialized { token, .. } = c.ok(Request::Init {
        password: s(PW),
        client_name: "cli".into(),
    }) else {
        panic!()
    };
    c.token = Some(token);
    assert!(
        C::new(&sock)
            .err(pair_request("x"))
            .contains("cannot show an approval prompt")
    );

    // The user's answers: allow everything except "deny"; "slow" takes a while.
    let seen = Arc::new(Mutex::new(Vec::<PairPrompt>::new()));
    let log = seen.clone();
    d.lock()
        .unwrap()
        .set_approver(Arc::new(move |p: &PairPrompt| -> Result<bool, String> {
            log.lock().unwrap().push(p.clone());
            if p.client_name == "slow" {
                std::thread::sleep(Duration::from_millis(800));
            }
            Ok(p.client_name != "deny")
        }));

    // One prompt at a time, and the daemon keeps serving while it is open.
    let slow_sock = sock.clone();
    let slow = std::thread::spawn(move || C::new(&slow_sock).call(pair_request("slow")));
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        C::new(&sock)
            .err(pair_request("second"))
            .contains("another pairing request")
    );
    assert!(status(&mut c).unlocked);
    let Response::Paired { token } = slow.join().unwrap() else {
        panic!("slow pairing failed")
    };

    // The approved client got exactly the scope it asked for.
    let mut a = C::new(&sock);
    a.token = Some(token);
    a.ok(Request::FindForOrigin {
        origin: "https://example.com".into(),
    });
    assert!(a.err(Request::ListItems).contains("autofill"));

    // The prompt names the program that connected, and a cleaned-up name.
    let mut b = C::new(&sock);
    b.ok(pair_request("  my\nbrowser "));
    {
        let seen = seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!(last.client_name, "mybrowser");
        assert_eq!(last.scope, ClientScope::Autofill);
        #[cfg(any(target_os = "linux", windows))]
        assert_eq!(
            last.program
                .as_deref()
                .and_then(|p| std::path::Path::new(p).file_name()),
            std::env::current_exe().unwrap().file_name()
        );
    }

    // A decline is final and holds off the next prompt for a while.
    assert!(C::new(&sock).err(pair_request("deny")).contains("declined"));
    assert!(
        C::new(&sock)
            .err(pair_request("again"))
            .contains("just declined")
    );
    assert_eq!(seen.lock().unwrap().len(), 3);
}

/// Serve the ssh-agent protocol for `d` on a second endpoint.
fn start_agent(dir: &Path, d: &server::Shared) -> std::path::PathBuf {
    #[cfg(unix)]
    let path = dir.join("run/agent.sock");
    #[cfg(windows)]
    let path = endpoint(dir);
    let l = server::bind(&path, false).unwrap();
    let d = d.clone();
    std::thread::spawn(move || {
        server::serve(l, server::current_user(), move |c, pid| {
            let _ = vaultd::ssh::connection(c, &d, pid);
        })
    });
    path
}

/// One raw agent request and its reply.
fn agent_call(path: &Path, body: &[u8]) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut s = vault_ipc::local::connect(path).unwrap();
    s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut out = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut out).unwrap();
    out
}

fn ssh_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// Public key blobs and comments from an identities answer.
fn agent_list(path: &Path) -> Vec<(Vec<u8>, String)> {
    let r = agent_call(path, &[11]);
    assert_eq!(r[0], 12);
    let mut p = &r[5..];
    let mut take = || {
        let n = u32::from_be_bytes(p[..4].try_into().unwrap()) as usize;
        let v = p[4..4 + n].to_vec();
        p = &p[4 + n..];
        v
    };
    let n = u32::from_be_bytes(r[1..5].try_into().unwrap());
    (0..n)
        .map(|_| {
            let blob = take();
            (blob, String::from_utf8(take()).unwrap())
        })
        .collect()
}

fn agent_sign(path: &Path, blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let mut req = vec![13];
    ssh_string(&mut req, blob);
    ssh_string(&mut req, data);
    req.extend_from_slice(&0u32.to_be_bytes());
    let r = agent_call(path, &req);
    match r[0] {
        14 => Some(r[5..].to_vec()),
        5 => None,
        other => panic!("unexpected agent reply {other}"),
    }
}

/// Approves pairing never, and key use as the flag says.
struct UseApprover(
    std::sync::atomic::AtomicBool,
    Mutex<Vec<vaultd::approve::UsePrompt>>,
);

impl vaultd::approve::Approver for UseApprover {
    fn approve(&self, _: &PairPrompt) -> Result<bool, String> {
        Ok(false)
    }
    fn confirm_use(&self, p: &vaultd::approve::UsePrompt) -> Result<bool, String> {
        self.1.lock().unwrap().push(p.clone());
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[test]
fn ssh_keys_and_agent() {
    use vault_ipc::KeyKind;
    let dir = tempfile::tempdir().unwrap();
    let (sock, d) = start_daemon(dir.path(), server::current_user(), Duration::from_secs(600));
    let approver = Arc::new(UseApprover(
        std::sync::atomic::AtomicBool::new(false),
        Mutex::new(Vec::new()),
    ));
    d.lock().unwrap().set_approver(approver.clone());
    let agent = start_agent(dir.path(), &d);
    let mut c = C::new(&sock);
    let Response::Initialized { token, .. } = c.ok(Request::Init {
        password: s(PW),
        client_name: "cli".into(),
    }) else {
        panic!()
    };
    c.token = Some(token);
    assert!(agent_list(&agent).is_empty());

    let Response::ItemSaved { id } = c.ok(Request::GenerateKey {
        title: "laptop".into(),
        kind: KeyKind::SshEd25519,
        confirm: false,
    }) else {
        panic!()
    };
    let Response::PublicKey(line) = c.ok(Request::PublicKey { id }) else {
        panic!()
    };
    assert!(line.starts_with("ssh-ed25519 "));
    let Response::Items(items) = c.ok(Request::ListItems) else {
        panic!()
    };
    assert!(items[0].key.as_deref().unwrap().contains("SHA256:"));

    // Clients never see the private key, and editing keeps it.
    let Response::Item { item, .. } = c.ok(Request::GetItem { id }) else {
        panic!()
    };
    assert!(item.key.is_none());
    let mut edited = item.clone();
    edited.notes = "my laptop key".into();
    c.ok(Request::PutItem {
        id: Some(id),
        item: edited,
    });
    let Response::PublicKey(again) = c.ok(Request::PublicKey { id }) else {
        panic!()
    };
    assert_eq!(again, line);

    // The agent lists and signs with it.
    let ids = agent_list(&agent);
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].1, "laptop");
    let blob = ids[0].0.clone();
    let sig = agent_sign(&agent, &blob, b"data to sign").unwrap();
    {
        use signature::Verifier;
        let pk = ssh_key::PublicKey::from_openssh(&line).unwrap();
        let sig = ssh_key::Signature::try_from(sig.as_slice()).unwrap();
        Verifier::verify(&pk, b"data to sign", &sig).unwrap();
    }
    assert!(agent_sign(&agent, b"unknown key", b"x").is_none());

    // With confirm on, the user is asked; declining fails the signature.
    c.ok(Request::SetKeyConfirm { id, confirm: true });
    let mut git = b"SSHSIG".to_vec();
    ssh_string(&mut git, b"git");
    assert!(agent_sign(&agent, &blob, &git).is_none());
    approver.0.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(agent_sign(&agent, &blob, &git).is_some());
    let asked = approver.1.lock().unwrap().clone();
    assert_eq!(asked.len(), 2);
    assert_eq!(asked[1].key, "laptop");
    assert_eq!(asked[1].purpose, "sign a git commit or tag");

    // Export needs the password again.
    assert!(
        c.err(Request::ExportKey {
            id,
            method: UnlockMethod::Password {
                password: s("wrong password")
            },
        })
        .contains("wrong")
    );
    let Response::ExportedKey(private) = c.ok(Request::ExportKey { id, method: pw() }) else {
        panic!()
    };
    assert!(private.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

    // Import the exported key under another title: same public key.
    let Response::ItemSaved { id: id2 } = c.ok(Request::ImportSshKey {
        title: "copy".into(),
        private: private.clone(),
        passphrase: None,
        confirm: false,
    }) else {
        panic!()
    };
    let Response::PublicKey(copy) = c.ok(Request::PublicKey { id: id2 }) else {
        panic!()
    };
    assert_eq!(copy.split(' ').nth(1), line.split(' ').nth(1));
    assert!(
        c.err(Request::ImportSshKey {
            title: "bad".into(),
            private: s("not a key"),
            passphrase: None,
            confirm: false,
        })
        .contains("not an OpenSSH private key")
    );

    // Locked: nothing listed, nothing signed.
    c.ok(Request::Lock);
    assert!(agent_list(&agent).is_empty());
    assert!(agent_sign(&agent, &blob, b"x").is_none());
}
