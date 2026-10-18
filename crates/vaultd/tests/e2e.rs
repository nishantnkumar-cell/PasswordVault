//! End-to-end: a real daemon on a real Unix socket, with software stand-ins
//! for the FIDO2 key and the TPM.

use std::os::unix::net::UnixStream;
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

fn start(dir: &Path, owner: u32, idle: Duration) -> std::path::PathBuf {
    let store = Store::open(dir.join("data/vault.svault"), dir.join("state")).unwrap();
    let d = Arc::new(Mutex::new(Daemon::new(
        store,
        soft_hw(),
        KdfCost::MINIMUM,
        idle,
    )));
    let sock = dir.join("run/vaultd.sock");
    let l = server::bind(&sock, false).unwrap();
    let d2 = d.clone();
    std::thread::spawn(move || server::serve(l, d2, owner));
    std::thread::spawn(move || server::idle_locker(d));
    sock
}

struct C {
    s: UnixStream,
    token: Option<ClientToken>,
}

impl C {
    fn new(sock: &Path) -> C {
        C {
            s: UnixStream::connect(sock).unwrap(),
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
    let sock = start(
        dir.path(),
        nix::unistd::getuid().as_raw(),
        Duration::from_secs(600),
    );
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
        method: pw(),
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
    let sock = start(
        dir.path(),
        nix::unistd::getuid().as_raw(),
        Duration::from_secs(600),
    );
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
    let sock = start(
        dir.path(),
        nix::unistd::getuid().as_raw(),
        Duration::from_secs(1),
    );
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
    let sock = start(
        dir.path(),
        nix::unistd::getuid().as_raw() + 1,
        Duration::from_secs(600),
    );
    assert!(C::new(&sock).err(Request::Status).contains("another user"));
}

#[test]
fn one_daemon_per_state_dir() {
    let dir = tempfile::tempdir().unwrap();
    let _a = Store::open(dir.path().join("v"), dir.path().join("state")).unwrap();
    assert!(Store::open(dir.path().join("v"), dir.path().join("state")).is_err());
}
