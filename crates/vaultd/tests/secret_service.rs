//! The Secret Service against a private D-Bus daemon, driven by real
//! clients where installed: `secret-tool` (libsecret) and Python's
//! `secretstorage`, both of which use the encrypted DH session.
#![cfg(all(feature = "secret-service", target_os = "linux"))]

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vault_core::KdfCost;
use vault_core::item::{ItemData, ItemKind};
use vault_ipc::{ClientToken, Envelope, Request, Response, UnlockMethod};
use vaultd::approve::Prompt;
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::secret_service::{self, COLLECTION, NAME};
use vaultd::server::{self, Shared};
use vaultd::store::Store;
use zbus::blocking::{Connection, MessageIterator, connection};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

/// A secret struct: session, parameters, value, content type.
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

const PW: &str = "correct horse battery";

struct Bus {
    child: std::process::Child,
    addr: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bus() -> Option<Bus> {
    let mut child = Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address"])
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut addr = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut addr,
    )
    .unwrap();
    Some(Bus {
        child,
        addr: addr.trim().to_owned(),
    })
}

fn call(d: &Shared, token: Option<&ClientToken>, request: Request) -> Response {
    d.lock().unwrap().handle(Envelope {
        token: token.cloned(),
        request,
    })
}

fn has(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Run `secret-tool` on the private bus, feeding `input`.
fn secret_tool(addr: &str, args: &[&str], input: &str) -> (bool, String) {
    let mut c = Command::new("secret-tool")
        .args(args)
        .env("DBUS_SESSION_BUS_ADDRESS", addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn proxy<'a>(c: &'a Connection, path: &'a str, iface: &'a str) -> zbus::blocking::Proxy<'a> {
    zbus::blocking::Proxy::new(c, NAME, path, iface).unwrap()
}

/// `Collection.Locked`, read on its own (a cached proxy would read every
/// property, and the rest need approval).
fn collection_locked(c: &Connection) -> bool {
    let v: OwnedValue = proxy(c, COLLECTION, "org.freedesktop.DBus.Properties")
        .call("Get", &("org.freedesktop.Secret.Collection", "Locked"))
        .unwrap();
    bool::try_from(v).unwrap()
}

/// A new, unlocked vault in `dir`, and a full client's token.
fn new_daemon(dir: &std::path::Path) -> (Shared, ClientToken) {
    let store = Store::open(dir.join("data/vault.svault"), dir.join("state")).unwrap();
    let d: Shared = Arc::new(Mutex::new(Daemon::new(
        store,
        Hardware {
            fido2: None,
            tpm: None,
            presence: None,
        },
        KdfCost::MINIMUM,
        Duration::from_secs(600),
    )));
    let Response::Initialized { token, .. } = call(
        &d,
        None,
        Request::Init {
            password: Zeroizing::new(PW.into()),
            client_name: "test".into(),
        },
    ) else {
        panic!("init failed")
    };
    (d, token)
}

fn approvals(d: &Shared, token: &ClientToken) -> Vec<String> {
    let Response::AppApprovals(list) = call(d, Some(token), Request::AppApprovals) else {
        panic!("no approvals list")
    };
    list.into_iter().map(|a| a.program).collect()
}

#[test]
fn apps_keep_passwords_with_approval_and_locking() {
    let Some(bus) = bus() else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (d, token) = new_daemon(dir.path());
    // One of the user's own logins, which no app may see.
    let mut mine = ItemData::new(ItemKind::Login, "My bank");
    mine.password = "x".repeat(20);
    assert!(matches!(
        call(
            &d,
            Some(&token),
            Request::PutItem {
                id: None,
                item: mine
            }
        ),
        Response::ItemSaved { .. }
    ));

    // The approval window: counts app prompts, answers `allow`.
    let asked = Arc::new(AtomicU32::new(0));
    let allow = Arc::new(AtomicBool::new(false));
    let programs = Arc::new(Mutex::new(Vec::new()));
    {
        let (asked, allow, programs) = (asked.clone(), allow.clone(), programs.clone());
        d.lock()
            .unwrap()
            .set_approver(Arc::new(move |p: &Prompt| -> Result<bool, String> {
                let Prompt::App(a) = p else {
                    return Err("unexpected prompt".into());
                };
                asked.fetch_add(1, Ordering::SeqCst);
                programs.lock().unwrap().push(a.program.clone());
                Ok(allow.load(Ordering::SeqCst))
            }));
    }

    let svc_conn = connection::Builder::address(bus.addr.as_str())
        .unwrap()
        .build()
        .unwrap();
    {
        let d = d.clone();
        let uid = server::current_user();
        std::thread::spawn(move || secret_service::serve(svc_conn, d, uid, None));
    }
    let client = connection::Builder::address(bus.addr.as_str())
        .unwrap()
        .build()
        .unwrap();
    let dbus = zbus::blocking::fdo::DBusProxy::new(&client).unwrap();
    let start = Instant::now();
    while !dbus
        .name_has_owner(NAME.try_into().unwrap())
        .unwrap_or(false)
    {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "service did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // A second service on the same bus finds the name taken.
    let again = connection::Builder::address(bus.addr.as_str())
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        secret_service::serve(again, d.clone(), server::current_user(), None),
        Err(secret_service::Stop::NameTaken)
    ));

    let service = proxy(
        &client,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    );
    let coll = proxy(&client, COLLECTION, "org.freedesktop.Secret.Collection");
    let alias: OwnedObjectPath = service.call("ReadAlias", &("default",)).unwrap();
    assert_eq!(alias.as_str(), COLLECTION);
    let (_, session): (OwnedValue, OwnedObjectPath) = service
        .call("OpenSession", &("plain", Value::from("")))
        .unwrap();

    let none: HashMap<&str, &str> = HashMap::new();
    assert!(!collection_locked(&client));

    allow.store(true, Ordering::SeqCst);
    if has("secret-tool") {
        let a = bus.addr.as_str();
        let store = [
            "store",
            "--label=Mail",
            "service",
            "mail",
            "user",
            "alex@example.com",
        ];
        let (ok, out) = secret_tool(a, &store, "first secret");
        assert!(ok, "secret-tool store: {out}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        // Storing again with the same attributes replaces the item.
        let (ok, out) = secret_tool(a, &store, "second secret");
        assert!(ok, "secret-tool store: {out}");
        let (ok, out) = secret_tool(a, &["lookup", "service", "mail"], "");
        assert!(ok && out == "second secret", "secret-tool lookup: {out}");
        let (ok, out) = secret_tool(a, &["search", "--all", "service", "mail"], "");
        assert!(
            ok && out.contains("label = Mail"),
            "secret-tool search: {out}"
        );
        assert_eq!(out.matches("label =").count(), 1);
        // secret-tool was asked about once.
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        // It is an ordinary login in the vault, with its attributes.
        let items = d
            .lock()
            .unwrap()
            .items_where(secret_service::is_app_secret)
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1.title, "Mail");
        assert_eq!(items[0].1.password, "second secret");
        assert_eq!(
            secret_service::attributes(&items[0].1)
                .get("user")
                .map(String::as_str),
            Some("alex@example.com")
        );

        let (ok, out) = secret_tool(a, &["clear", "service", "mail"], "");
        assert!(ok, "secret-tool clear: {out}");
        let (ok, _) = secret_tool(a, &["lookup", "service", "mail"], "");
        assert!(!ok);

        // The approval is listed, and once taken back the program is asked
        // again.
        let allowed = approvals(&d, &token);
        assert_eq!(allowed.len(), 1);
        assert!(allowed[0].ends_with("/secret-tool"), "{allowed:?}");
        assert!(matches!(
            call(
                &d,
                Some(&token),
                Request::RevokeAppApproval {
                    program: Some("/usr/bin/nothing".into())
                }
            ),
            Response::Error(_)
        ));
        assert!(matches!(
            call(
                &d,
                Some(&token),
                Request::RevokeAppApproval {
                    program: Some(allowed[0].clone())
                }
            ),
            Response::Ok
        ));
        assert!(approvals(&d, &token).is_empty());
        let _ = secret_tool(a, &["lookup", "service", "mail"], "");
        assert_eq!(asked.load(Ordering::SeqCst), 2);
    } else {
        eprintln!("skipped the secret-tool part: not installed");
    }

    let python_ok = Command::new("python3")
        .args(["-I", "-c", "import secretstorage"])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if python_ok {
        let script = r#"
import secretstorage
conn = secretstorage.dbus_init()
c = secretstorage.get_default_collection(conn)
it = c.create_item("Chat", {"app": "chat", "account": "alex"}, b"\xffbinary", replace=True)
assert [i.get_label() for i in c.get_all_items()] == ["Chat"], "only app passwords are listed"
found = list(c.search_items({"app": "chat"}))
assert len(found) == 1
assert found[0].get_secret() == b"\xffbinary"
found[0].set_label("Chat (work)")
found[0].set_attributes({"app": "chat", "account": "alex", "team": "ops"})
assert found[0].get_attributes()["team"] == "ops"
found[0].set_secret(b"new")
assert list(c.search_items({"team": "ops"}))[0].get_secret() == b"new"
print("ok")
"#;
        let out = Command::new("python3")
            .args(["-I", "-c", script])
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.addr)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "python secretstorage: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        eprintln!("skipped the python part: secretstorage is not installed");
    }

    // Import into a second vault, reading this one as the "other" Secret
    // Service. Twice: the second time finds everything already there.
    let dir2 = tempfile::tempdir().unwrap();
    let (d2, _) = new_daemon(dir2.path());
    let read = secret_service::read_other(&client, Duration::from_secs(5)).unwrap();
    assert!(read.skipped.is_empty());
    let n = read.found.len();
    assert!(n >= 1);
    if python_ok {
        let chat = read
            .found
            .iter()
            .find(|f| f.label == "Chat (work)")
            .unwrap();
        assert_eq!(&chat.secret[..], b"new");
        assert_eq!(chat.attributes.get("team").map(String::as_str), Some("ops"));
    }
    assert_eq!(secret_service::import(&d2, read.found).unwrap(), (n, 0));
    let again = secret_service::read_other(&client, Duration::from_secs(5)).unwrap();
    assert_eq!(secret_service::import(&d2, again.found).unwrap(), (0, n));
    let imported = d2
        .lock()
        .unwrap()
        .items_where(secret_service::is_app_secret)
        .unwrap();
    assert_eq!(imported.len(), n);
    // Take every approval back, so this test program is asked again below.
    assert!(matches!(
        call(
            &d,
            Some(&token),
            Request::RevokeAppApproval { program: None }
        ),
        Response::Ok
    ));
    assert!(approvals(&d, &token).is_empty());

    // Locked: nothing is found, secrets are refused, and an unlock prompt
    // completes once the user unlocks (here, through the daemon).
    let (locked, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
        .call(
            "Lock",
            &(vec![OwnedObjectPath::try_from(COLLECTION).unwrap()],),
        )
        .unwrap();
    assert_eq!(locked.len(), 1);
    assert!(!d.lock().unwrap().is_unlocked());
    let (found, hidden): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        service.call("SearchItems", &(none.clone(),)).unwrap();
    assert!(found.is_empty() && hidden.is_empty());
    assert!(collection_locked(&client));
    let r: zbus::Result<HashMap<OwnedObjectPath, Secret>> = service.call(
        "GetSecrets",
        &(Vec::<OwnedObjectPath>::new(), session.clone()),
    );
    assert!(format!("{:?}", r.unwrap_err()).contains("IsLocked"));

    let (now, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
        .call(
            "Unlock",
            &(vec![OwnedObjectPath::try_from(COLLECTION).unwrap()],),
        )
        .unwrap();
    assert!(now.is_empty() && prompt.as_str() != "/");
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.Secret.Prompt")
        .unwrap()
        .member("Completed")
        .unwrap()
        .build();
    let mut signals = MessageIterator::for_match_rule(rule, &client, None).unwrap();
    let p = proxy(&client, prompt.as_str(), "org.freedesktop.Secret.Prompt");
    let () = p.call("Prompt", &("",)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(matches!(
        call(
            &d,
            Some(&token),
            Request::Unlock {
                method: UnlockMethod::Password {
                    password: Zeroizing::new(PW.into())
                }
            }
        ),
        Response::Ok
    ));
    let msg = signals.next().unwrap().unwrap();
    let (dismissed, result): (bool, OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
    let paths: Vec<OwnedObjectPath> = result.try_into().unwrap();
    assert_eq!(paths.len(), 1);

    // Only the one session's opener may use it.
    let other = connection::Builder::address(bus.addr.as_str())
        .unwrap()
        .build()
        .unwrap();
    let close: zbus::Result<()> =
        proxy(&other, session.as_str(), "org.freedesktop.Secret.Session").call("Close", &());
    assert!(close.is_err());
    let () = proxy(&client, session.as_str(), "org.freedesktop.Secret.Session")
        .call("Close", &())
        .unwrap();

    // The user's own login was never touched.
    let mine: Vec<_> = d
        .lock()
        .unwrap()
        .items_where(|it| it.title == "My bank")
        .unwrap();
    assert_eq!(mine.len(), 1);

    allow.store(false, Ordering::SeqCst);
    let before = asked.load(Ordering::SeqCst);
    // This test program, declined: refused, and not asked again right away.
    let r: zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> =
        service.call("SearchItems", &(none.clone(),));
    assert!(format!("{:?}", r.unwrap_err()).contains("AccessDenied"));
    assert_eq!(asked.load(Ordering::SeqCst), before + 1);
    let r: zbus::Result<Vec<OwnedObjectPath>> = coll.call("SearchItems", &(none.clone(),));
    assert!(r.is_err());
    assert_eq!(asked.load(Ordering::SeqCst), before + 1);
    let me = std::env::current_exe().unwrap().display().to_string();
    assert_eq!(
        programs.lock().unwrap().last().unwrap().as_deref(),
        Some(me.as_str())
    );
}

/// Import from a real GNOME Keyring on a private bus, where installed.
#[test]
fn imports_from_gnome_keyring() {
    if !has("gnome-keyring-daemon") || !has("secret-tool") {
        eprintln!("skipped: gnome-keyring-daemon or secret-tool is not installed");
        return;
    }
    let Some(bus) = bus() else {
        eprintln!("skipped: dbus-daemon is not installed");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let run = home.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let mut keyring = Command::new("gnome-keyring-daemon")
        .args(["--foreground", "--components=secrets", "--unlock"])
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.addr)
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("XDG_RUNTIME_DIR", &run)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The login keyring's password, for --unlock.
    keyring
        .stdin
        .take()
        .unwrap()
        .write_all(b"keyring password")
        .unwrap();
    let a = bus.addr.as_str();
    // Wait for it to take the name, so the bus does not start another copy
    // through D-Bus activation.
    let conn = connection::Builder::address(a).unwrap().build().unwrap();
    let dbus = zbus::blocking::fdo::DBusProxy::new(&conn).unwrap();
    let start = Instant::now();
    while !dbus
        .name_has_owner(NAME.try_into().unwrap())
        .unwrap_or(false)
    {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "gnome-keyring did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    loop {
        let (ok, _) = secret_tool(
            a,
            &[
                "store",
                "--label=Work mail",
                "server",
                "imap.example.com",
                "user",
                "alex",
            ],
            "imap secret",
        );
        if ok {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "gnome-keyring did not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let (ok, out) = secret_tool(a, &["store", "--label=Chat", "app", "chat"], "chat secret");
    assert!(ok, "{out}");

    let read = secret_service::read_other(&conn, Duration::from_secs(5)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (d, _) = new_daemon(dir.path());
    let n = read.found.len();
    assert_eq!(secret_service::import(&d, read.found).unwrap(), (n, 0));
    let items = d
        .lock()
        .unwrap()
        .items_where(secret_service::is_app_secret)
        .unwrap();
    let mail = items
        .iter()
        .find(|(_, it)| it.title == "Work mail")
        .unwrap();
    assert_eq!(mail.1.password, "imap secret");
    assert_eq!(
        secret_service::attributes(&mail.1)
            .get("server")
            .map(String::as_str),
        Some("imap.example.com")
    );
    assert!(
        items
            .iter()
            .any(|(_, it)| it.title == "Chat" && it.password == "chat secret")
    );
    // A keyring that stays locked (no one answers its password prompt here)
    // is skipped, not an error.
    let login = OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login").unwrap();
    let (_, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = proxy(
        &conn,
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .call("Lock", &(vec![login],))
    .unwrap();
    let read = secret_service::read_other(&conn, Duration::from_secs(2)).unwrap();
    assert!(read.found.is_empty());
    assert_eq!(read.skipped.len(), 1, "{:?}", read.skipped);
    let _ = keyring.kill();
    let _ = keyring.wait();
}
