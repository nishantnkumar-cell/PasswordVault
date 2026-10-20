//! Drive the real window (headless, through its accessibility tree) against a
//! real daemon on a real socket, with software stand-ins for the hardware.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use vault_core::KdfCost;
use vault_gui::{App, Clip, Paths, Screen};
use vault_ipc::ItemKind;
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::server;
use vaultd::store::Store;

fn password() -> String {
    ["correct", "horse", "battery"].join(" ")
}

fn start(dir: &Path, idle: Duration) -> PathBuf {
    start_daemon(dir, idle).0
}

fn start_daemon(dir: &Path, idle: Duration) -> (PathBuf, server::Shared) {
    let store = Store::open(dir.join("data/vault.svault"), dir.join("state")).unwrap();
    let hw = Hardware {
        fido2: None,
        tpm: None,
    };
    let d = Arc::new(Mutex::new(Daemon::new(store, hw, KdfCost::MINIMUM, idle)));
    let sock = endpoint(dir);
    let l = server::bind(&sock, false).unwrap();
    let d2 = d.clone();
    std::thread::spawn(move || server::serve(l, d2, server::current_user()));
    let d3 = d.clone();
    std::thread::spawn(move || server::idle_locker(d3));
    (sock, d)
}

/// A socket in the test's directory, or a uniquely named pipe on Windows.
fn endpoint(dir: &Path) -> PathBuf {
    #[cfg(unix)]
    return dir.join("run/vaultd.sock");
    #[cfg(windows)]
    return format!(
        r"\\.\pipe\vault-gui-test-{}",
        dir.file_name().unwrap().to_string_lossy()
    )
    .into();
}

#[derive(Clone, Default)]
struct FakeClip(Arc<Mutex<Option<String>>>);

impl Clip for FakeClip {
    fn set(&mut self, text: &str) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(text.to_owned());
        Ok(())
    }
    fn get(&mut self) -> Option<String> {
        self.0.lock().unwrap().clone()
    }
    fn clear(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

fn window(sock: PathBuf, token: PathBuf, clip: FakeClip) -> Harness<'static, App> {
    let app = App::new(
        Paths {
            socket: sock,
            token,
        },
        Box::new(clip),
        || {},
    );
    Harness::builder()
        .with_size([920.0, 1000.0])
        .build_ui_state(|ui, app: &mut App| app.show(ui), app)
}

/// Run frames until the daemon has answered everything.
fn settle(h: &mut Harness<'_, App>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        h.step();
        if h.state().pending() == 0 {
            h.step();
            h.step();
            if h.state().pending() == 0 {
                return;
            }
        }
        assert!(Instant::now() < deadline, "daemon did not answer");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for(h: &mut Harness<'_, App>, want: Screen) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while *h.state().screen() != want {
        assert!(
            Instant::now() < deadline,
            "stuck on {:?}, wanted {want:?}",
            h.state().screen()
        );
        h.step();
        std::thread::sleep(Duration::from_millis(10));
    }
    settle(h);
}

fn type_into(h: &mut Harness<'_, App>, role: Role, label: &str, text: &str) {
    h.get_by_role_and_label(role, label).focus();
    h.step();
    h.get_by_role_and_label(role, label).type_text(text);
    h.step();
}

fn click(h: &mut Harness<'_, App>, label: &str) {
    h.get_by_role_and_label(Role::Button, label).click();
    h.step();
    h.step();
}

#[test]
fn create_add_copy_lock_unlock() {
    let dir = tempdir();
    let sock = start(&dir, Duration::from_secs(300));
    let clip = FakeClip::default();
    let mut h = window(sock, dir.join("token"), clip.clone());
    wait_for(&mut h, Screen::Create);

    let pw = password();
    type_into(&mut h, Role::PasswordInput, "Master password", &pw);
    type_into(&mut h, Role::PasswordInput, "Repeat it", "something else");
    click(&mut h, "Create vault");
    settle(&mut h);
    assert_eq!(h.state().error(), Some("The passwords don't match."));

    h.get_by_role_and_label(Role::PasswordInput, "Repeat it")
        .focus();
    h.step();
    for _ in 0.."something else".len() {
        h.key_press(eframe::egui::Key::Backspace);
    }
    type_into(&mut h, Role::PasswordInput, "Repeat it", &pw);
    click(&mut h, "Create vault");
    wait_for(&mut h, Screen::ShowRecovery);
    assert!(dir.join("token").exists(), "pairing token saved");
    click(&mut h, "I've written it down");
    wait_for(&mut h, Screen::Unlocked);

    click(&mut h, "New item");
    click(&mut h, "Login");
    type_into(&mut h, Role::TextInput, "Title", "Example");
    type_into(&mut h, Role::TextInput, "Username", "alice");
    click(&mut h, "Generate");
    settle(&mut h);
    type_into(&mut h, Role::TextInput, "Websites", "https://example.com");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert_eq!(h.state().items().len(), 1);
    assert_eq!(h.state().items()[0].urls, vec!["https://example.com"]);

    // Saving selects the item and shows it.
    click(&mut h, "Copy password");
    let copied = clip.0.lock().unwrap().clone().expect("copied");
    assert_eq!(
        copied.chars().count(),
        24,
        "generated with the default length"
    );
    assert!(h.query_by_label(&copied).is_none(), "hidden until Show");
    click(&mut h, "Show");
    assert!(h.query_by_label(&copied).is_some());

    // Search filters the list.
    type_into(&mut h, Role::TextInput, "Search", "nomatch");
    assert!(h.query_by_label_contains("Example\nalice").is_none());

    click(&mut h, "Lock");
    wait_for(&mut h, Screen::Locked);
    assert!(h.state().items().is_empty(), "items dropped on lock");
    assert_eq!(*clip.0.lock().unwrap(), None, "clipboard cleared on lock");
    assert!(h.query_by_label(&copied).is_none());

    type_into(
        &mut h,
        Role::PasswordInput,
        "Master password",
        "wrong password",
    );
    click(&mut h, "Unlock");
    settle(&mut h);
    assert!(h.state().error().is_some());
    assert_eq!(*h.state().screen(), Screen::Locked);

    h.get_by_role_and_label(Role::PasswordInput, "Master password")
        .focus();
    h.step();
    for _ in 0.."wrong password".len() {
        h.key_press(eframe::egui::Key::Backspace);
    }
    type_into(&mut h, Role::PasswordInput, "Master password", &pw);
    h.key_press(eframe::egui::Key::Enter);
    wait_for(&mut h, Screen::Unlocked);
    assert_eq!(h.state().items().len(), 1);
}

#[test]
fn pairs_a_second_window_and_follows_idle_lock() {
    let dir = tempdir();
    let sock = start(&dir, Duration::from_secs(2));
    let pw = password();
    let mut first = window(sock.clone(), dir.join("first"), FakeClip::default());
    wait_for(&mut first, Screen::Create);
    type_into(&mut first, Role::PasswordInput, "Master password", &pw);
    type_into(&mut first, Role::PasswordInput, "Repeat it", &pw);
    click(&mut first, "Create vault");
    wait_for(&mut first, Screen::ShowRecovery);

    let mut second = window(sock, dir.join("second"), FakeClip::default());
    wait_for(&mut second, Screen::Pair);
    type_into(&mut second, Role::PasswordInput, "Master password", &pw);
    click(&mut second, "Pair");
    wait_for(&mut second, Screen::Unlocked);
    assert!(dir.join("second").exists());

    // Status polls don't count as activity, so the daemon's idle lock wins.
    wait_for(&mut second, Screen::Locked);
}

#[test]
fn says_when_the_daemon_is_not_running() {
    let dir = tempdir();
    let mut h = window(
        dir.join("nothing.sock"),
        dir.join("token"),
        FakeClip::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(h.state().screen(), Screen::Unreachable(_)) {
        assert!(Instant::now() < deadline);
        h.step();
        std::thread::sleep(Duration::from_millis(10));
    }
    h.step();
    assert!(h.query_by_label_contains("Can't reach vaultd").is_some());
}

/// Create a vault through the window and land on the unlocked screen.
fn created(dir: &Path, idle: Duration, clip: FakeClip) -> Harness<'static, App> {
    let sock = start(dir, idle);
    let pw = password();
    let mut h = window(sock, dir.join("token"), clip);
    wait_for(&mut h, Screen::Create);
    type_into(&mut h, Role::PasswordInput, "Master password", &pw);
    type_into(&mut h, Role::PasswordInput, "Repeat it", &pw);
    click(&mut h, "Create vault");
    wait_for(&mut h, Screen::ShowRecovery);
    click(&mut h, "I've written it down");
    wait_for(&mut h, Screen::Unlocked);
    h
}

#[test]
fn import_totp_edit_delete_and_slots() {
    let dir = tempdir();
    let mut h = created(&dir, Duration::from_secs(300), FakeClip::default());

    // A browser export, written the way Chrome does.
    let csv = dir.join("export.csv");
    let secret = "x".repeat(16);
    std::fs::write(
        &csv,
        format!("name,url,username,password\nShop,https://shop.example,bob,{secret}\n"),
    )
    .unwrap();
    click(&mut h, "Import");
    h.get_by_role_and_label(
        Role::RadioButton,
        "Chrome, Edge or Firefox passwords (.csv)",
    )
    .click();
    h.step();
    type_into(&mut h, Role::TextInput, "File", csv.to_str().unwrap());
    h.get_all_by_role_and_label(Role::Button, "Import")
        .last()
        .unwrap()
        .click();
    h.step();
    settle(&mut h);
    assert_eq!(h.state().items().len(), 1);
    assert!(h.query_by_label_contains("Imported 1 items").is_some());

    // Add a TOTP seed (RFC 6238's test key) by editing the item.
    h.get_by_role_and_label(Role::Button, "Items").click();
    h.step();
    h.get_by_label_contains("Shop").click();
    h.step();
    settle(&mut h);
    click(&mut h, "Edit");
    type_into(
        &mut h,
        Role::PasswordInput,
        "One-time codes",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    );
    type_into(&mut h, Role::TextInput, "Title", " Online");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert_eq!(h.state().items()[0].title, "Shop Online");
    assert!(h.state().items()[0].has_totp);
    settle(&mut h);
    h.step();
    assert!(
        h.query_by_role_and_label(Role::Button, "Copy code")
            .is_some()
    );

    // A bad seed is refused before anything is sent.
    click(&mut h, "Edit");
    type_into(&mut h, Role::PasswordInput, "One-time codes", "not base32!");
    click(&mut h, "Save");
    assert!(h.state().error().unwrap().starts_with("TOTP"));
    click(&mut h, "Cancel");

    // Delete asks first.
    click(&mut h, "Delete");
    click(&mut h, "Yes, delete");
    settle(&mut h);
    assert!(h.state().items().is_empty());

    // Unlock methods: a new recovery code is shown once.
    click(&mut h, "Unlock methods");
    settle(&mut h);
    h.get_all_by_role_and_label(Role::Button, "Recovery code")
        .last()
        .unwrap()
        .click();
    h.step();
    type_into(&mut h, Role::TextInput, "Name", "spare");
    click(&mut h, "Add");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert!(h.query_by_label("spare").is_some());
    assert!(h.query_by_label_contains("New recovery code").is_some());
}

#[test]
fn cards_identities_and_notes() {
    let dir = tempdir();
    let clip = FakeClip::default();
    let mut h = created(&dir, Duration::from_secs(300), clip.clone());

    // A card: the number is cleaned up, checked, and hidden until Show.
    click(&mut h, "New item");
    click(&mut h, "Card");
    type_into(&mut h, Role::TextInput, "Title", "Travel");
    type_into(&mut h, Role::TextInput, "Name on card", "A Person");
    type_into(
        &mut h,
        Role::PasswordInput,
        "Card number",
        "4111 1111 1111 1111",
    );
    type_into(&mut h, Role::TextInput, "Expires", "13/31");
    click(&mut h, "Save");
    assert!(h.state().error().unwrap().contains("MM/YY"));
    h.get_by_role_and_label(Role::TextInput, "Expires").focus();
    h.step();
    for _ in 0..5 {
        h.key_press(eframe::egui::Key::Backspace);
    }
    type_into(&mut h, Role::TextInput, "Expires", "07/31");
    type_into(&mut h, Role::PasswordInput, "Security code", "123");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    let card = &h.state().items()[0];
    assert_eq!(card.kind, ItemKind::Card);
    assert_eq!(card.subtitle, "Visa \u{2022}\u{2022}\u{2022}\u{2022} 1111");
    assert!(h.query_by_label("4111111111111111").is_none());
    assert!(h.query_by_label("07/2031").is_some());
    click(&mut h, "Copy number");
    assert_eq!(clip.0.lock().unwrap().as_deref(), Some("4111111111111111"));

    // An identity, listed by name.
    click(&mut h, "New item");
    click(&mut h, "Identity");
    type_into(&mut h, Role::TextInput, "Title", "Home");
    type_into(&mut h, Role::TextInput, "First name", "Ada");
    type_into(&mut h, Role::TextInput, "Last name", "Lovelace");
    type_into(&mut h, Role::TextInput, "City", "London");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert!(h.query_by_label_contains("Home\nAda Lovelace").is_some());
    assert!(h.query_by_label_contains("London").is_some());

    // A secure note shows no subtitle.
    click(&mut h, "New item");
    click(&mut h, "Secure note");
    type_into(&mut h, Role::TextInput, "Title", "Wifi");
    type_into(&mut h, Role::MultilineTextInput, "Notes", "door code");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().items().len(), 3);
    let note = h
        .state()
        .items()
        .iter()
        .find(|i| i.title == "Wifi")
        .unwrap();
    assert_eq!((note.kind, note.subtitle.as_str()), (ItemKind::Note, ""));

    // The type filter.
    h.get_by_role_and_label(Role::Button, "Cards").click();
    h.step();
    h.step();
    assert!(h.query_by_label_contains("Home\nAda").is_none());
    assert!(h.query_by_label_contains("Travel\nVisa").is_some());
}

#[test]
fn forgets_a_token_the_daemon_does_not_know() {
    let dir = tempdir();
    let first = created(&dir, Duration::from_secs(300), FakeClip::default());
    drop(first);
    std::fs::write(dir.join("stale"), [7u8; 32]).unwrap();
    let mut h = window(endpoint(&dir), dir.join("stale"), FakeClip::default());
    wait_for(&mut h, Screen::Pair);
    assert!(h.state().error().unwrap().contains("Pair it again"));
    assert!(!dir.join("stale").exists());
}

#[test]
fn pairs_by_approval_in_the_daemons_window() {
    let dir = tempdir();
    let (sock, d) = start_daemon(&dir, Duration::from_secs(300));
    let pw = password();
    let mut first = window(sock.clone(), dir.join("first"), FakeClip::default());
    wait_for(&mut first, Screen::Create);
    type_into(&mut first, Role::PasswordInput, "Master password", &pw);
    type_into(&mut first, Role::PasswordInput, "Repeat it", &pw);
    click(&mut first, "Create vault");
    wait_for(&mut first, Screen::ShowRecovery);

    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    d.lock().unwrap().set_approver(Arc::new(
        move |p: &vaultd::approve::Prompt| -> Result<bool, String> {
            let vaultd::approve::Prompt::Pair(p) = p else {
                return Ok(false);
            };
            log.lock().unwrap().push((p.client_name.clone(), p.scope));
            Ok(true)
        },
    ));
    let mut second = window(sock, dir.join("second"), FakeClip::default());
    wait_for(&mut second, Screen::Pair);
    click(&mut second, "Ask for approval");
    wait_for(&mut second, Screen::Unlocked);
    assert!(dir.join("second").exists());
    assert_eq!(
        *asked.lock().unwrap(),
        vec![("desktop app".to_owned(), vault_ipc::ClientScope::Full)]
    );
}

fn tempdir() -> PathBuf {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let d = std::env::temp_dir().join(format!(
        "vault-gui-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    d
}

#[test]
fn turns_on_sync_and_a_second_device_joins() {
    let dir = tempdir();
    let shared = tempdir();
    let synced = shared.join("vault.svault");
    let path = synced.display().to_string();
    let mut h = created(&dir, Duration::from_secs(300), FakeClip::default());
    click(&mut h, "Sync");
    settle(&mut h);
    type_into(&mut h, Role::TextInput, "File in the synced folder", &path);
    click(&mut h, "Turn on");
    settle(&mut h);
    assert!(h.query_by_label("Synced.").is_some());
    assert!(h.query_by_label(&path).is_some());
    assert!(synced.exists());

    // Another device with no vault joins it, then pairs with the password.
    let other = tempdir();
    let mut g = window(
        start(&other, Duration::from_secs(300)),
        other.join("token"),
        FakeClip::default(),
    );
    wait_for(&mut g, Screen::Create);
    type_into(&mut g, Role::TextInput, "File in the synced folder", &path);
    click(&mut g, "Join");
    wait_for(&mut g, Screen::Pair);
    type_into(&mut g, Role::PasswordInput, "Master password", &password());
    click(&mut g, "Pair");
    wait_for(&mut g, Screen::Unlocked);
    assert!(other.join("data/vault.svault").exists());
}
