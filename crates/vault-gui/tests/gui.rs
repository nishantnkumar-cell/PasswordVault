//! Drive the real window (headless, through its accessibility tree) against a
//! real daemon on a real socket, with software stand-ins for the hardware.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
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
        presence: None,
    };
    let d = Arc::new(Mutex::new(Daemon::new(store, hw, KdfCost::MINIMUM, idle)));
    let sock = endpoint(dir);
    let l = server::bind(&sock, false).unwrap();
    let d2 = d.clone();
    std::thread::spawn(move || {
        server::serve(l, server::current_user(), move |c, pid| {
            let _ = server::connection(c, &d2, pid);
        })
    });
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
        .with_size([1180.0, 1000.0])
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
    click_last(h, label);
}

/// Click the last button called `label` once it has stopped moving: the
/// setup card re-centres a frame after its height changes, and a click
/// aimed at where the button was a frame ago can miss.
fn click_last(h: &mut Harness<'_, App>, label: &str) {
    let rect = |h: &Harness<'_, App>| {
        h.get_all_by_role_and_label(Role::Button, label)
            .last()
            .unwrap_or_else(|| panic!("no {label:?} button"))
            .rect()
    };
    for _ in 0..20 {
        let before = rect(h);
        h.step();
        if rect(h) == before {
            break;
        }
    }
    h.get_all_by_role_and_label(Role::Button, label)
        .last()
        .unwrap()
        .click();
    h.step();
    h.step();
}

/// Walk through the rest of the first-run wizard, skipping the extras.
fn finish_setup(h: &mut Harness<'_, App>) {
    h.get_by_role_and_label(
        Role::CheckBox,
        "I've written down my recovery code and put it somewhere safe",
    )
    .click();
    h.step();
    click(h, "Continue");
    click(h, "Skip for now");
    click(h, "Skip for now");
    click(h, "Open my vault");
    wait_for(h, Screen::Unlocked);
}

#[test]
fn create_add_copy_lock_unlock() {
    let dir = tempdir();
    let sock = start(&dir, Duration::from_secs(300));
    let clip = FakeClip::default();
    let mut h = window(sock, dir.join("token"), clip.clone());
    wait_for(&mut h, Screen::Create);
    click(&mut h, "Create a new vault");

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
    wait_for(&mut h, Screen::Setup);
    assert!(dir.join("token").exists(), "pairing token saved");
    assert!(
        h.query_by_label("Continue")
            .is_some_and(|c| c.accesskit_node().is_disabled()),
        "can't go on before saying the code is saved"
    );
    finish_setup(&mut h);

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
fn setup_wizard_steps_back_reports_failures_and_ends_on_import() {
    let dir = tempdir();
    let sock = start(&dir, Duration::from_secs(300));
    let mut h = window(sock, dir.join("token"), FakeClip::default());
    wait_for(&mut h, Screen::Create);
    click(&mut h, "Create a new vault");
    assert!(h.query_by_label("Choose your master password").is_some());
    click(&mut h, "Back");
    assert!(h.query_by_label("Welcome to Secret Vault").is_some());
    click(&mut h, "Create a new vault");
    let pw = password();
    type_into(&mut h, Role::PasswordInput, "Master password", &pw);
    assert!(h.query_by_label("Strong").is_some());
    type_into(&mut h, Role::PasswordInput, "Repeat it", &pw);
    click(&mut h, "Create vault");
    wait_for(&mut h, Screen::Setup);
    h.get_by_role_and_label(
        Role::CheckBox,
        "I've written down my recovery code and put it somewhere safe",
    )
    .click();
    h.step();
    click(&mut h, "Continue");

    // No security key support in this daemon: the wizard says so and stays.
    click_last(&mut h, "Set up");
    click(&mut h, "Add");
    settle(&mut h);
    assert!(
        h.state().error().is_some(),
        "adding a security key without support should fail"
    );
    assert_eq!(*h.state().screen(), Screen::Setup);
    click(&mut h, "Cancel");
    click(&mut h, "Skip for now");
    assert!(h.query_by_label("Fill passwords in your browser").is_some());
    type_into(
        &mut h,
        Role::TextInput,
        "Chrome or Edge extension ID",
        "not an id",
    );
    click(&mut h, "Register");
    assert!(h.query_by_label_contains("isn't an extension ID").is_some());
    click(&mut h, "Skip for now");
    assert!(h.query_by_label("You're all set").is_some());
    click(&mut h, "Import passwords");
    wait_for(&mut h, Screen::Unlocked);
    assert!(
        h.query_by_label("Bitwarden export (unencrypted .json)")
            .is_some()
    );
}

#[test]
fn pairs_a_second_window_and_follows_idle_lock() {
    let dir = tempdir();
    let sock = start(&dir, Duration::from_secs(2));
    let pw = password();
    let mut first = window(sock.clone(), dir.join("first"), FakeClip::default());
    wait_for(&mut first, Screen::Create);
    click(&mut first, "Create a new vault");
    type_into(&mut first, Role::PasswordInput, "Master password", &pw);
    type_into(&mut first, Role::PasswordInput, "Repeat it", &pw);
    click(&mut first, "Create vault");
    wait_for(&mut first, Screen::Setup);

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
    created_on(start(dir, idle), dir, clip)
}

fn created_on(sock: PathBuf, dir: &Path, clip: FakeClip) -> Harness<'static, App> {
    let pw = password();
    let mut h = window(sock, dir.join("token"), clip);
    wait_for(&mut h, Screen::Create);
    click(&mut h, "Create a new vault");
    type_into(&mut h, Role::PasswordInput, "Master password", &pw);
    type_into(&mut h, Role::PasswordInput, "Repeat it", &pw);
    click(&mut h, "Create vault");
    wait_for(&mut h, Screen::Setup);
    finish_setup(&mut h);
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
    h.get_by_role_and_label(Role::Button, "All items").click();
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
    type_into(&mut h, Role::TextInput, "First name", "Alex");
    type_into(&mut h, Role::TextInput, "Last name", "Example");
    type_into(&mut h, Role::TextInput, "City", "London");
    click(&mut h, "Save");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert!(h.query_by_label_contains("Home\nAlex Example").is_some());
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
    // Its text is hidden until shown.
    assert!(h.query_by_label("door code").is_none());
    click(&mut h, "Show");
    assert!(h.query_by_label("door code").is_some());

    // The type filter.
    h.get_by_role_and_label(Role::Button, "Cards").click();
    h.step();
    h.step();
    assert!(h.query_by_label_contains("Home\nAlex").is_none());
    assert!(h.query_by_label_contains("Travel\nVisa").is_some());
}

#[test]
fn command_palette_finds_copies_and_locks() {
    use eframe::egui::{Key, Modifiers};
    let dir = tempdir();
    let clip = FakeClip::default();
    let mut h = created(&dir, Duration::from_secs(300), clip.clone());
    click(&mut h, "New item");
    click(&mut h, "Login");
    type_into(&mut h, Role::TextInput, "Title", "Example");
    type_into(&mut h, Role::TextInput, "Username", "alex");
    click(&mut h, "Generate");
    settle(&mut h);
    click(&mut h, "Save");
    settle(&mut h);
    click(&mut h, "Copy password");
    let password = clip.0.lock().unwrap().clone().expect("copied");
    *clip.0.lock().unwrap() = None;

    // Ctrl K, type, Enter: the best match's password is copied.
    h.key_press_modifiers(Modifiers::COMMAND, Key::K);
    h.step();
    h.step();
    type_into(&mut h, Role::TextInput, "Find an item or action", "exa");
    h.step();
    assert!(
        h.query_by_role_and_label(Role::Button, "Copy username for Example")
            .is_some()
    );
    h.key_press(Key::Enter);
    h.step();
    settle(&mut h);
    assert_eq!(clip.0.lock().unwrap().as_deref(), Some(password.as_str()));
    assert!(
        h.query_by_label("Find an item or action").is_none(),
        "closed"
    );

    // Arrow keys pick another row; Escape closes without running anything.
    h.key_press_modifiers(Modifiers::COMMAND, Key::K);
    h.step();
    h.step();
    type_into(&mut h, Role::TextInput, "Find an item or action", "exa");
    h.step();
    h.key_press(Key::ArrowDown);
    h.key_press(Key::ArrowDown);
    h.step();
    h.key_press(Key::Enter);
    h.step();
    settle(&mut h);
    assert_eq!(clip.0.lock().unwrap().as_deref(), Some("alex"));
    h.key_press_modifiers(Modifiers::COMMAND, Key::K);
    h.step();
    h.key_press(Key::Escape);
    h.step();
    assert!(h.query_by_label("Find an item or action").is_none());

    // Vault actions run from the palette too.
    h.key_press_modifiers(Modifiers::COMMAND, Key::K);
    h.step();
    h.step();
    type_into(&mut h, Role::TextInput, "Find an item or action", "lock");
    h.step();
    click(&mut h, "Lock now");
    wait_for(&mut h, Screen::Locked);
}

#[test]
fn sidebar_filters_the_list() {
    let dir = tempdir();
    let mut h = created(&dir, Duration::from_secs(300), FakeClip::default());
    for (title, totp) in [
        ("Plain", None),
        ("Coded", Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
    ] {
        click(&mut h, "New item");
        click(&mut h, "Login");
        type_into(&mut h, Role::TextInput, "Title", title);
        if let Some(seed) = totp {
            type_into(&mut h, Role::PasswordInput, "One-time codes", seed);
        }
        click(&mut h, "Save");
        settle(&mut h);
    }
    let row = |h: &Harness<'_, App>, label: &str| {
        h.query_by_role_and_label(Role::Button, label).is_some()
    };
    assert!(row(&h, "Plain") && row(&h, "Coded 2FA"));
    click(&mut h, "One-time codes");
    assert!(!row(&h, "Plain") && row(&h, "Coded 2FA"));
    click(&mut h, "All items");
    assert!(row(&h, "Plain"));
}

/// Picking a category in the sidebar must visibly change the screen, even
/// when the category is empty or an item from another one is open.
#[test]
fn sidebar_categories_change_the_screen() {
    let dir = tempdir();
    let mut h = created(&dir, Duration::from_secs(300), FakeClip::default());
    let shown = |h: &Harness<'_, App>, label: &str| h.query_all_by_label(label).next().is_some();
    let button = |h: &Harness<'_, App>, label: &str| {
        h.query_by_role_and_label(Role::Button, label).is_some()
    };

    // An empty vault offers a first login.
    assert!(shown(&h, "No items yet."));
    click(&mut h, "New login");
    type_into(&mut h, Role::TextInput, "Title", "Example Mail");
    click(&mut h, "Save");
    settle(&mut h);
    assert!(button(&h, "Edit"), "the saved login is open");

    // An empty category says so, offers its own New button, and closes the
    // login, which isn't a note.
    click(&mut h, "Secure notes");
    assert!(shown(&h, "No secure notes yet."));
    assert!(!button(&h, "Edit"), "the login stayed open");
    assert!(!button(&h, "Example Mail"));
    click(&mut h, "New secure note");
    assert!(
        h.query_by_role_and_label(Role::MultilineTextInput, "Notes")
            .is_some()
    );
    type_into(&mut h, Role::TextInput, "Title", "Door codes");
    click(&mut h, "Save");
    settle(&mut h);
    assert!(button(&h, "Door codes"));

    // Keys: their own empty text and both New buttons.
    click(&mut h, "SSH and PGP keys");
    assert!(shown(&h, "No SSH or PGP keys yet."));
    assert!(button(&h, "New SSH key") && button(&h, "New OpenPGP key"));
    assert!(!button(&h, "Door codes"));
    click(&mut h, "New SSH key");
    assert!(button(&h, "Make key"), "the key form opened");

    // An item that is in the category stays open.
    click(&mut h, "Secure notes");
    click(&mut h, "Door codes");
    settle(&mut h);
    click(&mut h, "All items");
    assert!(button(&h, "Edit"), "the note was closed though it's listed");

    click(&mut h, "Cards");
    assert!(shown(&h, "No cards yet."));
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
    click(&mut first, "Create a new vault");
    type_into(&mut first, Role::PasswordInput, "Master password", &pw);
    type_into(&mut first, Role::PasswordInput, "Repeat it", &pw);
    click(&mut first, "Create vault");
    wait_for(&mut first, Screen::Setup);

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
    click(&mut g, "I already use Secret Vault on another device");
    type_into(&mut g, Role::TextInput, "File in the synced folder", &path);
    click(&mut g, "Join");
    wait_for(&mut g, Screen::Pair);
    type_into(&mut g, Role::PasswordInput, "Master password", &password());
    click(&mut g, "Pair");
    wait_for(&mut g, Screen::Unlocked);
    assert!(other.join("data/vault.svault").exists());
}

#[test]
fn key_shows_its_public_half_and_asks_before_use() {
    use vault_ipc::{Envelope, KeyKind, Request, Response};
    let dir = tempdir();
    let (sock, d) = start_daemon(&dir, Duration::from_secs(300));
    let clip = FakeClip::default();
    let mut h = created_on(sock, &dir, clip.clone());

    // A key made outside the window, as `vault key generate` would.
    let token: [u8; 32] = std::fs::read(dir.join("token"))
        .unwrap()
        .try_into()
        .unwrap();
    let r = d.lock().unwrap().handle(Envelope {
        token: Some(zeroize::Zeroizing::new(token)),
        request: Request::GenerateKey {
            title: "Deploy key".into(),
            kind: KeyKind::SshEd25519,
            confirm: false,
        },
    });
    assert!(matches!(r, Response::ItemSaved { .. }));

    // The window notices the change on its next status check.
    let deadline = Instant::now() + Duration::from_secs(20);
    while h.state().items().is_empty() {
        assert!(Instant::now() < deadline, "key never listed");
        h.step();
        std::thread::sleep(Duration::from_millis(20));
    }
    settle(&mut h);
    h.get_by_role_and_label(Role::Button, "Deploy key Key")
        .click();
    h.step();
    settle(&mut h);
    assert!(h.query_by_label("SSH key").is_some());
    // Keys don't fill websites, so there is no autofill card.
    assert!(h.query_by_label_contains("AUTOFILL").is_none());

    click(&mut h, "Copy public key");
    let copied = clip.0.lock().unwrap().clone().expect("copied");
    assert!(copied.starts_with("ssh-ed25519 "), "{copied}");

    assert!(!h.state().items()[0].key_confirm);
    h.get_by_role_and_label(Role::CheckBox, "Ask before each use")
        .click();
    h.step();
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert!(h.state().items()[0].key_confirm);
}

#[test]
fn makes_ssh_and_openpgp_keys() {
    let dir = tempdir();
    let clip = FakeClip::default();
    let mut h = created(&dir, Duration::from_secs(300), clip.clone());

    // An SSH key from the New item menu.
    click(&mut h, "New item");
    click(&mut h, "SSH key");
    assert!(h.query_by_label("New SSH key").is_some());
    click(&mut h, "Make key");
    assert!(h.state().error().unwrap().contains("title"));
    type_into(&mut h, Role::TextInput, "Title", "Laptop");
    click(&mut h, "Make key");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    assert!(h.query_by_label_contains("Key made.").is_some());
    let items = h.state().items();
    assert_eq!(items.len(), 1);
    assert!(
        items[0].key.as_deref().unwrap().starts_with("ssh-ed25519 "),
        "{:?}",
        items[0].key
    );
    assert!(items[0].key_confirm, "asks before each use by default");
    click(&mut h, "Copy public key");
    let copied = clip.0.lock().unwrap().clone().expect("copied");
    assert!(copied.starts_with("ssh-ed25519 "), "{copied}");

    // A classic OpenPGP key from the same menu, without asking before use.
    click(&mut h, "New item");
    click(&mut h, "OpenPGP key");
    type_into(&mut h, Role::TextInput, "Name", "Alex Example");
    type_into(&mut h, Role::TextInput, "Email", "alex@example.com");
    h.get_by_role_and_label(Role::CheckBox, "Ask before each use")
        .click();
    h.step();
    click(&mut h, "Make key");
    settle(&mut h);
    assert_eq!(h.state().error(), None);
    let items = h.state().items();
    assert_eq!(items.len(), 2);
    let pgp = items
        .iter()
        .find(|i| i.title == "Alex Example")
        .expect("listed");
    assert!(
        pgp.key.as_deref().unwrap().starts_with("OpenPGP"),
        "{:?}",
        pgp.key
    );
    assert!(!pgp.key_confirm);
    assert!(h.query_by_label("OpenPGP key").is_some());
    click(&mut h, "Copy public key");
    let copied = clip.0.lock().unwrap().clone().expect("copied");
    assert!(
        copied.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "{copied}"
    );
}
