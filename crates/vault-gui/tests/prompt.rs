//! The approval window, driven headless.

use eframe::egui::Key;
use eframe::egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use vault_gui::prompt::{Ask, Prompt, Request};

fn window(autofill: bool) -> Harness<'static, Prompt> {
    asking(Ask::Pair { autofill })
}

fn asking(ask: Ask) -> Harness<'static, Prompt> {
    let p = Prompt::new(Request {
        client: "browser".into(),
        ask,
        program: Some("/usr/lib/vault/vault-native-host".into()),
    });
    let mut h = Harness::builder().with_size([480.0, 440.0]).build_ui_state(
        |ui, p: &mut Prompt| {
            p.show(ui);
        },
        p,
    );
    h.step();
    h.step();
    h
}

#[test]
fn shows_who_asks_and_what_they_get() {
    let h = window(true);
    assert!(
        h.query_by_label_contains("Allow \u{201c}browser\u{201d}")
            .is_some()
    );
    assert!(
        h.query_by_label("/usr/lib/vault/vault-native-host")
            .is_some()
    );
    assert!(h.query_by_label_contains("fill your logins").is_some());
    let h = window(false);
    assert!(
        h.query_by_label_contains("read, change and delete every item")
            .is_some()
    );
}

#[test]
fn deny_has_the_focus_and_enter_does_not_allow() {
    let mut h = window(false);
    assert!(h.get_by_role_and_label(Role::Button, "Deny").is_focused());
    h.key_press(Key::Enter);
    h.step();
    assert_ne!(h.state().answer, Some(true));
}

#[test]
fn allow_and_escape() {
    let mut h = window(false);
    h.get_by_role_and_label(Role::Button, "Allow").click();
    h.step();
    assert_eq!(h.state().answer, Some(true));

    let mut h = window(false);
    h.key_press(Key::Escape);
    h.step();
    assert_eq!(h.state().answer, Some(false));
}

#[test]
fn a_card_fill_names_the_card_and_the_site() {
    let mut h = asking(Ask::FillCard {
        card: "Travel (Visa \u{2022}\u{2022}\u{2022}\u{2022} 1111)".into(),
        origin: "https://shop.example".into(),
    });
    assert!(h.query_by_label_contains("Fill Travel (Visa").is_some());
    assert!(h.query_by_label("https://shop.example").is_some());
    assert!(h.get_by_role_and_label(Role::Button, "Deny").is_focused());
    h.get_by_role_and_label(Role::Button, "Allow").click();
    h.step();
    assert_eq!(h.state().answer, Some(true));
}

#[test]
fn key_use_names_the_key_and_purpose() {
    let mut h = asking(Ask::Use {
        key: "laptop".into(),
        purpose: "sign a git commit or tag".into(),
    });
    assert!(
        h.query_by_label_contains("Use the key \u{201c}laptop\u{201d}")
            .is_some()
    );
    assert!(
        h.query_by_label_contains("To sign a git commit or tag.")
            .is_some()
    );
    assert!(
        h.query_by_label_contains("/usr/lib/vault/vault-native-host")
            .is_some()
    );
    h.get_by_label("Deny").click();
    h.step();
    assert_eq!(h.state().answer, Some(false));
}

#[test]
fn an_app_asking_for_its_passwords_shows_its_command_line() {
    let mut h = asking(Ask::App {
        command: Some("python3 mail-sync.py".into()),
    });
    assert!(
        h.query_by_label_contains("use its saved app passwords")
            .is_some()
    );
    assert!(h.query_by_label("python3 mail-sync.py").is_some());
    assert!(
        h.query_by_label_contains("none of your other items")
            .is_some()
    );
    assert!(h.get_by_role_and_label(Role::Button, "Deny").is_focused());
    h.get_by_role_and_label(Role::Button, "Allow").click();
    h.step();
    assert_eq!(h.state().answer, Some(true));
}
