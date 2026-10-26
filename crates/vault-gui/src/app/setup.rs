//! The first-run wizard: create a vault (or join one), save the recovery
//! code, add more ways to unlock, connect the browser.
//!
//! It runs while there is no vault (`Screen::Create`) and, once the vault is
//! made, while it is open (`Screen::Setup`). The master password is kept
//! here, zeroized on drop, only so the hardware methods can be added without
//! typing it again; it goes when the wizard ends or the vault locks.

use eframe::egui::{
    self, Align, Color32, CornerRadius, Layout, Margin, RichText, Sense, Stroke, Ui, Vec2,
};
use vault_ipc::{Request, Response, Secret, StatusInfo};

use super::{
    App, CLIENT_NAME, HELLO, HELLO_CONFIRM, HELLO_WAYS, Op, Screen, View, WINDOWS_ASKS_KEY_PIN,
    opt, stacked_secret,
};
use crate::theme::{self, Icon};

/// Where the wizard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Step {
    #[default]
    Welcome,
    Join,
    Password,
    Recovery,
    Unlock,
    Browser,
    Done,
}

/// The steps shown in the step list, in order, with a line under each.
const TRACK: [(Step, &str, &str); 5] = [
    (Step::Password, "Password", "Opens the vault"),
    (Step::Recovery, "Recovery code", "If you forget it"),
    (Step::Unlock, "Unlock methods", "Optional"),
    (Step::Browser, "Browser", "Optional"),
    (Step::Done, "Finish", ""),
];

/// Width of the step list on the left of the wizard's card.
const RAIL: f32 = 250.0;

/// An extra unlock method the wizard can add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Extra {
    Hello,
    Tpm,
    SecurityKey,
}

impl Extra {
    fn icon(self) -> Icon {
        match self {
            Extra::Hello => Icon::Identity,
            Extra::Tpm => Icon::Chip,
            Extra::SecurityKey => Icon::Key,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Extra::Hello => HELLO,
            Extra::Tpm => "This computer's TPM chip",
            Extra::SecurityKey => "Security key",
        }
    }
}

/// The wizard's state.
#[derive(Default)]
pub(super) struct Setup {
    pub(super) step: Step,
    /// The new master password, for adding hardware methods.
    password: Secret,
    recovery_code: Option<Secret>,
    recovery_saved: bool,
    /// The method whose options are open.
    open: Option<Extra>,
    added: Vec<Extra>,
    pin: Secret,
    require_uv: bool,
    chrome_id: String,
    firefox: bool,
    browser_done: bool,
    browser_error: Option<String>,
}

/// Which methods this build of the daemon can add, by platform.
fn extras() -> &'static [Extra] {
    if cfg!(windows) {
        &[Extra::Hello, Extra::Tpm, Extra::SecurityKey]
    } else if cfg!(target_os = "macos") {
        &[Extra::Hello, Extra::SecurityKey]
    } else {
        &[Extra::Tpm, Extra::SecurityKey]
    }
}

impl App {
    /// Start the wizard if it isn't running.
    pub(super) fn begin_setup(&mut self) {
        if self.setup.is_none() {
            self.setup = Some(Setup::default());
        }
    }

    /// The daemon answered a call the wizard made.
    pub(super) fn on_setup_result(&mut self, op: Op, r: Response) {
        let Some(s) = &mut self.setup else { return };
        match (op, r) {
            (
                Op::Init,
                Response::Initialized {
                    recovery_code,
                    token,
                },
            ) => {
                if let Err(e) = self.paths.save_token(&token) {
                    self.error = Some(format!("Couldn't save this app's pairing: {e}"));
                }
                self.token = Some(token);
                s.password = std::mem::take(&mut self.new_password);
                self.new_password2 = Secret::default();
                s.recovery_code = Some(recovery_code);
                s.step = Step::Recovery;
                self.screen = Screen::Setup;
            }
            (Op::SetupSlot(e), Response::SlotAdded { .. }) => {
                s.added.push(e);
                s.open = None;
                s.pin = Secret::default();
                self.notice = Some(format!("{} added.", e.name()));
            }
            (Op::SetupHello, Response::Status(st)) => {
                s.added.push(Extra::Hello);
                s.open = None;
                self.notice = Some(format!("{HELLO} quick unlock is on."));
                self.on_status(st);
            }
            _ => self.error = Some("Unexpected answer from vaultd.".into()),
        }
    }

    /// Leave the wizard for the vault, on `view`.
    fn finish_setup(&mut self, view: View) {
        self.setup = None;
        self.error = None;
        self.notice = None;
        self.screen = Screen::Unlocked;
        self.view = view;
        self.send(Op::ListItems, vault_ipc::Request::ListItems);
        self.send(Op::ListSlots, vault_ipc::Request::ListSlots);
    }

    /// The wizard's window: a card in the middle of the ground, with the
    /// steps listed down its left side when there is room.
    pub(super) fn setup_window(&mut self, ui: &mut Ui) {
        self.begin_setup();
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::SIDEBAR))
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        // Centred on the card's height in the last frame.
                        let id = egui::Id::unique("setup-card-height");
                        let last: f32 = ui.data(|d| d.get_temp(id)).unwrap_or(0.0);
                        let room = ui.available_height();
                        ui.add_space(((room - last) / 2.0).max(16.0));
                        let free = ui.available_width() - 32.0;
                        let wide = free >= 720.0;
                        let width = if wide {
                            free.min(880.0)
                        } else {
                            free.clamp(320.0, 600.0)
                        };
                        let card = theme::card()
                            .inner_margin(Margin::ZERO)
                            .corner_radius(CornerRadius::same(16))
                            .show(ui, |ui| {
                                ui.set_width(width);
                                if wide {
                                    self.setup_panes(ui, width);
                                } else {
                                    egui::Frame::new()
                                        .inner_margin(Margin::symmetric(36, 30))
                                        .show(ui, |ui| {
                                            ui.set_width(width - 72.0);
                                            ui.vertical(|ui| self.setup_card(ui, false));
                                        });
                                }
                            });
                        let h = card.response.rect.height();
                        if (h - last).abs() > 0.5 {
                            ui.data_mut(|d| d.insert_temp(id, h));
                            ui.ctx().request_repaint();
                        }
                        ui.add_space(16.0);
                    });
                });
            });
    }

    /// The wide card: the step list on a grey strip, the step on the right.
    fn setup_panes(&mut self, ui: &mut Ui, width: f32) {
        let step = self.setup.as_ref().map_or(Step::Welcome, |s| s.step);
        let strip = ui.painter().add(egui::Shape::Noop);
        let row = ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            egui::Frame::new()
                .inner_margin(Margin::symmetric(22, 28))
                .show(ui, |ui| {
                    ui.set_width(RAIL - 44.0);
                    ui.spacing_mut().item_spacing.x = 10.0;
                    ui.vertical(|ui| rail(ui, step));
                });
            egui::Frame::new()
                .inner_margin(Margin::symmetric(40, 32))
                .show(ui, |ui| {
                    ui.set_width(width - RAIL - 80.0);
                    ui.set_min_height(420.0);
                    ui.spacing_mut().item_spacing.x = 8.0;
                    ui.vertical(|ui| self.setup_card(ui, true));
                });
        });
        let full = row.response.rect;
        let left =
            egui::Rect::from_min_max(full.min, egui::pos2(full.left() + RAIL, full.bottom()));
        ui.painter().set(
            strip,
            egui::Shape::rect_filled(
                left,
                CornerRadius {
                    nw: 16,
                    sw: 16,
                    ne: 0,
                    se: 0,
                },
                theme::GROUND,
            ),
        );
        ui.painter().vline(
            left.right(),
            left.y_range(),
            Stroke::new(1.0, theme::DIVIDER),
        );
    }

    fn setup_card(&mut self, ui: &mut Ui, wide: bool) {
        let step = self.setup.as_ref().map_or(Step::Welcome, |s| s.step);
        if let Some(at) = TRACK.iter().position(|(s, _, _)| *s == step) {
            if wide {
                if step != Step::Done {
                    ui.label(
                        RichText::new(format!("STEP {} OF {}", at + 1, TRACK.len() - 1))
                            .size(11.0)
                            .family(theme::semibold())
                            .extra_letter_spacing(0.6)
                            .color(theme::ACCENT),
                    );
                    ui.add_space(6.0);
                }
            } else {
                progress(ui, step);
                ui.add_space(22.0);
            }
        }
        match step {
            Step::Welcome => self.welcome(ui),
            Step::Join => self.join(ui),
            Step::Password => self.choose_password(ui),
            Step::Recovery => self.recovery(ui),
            Step::Unlock => self.more_methods(ui),
            Step::Browser => self.browser(ui),
            Step::Done => self.done(ui),
        }
    }

    fn go_step(&mut self, step: Step) {
        self.error = None;
        self.notice = None;
        if let Some(s) = &mut self.setup {
            s.step = step;
        }
    }

    fn welcome(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        ui.label(theme::title("Welcome to Secret Vault", 26.0));
        ui.label(
            RichText::new("A few minutes of setup, then your passwords are ready.")
                .size(15.0)
                .color(theme::TEXT),
        );
        ui.add_space(22.0);
        for (icon, title, about) in [
            (
                Icon::Lock,
                "Stays on your computer",
                "Your vault is one encrypted file here. Nothing is sent to a server.",
            ),
            (
                Icon::Key,
                "Opens your way",
                if cfg!(target_os = "macos") {
                    "Your master password, plus a security key or Touch ID if you like."
                } else {
                    "Your master password, plus this computer's chip, a security key or \
                     Windows Hello if you like."
                },
            ),
            (
                Icon::Shield,
                "Fills only the right site",
                "The browser extension fills a login only on the website it belongs to.",
            ),
        ] {
            feature(ui, icon, title, about);
            ui.add_space(8.0);
        }
        ui.add_space(14.0);
        self.messages(ui);
        let ok = self.busy.is_none();
        ui.with_layout(Layout::top_down_justified(Align::Center), |ui| {
            if big_primary(ui, ok, Icon::Plus, "Create a new vault").clicked() {
                self.go_step(Step::Password);
            }
            ui.add_space(2.0);
            if big_secondary(
                ui,
                ok,
                Icon::Sync,
                "I already use Secret Vault on another device",
            )
            .clicked()
            {
                self.go_step(Step::Join);
            }
        });
    }

    fn join(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "Join your vault",
            "If your vault is synced through OneDrive, Google Drive, Dropbox or another \
             sync app, pick the vault file in that folder. Then unlock it with the master \
             password you already use.",
        );
        self.messages(ui);
        let join = self.sync_form(ui, "Join");
        if join {
            let path = self.sync_path.trim().to_owned();
            self.act("Joining…", Op::Sync, Request::SetSync { path: Some(path) });
        }
        ui.add_space(16.0);
        let ok = self.busy.is_none();
        if back(ui, ok).clicked() {
            self.go_step(Step::Welcome);
        }
    }

    fn choose_password(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "Choose your master password",
            "This one password opens everything in the vault. Make it long rather than \
             clever: four or five random words are easy to remember and hard to guess.",
        );
        let mut submit = false;
        submit |= stacked_secret(ui, "Master password", &mut self.new_password);
        ui.add_space(-4.0);
        strength(ui, &self.new_password);
        ui.add_space(8.0);
        submit |= stacked_secret(ui, "Repeat it", &mut self.new_password2);
        if !self.new_password2.is_empty() {
            let same = *self.new_password == *self.new_password2;
            ui.add_space(-6.0);
            ui.horizontal(|ui| {
                if same {
                    Icon::Check.show(ui, 14.0, theme::OK);
                    ui.label(RichText::new("They match").small().color(theme::OK));
                } else {
                    ui.label(
                        RichText::new("Not the same yet")
                            .small()
                            .color(theme::MUTED),
                    );
                }
            });
        }
        ui.add_space(10.0);
        note(
            ui,
            theme::ACCENT_WEAK,
            "Nobody can reset this password for you. If you forget it, only the recovery \
             code from the next step can open the vault.",
        );
        ui.add_space(12.0);
        self.messages(ui);
        let ok = self.busy.is_none();
        let mut go_back = false;
        nav(ui, |ui| {
            submit |= next(ui, ok, "Create vault").clicked();
            go_back = left(ui, |ui| back(ui, ok).clicked());
        });
        if go_back {
            self.go_step(Step::Welcome);
            return;
        }
        if submit && ok {
            if self.new_password.chars().count() < 8 {
                self.error = Some("The password needs at least 8 characters.".into());
            } else if *self.new_password != *self.new_password2 {
                self.error = Some("The passwords don't match.".into());
            } else {
                let password = self.new_password.clone();
                self.act(
                    "Creating the vault…",
                    Op::Init,
                    Request::Init {
                        password,
                        client_name: CLIENT_NAME.into(),
                    },
                );
            }
        }
    }

    fn recovery(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "Save your recovery code",
            "Your vault is ready. This code opens it if you ever forget your password or \
             lose your other unlock methods. It is shown only now.",
        );
        let Some(s) = &mut self.setup else { return };
        if let Some(code) = &s.recovery_code {
            egui::Frame::new()
                .fill(theme::GROUND)
                .stroke(Stroke::new(1.0, theme::BORDER))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    code_boxes(ui, code);
                });
        }
        ui.add_space(12.0);
        for line in [
            "Write it on paper or print it, and keep it somewhere safe, away from this computer.",
            "Don't store it in a file or photo on this computer: anyone who has it can open \
             the vault.",
        ] {
            bullet(ui, line);
        }
        ui.add_space(10.0);
        ui.checkbox(
            &mut s.recovery_saved,
            "I've written down my recovery code and put it somewhere safe",
        );
        let ready = s.recovery_saved;
        ui.add_space(12.0);
        self.messages(ui);
        nav(ui, |ui| {
            if next(ui, ready, "Continue").clicked() && ready {
                self.go_step(Step::Unlock);
            }
        });
    }

    fn more_methods(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "Add quicker or stronger ways to unlock",
            "Your master password and recovery code already work. You can add more now or \
             later under Unlock methods. Each one is optional.",
        );
        let hello = self
            .status
            .as_ref()
            .is_some_and(|(s, _)| s.quick_unlock.supported);
        let ok = self.busy.is_none();
        let mut request = None;
        let Some(s) = &mut self.setup else { return };
        for &e in extras() {
            if e == Extra::Hello && !hello {
                continue;
            }
            let added = s.added.contains(&e);
            let open = s.open == Some(e);
            option_card(ui, open, |ui| {
                ui.horizontal(|ui| {
                    let (tile, _) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                    let (fill, ink) = if added {
                        (theme::OK_WEAK, theme::OK)
                    } else {
                        (theme::GROUND, theme::TEXT)
                    };
                    ui.painter().rect_filled(tile, CornerRadius::same(10), fill);
                    e.icon().paint(ui.painter(), tile.shrink(9.0), ink);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(
                            RichText::new(e.name())
                                .family(theme::semibold())
                                .color(theme::INK),
                        );
                        ui.label(RichText::new(about(e)).small().color(theme::MUTED));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if added {
                            done_badge(ui, "Added");
                        } else if !open
                            && ui
                                .add_enabled_ui(ok, |ui| theme::button(ui, Icon::Plus, "Set up"))
                                .inner
                                .clicked()
                        {
                            s.open = Some(e);
                            s.pin = Secret::default();
                            s.require_uv = false;
                        }
                    });
                });
                if !open || added {
                    return;
                }
                ui.add_space(8.0);
                match e {
                    Extra::Hello => {
                        ui.label(format!(
                            "After you unlock with your password, {HELLO} can unlock the \
                             vault again for the next 8 hours, until the computer restarts. \
                             You can change the hours later. {HELLO_WAYS}: any of these \
                             confirms it's you."
                        ));
                    }
                    Extra::Tpm => {
                        ui.label(
                            "Unlocking then needs both your master password and this \
                             computer, so a copy of the vault file is useless elsewhere. An \
                             optional PIN adds a second check that the chip limits guesses on.",
                        );
                        egui::Grid::new("setup-tpm").num_columns(2).show(ui, |ui| {
                            wide_secret(ui, "PIN (optional)", &mut s.pin);
                            ui.end_row();
                        });
                    }
                    Extra::SecurityKey => {
                        ui.label(
                            "A FIDO2 key such as a YubiKey, Nitrokey or Google Titan. Plug it in \
                             now. Unlocking then takes your master password and a touch on the \
                             key.",
                        );
                        if !WINDOWS_ASKS_KEY_PIN {
                            egui::Grid::new("setup-key").num_columns(2).show(ui, |ui| {
                                wide_secret(ui, "Key PIN (if it has one)", &mut s.pin);
                                ui.end_row();
                            });
                        }
                        ui.checkbox(&mut s.require_uv, "Also ask for the key's PIN every time");
                        if WINDOWS_ASKS_KEY_PIN {
                            ui.label(
                                RichText::new(
                                    "Windows asks for the touch, and the key's PIN, in its own \
                                     window. If your key has a PIN, tick the box above.",
                                )
                                .small()
                                .color(theme::MUTED),
                            );
                        }
                    }
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let label = if e == Extra::Hello { "Turn on" } else { "Add" };
                    if theme::primary(ui, ok, label).clicked() && ok {
                        request = Some(match e {
                            Extra::Hello => (
                                HELLO_CONFIRM,
                                Op::SetupHello,
                                Request::SetQuickUnlock { hours: 8 },
                            ),
                            Extra::Tpm => (
                                "Adding…",
                                Op::SetupSlot(e),
                                Request::AddTpmSlot {
                                    password: s.password.clone(),
                                    pin: opt(&s.pin),
                                    bind_pcr7: false,
                                    label: "this computer".into(),
                                },
                            ),
                            Extra::SecurityKey => (
                                "Touch your security key when it blinks…",
                                Op::SetupSlot(e),
                                Request::AddFido2Slot {
                                    password: s.password.clone(),
                                    pin: opt(&s.pin),
                                    require_uv: s.require_uv,
                                    label: "security key".into(),
                                },
                            ),
                        });
                    }
                    if ui.add_enabled(ok, egui::Button::new("Cancel")).clicked() {
                        s.open = None;
                    }
                });
            });
            ui.add_space(8.0);
        }
        if cfg!(target_os = "macos") {
            ui.label(
                RichText::new(
                    "Macs have no TPM chip. Touch ID quick unlock re-opens the vault after a \
                     full unlock; unlocking with the Secure Enclave alone is not supported yet.",
                )
                .small()
                .color(theme::MUTED),
            );
        }
        let any = !s.added.is_empty();
        if let Some((busy, op, req)) = request {
            self.act(busy, op, req);
        }
        ui.add_space(8.0);
        self.messages(ui);
        nav(ui, |ui| {
            let label = if any { "Continue" } else { "Skip for now" };
            if next(ui, ok, label).clicked() && ok {
                self.go_step(Step::Browser);
            }
            if left(ui, |ui| back(ui, ok).clicked()) {
                self.go_step(Step::Recovery);
            }
        });
    }

    fn browser(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "Fill passwords in your browser",
            "The Secret Vault extension fills your logins in Chrome, Edge and Firefox, and \
             only on the website each login belongs to.",
        );
        let Some(s) = &mut self.setup else { return };
        numbered(ui, 1, "Add the extension to your browser", |ui| {
            ui.label(
                "It isn't in the browser stores yet. In Chrome or Edge, open the \
                 extensions page (chrome://extensions or edge://extensions), turn on \
                 Developer mode, click Load unpacked and choose the extension folder \
                 from your Secret Vault download. In Firefox, open about:debugging, \
                 choose This Firefox and load extension/manifest.json.",
            );
        });
        numbered(ui, 2, "Let the browser talk to the vault", |ui| {
            ui.label(
                "Copy the extension's ID from its card on the extensions page (32 \
                 letters) and paste it here.",
            );
            egui::Grid::new("setup-browser")
                .num_columns(2)
                .show(ui, |ui| {
                    let l = ui.label("Chrome or Edge extension ID");
                    ui.add(
                        egui::TextEdit::singleline(&mut s.chrome_id)
                            .desired_width(300.0)
                            .hint_text("32 letters, a to p"),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                });
            ui.checkbox(&mut s.firefox, "I also use Firefox");
            let id = s.chrome_id.trim().to_owned();
            if s.browser_done {
                done_badge(ui, "Registered with your browsers");
            } else if theme::primary_icon(ui, !id.is_empty(), Icon::Shield, "Register").clicked() {
                match register_browsers(&id, s.firefox) {
                    Ok(()) => {
                        s.browser_done = true;
                        s.browser_error = None;
                    }
                    Err(e) => s.browser_error = Some(e),
                }
            }
            if let Some(e) = &s.browser_error {
                ui.colored_label(theme::ERROR, e);
            }
        });
        numbered(ui, 3, "Connect the extension", |ui| {
            ui.label(
                "Click the Secret Vault icon in the browser's toolbar, then Connect. A \
                 Secret Vault window asks whether to allow the browser: press Allow.",
            );
        });
        let done = s.browser_done;
        ui.add_space(8.0);
        self.messages(ui);
        nav(ui, |ui| {
            let label = if done { "Continue" } else { "Skip for now" };
            if next(ui, true, label).clicked() {
                self.go_step(Step::Done);
            }
            if left(ui, |ui| back(ui, true).clicked()) {
                self.go_step(Step::Unlock);
            }
        });
    }

    fn done(&mut self, ui: &mut Ui) {
        heading(
            ui,
            "You're all set",
            "Your vault is open and ready. Here is what you set up:",
        );
        let Some(s) = &self.setup else { return };
        let mut rows: Vec<(bool, String)> = vec![
            (true, "Master password".into()),
            (s.recovery_saved, "Recovery code saved".into()),
        ];
        if s.added.is_empty() {
            rows.push((
                false,
                "No other unlock methods yet: add them under Unlock methods".into(),
            ));
        }
        rows.extend(s.added.iter().map(|e| (true, e.name().to_string())));
        rows.push(if s.browser_done {
            (true, "Browser extension registered".into())
        } else {
            (
                false,
                "Browser not connected yet: see Browser autofill in the guide".into(),
            )
        });
        theme::card()
            .inner_margin(Margin::symmetric(16, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 0.0;
                for (i, (ok, text)) in rows.into_iter().enumerate() {
                    if i > 0 {
                        theme::divider(ui);
                    }
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ok {
                            check(ui, theme::OK);
                        } else {
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
                            ui.painter().circle_stroke(
                                rect.center(),
                                7.0,
                                Stroke::new(1.5, theme::BORDER_STRONG),
                            );
                        }
                        let colour = if ok { theme::INK } else { theme::MUTED };
                        ui.label(RichText::new(text).color(colour));
                    });
                    ui.add_space(10.0);
                }
            });
        ui.add_space(14.0);
        note(
            ui,
            theme::GROUND,
            "Moving from another password manager? Bring your logins in with Import: \
             Bitwarden exports and the password files Chrome, Edge and Firefox save both work.",
        );
        ui.add_space(12.0);
        let mut go = None;
        nav(ui, |ui| {
            if next(ui, true, "Open my vault").clicked() {
                go = Some(View::Items);
            }
            if theme::button(ui, Icon::Import, "Import passwords").clicked() {
                go = Some(View::Import);
            }
            if left(ui, |ui| back(ui, true).clicked()) {
                self.go_step(Step::Browser);
            }
        });
        if let Some(v) = go {
            self.finish_setup(v);
        }
    }

    /// Whether the wizard should stay up for this status.
    pub(super) fn setup_screen(&mut self, s: &StatusInfo) -> Option<Screen> {
        if !s.initialized {
            self.begin_setup();
            return Some(Screen::Create);
        }
        // A vault exists: only a wizard that created it carries on, while it
        // stays open. Locking ends it and drops the password it held.
        if self.screen == Screen::Setup && s.unlocked && self.token.is_some() {
            return Some(Screen::Setup);
        }
        if self.setup.take().is_some() && self.screen == Screen::Setup {
            self.notice = Some("The vault locked, so setup ended.".into());
        }
        None
    }
}

/// The recovery code's groups, each in a white box, in even rows. A
/// screen reader reads the whole code at once.
fn code_boxes(ui: &mut Ui, code: &str) {
    let groups: Vec<&str> = code.split('-').collect();
    let per_row = if groups.len() > 8 {
        groups.len().div_ceil(2)
    } else {
        groups.len()
    }
    .max(1);
    let gap = 8.0;
    let w = ((ui.available_width() - gap * (per_row - 1) as f32) / per_row as f32).max(40.0);
    let rows = groups.len().div_ceil(per_row);
    let height = rows as f32 * 40.0 + (rows - 1) as f32 * gap;
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, code));
    let p = ui.painter();
    for (i, g) in groups.iter().enumerate() {
        let (r, c) = (i / per_row, i % per_row);
        let b = egui::Rect::from_min_size(
            rect.min + Vec2::new(c as f32 * (w + gap), r as f32 * (40.0 + gap)),
            Vec2::new(w, 40.0),
        );
        p.rect(
            b,
            CornerRadius::same(8),
            theme::SURFACE,
            Stroke::new(1.0, theme::DIVIDER),
            egui::StrokeKind::Inside,
        );
        p.text(
            b.center(),
            egui::Align2::CENTER_CENTER,
            *g,
            egui::FontId::monospace(16.0),
            theme::INK,
        );
    }
}

/// A labelled password box, wider than the app's own. True on Enter.
fn wide_secret(ui: &mut Ui, label: &str, text: &mut Secret) -> bool {
    let l = ui.label(label);
    let r = ui
        .add(
            egui::TextEdit::singleline(&mut **text)
                .password(true)
                .desired_width(300.0),
        )
        .labelled_by(l.id);
    r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

fn about(e: Extra) -> &'static str {
    match e {
        Extra::Hello if cfg!(target_os = "macos") => {
            "Unlock again with your fingerprint, Apple Watch or Mac password"
        }
        Extra::Hello => "Unlock again with your face, fingerprint or Windows PIN",
        Extra::Tpm => "Ties the vault to this computer, together with your password",
        Extra::SecurityKey => "Your password plus a touch on a USB or NFC key",
    }
}

/// Run `vault-native-host --install` from beside this program.
fn register_browsers(chrome_id: &str, firefox: bool) -> Result<(), String> {
    if chrome_id.len() != 32 || !chrome_id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        return Err(
            "That isn't an extension ID: it is 32 lowercase letters from a to p, shown on \
             the extension's card."
                .into(),
        );
    }
    let exe = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name(format!("vault-native-host{}", std::env::consts::EXE_SUFFIX));
    let mut args = vec!["--install", chrome_id];
    if firefox {
        args.push("autofill@passwordvault.dev");
    }
    let manual = format!("vault-native-host {}", args.join(" "));
    if !exe.exists() {
        return Err(format!(
            "vault-native-host isn't next to this app, so run this yourself: {manual}"
        ));
    }
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(&args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: no console flashes up behind the app.
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("{}: {e}", exe.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        let why = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{} Try running it yourself: {manual}",
            why.trim().trim_start_matches("vault-native-host: ")
        ))
    }
}

/// How good a new master password looks: a 0..=1 fill, a word and a colour.
pub(super) fn rate(pw: &str) -> (f32, &'static str, Color32) {
    let n = pw.chars().count();
    let kinds = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&k| k)
    .count();
    if n < 8 {
        (n as f32 / 32.0, "Too short", theme::ERROR)
    } else if n >= 20 || (n >= 14 && kinds >= 3) {
        (1.0, "Strong", theme::OK)
    } else if n >= 12 || kinds >= 3 {
        (0.66, "Good", theme::OK)
    } else {
        (0.4, "Fair: longer is better", theme::WARN)
    }
}

fn strength(ui: &mut Ui, pw: &str) {
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 150.0).max(150.0);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 6.0), Sense::hover());
        let p = ui.painter();
        p.rect_filled(rect, CornerRadius::same(3), theme::BORDER);
        if pw.is_empty() {
            ui.label(
                RichText::new("At least 8 characters")
                    .small()
                    .color(theme::MUTED),
            );
            return;
        }
        let (fill, word, colour) = rate(pw);
        let mut bar = rect;
        bar.set_width(rect.width() * fill.max(0.06));
        p.rect_filled(bar, CornerRadius::same(3), colour);
        ui.label(RichText::new(word).small().color(colour));
    });
}

/// The step list down the left of the wide card: done steps ticked in
/// green, the current one in blue, joined by a line.
fn rail(ui: &mut Ui, step: Step) {
    ui.horizontal(|ui| {
        theme::lock_tile(ui, 34.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(theme::title("Secret Vault", 15.0));
            ui.label(
                RichText::new("First-time setup")
                    .small()
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(30.0);
    let at = TRACK.iter().position(|(s, _, _)| *s == step);
    for (i, (_, name, sub)) in TRACK.iter().enumerate() {
        let done = at.is_some_and(|a| i < a);
        let on = at == Some(i);
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 58.0), Sense::hover());
        let p = ui.painter();
        let c = egui::pos2(rect.left() + 12.0, rect.top() + 12.0);
        if i + 1 < TRACK.len() {
            let colour = if done { theme::OK } else { theme::BORDER };
            p.line_segment(
                [
                    c + Vec2::new(0.0, 16.0),
                    egui::pos2(c.x, rect.bottom() - 4.0),
                ],
                Stroke::new(2.0, colour),
            );
        }
        if done {
            p.circle_filled(c, 12.0, theme::OK);
            tick(p, c, 4.5, Color32::WHITE);
        } else if on {
            p.circle_filled(c, 16.0, theme::ACCENT_WEAK);
            p.circle_filled(c, 12.0, theme::ACCENT);
        } else {
            p.circle_filled(c, 12.0, theme::SURFACE);
            p.circle_stroke(c, 11.0, Stroke::new(1.5, theme::BORDER_STRONG));
        }
        if !done {
            p.text(
                c,
                egui::Align2::CENTER_CENTER,
                (i + 1).to_string(),
                egui::FontId::new(12.0, theme::semibold()),
                if on { Color32::WHITE } else { theme::MUTED },
            );
        }
        let x = c.x + 24.0;
        let font = if on || done {
            egui::FontId::new(14.0, theme::semibold())
        } else {
            egui::FontId::proportional(14.0)
        };
        let ink = if on || done { theme::INK } else { theme::MUTED };
        p.text(
            egui::pos2(x, c.y),
            egui::Align2::LEFT_CENTER,
            *name,
            font,
            ink,
        );
        if !sub.is_empty() {
            p.text(
                egui::pos2(x, c.y + 18.0),
                egui::Align2::LEFT_CENTER,
                *sub,
                egui::FontId::proportional(12.0),
                theme::MUTED,
            );
        }
    }
    ui.add_space(14.0);
    ui.label(
        RichText::new(
            "Takes about three minutes. Everything except the password and recovery code \
             can be changed later.",
        )
        .small()
        .color(theme::MUTED),
    );
}

/// Five dots joined by a line, the current one ringed, done ones ticked.
fn progress(ui: &mut Ui, step: Step) {
    let at = TRACK.iter().position(|(s, _, _)| *s == step).unwrap_or(0);
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 46.0), Sense::hover());
    let p = ui.painter();
    let gap = width / TRACK.len() as f32;
    let y = rect.top() + 10.0;
    let x = |i: usize| rect.left() + gap * (i as f32 + 0.5);
    for i in 0..TRACK.len() - 1 {
        let colour = if i < at { theme::ACCENT } else { theme::BORDER };
        p.line_segment(
            [egui::pos2(x(i) + 12.0, y), egui::pos2(x(i + 1) - 12.0, y)],
            Stroke::new(2.0, colour),
        );
    }
    for (i, (_, name, _)) in TRACK.iter().enumerate() {
        let c = egui::pos2(x(i), y);
        if i < at {
            p.circle_filled(c, 9.0, theme::ACCENT);
            tick(p, c, 4.0, Color32::WHITE);
        } else if i == at {
            p.circle_filled(c, 9.0, theme::SURFACE);
            p.circle_stroke(c, 9.0, Stroke::new(2.0, theme::ACCENT));
            p.circle_filled(c, 4.0, theme::ACCENT);
        } else {
            p.circle_filled(c, 9.0, theme::SURFACE);
            p.circle_stroke(c, 9.0, Stroke::new(1.5, theme::BORDER_STRONG));
        }
        let colour = if i <= at { theme::INK } else { theme::MUTED };
        p.text(
            egui::pos2(x(i), y + 18.0),
            egui::Align2::CENTER_TOP,
            *name,
            egui::FontId::proportional(12.0),
            colour,
        );
    }
}

/// A tick mark centred on `c`.
fn tick(p: &egui::Painter, c: egui::Pos2, r: f32, colour: Color32) {
    p.line(
        vec![
            c + Vec2::new(-r, 0.0),
            c + Vec2::new(-r * 0.3, r * 0.7),
            c + Vec2::new(r, -r * 0.6),
        ],
        Stroke::new(2.0, colour),
    );
}

/// A green circle with a tick, sized like a line of text.
fn check(ui: &mut Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 8.0, colour);
    tick(ui.painter(), rect.center(), 3.5, Color32::WHITE);
}

fn done_badge(ui: &mut Ui, text: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(0xE3, 0xF1, 0xE8))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                check(ui, theme::OK);
                ui.label(
                    RichText::new(text)
                        .small()
                        .family(theme::semibold())
                        .color(theme::OK),
                );
            });
        });
}

fn heading(ui: &mut Ui, title: &str, about: &str) {
    ui.label(
        RichText::new(title)
            .family(theme::semibold())
            .size(22.0)
            .color(theme::INK),
    );
    ui.add_space(4.0);
    ui.label(RichText::new(about).color(theme::MUTED));
    ui.add_space(18.0);
}

/// A promise on the welcome step: an icon on a blue tile, a name and a line.
fn feature(ui: &mut Ui, icon: Icon, title: &str, about: &str) {
    ui.horizontal_top(|ui| {
        let (tile, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
        ui.painter()
            .rect_filled(tile, CornerRadius::same(10), theme::ACCENT_WEAK);
        icon.paint(ui.painter(), tile.shrink(9.0), theme::ACCENT);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.label(
                RichText::new(title)
                    .family(theme::semibold())
                    .color(theme::INK),
            );
            ui.label(RichText::new(about).color(theme::MUTED));
        });
    });
}

fn bullet(ui: &mut Ui, text: &str) {
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 18.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 2.5, theme::MUTED);
        ui.add(egui::Label::new(RichText::new(text).color(theme::TEXT)).wrap());
    });
}

fn note(ui: &mut Ui, fill: Color32, text: &str) {
    egui::Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(theme::TEXT));
        });
}

/// One numbered instruction with its body indented under the title.
fn numbered(ui: &mut Ui, n: u32, title: &str, body: impl FnOnce(&mut Ui)) {
    ui.horizontal_top(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(24.0), Sense::hover());
        let p = ui.painter();
        p.circle_filled(rect.center(), 11.0, theme::ACCENT_WEAK);
        p.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            n.to_string(),
            egui::FontId::proportional(12.0),
            theme::ACCENT_DARK,
        );
        ui.vertical(|ui| {
            ui.label(
                RichText::new(title)
                    .family(theme::semibold())
                    .color(theme::INK),
            );
            body(ui);
        });
    });
    ui.add_space(12.0);
}

/// A bordered option row; blue-edged while its options are open.
fn option_card(ui: &mut Ui, open: bool, body: impl FnOnce(&mut Ui)) {
    let stroke = if open {
        Stroke::new(1.5, theme::ACCENT)
    } else {
        Stroke::new(1.0, theme::BORDER)
    };
    egui::Frame::new()
        .fill(theme::SURFACE)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui);
        });
}

/// The row of buttons at the bottom of a step, under a soft line: the main
/// one on the right.
fn nav(ui: &mut Ui, buttons: impl FnOnce(&mut Ui)) {
    ui.add_space(10.0);
    theme::divider(ui);
    ui.add_space(14.0);
    let size = Vec2::new(ui.available_width(), 38.0);
    ui.allocate_ui_with_layout(size, Layout::right_to_left(Align::Center), buttons);
}

/// The blue button that moves the wizard on, with an arrow after its name.
fn next(ui: &mut Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((
            RichText::new(text)
                .family(theme::semibold())
                .color(Color32::WHITE),
            Icon::ArrowRight.atom_in(14.0, Color32::WHITE),
        ))
        .fill(theme::ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 38.0)),
    )
}

/// Lay out `add` from the left of the room that is left: Back sits at the
/// far left of the button row while the others line up on the right.
fn left<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.with_layout(Layout::left_to_right(Align::Center), add)
        .inner
}

/// Back to the step before, with an arrow.
fn back(ui: &mut Ui, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((Icon::ArrowLeft.atom(14.0), theme::bold("Back").size(13.0)))
            .fill(theme::SURFACE)
            .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
            .min_size(Vec2::new(0.0, 38.0)),
    )
}

fn big_primary(ui: &mut Ui, enabled: bool, icon: Icon, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((
            icon.atom_in(16.0, Color32::WHITE),
            RichText::new(text)
                .color(Color32::WHITE)
                .family(theme::semibold()),
        ))
        .fill(theme::ACCENT)
        .stroke(Stroke::NONE)
        .min_size(Vec2::new(0.0, 42.0)),
    )
}

fn big_secondary(ui: &mut Ui, enabled: bool, icon: Icon, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((icon.atom(16.0), theme::bold(text)))
            .fill(theme::SURFACE)
            .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
            .min_size(Vec2::new(0.0, 42.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_passwords() {
        assert_eq!(rate("short").1, "Too short");
        assert_eq!(rate("abcdefgh").1, "Fair: longer is better");
        assert_eq!(rate("abcdefghijkl").1, "Good");
        assert_eq!(rate("Abcdefgh1!").1, "Good");
        assert_eq!(rate("correct horse battery staple").1, "Strong");
    }

    #[test]
    fn checks_the_extension_id_before_running_anything() {
        assert!(register_browsers("not-an-id", false).is_err());
        assert!(register_browsers(&"z".repeat(32), false).is_err());
    }
}
