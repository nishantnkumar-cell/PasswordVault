//! Add a one-time code from the Codes category: paste the setup key or
//! `otpauth://` link a site shows when it turns on two-step sign-in, or read
//! its QR code from a screenshot, then put it on a login.
//!
//! A new login is saved with one request. For an existing login the app
//! reads the login first and saves it back with the code, so nothing else on
//! it changes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, RichText, TextEdit, Ui};
use vault_core::item::{ItemData, ItemKind};
use vault_core::totp::TotpConfig;
use vault_ipc::{ItemId, ItemSummary, Request, Secret};

use super::{App, Filter, Op, spaced};
use crate::theme::{self, Icon};

/// The largest image read for a QR code.
const MAX_IMAGE: u64 = 32 << 20;

/// The Add code form.
#[derive(Default)]
pub(super) struct CodeForm {
    input: Secret,
    show: bool,
    image: String,
    title: String,
    account: String,
    /// The login the code goes on; `None` makes a new one.
    to: Option<ItemId>,
    /// The user chose `to`, so a pasted link doesn't change it.
    picked: bool,
    /// The title and account last filled in from the link, so typing the
    /// link a letter at a time keeps them up to date until the user types
    /// their own.
    filled: (String, String),
}

impl CodeForm {
    /// Take a pasted key or link: fill the title and account it names, and
    /// pick the one login it fits, if there is exactly one.
    fn take(&mut self, logins: &[&ItemSummary]) {
        let Some((issuer, account)) = TotpConfig::label(&self.input) else {
            return;
        };
        if self.title.trim().is_empty() || self.title == self.filled.0 {
            self.title = issuer.clone();
            self.filled.0 = issuer.clone();
        }
        if self.account.trim().is_empty() || self.account == self.filled.1 {
            self.account = account.clone();
            self.filled.1 = account;
        }
        if self.picked || issuer.is_empty() {
            return;
        }
        let issuer = issuer.to_lowercase();
        let fits: Vec<_> = logins
            .iter()
            .filter(|i| {
                i.title.to_lowercase().contains(&issuer)
                    || i.urls.iter().any(|u| u.to_lowercase().contains(&issuer))
            })
            .collect();
        self.to = match fits.as_slice() {
            [one] => Some(one.id),
            _ => None,
        };
    }

    /// Read the QR code in the image at `path`.
    fn read_image(&mut self, path: &str) -> Result<(), String> {
        let shown = |e: &dyn std::fmt::Display| format!("{path}: {e}");
        if path.trim().is_empty() {
            return Err("Type where the screenshot of the QR code is.".into());
        }
        let len = std::fs::metadata(path).map_err(|e| shown(&e))?.len();
        if len > MAX_IMAGE {
            return Err(shown(&"too big for a screenshot; crop it to the QR code"));
        }
        let bytes = std::fs::read(path).map_err(|e| shown(&e))?;
        let link = vault_import::qr::otpauth_from_image(&bytes).map_err(|e| shown(&e))?;
        self.input = Secret::new(link.to_string());
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Logins a code can go on: not keys, and without a code already (to swap
/// a code, edit the login).
fn targets(items: &[ItemSummary]) -> Vec<&ItemSummary> {
    items
        .iter()
        .filter(|i| i.kind == ItemKind::Login && i.key.is_none() && !i.has_totp)
        .collect()
}

impl App {
    /// Open the Add code form in place of the item details.
    pub(super) fn start_code(&mut self) {
        self.selected = None;
        self.open = None;
        self.totp = None;
        self.edit = None;
        self.new_key = None;
        self.import_key = None;
        self.export = None;
        self.error = None;
        self.notice = None;
        self.add_code = Some(CodeForm::default());
    }

    pub(super) fn code_form(&mut self, ui: &mut Ui) {
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.first().cloned());
        let hovering = ui.ctx().input(|i| !i.raw.hovered_files.is_empty());
        let logins = targets(&self.items);
        let Some(f) = &mut self.add_code else {
            return;
        };
        let mut error = None;
        if let Some(d) = dropped {
            let path = d.path().display().to_string();
            match f.read_image(&path) {
                Ok(()) => {
                    f.image = path;
                    f.take(&logins);
                }
                Err(m) => error = Some(m),
            }
        }

        ui.label(theme::title("Add a one-time code", 20.0));
        ui.add(
            egui::Label::new(
                RichText::new(
                    "When a site turns on two-step sign-in, it shows a QR code for an \
                     authenticator app and, under a link such as \u{201c}Can't scan \
                     it?\u{201d}, a setup key. Paste the key here, or save a screenshot \
                     of the QR code and drop it on this window.",
                )
                .color(theme::MUTED),
            )
            .wrap(),
        );
        if hovering {
            ui.label(
                RichText::new("Drop the image to read its QR code.")
                    .family(theme::semibold())
                    .color(theme::ACCENT),
            );
        }
        ui.add_space(10.0);
        let mut read = false;
        egui::Grid::new("add-code")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                let l = ui.label("Setup key");
                ui.horizontal(|ui| {
                    let r = ui
                        .add(
                            TextEdit::singleline(&mut *f.input)
                                .password(!f.show)
                                .font(egui::TextStyle::Monospace)
                                .hint_text("JBSW Y3DP EHPK 3PXP or otpauth://totp/…")
                                .desired_width(300.0),
                        )
                        .labelled_by(l.id);
                    if r.changed() {
                        f.take(&logins);
                    }
                    let (icon, tip) = if f.show {
                        (Icon::EyeOff, "Hide the key")
                    } else {
                        (Icon::Eye, "Show the key")
                    };
                    if ui
                        .add(egui::Button::new(icon.atom(15.0)).frame(false))
                        .on_hover_text(tip)
                        .clicked()
                    {
                        f.show = !f.show;
                    }
                });
                ui.end_row();

                let l = ui.label("Or a QR image");
                ui.horizontal(|ui| {
                    let r = ui
                        .add(
                            TextEdit::singleline(&mut f.image)
                                .hint_text(if cfg!(windows) {
                                    r"C:\Users\you\Pictures\qr.png"
                                } else {
                                    "~/Pictures/qr.png"
                                })
                                .desired_width(240.0),
                        )
                        .labelled_by(l.id);
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    read = ui.button("Read QR code").clicked() || enter;
                });
                ui.end_row();

                let l = ui.label("Put it on");
                let name = |id: Option<ItemId>| {
                    id.and_then(|id| logins.iter().find(|i| i.id == id))
                        .map_or("A new login".to_owned(), |i| i.title.clone())
                };
                let before = f.to;
                let r = egui::ComboBox::from_id_salt("code-target")
                    .selected_text(name(f.to))
                    .width(300.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut f.to, None, "A new login");
                        for i in &logins {
                            let text = if i.subtitle.is_empty() {
                                i.title.clone()
                            } else {
                                format!("{}  ({})", i.title, i.subtitle)
                            };
                            ui.selectable_value(&mut f.to, Some(i.id), text);
                        }
                    });
                r.response.labelled_by(l.id);
                if f.to != before {
                    f.picked = true;
                }
                ui.end_row();

                if f.to.is_none() {
                    let l = ui.label("Title");
                    ui.add(
                        TextEdit::singleline(&mut f.title)
                            .hint_text("The site it's for, such as Example Mail")
                            .desired_width(300.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                    let l = ui.label("Username");
                    ui.add(
                        TextEdit::singleline(&mut f.account)
                            .hint_text("alex@example.com (optional)")
                            .desired_width(300.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                }
            });
        if read {
            let path = super::keys::expand(&f.image);
            match f.read_image(&path) {
                Ok(()) => f.take(&logins),
                Err(m) => error = Some(m),
            }
        }

        // The first code, so the user can finish the site's setup and see
        // the key was copied right.
        ui.add_space(10.0);
        if !f.input.trim().is_empty() {
            match TotpConfig::parse(&f.input) {
                Ok(cfg) => {
                    let t = now();
                    if let Ok(code) = cfg.code_at(t) {
                        ui.horizontal(|ui| {
                            ui.label("Current code");
                            ui.label(
                                RichText::new(spaced(&code))
                                    .family(egui::FontFamily::Monospace)
                                    .size(20.0)
                                    .color(theme::INK),
                            );
                            ui.label(
                                RichText::new(format!("{} s", cfg.remaining(t)))
                                    .small()
                                    .color(theme::MUTED),
                            );
                        });
                        ui.label(
                            RichText::new("If the site asks for a code to finish, type this one.")
                                .small()
                                .color(theme::MUTED),
                        );
                        ui.ctx().request_repaint_after(Duration::from_secs(1));
                    }
                }
                Err(_) => {
                    ui.label(
                        RichText::new(
                            "That isn't a setup key or otpauth:// link yet. Copy it again \
                             from the site.",
                        )
                        .small()
                        .color(theme::WARN),
                    );
                }
            }
        }

        ui.add_space(12.0);
        let ok = self.busy.is_none();
        let (mut go, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            go = theme::primary_icon(ui, ok, Icon::Plus, "Add code").clicked();
            cancel = ui.button("Cancel").clicked();
        });
        if cancel {
            self.add_code = None;
            self.error = None;
        } else if go && ok {
            match self.code_request() {
                Ok((op, request)) => self.act("Adding the code…", op, request),
                Err(m) => error = Some(m),
            }
        }
        if let Some(m) = error {
            self.notice = None;
            self.error = Some(m);
        }
    }

    /// What Add code sends first: the new login, or a read of the login the
    /// code goes on.
    fn code_request(&self) -> Result<(Op, Request), String> {
        let f = self.add_code.as_ref().ok_or("The form closed.")?;
        let totp = TotpConfig::parse(&f.input).map_err(|_| {
            if f.input.trim().is_empty() {
                "Paste the setup key, or read the QR code from a screenshot.".to_owned()
            } else {
                "That isn't a setup key or otpauth:// link. Copy it again from the site.".to_owned()
            }
        })?;
        if let Some(id) = f.to {
            return Ok((Op::CodeTarget(id), Request::GetItem { id }));
        }
        let (title, username) = TotpConfig::login_names(&f.input, &f.title, &f.account)
            .ok_or("Give the code a title, such as the site it's for.")?;
        let mut item = ItemData::new(ItemKind::Login, title);
        item.username = username;
        item.totp = Some(totp);
        Ok((Op::SaveCode, Request::PutItem { id: None, item }))
    }

    /// The login the code goes on has been read: save it with the code.
    pub(super) fn on_code_target(&mut self, id: ItemId, mut item: ItemData) {
        let Some(f) = &self.add_code else { return };
        let Ok(totp) = TotpConfig::parse(&f.input) else {
            return;
        };
        if item.kind != ItemKind::Login {
            self.error = Some("Codes go on a login.".into());
            return;
        }
        item.totp = Some(totp);
        self.act(
            "Adding the code…",
            Op::SaveCode,
            Request::PutItem { id: Some(id), item },
        );
    }

    pub(super) fn on_code_saved(&mut self, id: ItemId) {
        self.add_code = None;
        self.notice = Some("Code added. It's in One-time codes.".into());
        if !matches!(self.filter, Filter::All | Filter::Codes) {
            self.filter = Filter::Codes;
        }
        self.send(Op::ListItems, Request::ListItems);
        self.select(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, url: &str) -> ItemSummary {
        ItemSummary {
            id: [title.len() as u8; 16],
            kind: ItemKind::Login,
            title: title.into(),
            subtitle: String::new(),
            urls: vec![url.into()],
            has_totp: false,
            key: None,
            key_confirm: false,
        }
    }

    #[test]
    fn a_link_fills_the_form_and_picks_the_login_it_fits() {
        let mail = login("Mail", "https://mail.example.com");
        let shop = login("Shop", "https://shop.example.net");
        let mut f = CodeForm {
            input: Secret::new(
                "otpauth://totp/example.com:alex%40example.com?secret=JBSWY3DPEHPK3PXP\
                 &issuer=example.com"
                    .into(),
            ),
            ..CodeForm::default()
        };
        f.take(&[&mail, &shop]);
        assert_eq!(f.title, "example.com");
        // Typed a letter at a time, the half-typed link's names give way.
        let mut typed = CodeForm::default();
        let link = f.input.clone();
        for n in 1..=link.len() {
            typed.input = Secret::new(link[..n].to_owned());
            typed.take(&[&mail, &shop]);
        }
        assert_eq!(
            (typed.title.as_str(), typed.account.as_str()),
            ("example.com", "alex@example.com")
        );
        // What the user typed stays.
        typed.title = "Work mail".into();
        typed.take(&[&mail, &shop]);
        assert_eq!(typed.title, "Work mail");
        assert_eq!(f.account, "alex@example.com");
        assert_eq!(f.to, Some(mail.id));

        // Two fits, or one the user overrode, leave the choice alone.
        let mut f = CodeForm {
            input: Secret::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=example".into()),
            ..CodeForm::default()
        };
        f.take(&[&mail, &shop]);
        assert_eq!(f.to, None);
        f.to = Some(shop.id);
        f.picked = true;
        f.input =
            Secret::new("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=mail.example.com".into());
        f.take(&[&mail, &shop]);
        assert_eq!(f.to, Some(shop.id));
    }
}
