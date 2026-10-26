//! The approval window `vaultd` opens: a program asking to pair, to fill a
//! card into a web page, to use a key held in the vault (an SSH login, a
//! git signature), or an application asking to use the Secret Service. Who is asking, what they would get, Deny or Allow. Deny
//! has the focus, Escape denies, and the window denies by itself after a
//! minute.

use std::time::{Duration, Instant};

use eframe::egui::{self, Key, Margin, RichText, Ui};

use crate::theme;

/// How long the window waits before denying.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// What the daemon passed on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The client's name; empty for a key use, which names no client.
    pub client: String,
    pub ask: Ask,
    pub program: Option<String>,
}

/// What is being approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// Pair the client, for autofill only or for everything.
    Pair { autofill: bool },
    /// Fill the described card into a page on `origin`.
    FillCard { card: String, origin: String },
    /// Use the key titled `key`, for `purpose`.
    Use { key: String, purpose: String },
    /// Let the program read and store app passwords through the Secret
    /// Service; `command` is its command line, if known.
    App { command: Option<String> },
}

impl Request {
    /// Parse `--client NAME --scope full|autofill [--program PATH]`,
    /// `--client NAME --fill-card DESCRIPTION --origin ORIGIN [--program PATH]`
    /// `--use --key TITLE --purpose TEXT [--program PATH]` or
    /// `--secret-service [--command LINE] [--program PATH]`.
    pub fn from_args(args: &[String]) -> Result<Request, String> {
        let mut client = None;
        let mut scope = None;
        let mut card = None;
        let mut origin = None;
        let mut program = None;
        let mut key = None;
        let mut purpose = None;
        let mut use_key = false;
        let mut app = false;
        let mut command = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
            match a.as_str() {
                "--client" => client = Some(val()?),
                "--scope" => scope = Some(val()?),
                "--fill-card" => card = Some(val()?),
                "--origin" => origin = Some(val()?),
                "--program" => program = Some(val()?),
                "--use" => use_key = true,
                "--key" => key = Some(val()?),
                "--purpose" => purpose = Some(val()?),
                "--secret-service" => app = true,
                "--command" => command = Some(val()?),
                _ => return Err(format!("unknown argument {a}")),
            }
        }
        if app {
            if use_key || client.is_some() || scope.is_some() || card.is_some() {
                return Err("--secret-service takes only --command and --program".into());
            }
            if origin.is_some() || key.is_some() || purpose.is_some() {
                return Err("--secret-service takes only --command and --program".into());
            }
            return Ok(Request {
                client: String::new(),
                ask: Ask::App { command },
                program,
            });
        }
        if command.is_some() {
            return Err("--command needs --secret-service".into());
        }
        if use_key {
            if client.is_some() || scope.is_some() || card.is_some() || origin.is_some() {
                return Err("--use takes only --key, --purpose and --program".into());
            }
            return Ok(Request {
                client: String::new(),
                ask: Ask::Use {
                    key: key.ok_or("--key is required")?,
                    purpose: purpose.ok_or("--purpose is required")?,
                },
                program,
            });
        }
        if key.is_some() || purpose.is_some() {
            return Err("--key and --purpose need --use".into());
        }
        let ask = match (scope.as_deref(), card, origin) {
            (Some("autofill"), None, None) => Ask::Pair { autofill: true },
            (Some("full"), None, None) => Ask::Pair { autofill: false },
            (None, Some(card), Some(origin)) => Ask::FillCard { card, origin },
            (None, Some(_), None) => return Err("--fill-card needs --origin".into()),
            _ => {
                return Err("give --scope full|autofill, or --fill-card with --origin".into());
            }
        };
        Ok(Request {
            client: client.ok_or("--client is required")?,
            ask,
            program,
        })
    }

    /// The window title.
    pub fn title(&self) -> &'static str {
        match self.ask {
            Ask::Pair { .. } => "Secret Vault: approve pairing",
            Ask::FillCard { .. } => "Secret Vault: fill a card?",
            Ask::Use { .. } => "Secret Vault: approve key use",
            Ask::App { .. } => "Secret Vault: approve app passwords",
        }
    }
}

/// The window's state; `answer` is set once the user (or the clock) decides.
pub struct Prompt {
    request: Request,
    opened: Instant,
    focused: bool,
    styled: bool,
    /// The height the content needed on the last frame, in points.
    pub height: f32,
    pub answer: Option<bool>,
}

impl Prompt {
    pub fn new(request: Request) -> Prompt {
        Prompt {
            request,
            opened: Instant::now(),
            focused: false,
            styled: false,
            height: 0.0,
            answer: None,
        }
    }

    /// Draw the window. Returns true once answered.
    pub fn show(&mut self, ui: &mut Ui) -> bool {
        if !self.styled {
            theme::apply(ui.ctx());
            self.styled = true;
        }
        if self.answer.is_none()
            && (ui.input(|i| i.key_pressed(Key::Escape)) || self.opened.elapsed() >= TIMEOUT)
        {
            self.answer = Some(false);
        }
        let r = &self.request;
        let frame = egui::Frame::new()
            .fill(theme::SURFACE)
            .inner_margin(Margin::symmetric(28, 24));
        let panel = egui::CentralPanel::default().frame(frame).show(ui, |ui| {
            let wrap = |ui: &mut Ui, text: RichText| {
                ui.add(egui::Label::new(text).wrap());
            };
            ui.horizontal(|ui| {
                theme::lock_tile(ui, 32.0);
                ui.add_space(4.0);
                ui.label(RichText::new("Secret Vault").size(13.0).color(theme::MUTED));
            });
            ui.add_space(10.0);
            let heading = match &r.ask {
                Ask::Pair { .. } => {
                    format!("Allow \u{201c}{}\u{201d} to use your vault?", r.client)
                }
                Ask::FillCard { card, .. } => format!("Fill {card}?"),
                Ask::Use { key, .. } => format!("Use the key \u{201c}{key}\u{201d}?"),
                Ask::App { .. } => "Let this program use its saved app passwords?".into(),
            };
            wrap(ui, theme::title(heading, 19.0));
            ui.add_space(2.0);
            match &r.ask {
                Ask::Pair { autofill } => {
                    wrap(
                        ui,
                        RichText::new(if *autofill {
                            "It will be able to fill your logins on websites that match them, \
                             and your cards and addresses on secure pages, and nothing else."
                        } else {
                            "It will be able to read, change and delete every item in your vault."
                        })
                        .color(theme::TEXT),
                    );
                }
                Ask::FillCard { origin, .. } => {
                    wrap(
                        ui,
                        RichText::new(format!(
                            "\u{201c}{}\u{201d} asked for the card number, expiry and \
                             security code, to fill into a page on:",
                            r.client
                        ))
                        .color(theme::TEXT),
                    );
                    wrap(ui, RichText::new(origin).monospace().color(theme::INK));
                }
                Ask::Use { purpose, .. } => {
                    wrap(
                        ui,
                        RichText::new(format!("To {purpose}.")).color(theme::TEXT),
                    );
                }
                Ask::App { command } => {
                    wrap(
                        ui,
                        RichText::new(
                            "It asked the Secret Service for passwords that apps keep in \
                             your vault, such as mail, chat and Wi-Fi passwords. If you \
                             allow it, it can read, change and delete those until vaultd \
                             restarts, but none of your other items.",
                        )
                        .color(theme::TEXT),
                    );
                    if let Some(c) = command {
                        wrap(ui, RichText::new(c).monospace().color(theme::INK));
                    }
                }
            }
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(theme::GROUND)
                .stroke(egui::Stroke::new(1.0, theme::DIVIDER))
                .corner_radius(8)
                .inner_margin(Margin::symmetric(12, 10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 3.0;
                    ui.label(
                        RichText::new("Program asking")
                            .size(12.0)
                            .color(theme::MUTED),
                    );
                    wrap(
                        ui,
                        RichText::new(r.program.as_deref().unwrap_or("unknown"))
                            .monospace()
                            .color(theme::INK),
                    );
                });
            ui.add_space(4.0);
            wrap(
                ui,
                RichText::new(match r.ask {
                    Ask::Pair { .. } => {
                        "If you didn't just connect something to your vault, choose Deny."
                    }
                    Ask::FillCard { .. } => {
                        "If you didn't just ask to fill a card on this site, choose Deny."
                    }
                    Ask::Use { .. } => "If you didn't just start this, choose Deny.",
                    Ask::App { .. } => {
                        "Allowing one program allows every copy of it: for python3 or \
                         another interpreter, that is every script it runs."
                    }
                })
                .size(13.0)
                .color(theme::MUTED),
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let left = TIMEOUT.saturating_sub(self.opened.elapsed()).as_secs();
                ui.label(
                    RichText::new(format!("Denies by itself in {left} s."))
                        .small()
                        .color(theme::MUTED),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::primary(ui, true, "Allow").clicked() {
                        self.answer = Some(true);
                    }
                    let deny = ui.add(
                        egui::Button::new(theme::bold("Deny"))
                            .min_size(egui::Vec2::new(84.0, 36.0)),
                    );
                    if !self.focused {
                        deny.request_focus();
                        self.focused = true;
                    }
                    if deny.clicked() {
                        self.answer = Some(false);
                    }
                });
            });
            ui.min_rect().height()
        });
        // The window's height follows its text, which differs per request
        // and with the display's text size.
        self.height = panel.inner + 2.0 * 24.0;
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        self.answer.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_what_vaultd_passes() {
        let args = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            Request::from_args(&args(
                "--client browser --scope autofill --program /usr/bin/x"
            )),
            Ok(Request {
                client: "browser".into(),
                ask: Ask::Pair { autofill: true },
                program: Some("/usr/bin/x".into()),
            })
        );
        assert_eq!(
            Request::from_args(&args(
                "--client browser --fill-card Travel --origin https://shop.example"
            ))
            .unwrap()
            .ask,
            Ask::FillCard {
                card: "Travel".into(),
                origin: "https://shop.example".into()
            }
        );
        assert_eq!(
            Request::from_args(&args(
                "--use --key laptop --purpose sign --program /usr/bin/ssh"
            )),
            Ok(Request {
                client: String::new(),
                ask: Ask::Use {
                    key: "laptop".into(),
                    purpose: "sign".into(),
                },
                program: Some("/usr/bin/ssh".into()),
            })
        );
        assert_eq!(
            Request::from_args(&args("--secret-service --program /usr/bin/x")),
            Ok(Request {
                client: String::new(),
                ask: Ask::App { command: None },
                program: Some("/usr/bin/x".into()),
            })
        );
        assert_eq!(
            Request::from_args(&args("--secret-service --command x"))
                .unwrap()
                .ask,
            Ask::App {
                command: Some("x".into())
            }
        );
        assert!(Request::from_args(&args("--secret-service --client x")).is_err());
        assert!(Request::from_args(&args("--secret-service --scope full")).is_err());
        assert!(Request::from_args(&args("--client x --scope full --command c")).is_err());
        assert!(Request::from_args(&args("--client x --fill-card Travel")).is_err());
        assert!(
            Request::from_args(&args(
                "--client x --scope full --fill-card T --origin https://a"
            ))
            .is_err()
        );
        assert!(Request::from_args(&args("--use --key laptop")).is_err());
        assert!(Request::from_args(&args("--use --key k --purpose p --scope full")).is_err());
        assert!(Request::from_args(&args("--client x --scope full --key k")).is_err());
        assert!(Request::from_args(&args("--client x --scope root")).is_err());
        assert!(Request::from_args(&args("--scope full")).is_err());
        assert!(Request::from_args(&args("--client x --scope full --evil")).is_err());
    }
}
