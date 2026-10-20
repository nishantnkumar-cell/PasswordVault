//! The approval window `vaultd` opens: a program asking to pair, to fill a
//! card into a web page, or to use a key held in the vault (an SSH login, a
//! git signature). Who is asking, what they would get, Deny or Allow. Deny
//! has the focus, Escape denies, and the window denies by itself after a
//! minute.

use std::time::{Duration, Instant};

use eframe::egui::{self, Key, RichText, Ui};

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
}

impl Request {
    /// Parse `--client NAME --scope full|autofill [--program PATH]`,
    /// `--client NAME --fill-card DESCRIPTION --origin ORIGIN [--program PATH]`
    /// or `--use --key TITLE --purpose TEXT [--program PATH]`.
    pub fn from_args(args: &[String]) -> Result<Request, String> {
        let mut client = None;
        let mut scope = None;
        let mut card = None;
        let mut origin = None;
        let mut program = None;
        let mut key = None;
        let mut purpose = None;
        let mut use_key = false;
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
                _ => return Err(format!("unknown argument {a}")),
            }
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
        }
    }
}

/// The window's state; `answer` is set once the user (or the clock) decides.
pub struct Prompt {
    request: Request,
    opened: Instant,
    focused: bool,
    pub answer: Option<bool>,
}

impl Prompt {
    pub fn new(request: Request) -> Prompt {
        Prompt {
            request,
            opened: Instant::now(),
            focused: false,
            answer: None,
        }
    }

    /// Draw the window. Returns true once answered.
    pub fn show(&mut self, ui: &mut Ui) -> bool {
        if self.answer.is_none()
            && (ui.input(|i| i.key_pressed(Key::Escape)) || self.opened.elapsed() >= TIMEOUT)
        {
            self.answer = Some(false);
        }
        let r = &self.request;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(4.0);
            match &r.ask {
                Ask::Pair { autofill } => {
                    ui.heading(format!(
                        "Allow \u{201c}{}\u{201d} to use your vault?",
                        r.client
                    ));
                    ui.add_space(8.0);
                    ui.label(if *autofill {
                        "It will be able to fill your logins on websites that match them, \
                         and your cards and addresses on secure pages, and nothing else."
                    } else {
                        "It will be able to read, change and delete every item in your vault."
                    });
                }
                Ask::FillCard { card, origin } => {
                    ui.heading(format!("Fill {card}?"));
                    ui.add_space(8.0);
                    ui.label("Into a page on:");
                    ui.label(RichText::new(origin).monospace().strong());
                    ui.add_space(4.0);
                    ui.label(format!(
                        "\u{201c}{}\u{201d} asked for the card number, expiry and security code.",
                        r.client
                    ));
                }
                Ask::Use { key, purpose } => {
                    ui.heading(format!("Use the key \u{201c}{key}\u{201d}?"));
                    ui.add_space(8.0);
                    ui.label(format!("To {purpose}."));
                }
            }
            let program = &r.program;
            ui.add_space(8.0);
            ui.label("Program asking:");
            ui.label(RichText::new(program.as_deref().unwrap_or("unknown")).monospace());
            ui.add_space(8.0);
            ui.label(match r.ask {
                Ask::Pair { .. } => {
                    "If you didn't just connect something to your vault, choose Deny."
                }
                Ask::FillCard { .. } => {
                    "If you didn't just ask to fill a card on this site, choose Deny."
                }
                Ask::Use { .. } => "If you didn't just start this, choose Deny.",
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let deny = ui.button("Deny");
                if !self.focused {
                    deny.request_focus();
                    self.focused = true;
                }
                if deny.clicked() {
                    self.answer = Some(false);
                }
                if ui.button("Allow").clicked() {
                    self.answer = Some(true);
                }
            });
            let left = TIMEOUT.saturating_sub(self.opened.elapsed()).as_secs();
            ui.add_space(8.0);
            ui.label(RichText::new(format!("Denies by itself in {left} s.")).small());
        });
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
