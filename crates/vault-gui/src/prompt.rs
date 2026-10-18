//! The pairing approval window `vaultd` opens: who is asking, what they
//! would get, Deny or Allow. Deny has the focus, Escape denies, and the
//! window denies by itself after a minute.

use std::time::{Duration, Instant};

use eframe::egui::{self, Key, RichText, Ui};

/// How long the window waits before denying.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// What the daemon passed on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub client: String,
    pub autofill: bool,
    pub program: Option<String>,
}

impl Request {
    /// Parse `--client NAME --scope full|autofill [--program PATH]`.
    pub fn from_args(args: &[String]) -> Result<Request, String> {
        let mut client = None;
        let mut scope = None;
        let mut program = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
            match a.as_str() {
                "--client" => client = Some(val()?),
                "--scope" => scope = Some(val()?),
                "--program" => program = Some(val()?),
                _ => return Err(format!("unknown argument {a}")),
            }
        }
        let autofill = match scope.as_deref() {
            Some("autofill") => true,
            Some("full") => false,
            _ => return Err("--scope must be full or autofill".into()),
        };
        Ok(Request {
            client: client.ok_or("--client is required")?,
            autofill,
            program,
        })
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
            ui.heading(format!(
                "Allow \u{201c}{}\u{201d} to use your vault?",
                r.client
            ));
            ui.add_space(8.0);
            ui.label(if r.autofill {
                "It will be able to fill your logins on websites that match them, \
                 and nothing else."
            } else {
                "It will be able to read, change and delete every item in your vault."
            });
            ui.add_space(8.0);
            ui.label("Program asking:");
            ui.label(RichText::new(r.program.as_deref().unwrap_or("unknown")).monospace());
            ui.add_space(8.0);
            ui.label("If you didn't just connect something to your vault, choose Deny.");
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
                autofill: true,
                program: Some("/usr/bin/x".into()),
            })
        );
        assert!(Request::from_args(&args("--client x --scope root")).is_err());
        assert!(Request::from_args(&args("--scope full")).is_err());
        assert!(Request::from_args(&args("--client x --scope full --evil")).is_err());
    }
}
