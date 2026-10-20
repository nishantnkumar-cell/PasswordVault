//! Approval prompts: the daemon asks the user itself, in a window it starts
//! (`vault-prompt`), naming the program that asked. Used for pairing a client
//! and before releasing a card to the browser. A client can make the request
//! but cannot answer it.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vault_ipc::ClientScope;

/// What the user is asked to approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairPrompt {
    /// The name the client gave. Not verified.
    pub client_name: String,
    /// What the client may do once paired.
    pub scope: ClientScope,
    /// The connecting process's executable, as the OS reports it.
    pub program: Option<String>,
}

/// A card about to be filled into a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardPrompt {
    /// The paired client's name. Not verified.
    pub client_name: String,
    /// The card's title and network with its last four digits.
    pub card: String,
    /// The page the card would be filled into, as the browser reported it.
    pub origin: String,
    /// The connecting process's executable, as the OS reports it.
    pub program: Option<String>,
}

/// What the user is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prompt {
    /// Let a new client use the vault.
    Pair(PairPrompt),
    /// Release a card for filling.
    FillCard(CardPrompt),
}

/// Something that can ask the user. `Ok(true)` means approved.
pub trait Approver: Send + Sync {
    fn approve(&self, prompt: &Prompt) -> Result<bool, String>;
}

/// Any closure can approve (tests, embedders).
impl<F: Fn(&Prompt) -> Result<bool, String> + Send + Sync> Approver for F {
    fn approve(&self, prompt: &Prompt) -> Result<bool, String> {
        self(prompt)
    }
}

/// Runs the `vault-prompt` window: exit 0 approves, 1 declines, anything
/// else (no display, a crash) is an error. Declines after `timeout`.
pub struct Helper {
    pub exe: PathBuf,
    pub timeout: Duration,
}

impl Helper {
    /// `VAULT_PROMPT`, else `vault-prompt` next to this executable.
    pub fn find() -> Option<Helper> {
        let exe = match std::env::var_os("VAULT_PROMPT") {
            Some(p) => PathBuf::from(p),
            None => std::env::current_exe()
                .ok()?
                .with_file_name(format!("vault-prompt{}", std::env::consts::EXE_SUFFIX)),
        };
        exe.is_file().then_some(Helper {
            exe,
            timeout: Duration::from_secs(65),
        })
    }
}

impl Approver for Helper {
    fn approve(&self, p: &Prompt) -> Result<bool, String> {
        let mut cmd = Command::new(&self.exe);
        let program = match p {
            Prompt::Pair(p) => {
                let scope = match p.scope {
                    ClientScope::Full => "full",
                    ClientScope::Autofill => "autofill",
                };
                cmd.arg("--client")
                    .arg(&p.client_name)
                    .arg("--scope")
                    .arg(scope);
                &p.program
            }
            Prompt::FillCard(p) => {
                cmd.arg("--client")
                    .arg(&p.client_name)
                    .arg("--fill-card")
                    .arg(&p.card)
                    .arg("--origin")
                    .arg(&p.origin);
                &p.program
            }
        };
        cmd.stdin(Stdio::null()).stdout(Stdio::null());
        if let Some(prog) = program {
            cmd.arg("--program").arg(prog);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("{}: {e}", self.exe.display()))?;
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                return match status.code() {
                    Some(0) => Ok(true),
                    Some(1) => Ok(false),
                    _ => Err(format!("the approval window failed ({status})")),
                };
            }
            if start.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The executable of process `pid`, for the prompt. Informational: on Linux
/// the PID could be reused between the connection and this lookup.
pub fn program_of(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    return std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.display().to_string());
    #[cfg(windows)]
    return vault_ipc::win::process_path(pid).ok();
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        None
    }
}

/// A client name fit to show: printable, single-line, at most 64 characters.
pub fn clean_name(name: &str) -> String {
    let s: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let s = s.trim();
    if s.is_empty() {
        "unnamed client".into()
    } else {
        s.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_for_display() {
        assert_eq!(clean_name("  my\napp\u{7}  "), "myapp");
        assert_eq!(clean_name(""), "unnamed client");
        assert_eq!(clean_name(&"x".repeat(100)).len(), 64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_our_own_program() {
        let me = program_of(std::process::id()).unwrap();
        assert_eq!(me, std::env::current_exe().unwrap().display().to_string());
    }

    #[cfg(unix)]
    #[test]
    fn helper_exit_codes() {
        let dir = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            Helper {
                exe: p,
                timeout: Duration::from_millis(500),
            }
        };
        let p = Prompt::Pair(PairPrompt {
            client_name: "x".into(),
            scope: ClientScope::Autofill,
            program: None,
        });
        assert_eq!(script("yes", "exit 0").approve(&p), Ok(true));
        assert_eq!(script("no", "exit 1").approve(&p), Ok(false));
        assert!(script("broken", "exit 2").approve(&p).is_err());
        assert_eq!(script("slow", "sleep 5").approve(&p), Ok(false));
        // The arguments the window gets.
        let echo = script(
            "echo",
            r#"[ "$*" = "--client x --scope autofill" ] || exit 2"#,
        );
        assert_eq!(echo.approve(&p), Ok(true));
        let card = Prompt::FillCard(CardPrompt {
            client_name: "browser".into(),
            card: "Visa 1111".into(),
            origin: "https://shop.example".into(),
            program: None,
        });
        let echo = script(
            "echo-card",
            r#"[ "$*" = "--client browser --fill-card Visa 1111 --origin https://shop.example" ] || exit 2"#,
        );
        assert_eq!(echo.approve(&card), Ok(true));
    }
}
