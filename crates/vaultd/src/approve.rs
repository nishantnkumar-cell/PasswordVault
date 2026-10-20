//! Approval by the user: the daemon asks itself, in a window it starts
//! (`vault-prompt`), naming the program that asked. Used for pairing (a
//! client can request pairing but cannot answer its own request) and before
//! each use of a key marked `confirm`.

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

/// A key use the user is asked to approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsePrompt {
    /// The key item's title.
    pub key: String,
    /// What the signature is for, read from the request. Not verified.
    pub purpose: String,
    /// The connecting process's executable, as the OS reports it.
    pub program: Option<String>,
}

/// Something that can ask the user. `Ok(true)` means approved.
pub trait Approver: Send + Sync {
    fn approve(&self, prompt: &PairPrompt) -> Result<bool, String>;

    /// Ask before using a key. Approvers that cannot ask refuse.
    fn confirm_use(&self, _prompt: &UsePrompt) -> Result<bool, String> {
        Err("this approver cannot ask about key use".into())
    }
}

/// Any closure can approve (tests, embedders).
impl<F: Fn(&PairPrompt) -> Result<bool, String> + Send + Sync> Approver for F {
    fn approve(&self, prompt: &PairPrompt) -> Result<bool, String> {
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

impl Helper {
    /// Run the window with `args`: exit 0 approves, 1 declines.
    fn run(&self, cmd: &mut Command) -> Result<bool, String> {
        cmd.stdin(Stdio::null()).stdout(Stdio::null());
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

impl Approver for Helper {
    fn confirm_use(&self, p: &UsePrompt) -> Result<bool, String> {
        let mut cmd = Command::new(&self.exe);
        cmd.arg("--use")
            .arg("--key")
            .arg(&p.key)
            .arg("--purpose")
            .arg(&p.purpose);
        if let Some(prog) = &p.program {
            cmd.arg("--program").arg(prog);
        }
        self.run(&mut cmd)
    }

    fn approve(&self, p: &PairPrompt) -> Result<bool, String> {
        let scope = match p.scope {
            ClientScope::Full => "full",
            ClientScope::Autofill => "autofill",
        };
        let mut cmd = Command::new(&self.exe);
        cmd.arg("--client")
            .arg(&p.client_name)
            .arg("--scope")
            .arg(scope);
        if let Some(prog) = &p.program {
            cmd.arg("--program").arg(prog);
        }
        self.run(&mut cmd)
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
        let p = PairPrompt {
            client_name: "x".into(),
            scope: ClientScope::Autofill,
            program: None,
        };
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
        let u = UsePrompt {
            key: "laptop".into(),
            purpose: "sign a git commit or tag".into(),
            program: Some("/usr/bin/ssh-keygen".into()),
        };
        let echo = script(
            "echo-use",
            r#"[ "$*" = "--use --key laptop --purpose sign a git commit or tag --program /usr/bin/ssh-keygen" ] || exit 2"#,
        );
        assert_eq!(echo.confirm_use(&u), Ok(true));
        assert_eq!(script("no-use", "exit 1").confirm_use(&u), Ok(false));
    }
}
