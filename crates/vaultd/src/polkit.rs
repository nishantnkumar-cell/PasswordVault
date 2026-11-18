//! Quick unlock on Linux: the person proves they are at the computer to
//! polkit, with their login password, or a fingerprint (or face) where the
//! system's PAM setup offers one (fprintd, Howdy). Like Windows Hello and
//! Touch ID (`vault_hw::Presence`), polkit returns no secret: it only lets
//! `vaultd` re-open a vault key it already holds (format.md section 4.6). It
//! never opens a vault on its own.
//!
//! The check asks polkit about the action [`ACTION`] for the client process
//! that asked for the quick unlock (`vault-gui` or `vault unlock --hello`),
//! so the polkit agent of that program's desktop session (GNOME, KDE, Xfce,
//! ...) shows the dialog. A program in an SSH login has no agent, and quick
//! unlock fails there; the password still works. The action's policy
//! file, `contrib/polkit/dev.passwordvault.quick-unlock.policy`, says
//! `auth_self` for the active session and "no" otherwise, and never keeps an
//! earlier answer, so each quick unlock asks again.
//!
//! Two guards keep a misconfigured system from turning the check into a
//! no-op: before asking, `vaultd` checks without interaction and goes on only
//! if polkit says a challenge is needed. If a local rule allows the action
//! without asking (or the policy file is missing), quick unlock is refused.
//!
//! Not exercised by automated tests against a real agent: it needs a person.
//! The answer parsing and guards are tested below.

use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

use zbus::Variant as Value;

use crate::dbus::{Connection, Proxy};

/// The polkit action vaultd asks about.
pub const ACTION: &str = "dev.passwordvault.quick-unlock";
/// How long the dialog may stay open before vaultd gives up.
const TIMEOUT: Duration = Duration::from_secs(120);
/// `AllowUserInteraction`.
const INTERACT: u32 = 1;

const POLKIT: &str = "org.freedesktop.PolicyKit1";
const AUTHORITY: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// The polkit subject: `(kind, details)`.
type Subject<'a> = (&'a str, HashMap<&'a str, Value<'a>>);
/// The reply to `CheckAuthorization`: authorised, challenge, details.
type Answer = (bool, bool, HashMap<String, String>);

/// The polkit check for the person who owns this daemon.
pub struct Polkit {
    /// The owner's UID, the only one the server lets connect.
    owner: u32,
}

impl Polkit {
    pub fn new(owner: u32) -> Self {
        Polkit { owner }
    }

    /// Ask polkit about [`ACTION`] for the client process `pid`.
    fn check(&self, conn: &Connection, pid: u32, flags: u32, cancel: &str) -> R<Answer> {
        let start = start_time(pid)?;
        let authority = Proxy::new(conn, POLKIT, AUTHORITY, AUTHORITY_IFACE)
            .map_err(|e| format!("cannot reach polkit: {e}"))?;
        // The UID is the owner's: the server lets no one else connect.
        let uid = i32::try_from(self.owner).map_err(|_| "UID out of range".to_string())?;
        let subject: Subject = (
            "unix-process",
            HashMap::from([
                ("pid", Value::from(pid)),
                ("start-time", Value::from(start)),
                ("uid", Value::from(uid)),
            ]),
        );
        // Only trusted callers may pass details; vaultd passes none.
        let details: HashMap<&str, &str> = HashMap::new();
        authority
            .call(
                "CheckAuthorization",
                &(subject, ACTION, details, flags, cancel),
            )
            .map_err(explain)
    }
}

/// The start time of process `pid` in clock ticks since boot, field 22 of
/// `/proc/<pid>/stat`, which polkit uses to tell a process from a later one
/// with the same PID. (The server holds the client's pidfd meanwhile, so the
/// PID cannot be reused while it asks.)
fn start_time(pid: u32) -> R<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("cannot read the requesting program's details: {e}"))?;
    parse_start_time(&stat).ok_or_else(|| "cannot read the requesting program's start time".into())
}

fn parse_start_time(stat: &str) -> Option<u64> {
    // The command name, field 2, is in parentheses and may hold spaces or
    // ")"; the fields after the last ")" start at field 3.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(22 - 3)?.parse().ok()
}

type R<T> = Result<T, String>;

const NO_PEER: &str = "quick unlock on Linux asks in the session of the program that requested \
                       it, and vaultd could not tell which program that was";

/// A message for a failed polkit call.
fn explain(e: zbus::Error) -> String {
    let s = e.to_string();
    if s.contains("Only trusted callers") {
        // vaultd runs as a user the policy file does not name as the
        // action's owner, so polkit will not answer about your session.
        format!(
            "polkit does not let this vaultd ask about your session: the {ACTION} policy \
             file must name the account vaultd runs as; run `sudo vault-setup-user refresh`"
        )
    } else if s.contains("Cancelled") {
        "quick unlock: cancelled".into()
    } else {
        format!("quick unlock: polkit: {s}")
    }
}

const NO_AGENT: &str = "no password dialog could be shown in your desktop session (its polkit \
                        agent is not running); unlock with your password";

/// What a check without interaction says about going on. polkit must want
/// a challenge: an answer of "yes" without one means a local rule turned the
/// check off, and "no" without one means the action is unknown or not
/// allowed here.
fn before_asking(a: &Answer) -> R<()> {
    match (a.0, a.1) {
        (false, true) => Ok(()),
        (true, _) => Err(format!(
            "polkit allows {ACTION} without asking (a local rule in \
             /etc/polkit-1/rules.d?), so it cannot confirm it's you; quick unlock is refused"
        )),
        (false, false) => Err(format!(
            "polkit does not know {ACTION} or does not allow it here: install \
             dev.passwordvault.quick-unlock.policy in /usr/share/polkit-1/actions (the \
             installers do), and use a local, active desktop session"
        )),
    }
}

/// What the interactive check's answer means.
fn after_asking(a: &Answer) -> R<()> {
    if a.0 {
        Ok(())
    } else if a.1 {
        // Still a challenge after asking: nobody could be asked.
        Err(NO_AGENT.into())
    } else if a.2.get("polkit.dismissed").is_some_and(|v| v == "true") {
        Err("quick unlock: cancelled".into())
    } else {
        Err("quick unlock: not confirmed".into())
    }
}

impl vault_hw::Presence for Polkit {
    fn check_available(&self) -> R<()> {
        self.check_available_for(None)
    }

    fn verify(&self, message: &str) -> R<()> {
        self.verify_for(message, None)
    }

    fn check_available_for(&self, peer: Option<u32>) -> R<()> {
        let pid = peer.ok_or(NO_PEER)?;
        let conn = Connection::system().map_err(|e| format!("no system bus: {e}"))?;
        before_asking(&self.check(&conn, pid, 0, "")?)
    }

    fn verify_for(&self, _message: &str, peer: Option<u32>) -> R<()> {
        // The dialog's text comes from the policy file: polkit takes a
        // caller's own message only from trusted callers.
        let pid = peer.ok_or(NO_PEER)?;
        let conn = Connection::system().map_err(|e| format!("no system bus: {e}"))?;
        before_asking(&self.check(&conn, pid, 0, "")?)?;
        let cancel = format!("vaultd-{}-{}", std::process::id(), rand::random::<u64>());
        let (tx, rx) = mpsc::channel();
        {
            let (conn, cancel) = (conn.clone(), cancel.clone());
            let me = Polkit::new(self.owner);
            std::thread::spawn(move || {
                let _ = tx.send(me.check(&conn, pid, INTERACT, &cancel));
            });
        }
        match rx.recv_timeout(TIMEOUT) {
            Ok(answer) => after_asking(&answer?),
            Err(_) => {
                if let Ok(a) = Proxy::new(&conn, POLKIT, AUTHORITY, AUTHORITY_IFACE) {
                    let _: Result<(), _> = a.call("CancelCheckAuthorization", &(cancel.as_str(),));
                }
                Err("quick unlock: timed out".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(ok: bool, challenge: bool, details: &[(&str, &str)]) -> Answer {
        let d = details
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        (ok, challenge, d)
    }

    #[test]
    fn asks_only_when_polkit_wants_a_challenge() {
        assert!(before_asking(&answer(false, true, &[])).is_ok());
        // A rule that says yes would make quick unlock ask nothing.
        let e = before_asking(&answer(true, false, &[])).unwrap_err();
        assert!(e.contains("without asking"), "{e}");
        // Even with a challenge flag, an authorised answer is not fresh presence.
        assert!(before_asking(&answer(true, true, &[])).is_err());
        let e = before_asking(&answer(false, false, &[])).unwrap_err();
        assert!(e.contains(".policy"), "{e}");
    }

    #[test]
    fn interactive_answer() {
        assert!(after_asking(&answer(true, false, &[])).is_ok());
        let e = after_asking(&answer(false, false, &[("polkit.dismissed", "true")])).unwrap_err();
        assert!(e.contains("cancelled"), "{e}");
        assert!(after_asking(&answer(false, false, &[])).is_err());
        let e = after_asking(&answer(false, true, &[])).unwrap_err();
        assert!(e.contains("polkit agent"), "{e}");
    }

    #[test]
    fn start_time_from_stat() {
        let stat = "4242 (a (weird) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 \
                    987654 1000 200";
        assert_eq!(parse_start_time(stat), Some(987654));
        let own = start_time(std::process::id()).unwrap();
        assert!(own > 0);
        assert!(parse_start_time("12 (x) S 1").is_none());
    }

    #[test]
    fn no_peer_no_check() {
        use vault_hw::Presence;
        let e = Polkit::new(1000).verify("x").unwrap_err();
        assert!(e.contains("which program"), "{e}");
    }

    #[test]
    fn policy_file_never_keeps_an_answer() {
        let p = include_str!("../../../contrib/polkit/dev.passwordvault.quick-unlock.policy");
        assert!(p.contains(&format!("<action id=\"{ACTION}\">")));
        assert!(p.contains("<allow_active>auth_self</allow_active>"));
        assert!(p.contains("<allow_any>no</allow_any>"));
        assert!(p.contains("<allow_inactive>no</allow_inactive>"));
        assert!(!p.contains("_keep"), "a kept answer would skip the check");
        assert!(p.contains("org.freedesktop.policykit.owner"));
    }

    /// By hand, against a running polkitd: the process `VAULT_POLKIT_PID`
    /// (owned by `VAULT_POLKIT_UID`) must be in an active local session.
    /// Run as the user vaultd runs as.
    #[test]
    #[ignore = "needs polkitd and a process in a desktop session"]
    fn live() {
        use vault_hw::Presence;
        let var = |n: &str| std::env::var(n).unwrap().parse::<u32>().unwrap();
        let p = Polkit::new(var("VAULT_POLKIT_UID"));
        let pid = Some(var("VAULT_POLKIT_PID"));
        eprintln!("check_available: {:?}", p.check_available_for(pid));
        eprintln!("verify: {:?}", p.verify_for("x", pid));
    }
}
