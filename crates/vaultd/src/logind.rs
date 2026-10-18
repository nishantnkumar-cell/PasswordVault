//! Lock when the machine is about to sleep or a session is locked, from
//! systemd-logind's D-Bus signals (threat model section 6).
//!
//! Any session's `Lock` locks the vault: locking too often is safe, missing a
//! lock is not.

use zbus::blocking::{Connection, MessageIterator};
use zbus::message::Type;
use zbus::{MatchRule, Result};

/// Why a lock was triggered.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// `Manager.PrepareForSleep(true)`: suspend or hibernate is starting.
    Sleep,
    /// `Session.Lock`: a screen locker was asked to lock.
    SessionLock,
}

/// Watch logind on `conn` (the system bus in production) and call `on_event`
/// for each lock trigger. Returns only if the connection fails.
pub fn watch(conn: &Connection, mut on_event: impl FnMut(Event)) -> Result<()> {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender("org.freedesktop.login1")?
        .build();
    for msg in MessageIterator::for_match_rule(rule, conn, None)? {
        let msg = msg?;
        let h = msg.header();
        match (
            h.interface().map(|i| i.as_str()),
            h.member().map(|m| m.as_str()),
        ) {
            (Some("org.freedesktop.login1.Manager"), Some("PrepareForSleep")) => {
                if msg.body().deserialize::<bool>().unwrap_or(true) {
                    on_event(Event::Sleep);
                }
            }
            (Some("org.freedesktop.login1.Session"), Some("Lock")) => on_event(Event::SessionLock),
            _ => {}
        }
    }
    Ok(())
}

/// Connect to the system bus and lock `daemon` on every event. Runs on its
/// own thread; logs and gives up if there is no system bus.
pub fn run(daemon: crate::server::Shared) {
    let conn = match Connection::system() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "vaultd: warning: no system bus, will not lock on suspend or screen lock: {e}"
            );
            return;
        }
    };
    let r = watch(&conn, |ev| {
        daemon.lock().unwrap_or_else(|p| p.into_inner()).lock();
        eprintln!("vaultd: locked ({ev:?})");
    });
    if let Err(e) = r {
        eprintln!("vaultd: warning: lost the logind watch: {e}");
    }
}
