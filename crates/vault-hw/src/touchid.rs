//! Touch ID as a user-presence check, through LocalAuthentication: Touch ID,
//! a paired Apple Watch, or the Mac's login password when neither is there.
//! Like Windows Hello (`hello`), it returns no secret, so it gates a quick
//! unlock of a key `vaultd` already holds; it never opens a vault on its own
//! (brief section 7, architecture review 2.2).
//!
//! Not exercised by automated tests: needs a person. Check a Mac with
//! `cargo run -p vault-hw --example hello-check`.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use super::{HwResult, Presence};

pub struct TouchId;

/// Touch ID or the login password, as the macOS screen saver lock does.
const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

/// How long to wait for the person before giving up.
const TIMEOUT: Duration = Duration::from_secs(120);

/// A message for a LocalAuthentication error (LAError codes).
fn explain(e: &NSError) -> String {
    match e.code() {
        -2 | -4 | -9 => "Touch ID: cancelled".into(),
        -1 => "Touch ID: not recognised".into(),
        -5 => "Touch ID needs a login password on this Mac".into(),
        -6 | -7 => "Touch ID is not set up; add a fingerprint in System Settings > Touch ID & \
                    Password"
            .into(),
        -8 => "Touch ID is locked after too many tries; unlock the Mac with your password first"
            .into(),
        -1004 => "Touch ID cannot ask from here: vaultd must run in your desktop session".into(),
        _ => format!("Touch ID: {}", e.localizedDescription()),
    }
}

impl Presence for TouchId {
    fn check_available(&self) -> HwResult<()> {
        // SAFETY: a fresh context, used on this thread only.
        let ctx = unsafe { LAContext::new() };
        // SAFETY: a valid policy; the error is returned, not written through.
        unsafe { ctx.canEvaluatePolicy_error(POLICY) }.map_err(|e| explain(&e))
    }

    fn verify(&self, message: &str) -> HwResult<()> {
        // SAFETY: as in `check_available`.
        let ctx = unsafe { LAContext::new() };
        let (tx, rx) = mpsc::channel();
        // The reply comes on a private queue, once.
        let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let r = if ok.as_bool() {
                Ok(())
            } else {
                // SAFETY: on failure LocalAuthentication passes a live NSError
                // or null, valid for the duration of this call.
                Err(unsafe { err.as_ref() }
                    .map(explain)
                    .unwrap_or_else(|| "Touch ID: failed".into()))
            };
            let _ = tx.send(r);
        });
        // macOS shows the reason under "vaultd wants to"; keep it a phrase.
        let reason = NSString::from_str(&reason(message));
        // SAFETY: the context, string and block outlive the call; the block
        // is retained by LocalAuthentication until it replies.
        unsafe { ctx.evaluatePolicy_localizedReason_reply(POLICY, &reason, &reply) };
        match rx.recv_timeout(TIMEOUT) {
            Ok(r) => r,
            Err(_) => {
                // SAFETY: cancels the pending prompt; safe from any thread.
                unsafe { ctx.invalidate() };
                Err("Touch ID: timed out".into())
            }
        }
    }
}

/// "Unlock Secret Vault" reads as "vaultd is trying to unlock Secret Vault".
fn reason(message: &str) -> String {
    let mut c = message.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => "unlock Secret Vault".into(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reason_reads_as_a_phrase() {
        assert_eq!(super::reason("Unlock Secret Vault"), "unlock Secret Vault");
        assert_eq!(super::reason(""), "unlock Secret Vault");
    }
}
