//! Windows Hello as a user-presence check (face, fingerprint or the Windows
//! PIN), through `UserConsentVerifier`. It returns no secret, so it gates a
//! quick unlock of a key `vaultd` already holds; it never opens a vault on
//! its own (brief section 7, architecture review 2.2).
//!
//! Not exercised by automated tests: needs a person. Check a machine with
//! `cargo run -p vault-hw --example hello-check`.

use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows::core::{HSTRING, factory};
use windows_future::IAsyncOperation;

use super::{HwResult, Presence};

pub struct WinHello;

fn not_set_up(what: &str) -> String {
    format!(
        "Windows Hello is {what}; set up a face, fingerprint or PIN in Settings > Accounts > \
         Sign-in options"
    )
}

impl Presence for WinHello {
    fn check_available(&self) -> HwResult<()> {
        let a = UserConsentVerifier::CheckAvailabilityAsync()
            .and_then(|op| op.join())
            .map_err(|e| format!("Windows Hello: {e}"))?;
        match a {
            UserConsentVerifierAvailability::Available => Ok(()),
            UserConsentVerifierAvailability::DeviceBusy => {
                Err("Windows Hello is busy; try again".into())
            }
            UserConsentVerifierAvailability::DisabledByPolicy => {
                Err("Windows Hello is turned off by policy on this computer".into())
            }
            UserConsentVerifierAvailability::NotConfiguredForUser => {
                Err(not_set_up("not set up for this user"))
            }
            _ => Err(not_set_up("not available")),
        }
    }

    fn verify(&self, message: &str) -> HwResult<()> {
        let interop: IUserConsentVerifierInterop =
            factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
                .map_err(|e| format!("Windows Hello: {e}"))?;
        // The prompt is owned by the window in front, as with the security
        // key prompt, so it opens over the app that asked for the unlock.
        // SAFETY: a valid (possibly null) window handle and a live HSTRING.
        let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
            interop
                .RequestVerificationForWindowAsync(GetForegroundWindow(), &HSTRING::from(message))
        }
        .map_err(|e| format!("Windows Hello: {e}"))?;
        let r = op.join().map_err(|e| format!("Windows Hello: {e}"))?;
        match r {
            UserConsentVerificationResult::Verified => Ok(()),
            UserConsentVerificationResult::Canceled => Err("Windows Hello: cancelled".into()),
            UserConsentVerificationResult::RetriesExhausted => {
                Err("Windows Hello: too many failed attempts".into())
            }
            UserConsentVerificationResult::DeviceBusy => {
                Err("Windows Hello is busy; try again".into())
            }
            UserConsentVerificationResult::DisabledByPolicy => {
                Err("Windows Hello is turned off by policy on this computer".into())
            }
            UserConsentVerificationResult::NotConfiguredForUser => {
                Err(not_set_up("not set up for this user"))
            }
            _ => Err(not_set_up("not available")),
        }
    }
}
