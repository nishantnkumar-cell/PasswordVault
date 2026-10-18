//! Check a FIDO2 security key against what the vault needs. Runs on Linux,
//! macOS and Windows:
//!
//!     cargo run -p vault-hw --example fido2-check
//!
//! It creates two throwaway credentials (one with PIN, one touch-only) under
//! the relying party "vault-check.local", then asks for hmac-secret twice
//! with each. Touch the key whenever it blinks (six times in total). Nothing
//! is stored; the credentials are non-resident and useless without the IDs
//! this program forgets on exit.

use vault_hw::fido2::HidFido2;
use vault_hw::{Fido2, prf_salt};

const RP: &str = "vault-check.local";

fn check(dev: &HidFido2, pin: Option<&str>, uv: bool) -> Result<(), String> {
    let mode = if uv { "with PIN" } else { "touch only" };
    println!("[{mode}] creating a credential: touch the key...");
    let cred = dev.enroll(RP, pin, uv)?;
    let salt = prf_salt(&[7u8; 32]);
    println!("[{mode}] first hmac-secret: touch the key...");
    let a = dev.hmac_secret(RP, &cred, &salt, pin, uv)?;
    println!("[{mode}] second hmac-secret: touch the key...");
    let b = dev.hmac_secret(RP, &cred, &salt, pin, uv)?;
    if !a.ct_eq_key(&b) {
        return Err(format!(
            "[{mode}] the key returned different secrets for the same input"
        ));
    }
    if a.ct_eq(&[0; 32]) {
        return Err(format!("[{mode}] the key returned an all-zero secret"));
    }
    println!("[{mode}] OK: same secret both times");
    Ok(())
}

fn main() {
    let pin = rpassword::prompt_password("Security key PIN (Enter to skip the PIN test): ")
        .unwrap_or_default();
    let dev = HidFido2;
    let touch = check(&dev, None, false);
    let with_pin = if pin.is_empty() {
        None
    } else {
        Some(check(&dev, Some(&pin), true))
    };
    match (&touch, &with_pin) {
        (Ok(_), None) => {
            println!("\nPASS (touch only). Run again with a PIN to test the PIN mode too.")
        }
        (Ok(_), Some(Ok(_))) => println!("\nPASS: this key works for both vault slot types."),
        _ => {
            for e in [touch.err(), with_pin.and_then(Result::err)]
                .into_iter()
                .flatten()
            {
                eprintln!("FAIL: {e}");
            }
            std::process::exit(1);
        }
    }
}
