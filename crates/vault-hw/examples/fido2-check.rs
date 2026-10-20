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
//!
//! It uses the backend vaultd would: on Windows that is Windows' own WebAuthn
//! API, which needs no administrator rights and asks for the PIN itself.
//! `--compare` (Windows, in an administrator terminal) also reads the secret
//! over USB HID, the way Linux and macOS do, and checks the two agree.

use vault_hw::Fido2;

const RP: &str = "vault-check.local";

/// `pin` is given to registration in both modes (a key with a PIN set may
/// require it there); hmac-secret uses it only with `uv`.
fn check(dev: &dyn Fido2, pin: Option<&str>, uv: bool) -> Result<(), String> {
    let mode = if uv { "with PIN" } else { "touch only" };
    println!("[{mode}] creating a credential: touch the key...");
    let cred = dev.enroll(RP, pin, uv)?;
    let input = [7u8; 32];
    println!("[{mode}] first hmac-secret: touch the key...");
    let a = dev.hmac_secret(RP, &cred, &input, pin, uv)?;
    println!("[{mode}] second hmac-secret: touch the key...");
    let b = dev.hmac_secret(RP, &cred, &input, pin, uv)?;
    if !a.ct_eq_key(&b) {
        return Err(format!(
            "[{mode}] the key returned different secrets for the same input"
        ));
    }
    if a.ct_eq(&[0; 32]) {
        return Err(format!("[{mode}] the key returned an all-zero secret"));
    }
    println!("[{mode}] OK: same secret both times");
    if std::env::args().any(|a| a == "--compare") {
        println!("[{mode}] the same over USB HID: touch the key...");
        let c = vault_hw::fido2::HidFido2
            .hmac_secret(RP, &cred, &input, pin, uv)
            .map_err(|e| {
                format!("[{mode}] USB HID: {e} (on Windows, run --compare as administrator)")
            })?;
        if !a.ct_eq_key(&c) {
            return Err(format!(
                "[{mode}] USB HID gave a different secret: a slot made here would not unlock on Linux"
            ));
        }
        println!("[{mode}] OK: USB HID gives the same secret");
    }
    Ok(())
}

fn main() {
    let pin = rpassword::prompt_password("Security key PIN (Enter to skip the PIN test): ")
        .unwrap_or_default();
    let dev = vault_hw::system_fido2();
    let pin = (!pin.is_empty()).then_some(pin);
    let touch = check(dev.as_ref(), pin.as_deref(), false);
    let with_pin = pin.as_deref().map(|p| check(dev.as_ref(), Some(p), true));
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
