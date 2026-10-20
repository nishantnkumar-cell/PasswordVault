//! Check this computer's TPM against what the vault needs. Runs on Linux
//! and Windows (no administrator rights needed on Windows):
//!
//!     cargo run -p vault-hw --example tpm-check
//!
//! It wraps a random test secret three ways (no PIN, with a PIN, bound to
//! PCR 7) and unwraps each again. With a PIN it also tries one wrong PIN,
//! which the TPM counts towards its lockout like any wrong guess. Nothing is
//! stored, in the TPM or on disk.

#[cfg(any(target_os = "linux", windows))]
fn check(tpm: &dyn vault_hw::Tpm, pin: Option<&str>, pcr7: bool) -> Result<(), String> {
    use vault_core::SecureRandom;
    let mode = match (pin.is_some(), pcr7) {
        (false, false) => "no PIN",
        (true, _) => "with PIN",
        (false, true) => "PCR 7",
    };
    let mut secret = [0u8; 32];
    vault_core::OsRandom
        .fill(&mut secret)
        .map_err(|e| e.to_string())?;
    let blob = tpm
        .seal(&secret, pin, pcr7)
        .map_err(|e| format!("[{mode}] seal: {e}"))?;
    let back = tpm
        .unseal(&blob, pin, pcr7)
        .map_err(|e| format!("[{mode}] unseal: {e}"))?;
    if !back.ct_eq(&secret) {
        return Err(format!("[{mode}] unsealed a different secret"));
    }
    if let Some(p) = pin {
        let wrong = format!("{p}x");
        if tpm.unseal(&blob, Some(&wrong), pcr7).is_ok() {
            return Err(format!("[{mode}] a wrong PIN was accepted"));
        }
    }
    println!("[{mode}] OK ({} byte slot blob)", blob.len());
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
fn main() {
    let tpm = match vault_hw::Hardware::system().tpm {
        Some(t) => t,
        None => {
            eprintln!("FAIL: TPM support is not built in (build with the `tpm` feature)");
            std::process::exit(1);
        }
    };
    let pin = rpassword::prompt_password("Test PIN to use (Enter to skip the PIN test): ")
        .unwrap_or_default();
    let pin = (!pin.is_empty()).then_some(pin);
    let mut cases = vec![(None, false), (None, true)];
    if let Some(p) = pin.as_deref() {
        cases.insert(1, (Some(p), false));
    }
    let mut failed = false;
    for (p, pcr7) in cases {
        if let Err(e) = check(tpm.as_ref(), p, pcr7) {
            eprintln!("FAIL: {e}");
            failed = true;
        }
    }
    if failed {
        std::process::exit(1);
    }
    if pin.is_none() {
        println!("\nPASS (no PIN, PCR 7). Run again with a PIN to test the PIN mode too.");
    } else {
        println!("\nPASS: this TPM works for vault TPM slots.");
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    eprintln!("This system has no TPM support (macOS uses the Secure Enclave instead).");
    std::process::exit(1);
}
