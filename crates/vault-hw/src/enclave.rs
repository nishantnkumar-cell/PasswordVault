//! The Secure Enclave as a macOS "this device" slot: the Mac counterpart of
//! a TPM slot (format.md 4.2). Like a TPM slot it is the master password
//! plus a secret that only this Mac's hardware can recover, so a copied
//! vault file is useless without the Mac.
//!
//! The enclave is reached through Apple's CryptoKit, which is Swift-only, so
//! the work is done by `vault-se` (contrib/macos/secure-enclave), a small
//! program shipped next to `vaultd` in Secret Vault.app. It needs no
//! entitlement or provisioning profile, so it also works in builds signed
//! ad hoc. The slot secret crosses a pipe to and from it; nothing else does.
//!
//! The Secure Enclave has no PIN with a guess counter and no PCRs, so
//! `pin` and `bind_pcr7` are refused rather than half-supported.
//!
//! Not exercised by automated tests against a real enclave (CI runners have
//! none); `vault-se check` and `cargo run -p vault-hw --example tpm-check`
//! test a Mac by hand. The blob format is tested with a software build of
//! `vault-se` in CI.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use vault_core::HwKey;
use zeroize::Zeroizing;

use super::{HwResult, LINUX_TPM_HINT, MAC_SE_MAGIC, Tpm, WIN_TPM_HINT, WIN_TPM_PREFIX};

pub struct SecureEnclave;

/// `VAULT_SE_HELPER`, else `vault-se` next to this program.
fn helper() -> PathBuf {
    if let Some(p) = std::env::var_os("VAULT_SE_HELPER") {
        return p.into();
    }
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("vaultd"))
        .with_file_name("vault-se")
}

/// Run `vault-se <cmd>` with `input` on its stdin; its stdout, or its
/// one-sentence error.
fn run(cmd: &str, input: &[u8]) -> HwResult<Zeroizing<Vec<u8>>> {
    let path = helper();
    let mut child = Command::new(&path)
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "cannot start the Secure Enclave helper {} ({e}); it ships in Secret Vault.app, \
                 or build it with contrib/macos/build-se.sh",
                path.display()
            )
        })?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("Secure Enclave helper: no stdin")?;
        stdin
            .write_all(input)
            .map_err(|e| format!("Secure Enclave helper: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("Secure Enclave helper: {e}"))?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if msg.is_empty() {
            format!("Secure Enclave helper failed ({})", out.status)
        } else {
            msg
        });
    }
    Ok(stdout)
}

/// Refuse what the Secure Enclave cannot do.
fn plain(pin: Option<&str>, bind_pcr7: bool) -> HwResult<()> {
    if pin.is_some_and(|p| !p.is_empty()) {
        return Err("a Secure Enclave slot has no PIN on a Mac; add it without one".into());
    }
    if bind_pcr7 {
        return Err("Macs have no PCRs; add the Secure Enclave slot without --pcr7".into());
    }
    Ok(())
}

/// Why a blob is not one this Mac can open, if it was made elsewhere.
pub fn foreign_hint(blob: &[u8]) -> Option<&'static str> {
    if blob.starts_with(MAC_SE_MAGIC) {
        None
    } else if blob.starts_with(WIN_TPM_PREFIX) {
        Some(WIN_TPM_HINT)
    } else {
        Some(LINUX_TPM_HINT)
    }
}

impl SecureEnclave {
    /// Whether this Mac has a Secure Enclave that `vault-se` can use.
    pub fn check(&self) -> HwResult<()> {
        run("check", &[]).map(|_| ())
    }
}

impl Tpm for SecureEnclave {
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, bind_pcr7: bool) -> HwResult<Vec<u8>> {
        plain(pin, bind_pcr7)?;
        let blob = run("seal", secret)?;
        if !blob.starts_with(MAC_SE_MAGIC) {
            return Err(
                "the Secure Enclave helper is a test build; install Secret Vault again".into(),
            );
        }
        Ok(blob.to_vec())
    }

    fn unseal(&self, blob: &[u8], pin: Option<&str>, bind_pcr7: bool) -> HwResult<HwKey> {
        plain(pin, bind_pcr7)?;
        if let Some(hint) = foreign_hint(blob) {
            return Err(hint.into());
        }
        let out = run("unseal", blob)?;
        let bytes: [u8; 32] = out
            .as_slice()
            .try_into()
            .map_err(|_| "Secure Enclave helper returned a secret of the wrong size")?;
        Ok(HwKey::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_pin_and_pcrs() {
        assert!(plain(None, false).is_ok());
        assert!(plain(Some(""), false).is_ok());
        assert!(plain(Some("1234"), false).is_err());
        assert!(plain(None, true).is_err());
    }

    #[test]
    fn names_where_a_foreign_blob_came_from() {
        assert_eq!(foreign_hint(b"VMSEP1\x00\x10"), None);
        assert_eq!(foreign_hint(b"VWTPM2\x00"), Some(WIN_TPM_HINT));
        assert_eq!(foreign_hint(&[0x4e, 0x00, 0x00]), Some(LINUX_TPM_HINT));
    }

    /// Round trip through a software build of vault-se
    /// (`VAULT_SE_SOFTWARE=1 contrib/macos/build-se.sh DIR`), named by
    /// `VAULT_SE_TEST_HELPER`; CI runs it on macOS. Skipped without it.
    #[test]
    fn software_helper_round_trip() {
        let Some(path) = std::env::var_os("VAULT_SE_TEST_HELPER") else {
            eprintln!("skipped: VAULT_SE_TEST_HELPER is not set");
            return;
        };
        // SAFETY: test-only; no other test reads this variable.
        unsafe { std::env::set_var("VAULT_SE_HELPER", path) };
        let secret = [7u8; 32];
        let blob = run("seal", &secret).unwrap();
        assert!(blob.starts_with(b"VMSOFT"));
        assert_eq!(blob.len(), 6 + 2 + 32 + 65 + 32 + 60);
        let back = run("unseal", &blob).unwrap();
        assert_eq!(back.as_slice(), &secret);
        // Any changed byte is caught by AES-GCM.
        let mut bad = blob.to_vec();
        bad[50] ^= 1;
        assert!(run("unseal", &bad).is_err());
        let mut bad = blob.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        assert!(run("unseal", &bad).is_err());
        // A real slot is refused by SecureEnclave before the helper runs.
        assert!(SecureEnclave.unseal(&blob, None, false).is_err());
        run("check", &[]).unwrap();
    }
}
