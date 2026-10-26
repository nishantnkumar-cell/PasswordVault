//! Hardware unlock factors. Real implementations talk to devices; tests use
//! the soft ones in `soft`. Kept apart from `vaultd` so the FIDO2 code builds
//! and can be checked on any OS (`cargo run -p vault-hw --example fido2-check`).

use vault_core::HwKey;

#[cfg(feature = "fido2")]
pub mod fido2;
#[cfg(windows)]
pub mod hello;
#[cfg(feature = "phone")]
pub mod phone;
pub mod protect;
pub mod soft;
#[cfg(all(feature = "tpm", target_os = "linux"))]
pub mod tpm;
#[cfg(all(feature = "tpm", any(windows, test)))]
pub mod tpm2;
#[cfg(all(feature = "fido2", windows))]
pub mod webauthn;
#[cfg(all(feature = "tpm", windows))]
pub mod wintpm;

/// The TPM tests share one simulator, and one of them changes PCR 7.
#[cfg(test)]
pub(crate) static TPM_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub type HwResult<T> = Result<T, String>;

/// The relying party ID of every security key and phone passkey slot the
/// vault makes; fixed, since changing it changes the derived secret.
pub const RP_ID: &str = "vault.local";

/// Starts every TPM slot blob made on Windows (`wintpm`). Blobs made on
/// Linux (`tpm`) start with a small length instead, so the two never collide.
pub const WIN_TPM_PREFIX: &[u8] = b"VWTPM";
/// A Windows blob made by earlier versions: the secret wrapped with a TPM RSA key,
/// which a quantum computer could unwrap from the vault file alone.
pub const WIN_TPM_MAGIC: &[u8] = b"VWTPM1";
/// A Windows blob sealed by the TPM under Windows' storage key (`tpm2`).
pub const WIN_TPM_SEALED: &[u8] = b"VWTPM2";

/// Whether a TPM slot blob depends on public-key cryptography that a quantum
/// computer could break (an old Windows slot). Such a slot still works;
/// enrolling the TPM again replaces it with a sealed one.
pub fn tpm_blob_is_classical(blob: &[u8]) -> bool {
    blob.starts_with(WIN_TPM_MAGIC)
}

pub const LINUX_TPM_HINT: &str =
    "this TPM slot was made on Linux; Windows cannot use it, even on the same computer";
pub const WIN_TPM_HINT: &str =
    "this TPM slot was made on Windows; Linux cannot use it, even on the same computer";

/// A FIDO2 authenticator with the hmac-secret extension.
pub trait Fido2: Send {
    /// Create a non-discoverable credential with hmac-secret. Returns its ID.
    fn enroll(&self, rp_id: &str, pin: Option<&str>, require_uv: bool) -> HwResult<Vec<u8>>;
    /// hmac-secret output for the salt `prf_salt(prf_input)`, the WebAuthn PRF
    /// construction (Windows' WebAuthn API applies it itself). UV is performed
    /// iff `require_uv`, which selects the authenticator's CredRandomWithUV or
    /// WithoutUV.
    fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        prf_input: &[u8; 32],
        pin: Option<&str>,
        require_uv: bool,
    ) -> HwResult<HwKey>;
}

/// A TPM 2.0 that can seal a secret to itself.
pub trait Tpm: Send {
    /// Seal `secret`; returns the opaque blob stored in the keyslot.
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, bind_pcr7: bool) -> HwResult<Vec<u8>>;
    /// Unseal a blob from `seal`.
    fn unseal(&self, blob: &[u8], pin: Option<&str>, bind_pcr7: bool) -> HwResult<HwKey>;
}

/// The operating system's own check that the user is at the computer
/// (Windows Hello). It yields no secret, so it only approves a quick unlock
/// of a key the daemon still holds; it never opens a vault on its own.
pub trait Presence: Send {
    /// Whether the check is set up and usable for this user.
    fn check_available(&self) -> HwResult<()>;
    /// Ask the user, showing `message`. Ok only if the OS verified them.
    fn verify(&self, message: &str) -> HwResult<()>;
}

/// The factors this daemon can use.
pub struct Hardware {
    pub fido2: Option<Box<dyn Fido2>>,
    pub tpm: Option<Box<dyn Tpm>>,
    pub presence: Option<Box<dyn Presence>>,
}

impl Hardware {
    /// Real devices, where compiled in.
    pub fn system() -> Hardware {
        Hardware {
            #[cfg(feature = "fido2")]
            fido2: Some(system_fido2()),
            #[cfg(not(feature = "fido2"))]
            fido2: None,
            #[cfg(all(feature = "tpm", target_os = "linux"))]
            tpm: Some(Box::new(tpm::SystemTpm)),
            #[cfg(all(feature = "tpm", windows))]
            tpm: Some(Box::new(wintpm::WinTpm)),
            #[cfg(not(all(feature = "tpm", any(target_os = "linux", windows))))]
            tpm: None,
            #[cfg(windows)]
            presence: Some(Box::new(hello::WinHello)),
            #[cfg(not(windows))]
            presence: None,
        }
    }
}

/// The security key backend for this system. On Windows that is the WebAuthn
/// API (webauthn.dll), which needs no administrator rights, when it is new
/// enough for hmac-secret; otherwise, or with `VAULT_FIDO2=hid`, direct USB
/// HID, which Windows allows only to administrators.
#[cfg(feature = "fido2")]
pub fn system_fido2() -> Box<dyn Fido2> {
    #[cfg(windows)]
    if std::env::var_os("VAULT_FIDO2").is_none_or(|v| v != "hid") && webauthn::available() {
        return Box::new(webauthn::WinFido2);
    }
    Box::new(fido2::HidFido2)
}

/// The hmac-secret salt for a slot: the WebAuthn PRF construction (format.md 4.2).
pub fn prf_salt(prf_input: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(b"WebAuthn PRF")
        .chain_update([0u8])
        .chain_update(prf_input)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rsa_wrapped_windows_blobs_are_classical() {
        assert!(tpm_blob_is_classical(b"VWTPM1\x01\x00\x00"));
        assert!(!tpm_blob_is_classical(b"VWTPM2\x00\x00"));
        // Linux blobs start with a small length.
        assert!(!tpm_blob_is_classical(&[0x4e, 0x00, 0x00, 0x08]));
    }
}
