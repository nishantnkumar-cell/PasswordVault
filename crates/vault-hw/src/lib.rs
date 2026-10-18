//! Hardware unlock factors. Real implementations talk to devices; tests use
//! the soft ones in `soft`. Kept apart from `vaultd` so the FIDO2 code builds
//! and can be checked on any OS (`cargo run -p vault-hw --example fido2-check`).

use vault_core::HwKey;

#[cfg(feature = "fido2")]
pub mod fido2;
pub mod soft;
#[cfg(all(feature = "tpm", target_os = "linux"))]
pub mod tpm;

pub type HwResult<T> = Result<T, String>;

/// A FIDO2 authenticator with the hmac-secret extension.
pub trait Fido2: Send {
    /// Create a non-discoverable credential with hmac-secret. Returns its ID.
    fn enroll(&self, rp_id: &str, pin: Option<&str>, require_uv: bool) -> HwResult<Vec<u8>>;
    /// hmac-secret output for `salt`. UV is performed iff `require_uv`, which
    /// selects the authenticator's CredRandomWithUV or WithoutUV.
    fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
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

/// The factors this daemon can use.
pub struct Hardware {
    pub fido2: Option<Box<dyn Fido2>>,
    pub tpm: Option<Box<dyn Tpm>>,
}

impl Hardware {
    /// Real devices, where compiled in.
    pub fn system() -> Hardware {
        Hardware {
            #[cfg(feature = "fido2")]
            fido2: Some(Box::new(fido2::HidFido2)),
            #[cfg(not(feature = "fido2"))]
            fido2: None,
            #[cfg(all(feature = "tpm", target_os = "linux"))]
            tpm: Some(Box::new(tpm::SystemTpm)),
            #[cfg(not(all(feature = "tpm", target_os = "linux")))]
            tpm: None,
        }
    }
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
