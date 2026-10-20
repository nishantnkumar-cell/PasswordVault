//! Software stand-ins for hardware factors, for tests and development only.
//! They provide no security.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use vault_core::HwKey;

use super::{Fido2, HwResult, Presence, Tpm};

/// Simulates an authenticator with distinct UV and non-UV secrets.
pub struct SoftFido2 {
    pub device_secret: [u8; 32],
    pub pin: String,
    pub counter: Mutex<u32>,
}

impl Fido2 for SoftFido2 {
    fn enroll(&self, _rp_id: &str, pin: Option<&str>, require_uv: bool) -> HwResult<Vec<u8>> {
        if require_uv && pin != Some(self.pin.as_str()) {
            return Err("PIN required".into());
        }
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        Ok(Sha256::digest(c.to_le_bytes()).to_vec())
    }

    fn hmac_secret(
        &self,
        rp_id: &str,
        cred: &[u8],
        prf_input: &[u8; 32],
        pin: Option<&str>,
        require_uv: bool,
    ) -> HwResult<HwKey> {
        if require_uv && pin != Some(self.pin.as_str()) {
            return Err("PIN invalid".into());
        }
        let d = Sha256::new()
            .chain_update(self.device_secret)
            .chain_update(rp_id)
            .chain_update(cred)
            .chain_update([require_uv as u8])
            .chain_update(prf_input)
            .finalize();
        Ok(HwKey::new(d.into()))
    }
}

/// Simulates sealing by XOR with a device key; checks the PIN.
pub struct SoftTpm {
    pub device_key: [u8; 32],
}

impl Tpm for SoftTpm {
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, _pcr7: bool) -> HwResult<Vec<u8>> {
        let mut out: Vec<u8> = secret
            .iter()
            .zip(self.device_key)
            .map(|(a, b)| a ^ b)
            .collect();
        out.extend_from_slice(&Sha256::digest(pin.unwrap_or("")));
        Ok(out)
    }

    fn unseal(&self, blob: &[u8], pin: Option<&str>, _pcr7: bool) -> HwResult<HwKey> {
        if blob.len() != 64 || blob[32..] != Sha256::digest(pin.unwrap_or(""))[..] {
            return Err("TPM authorization failed".into());
        }
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = blob[i] ^ self.device_key[i];
        }
        Ok(HwKey::new(s))
    }
}

/// Answers presence checks with a fixed verdict, and counts them.
pub struct SoftPresence {
    pub allow: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub asked: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl Presence for SoftPresence {
    fn check_available(&self) -> HwResult<()> {
        Ok(())
    }

    fn verify(&self, _message: &str) -> HwResult<()> {
        use std::sync::atomic::Ordering;
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.allow.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("Windows Hello: cancelled".into())
        }
    }
}
