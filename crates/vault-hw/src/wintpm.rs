//! TPM 2.0 through Windows' Platform Crypto Provider (CNG, ncrypt.dll), which
//! any user may use: no administrator rights, no TPM driver of our own.
//!
//! Windows does not let user programs seal data the way `tpm.rs` does on
//! Linux, so the slot's random secret is wrapped instead (brief section 10):
//! the TPM makes a fresh RSA-2048 decryption key, the secret is encrypted to it
//! with RSA-OAEP (SHA-256), and the slot keeps the ciphertext and the key's
//! opaque blob. That blob is the TPM's own wrapped private key, usable only by
//! this TPM, so nothing is stored outside the vault file. With a PIN the key
//! gets that usage authorization, and the TPM's dictionary-attack lockout
//! limits guesses. With PCR 7 the key is bound to the current Secure Boot
//! state.
//!
//! Blob: `WIN_TPM_MAGIC` || u8 OAEP hash (1 = SHA-256) || u16 LE key blob
//! length || opaque key blob || RSA-OAEP ciphertext.
//!
//! Not exercised by automated tests: CI runners have no TPM. Check a machine
//! with `cargo run -p vault-hw --example tpm-check`.

use std::ptr::{null, null_mut};

use vault_core::HwKey;
use windows_sys::Win32::Foundation::{
    NTE_BAD_KEYSET, NTE_DEVICE_NOT_FOUND, TBS_E_SERVICE_NOT_RUNNING, TBS_E_TPM_NOT_FOUND,
    TPM_20_E_AUTH_FAIL, TPM_20_E_BAD_AUTH, TPM_20_E_LOCKOUT, TPM_20_E_PCR_CHANGED,
    TPM_20_E_POLICY_FAIL,
};
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::core::{HRESULT, PCWSTR};
use zeroize::Zeroizing;

use super::{HwResult, LINUX_TPM_HINT, Tpm, WIN_TPM_MAGIC};

/// The machine's TPM, through the Microsoft Platform Crypto Provider.
pub struct WinTpm;

const OAEP_SHA256: u8 = 1;
const RSA_BITS: u32 = 2048;
const RSA_BYTES: usize = RSA_BITS as usize / 8;
const MAX_KEY_BLOB: usize = 2048;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn check(what: &str, hr: HRESULT) -> HwResult<()> {
    if hr == 0 {
        return Ok(());
    }
    let why = match hr {
        TPM_20_E_AUTH_FAIL | TPM_20_E_BAD_AUTH => "wrong TPM PIN",
        TPM_20_E_LOCKOUT => {
            "the TPM is locked out after too many wrong PINs; wait (usually 10 minutes \
             to 2 hours) or unlock with another method"
        }
        TPM_20_E_POLICY_FAIL | TPM_20_E_PCR_CHANGED => {
            "PCR 7 changed (Secure Boot settings or keys changed), so this slot no longer \
             works; unlock with another method and enroll the TPM again"
        }
        TBS_E_TPM_NOT_FOUND | NTE_DEVICE_NOT_FOUND | TBS_E_SERVICE_NOT_RUNNING => {
            "no usable TPM 2.0 (check tpm.msc, or TPM in the firmware settings)"
        }
        NTE_BAD_KEYSET => "this TPM cannot load the slot's key (was it made on another computer?)",
        _ => "",
    };
    Err(if why.is_empty() {
        format!("TPM {what}: error 0x{:08x}", hr as u32)
    } else {
        format!("TPM {what}: {why}")
    })
}

struct Handle(NCRYPT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: a handle this module opened and nothing else frees.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

fn provider() -> HwResult<Handle> {
    let mut p: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: out-pointer to a local.
    check("open", unsafe {
        NCryptOpenStorageProvider(&mut p, MS_PLATFORM_CRYPTO_PROVIDER, 0)
    })?;
    Ok(Handle(p))
}

fn set(key: &Handle, name: PCWSTR, value: &[u8]) -> HwResult<()> {
    // SAFETY: `value` is a live slice of the given length.
    check("set property", unsafe {
        NCryptSetProperty(
            key.0,
            name,
            value.as_ptr(),
            value.len() as u32,
            NCRYPT_SILENT_FLAG,
        )
    })
}

/// The PIN as the key's usage authorization: a NUL-terminated UTF-16 string,
/// which the provider hashes. Set before finalizing (enroll) or before use.
fn set_pin(key: &Handle, pin: Option<&str>) -> HwResult<()> {
    let Some(pin) = pin.filter(|p| !p.is_empty()) else {
        return Ok(());
    };
    let w = Zeroizing::new(wide(pin));
    // SAFETY: reinterpreting a live [u16] as bytes.
    let bytes = unsafe { std::slice::from_raw_parts(w.as_ptr().cast::<u8>(), w.len() * 2) };
    set(key, NCRYPT_PIN_PROPERTY, bytes)
}

fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: null_mut(),
        cbLabel: 0,
    }
}

/// Run an ncrypt call that writes a variable-length output: once for the
/// length, once for the data. Only for calls that do not use the key's PIN.
fn two_pass(what: &str, mut f: impl FnMut(*mut u8, u32, &mut u32) -> HRESULT) -> HwResult<Vec<u8>> {
    let mut len = 0u32;
    check(what, f(null_mut(), 0, &mut len))?;
    let mut out = vec![0u8; len as usize];
    check(what, f(out.as_mut_ptr(), len, &mut len))?;
    out.truncate(len as usize);
    Ok(out)
}

/// A new TPM decryption key, not saved by Windows (no name).
fn create_key(prov: &Handle, pin: Option<&str>, bind_pcr7: bool) -> HwResult<Handle> {
    let mut k: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: out-pointer to a local; a null name makes an ephemeral key.
    check("create key", unsafe {
        NCryptCreatePersistedKey(prov.0, &mut k, BCRYPT_RSA_ALGORITHM, null(), 0, 0)
    })?;
    let key = Handle(k);
    set(&key, NCRYPT_LENGTH_PROPERTY, &RSA_BITS.to_le_bytes())?;
    set(
        &key,
        NCRYPT_KEY_USAGE_PROPERTY,
        &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
    )?;
    set_pin(&key, pin)?;
    if bind_pcr7 {
        // A 24-bit PCR mask with bit 7 set; the provider binds the key to the
        // PCR's current value.
        set(
            &key,
            NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
            &[0x80, 0, 0],
        )?;
    }
    // SAFETY: a key handle from above.
    check("create key", unsafe {
        NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG)
    })?;
    Ok(key)
}

impl Tpm for WinTpm {
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, bind_pcr7: bool) -> HwResult<Vec<u8>> {
        let prov = provider()?;
        let key = create_key(&prov, pin, bind_pcr7)?;
        let pad = oaep();
        let mut ct = vec![0u8; RSA_BYTES];
        let mut len = 0u32;
        // SAFETY: `secret`, `pad` and `ct` outlive the call.
        check("encrypt", unsafe {
            NCryptEncrypt(
                key.0,
                secret.as_ptr(),
                secret.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                ct.as_mut_ptr(),
                ct.len() as u32,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        })?;
        ct.truncate(len as usize);
        let opaque = two_pass("export key", |out, cap, len| {
            // SAFETY: as above.
            unsafe {
                // The provider refuses NCRYPT_SILENT_FLAG here (NTE_BAD_FLAGS);
                // exporting the wrapped blob shows no UI anyway.
                NCryptExportKey(key.0, 0, BCRYPT_OPAQUE_KEY_BLOB, null(), out, cap, len, 0)
            }
        })?;
        if opaque.len() > MAX_KEY_BLOB {
            return Err("TPM key blob too large".into());
        }
        let mut blob = Vec::with_capacity(WIN_TPM_MAGIC.len() + 3 + opaque.len() + ct.len());
        blob.extend_from_slice(WIN_TPM_MAGIC);
        blob.push(OAEP_SHA256);
        blob.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
        blob.extend_from_slice(&opaque);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    /// `bind_pcr7` is not needed here: the key carries its own PCR binding.
    fn unseal(&self, blob: &[u8], pin: Option<&str>, _bind_pcr7: bool) -> HwResult<HwKey> {
        let rest = blob.strip_prefix(WIN_TPM_MAGIC).ok_or(LINUX_TPM_HINT)?;
        let [hash, l0, l1, rest @ ..] = rest else {
            return Err("TPM blob truncated".into());
        };
        if *hash != OAEP_SHA256 {
            return Err("TPM blob uses an unknown padding".into());
        }
        let (opaque, ct) = rest
            .split_at_checked(u16::from_le_bytes([*l0, *l1]) as usize)
            .ok_or("TPM blob truncated")?;

        let prov = provider()?;
        let mut k: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: `opaque` is a live slice; out-pointer to a local.
        check("load key", unsafe {
            NCryptImportKey(
                prov.0,
                0,
                BCRYPT_OPAQUE_KEY_BLOB,
                null(),
                &mut k,
                opaque.as_ptr(),
                opaque.len() as u32,
                0,
            )
        })?;
        let key = Handle(k);
        set_pin(&key, pin)?;
        let pad = oaep();
        // One call with a full-size buffer, so a wrong PIN counts once
        // against the lockout.
        let mut pt = Zeroizing::new(vec![0u8; RSA_BYTES]);
        let mut len = 0u32;
        // SAFETY: `ct`, `pad` and `pt` outlive the call.
        check("decrypt", unsafe {
            NCryptDecrypt(
                key.0,
                ct.as_ptr(),
                ct.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                pt.as_mut_ptr(),
                pt.len() as u32,
                &mut len,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        })?;
        pt.truncate(len as usize);
        let arr: [u8; 32] = pt
            .as_slice()
            .try_into()
            .map_err(|_| "TPM secret has wrong length")?;
        Ok(HwKey::new(arr))
    }
}
