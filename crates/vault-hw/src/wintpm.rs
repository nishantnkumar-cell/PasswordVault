//! TPM 2.0 on Windows, without administrator rights or a TPM driver of our own.
//!
//! New slots (`VWTPM2`) are sealed like on Linux: through TPM Base Services
//! (tbs.dll), which any user may call, `tpm2.rs` seals the slot's random
//! secret as a keyed-hash object under the storage key Windows keeps at
//! 0x81000001. The object's private part is protected by the TPM's own
//! symmetric key, so nothing in the vault file yields to a quantum computer.
//! With a PIN the object gets it as its authValue, and the TPM's
//! dictionary-attack lockout limits guesses. With PCR 7 it is bound to the
//! current Secure Boot state. The session that carries the secret and the
//! PIN is salted to the storage key (RSA-OAEP through CNG) and encrypted
//! both ways.
//!
//! Blob: `WIN_TPM_SEALED` || u16 LE public length || TPMT_PUBLIC ||
//! TPM2B_PRIVATE contents.
//!
//! Slots made before (`VWTPM1`) still unlock: their secret was wrapped with
//! RSA-OAEP (SHA-256) to a TPM-bound RSA-2048 key of the Platform Crypto
//! Provider (ncrypt.dll). Blob: `WIN_TPM_MAGIC` || u8 OAEP hash (1 = SHA-256)
//! || u16 LE key blob length || opaque key blob || RSA-OAEP ciphertext. The
//! key blob holds the RSA public key, so a quantum computer could unwrap the
//! secret from the file; enrolling the TPM again replaces such a slot.
//!
//! Not exercised by automated tests on Windows: CI runners have no TPM
//! (`tpm2.rs` is tested against swtpm on Linux). Check a machine with
//! `cargo run -p vault-hw --example tpm-check`.

use std::ptr::{null, null_mut};

use vault_core::HwKey;
use windows_sys::Win32::Foundation::{
    NTE_BAD_KEYSET, NTE_DEVICE_NOT_FOUND, TBS_E_ACCESS_DENIED, TBS_E_SERVICE_NOT_RUNNING,
    TBS_E_TPM_NOT_FOUND, TPM_20_E_AUTH_FAIL, TPM_20_E_BAD_AUTH, TPM_20_E_LOCKOUT,
    TPM_20_E_PCR_CHANGED, TPM_20_E_POLICY_FAIL,
};
use windows_sys::Win32::Security::Cryptography::*;
use windows_sys::Win32::System::TpmBaseServices::*;
use windows_sys::core::{HRESULT, PCWSTR};
use zeroize::Zeroizing;

use super::tpm2::{self, RsaPublic};
use super::{HwResult, LINUX_TPM_HINT, Tpm, WIN_TPM_MAGIC, WIN_TPM_SEALED};

/// The machine's TPM, through the Microsoft Platform Crypto Provider.
pub struct WinTpm;

const OAEP_SHA256: u8 = 1;
const RSA_BYTES: usize = 256;

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

/// A TPM Base Services context: commands go to the TPM as they are, and
/// the handles they create are this context's and freed with it.
struct Tbs(*mut core::ffi::c_void);

impl Tbs {
    fn open() -> HwResult<Tbs> {
        let mut params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            ..Default::default()
        };
        // includeTpm20
        params.Anonymous.asUINT32 = 1 << 2;
        let mut h = null_mut();
        // SAFETY: a valid parameter block and an out-pointer to a local.
        let r =
            unsafe { Tbsi_Context_Create((&params as *const TBS_CONTEXT_PARAMS2).cast(), &mut h) };
        tbs_check(r)?;
        Ok(Tbs(h))
    }
}

impl Drop for Tbs {
    fn drop(&mut self) {
        // SAFETY: a context this module opened.
        unsafe { Tbsip_Context_Close(self.0) };
    }
}

fn tbs_check(r: u32) -> HwResult<()> {
    if r == TBS_SUCCESS {
        return Ok(());
    }
    Err(match r as HRESULT {
        TBS_E_TPM_NOT_FOUND | TBS_E_SERVICE_NOT_RUNNING => {
            "TPM: no usable TPM 2.0 (check tpm.msc, or TPM in the firmware settings)".into()
        }
        TBS_E_ACCESS_DENIED => {
            "TPM: Windows refused this TPM command (a group policy may block it)".into()
        }
        _ => format!("TPM: TPM Base Services error 0x{r:08x}"),
    })
}

impl tpm2::Transport for Tbs {
    fn transact(&mut self, command: &[u8]) -> HwResult<Vec<u8>> {
        let mut out = vec![0u8; 4096];
        let mut len = out.len() as u32;
        // SAFETY: `command` and `out` are live for the call, `len` is `out`'s size.
        let r = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                &mut len,
            )
        };
        tbs_check(r)?;
        out.truncate(len as usize);
        Ok(out)
    }
}

/// RSA-OAEP (SHA-256, label "SECRET\0") to the storage key, through CNG.
fn encrypt_salt(k: &RsaPublic, salt: &[u8]) -> HwResult<Vec<u8>> {
    let e = k.e.to_be_bytes();
    let e = &e[e.iter().position(|&b| b != 0).unwrap_or(3)..];
    let header = BCRYPT_RSAKEY_BLOB {
        Magic: BCRYPT_RSAPUBLIC_MAGIC,
        BitLength: (k.n.len() * 8) as u32,
        cbPublicExp: e.len() as u32,
        cbModulus: k.n.len() as u32,
        cbPrime1: 0,
        cbPrime2: 0,
    };
    let mut blob = Vec::with_capacity(size_of::<BCRYPT_RSAKEY_BLOB>() + e.len() + k.n.len());
    // SAFETY: a plain repr(C) struct of u32s, read as its bytes.
    blob.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            (&header as *const BCRYPT_RSAKEY_BLOB).cast::<u8>(),
            size_of::<BCRYPT_RSAKEY_BLOB>(),
        )
    });
    blob.extend_from_slice(e);
    blob.extend_from_slice(&k.n);

    let ok = |what: &str, s: i32| {
        if s >= 0 {
            Ok(())
        } else {
            Err(format!("TPM salt {what}: error 0x{:08x}", s as u32))
        }
    };
    let mut alg: BCRYPT_ALG_HANDLE = null_mut();
    // SAFETY: out-pointer to a local.
    ok("open", unsafe {
        BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_RSA_ALGORITHM, null(), 0)
    })?;
    let mut key: BCRYPT_KEY_HANDLE = null_mut();
    // SAFETY: `blob` is live; out-pointer to a local.
    let r = ok("import", unsafe {
        BCryptImportKeyPair(
            alg,
            null_mut(),
            BCRYPT_RSAPUBLIC_BLOB,
            &mut key,
            blob.as_ptr(),
            blob.len() as u32,
            0,
        )
    });
    let out = r.and_then(|()| {
        let label = b"SECRET\0";
        let pad = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: label.as_ptr().cast_mut(),
            cbLabel: label.len() as u32,
        };
        let mut out = vec![0u8; k.n.len()];
        let mut len = 0u32;
        // SAFETY: `salt`, `pad` and `out` outlive the call.
        ok("encrypt", unsafe {
            BCryptEncrypt(
                key,
                salt.as_ptr(),
                salt.len() as u32,
                (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                null_mut(),
                0,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut len,
                BCRYPT_PAD_OAEP,
            )
        })?;
        out.truncate(len as usize);
        Ok(out)
    });
    // SAFETY: handles from above, each freed once.
    unsafe {
        if !key.is_null() {
            BCryptDestroyKey(key);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    out
}

fn client() -> HwResult<tpm2::Client<Tbs>> {
    tpm2::Client::new(Tbs::open()?, tpm2::WINDOWS_SRK, encrypt_salt)
}

/// The PIN as the sealed object's authValue: its UTF-8 bytes, as on Linux.
fn pin_bytes(pin: Option<&str>) -> Option<&[u8]> {
    pin.filter(|p| !p.is_empty()).map(str::as_bytes)
}

impl Tpm for WinTpm {
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, bind_pcr7: bool) -> HwResult<Vec<u8>> {
        let (public, private) = client()?.seal(secret, pin_bytes(pin), bind_pcr7)?;
        let mut blob = Vec::with_capacity(WIN_TPM_SEALED.len() + 2 + public.len() + private.len());
        blob.extend_from_slice(WIN_TPM_SEALED);
        blob.extend_from_slice(
            &u16::try_from(public.len())
                .map_err(|_| "TPM public too large")?
                .to_le_bytes(),
        );
        blob.extend_from_slice(&public);
        blob.extend_from_slice(&private);
        Ok(blob)
    }

    fn unseal(&self, blob: &[u8], pin: Option<&str>, bind_pcr7: bool) -> HwResult<HwKey> {
        if let Some(rest) = blob.strip_prefix(WIN_TPM_SEALED) {
            let (len, rest) = rest.split_at_checked(2).ok_or("TPM blob truncated")?;
            let len = u16::from_le_bytes([len[0], len[1]]) as usize;
            let (public, private) = rest.split_at_checked(len).ok_or("TPM blob truncated")?;
            return client()?.unseal(public, private, pin_bytes(pin), bind_pcr7);
        }
        unseal_wrapped(blob, pin)
    }
}

/// Unwrap a `VWTPM1` slot. `bind_pcr7` is not needed: the key carries its
/// own PCR binding.
fn unseal_wrapped(blob: &[u8], pin: Option<&str>) -> HwResult<HwKey> {
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
