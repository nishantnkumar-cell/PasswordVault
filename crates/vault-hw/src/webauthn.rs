//! FIDO2 security keys through Windows' WebAuthn API (webauthn.dll). Windows
//! talks to the key on the caller's behalf, so the daemon needs no
//! administrator rights, and it shows its own window for the touch and the
//! PIN: the PIN passed in here is not used.
//!
//! The PRF input goes in as is: the API hashes it with the WebAuthn PRF
//! construction before sending it to the key, which gives the same secret
//! `HidFido2` gets for the same credential, so a slot made on Linux unlocks on
//! Windows and the other way round.
//!
//! Not exercised by automated tests: needs a physical key. Check one with
//! `cargo run -p vault-hw --example fido2-check`.

use std::ptr::{null, null_mut};

use vault_core::HwKey;
use windows_sys::Win32::Foundation::NTE_USER_CANCELLED;
use windows_sys::Win32::Networking::WindowsWebServices::*;
use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use windows_sys::core::{BOOL, HRESULT, PCWSTR};

use super::{Fido2, HwResult};

/// How long Windows waits for a touch.
const TIMEOUT_MS: u32 = 60_000;

pub struct WinFido2;

const TOUCH_ONLY_WITH_UV: &str = "this security key has a PIN or fingerprint, and Windows \
     always checks it, which gives a different secret than a touch alone; on Windows use a \
     slot that asks for the PIN with this key (`--uv`, or tick \"Also ask for the key's PIN \
     every time\" in the app)";

/// The API version that added hmac-secret to GetAssertion (Windows 11, and
/// Windows 10 with recent updates).
pub fn available() -> bool {
    // SAFETY: no arguments; webauthn.dll is part of Windows 10 1903 and later.
    unsafe { WebAuthNGetApiVersionNumber() >= WEBAUTHN_API_VERSION_4 }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn error(what: &str, hr: HRESULT) -> String {
    // Cancel in Windows' window gives HRESULT_FROM_WIN32(ERROR_CANCELLED).
    const CANCELLED: HRESULT = 0x8007_04C7_u32 as HRESULT;
    if hr == NTE_USER_CANCELLED || hr == CANCELLED {
        return format!("{what}: cancelled or timed out");
    }
    // SAFETY: returns a static string for any HRESULT.
    let name = unsafe { WebAuthNGetErrorName(hr) };
    let name = if name.is_null() {
        String::new()
    } else {
        // SAFETY: a NUL-terminated UTF-16 string owned by webauthn.dll.
        let len = (0..).take_while(|&i| unsafe { *name.add(i) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name, len) })
    };
    format!("{what}: {name} (0x{:08x})", hr as u32)
}

fn random<const N: usize>() -> [u8; N] {
    use vault_core::SecureRandom;
    let mut b = [0u8; N];
    vault_core::OsRandom.fill(&mut b).expect("OS RNG");
    b
}

/// Client data for one request. Nothing checks it: the key signs its hash and
/// the vault never verifies the signature, only uses the hmac-secret output.
fn client_data(kind: &str, rp_id: &str) -> Vec<u8> {
    let challenge: String = random::<32>().iter().map(|b| format!("{b:02x}")).collect();
    format!(r#"{{"type":"{kind}","challenge":"{challenge}","origin":"vault:{rp_id}"}}"#)
        .into_bytes()
}

fn uv(require_uv: bool) -> u32 {
    if require_uv {
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
    } else {
        WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
    }
}

impl Fido2 for WinFido2 {
    fn enroll(&self, rp_id: &str, _pin: Option<&str>, require_uv: bool) -> HwResult<Vec<u8>> {
        let rp = wide(rp_id);
        let rp_name = wide("Secret Vault");
        let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: rp.as_ptr(),
            pwszName: rp_name.as_ptr(),
            pwszIcon: null(),
        };
        // A throwaway user handle: the credential is not discoverable and the
        // vault keeps its ID, so nothing ever looks the user up.
        let mut user_id = random::<16>();
        let user_name = wide("vault");
        let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: user_name.as_ptr(),
            pwszIcon: null(),
            pwszDisplayName: rp_name.as_ptr(),
        };
        let mut alg = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut alg,
        };
        let mut cd = client_data("webauthn.create", rp_id);
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: cd.len() as u32,
            pbClientDataJSON: cd.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut hmac_secret: BOOL = 1;
        let mut ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: size_of::<BOOL>() as u32,
            pvExtension: (&mut hmac_secret as *mut BOOL).cast(),
        };
        // SAFETY: all-zero is valid for this plain C struct (null pointers,
        // zero counts); version 4 covers every field set below.
        let mut opts: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS =
            unsafe { std::mem::zeroed() };
        opts.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4;
        opts.dwTimeoutMilliseconds = TIMEOUT_MS;
        opts.Extensions = WEBAUTHN_EXTENSIONS {
            cExtensions: 1,
            pExtensions: &mut ext,
        };
        opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        opts.dwUserVerificationRequirement = uv(require_uv);
        opts.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;

        let mut att: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
        // SAFETY: every pointer refers to a local that outlives the call.
        let hr = unsafe {
            WebAuthNAuthenticatorMakeCredential(
                GetForegroundWindow(),
                &rp_info,
                &user_info,
                &params,
                &client,
                &opts,
                &mut att,
            )
        };
        if hr != 0 || att.is_null() {
            return Err(error("registration failed", hr));
        }
        // SAFETY: on success `att` points to a structure webauthn.dll owns
        // until it is freed below; the ID and flags are copied out first.
        let (id, flags) = unsafe {
            let a = &*att;
            let id =
                std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
            let flags = (a.cbAuthenticatorData > 32).then(|| *a.pbAuthenticatorData.add(32));
            WebAuthNFreeCredentialAttestation(att);
            (id, flags)
        };
        // Windows verifies a key that has a PIN or fingerprint set whatever
        // was asked for. If it did so here, it will at unlock too, and a
        // touch-only slot can never open: say so now, before the second touch.
        if !require_uv && flags.is_some_and(|f| f & 0x04 != 0) {
            return Err(TOUCH_ONLY_WITH_UV.into());
        }
        // Windows does not always echo the hmac-secret extension back; the
        // caller asks for a secret right away, which fails on a key without it.
        Ok(id)
    }

    fn hmac_secret(
        &self,
        rp_id: &str,
        cred: &[u8],
        prf_input: &[u8; 32],
        _pin: Option<&str>,
        require_uv: bool,
    ) -> HwResult<HwKey> {
        let rp = wide(rp_id);
        let mut cred_id = cred.to_vec();
        let mut allowed = WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: cred_id.len() as u32,
            pbId: cred_id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        };
        let mut cd = client_data("webauthn.get", rp_id);
        let client = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: cd.len() as u32,
            pbClientDataJSON: cd.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut input = *prf_input;
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: input.len() as u32,
            pbFirst: input.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: null_mut(),
        };
        let mut salts = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: null_mut(),
        };
        // SAFETY: as in `enroll`; version 6 adds pHmacSecretSaltValues.
        let mut opts: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
        opts.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
        opts.dwTimeoutMilliseconds = TIMEOUT_MS;
        opts.CredentialList = WEBAUTHN_CREDENTIALS {
            cCredentials: 1,
            pCredentials: &mut allowed,
        };
        opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
        opts.dwUserVerificationRequirement = uv(require_uv);
        // No WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG: the salt is a PRF
        // input, hashed by Windows (format.md 4.2).
        opts.pHmacSecretSaltValues = &mut salts;

        let mut a: *mut WEBAUTHN_ASSERTION = null_mut();
        // SAFETY: every pointer refers to a local that outlives the call.
        let hr = unsafe {
            WebAuthNAuthenticatorGetAssertion(
                GetForegroundWindow(),
                rp.as_ptr() as PCWSTR,
                &client,
                &opts,
                &mut a,
            )
        };
        if hr != 0 || a.is_null() {
            return Err(error("security key", hr));
        }
        // SAFETY: on success `a` is valid until freed; pHmacSecret exists from
        // assertion version 3 and is checked for null before use.
        let (out, flags) = unsafe {
            let r = &*a;
            // authenticatorData: rpIdHash (32 bytes), then the flags byte.
            let flags = (r.cbAuthenticatorData > 32).then(|| *r.pbAuthenticatorData.add(32));
            let out = if r.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3
                && !r.pHmacSecret.is_null()
                && (*r.pHmacSecret).cbFirst == 32
            {
                let mut o = [0u8; 32];
                o.copy_from_slice(std::slice::from_raw_parts((*r.pHmacSecret).pbFirst, 32));
                Some(o)
            } else {
                None
            };
            WebAuthNFreeAssertion(a);
            (out, flags)
        };
        // The key picks CredRandomWithUV or WithoutUV by whether it verified
        // the user, whatever was asked for. Windows may verify the PIN anyway,
        // and then the secret is not this slot's.
        let verified = flags.ok_or("security key returned no authenticator data")? & 0x04 != 0;
        if verified != require_uv {
            return Err(if verified {
                TOUCH_ONLY_WITH_UV
            } else {
                "the security key did not check its PIN for a slot that requires it"
            }
            .into());
        }
        let out = out.ok_or("security key returned no hmac-secret output")?;
        Ok(HwKey::new(out))
    }
}

// Phone passkeys (`crate::phone`) over Windows' own hybrid transport: Windows
// shows the QR code and talks to the phone, and the PRF extension carries the
// same salt as for a security key.

#[cfg(feature = "phone")]
use crate::phone::{Enrolled, PasskeyCred, PhoneEvent, TIMEOUT_SECS, USER_NAME};

/// The API version whose MakeCredential takes `bEnablePrf`, which phones need
/// instead of the hmac-secret extension.
#[cfg(feature = "phone")]
const PHONE_API: u32 = WEBAUTHN_API_VERSION_6;

#[cfg(feature = "phone")]
pub fn phone_check_available() -> HwResult<()> {
    // SAFETY: as in `available`.
    if unsafe { WebAuthNGetApiVersionNumber() } >= PHONE_API {
        Ok(())
    } else {
        Err("phone passkeys need a newer Windows (Windows 11 23H2 or later)".into())
    }
}

#[cfg(feature = "phone")]
pub fn phone_enroll(
    rp_id: &str,
    _prf_input: &[u8; 32],
    events: &dyn Fn(PhoneEvent),
) -> HwResult<Enrolled> {
    phone_check_available()?;
    events(PhoneEvent::Status(
        "In the Windows window, choose \"iPhone, iPad or Android device\"".into(),
    ));
    let rp = wide(rp_id);
    let rp_name = wide("Secret Vault");
    let rp_info = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: rp.as_ptr(),
        pwszName: rp_name.as_ptr(),
        pwszIcon: null(),
    };
    let mut user_id = random::<16>();
    let user_name = wide(USER_NAME);
    let user_info = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: user_id.len() as u32,
        pbId: user_id.as_mut_ptr(),
        pwszName: user_name.as_ptr(),
        pwszIcon: null(),
        pwszDisplayName: user_name.as_ptr(),
    };
    let mut alg = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    };
    let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: 1,
        pCredentialParameters: &mut alg,
    };
    let mut cd = client_data("webauthn.create", rp_id);
    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: cd.len() as u32,
        pbClientDataJSON: cd.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    // SAFETY: all-zero is valid for this plain C struct; version 6 covers
    // every field set below.
    let mut opts: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = unsafe { std::mem::zeroed() };
    opts.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6;
    opts.dwTimeoutMilliseconds = (TIMEOUT_SECS * 1000) as u32;
    opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    // Phones keep only discoverable credentials.
    opts.bRequireResidentKey = 1;
    opts.dwUserVerificationRequirement = uv(true);
    opts.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    opts.bEnablePrf = 1;

    let mut att: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
    // SAFETY: every pointer refers to a local that outlives the call.
    let hr = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            GetForegroundWindow(),
            &rp_info,
            &user_info,
            &params,
            &client,
            &opts,
            &mut att,
        )
    };
    if hr != 0 || att.is_null() {
        return Err(error("creating the passkey", hr));
    }
    // SAFETY: as in `enroll`.
    let id = unsafe {
        let a = &*att;
        let id = std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
        WebAuthNFreeCredentialAttestation(att);
        id
    };
    // Windows returns no PRF output at creation; the caller asks once more.
    Ok(Enrolled {
        credential_id: id,
        prf: None,
    })
}

#[cfg(feature = "phone")]
pub fn phone_prf(
    rp_id: &str,
    creds: &[PasskeyCred],
    events: &dyn Fn(PhoneEvent),
) -> HwResult<(Vec<u8>, HwKey)> {
    phone_check_available()?;
    events(PhoneEvent::Status(
        "In the Windows window, choose your phone, or scan the QR code with it".into(),
    ));
    let rp = wide(rp_id);
    let mut ids: Vec<Vec<u8>> = creds.iter().map(|c| c.credential_id.clone()).collect();
    let mut inputs: Vec<[u8; 32]> = creds.iter().map(|c| c.prf_input).collect();
    let mut salts: Vec<WEBAUTHN_HMAC_SECRET_SALT> = inputs
        .iter_mut()
        .map(|i| WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 32,
            pbFirst: i.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: null_mut(),
        })
        .collect();
    let mut per_cred: Vec<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> = ids
        .iter_mut()
        .zip(salts.iter_mut())
        .map(|(id, s)| WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT {
            cbCredID: id.len() as u32,
            pbCredID: id.as_mut_ptr(),
            pHmacSecretSalt: s,
        })
        .collect();
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: null_mut(),
        cCredWithHmacSecretSaltList: per_cred.len() as u32,
        pCredWithHmacSecretSaltList: per_cred.as_mut_ptr(),
    };
    // The hybrid transport hint steers Windows to the phone rather than a
    // security key.
    let mut ex: Vec<WEBAUTHN_CREDENTIAL_EX> = ids
        .iter_mut()
        .map(|id| WEBAUTHN_CREDENTIAL_EX {
            dwVersion: WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_mut_ptr(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            dwTransports: WEBAUTHN_CTAP_TRANSPORT_HYBRID,
        })
        .collect();
    let mut ex_ptrs: Vec<*mut WEBAUTHN_CREDENTIAL_EX> =
        ex.iter_mut().map(|e| e as *mut _).collect();
    let mut allow = WEBAUTHN_CREDENTIAL_LIST {
        cCredentials: ex_ptrs.len() as u32,
        ppCredentials: ex_ptrs.as_mut_ptr(),
    };
    let mut cd = client_data("webauthn.get", rp_id);
    let client = WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: cd.len() as u32,
        pbClientDataJSON: cd.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    };
    // SAFETY: as in `hmac_secret`.
    let mut opts: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = unsafe { std::mem::zeroed() };
    opts.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;
    opts.dwTimeoutMilliseconds = (TIMEOUT_SECS * 1000) as u32;
    opts.pAllowCredentialList = &mut allow;
    opts.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
    opts.dwUserVerificationRequirement = uv(true);
    opts.pHmacSecretSaltValues = &mut salt_values;

    let mut a: *mut WEBAUTHN_ASSERTION = null_mut();
    // SAFETY: every pointer refers to a local that outlives the call.
    let hr = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            GetForegroundWindow(),
            rp.as_ptr() as PCWSTR,
            &client,
            &opts,
            &mut a,
        )
    };
    if hr != 0 || a.is_null() {
        return Err(error("phone", hr));
    }
    // SAFETY: as in `hmac_secret`; the credential ID is copied out first.
    let (id, out, flags) = unsafe {
        let r = &*a;
        let flags = (r.cbAuthenticatorData > 32).then(|| *r.pbAuthenticatorData.add(32));
        let id = if r.Credential.pbId.is_null() {
            None
        } else {
            Some(std::slice::from_raw_parts(r.Credential.pbId, r.Credential.cbId as usize).to_vec())
        };
        let out = if r.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3
            && !r.pHmacSecret.is_null()
            && (*r.pHmacSecret).cbFirst == 32
        {
            let mut o = [0u8; 32];
            o.copy_from_slice(std::slice::from_raw_parts((*r.pHmacSecret).pbFirst, 32));
            Some(o)
        } else {
            None
        };
        WebAuthNFreeAssertion(a);
        (id, out, flags)
    };
    let id = match id {
        Some(id) => id,
        None if creds.len() == 1 => creds[0].credential_id.clone(),
        None => return Err("the phone did not say which passkey it used".into()),
    };
    if !creds.iter().any(|c| c.credential_id == id) {
        return Err("the phone used a passkey this vault does not know".into());
    }
    if flags.ok_or("the phone returned no authenticator data")? & 0x04 == 0 {
        return Err("the phone did not verify you (screen lock, face or fingerprint)".into());
    }
    let out = out.ok_or("the phone returned no PRF output; its passkeys may not support PRF")?;
    Ok((id, HwKey::new(out)))
}
