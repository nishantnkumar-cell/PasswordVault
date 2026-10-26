//! Phone passkeys: a passkey in the phone's password manager (iCloud
//! Keychain, Google Password Manager and others) whose WebAuthn PRF output is
//! the slot's hardware secret. The phone connects over the hybrid transport:
//! the computer shows a QR code, the phone scans it, Bluetooth proves the two
//! are near each other, and the request goes through the phone maker's relay.
//!
//! This runs in the client (the desktop app or `vault`), not in the daemon:
//! the client can show the QR code and reach the network and Bluetooth, which
//! the daemon's sandbox does not allow. The client hands the 32-byte PRF
//! output to the daemon with the password, over the same local connection the
//! password already uses.
//!
//! PRF is hmac-secret with the salt `prf_salt(prf_input)` (format.md 4.2), so
//! a phone slot is stored as a `PasswordFido2` slot with `require_uv`: phones
//! always verify the user. The same slot also opens with a security key that
//! holds the credential, and a slot made on Linux opens on Windows.
//!
//! - Linux: `libwebauthn`'s caBLE client; needs a Bluetooth adapter (BlueZ).
//! - Windows: the WebAuthn API (webauthn.dll), which shows its own QR code.
//! - macOS: not yet.
//!
//! Not exercised by automated tests: needs a phone.

use vault_core::HwKey;

use super::HwResult;

/// What the phone ceremony tells the user while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneEvent {
    /// Show this as a QR code (a `FIDO:/` URI) for the phone's camera. Not
    /// sent on Windows, which shows its own.
    Qr(String),
    /// A short progress line, such as "Connecting to your phone".
    Status(String),
}

/// A passkey slot the vault can be opened with: its credential and PRF input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCred {
    pub credential_id: Vec<u8>,
    pub prf_input: [u8; 32],
}

/// A new passkey on the phone.
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    /// The PRF output for the `prf_input` given, when the phone returned it
    /// while creating the passkey (Android does, iPhones may not). Without it
    /// the caller asks once more with [`prf`].
    pub prf: Option<HwKey>,
}

/// How long to wait for the phone.
pub const TIMEOUT_SECS: u64 = 120;

/// Why phone passkeys cannot be used here, if they cannot.
pub fn check_available() -> HwResult<()> {
    imp::check_available()
}

/// Create a passkey for `rp_id` on a phone, asking for the PRF output of
/// `prf_input` at the same time where the platform allows.
pub fn enroll(
    rp_id: &str,
    prf_input: &[u8; 32],
    events: &dyn Fn(PhoneEvent),
) -> HwResult<Enrolled> {
    imp::enroll(rp_id, prf_input, events)
}

/// Ask the phone for the PRF output of whichever of `creds` it holds.
/// Returns that credential's ID and its output.
pub fn prf(
    rp_id: &str,
    creds: &[PasskeyCred],
    events: &dyn Fn(PhoneEvent),
) -> HwResult<(Vec<u8>, HwKey)> {
    if creds.is_empty() {
        return Err("no phone or security key slot that checks the PIN is enrolled".into());
    }
    imp::prf(rp_id, creds, events)
}

/// The user entity a new passkey is stored under. The phone's password
/// manager lists it by these names, so they say what it is for.
pub const USER_NAME: &str = "Secret Vault unlock";

#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(windows)]
mod imp {
    pub use crate::webauthn::{
        phone_check_available as check_available, phone_enroll as enroll, phone_prf as prf,
    };
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    use super::*;

    const NOT_YET: &str = "phone passkeys are not supported on this system yet";

    pub fn check_available() -> HwResult<()> {
        Err(NOT_YET.into())
    }
    pub fn enroll(_: &str, _: &[u8; 32], _: &dyn Fn(PhoneEvent)) -> HwResult<Enrolled> {
        Err(NOT_YET.into())
    }
    pub fn prf(_: &str, _: &[PasskeyCred], _: &dyn Fn(PhoneEvent)) -> HwResult<(Vec<u8>, HwKey)> {
        Err(NOT_YET.into())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::time::Duration;

    use libwebauthn::fido::AuthenticatorDataFlags;
    use libwebauthn::ops::webauthn::{
        GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialPrfInput,
        MakeCredentialRequest, MakeCredentialsRequestExtensions, PrfInput, PrfInputValue,
        ResidentKeyRequirement, UserVerificationRequirement,
    };
    use libwebauthn::proto::ctap2::{
        Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
        Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
    };
    use libwebauthn::transport::cable::channel::{CableChannel, CableUpdate, CableUxUpdate};
    use libwebauthn::transport::cable::qr_code_device::{
        CableQrCodeDevice, CableTransports, QrCodeOperationHint,
    };
    use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
    use libwebauthn::webauthn::{WebAuthn as _, WebAuthnError};
    use serde_bytes::ByteBuf;
    use tokio::sync::broadcast::Receiver;

    use super::*;

    fn runtime() -> HwResult<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("phone: {e}"))
    }

    fn random<const N: usize>() -> [u8; N] {
        use vault_core::SecureRandom;
        let mut b = [0u8; N];
        vault_core::OsRandom.fill(&mut b).expect("OS RNG");
        b
    }

    /// The origin in the client data. Nothing checks it: the vault uses only
    /// the PRF output, never the signature.
    fn origin(rp_id: &str) -> String {
        format!("https://{rp_id}")
    }

    fn timeout() -> Duration {
        Duration::from_secs(TIMEOUT_SECS)
    }

    pub fn check_available() -> HwResult<()> {
        if runtime()?.block_on(libwebauthn::transport::cable::is_available()) {
            Ok(())
        } else {
            Err(
                "phone passkeys need Bluetooth, and no Bluetooth adapter was found \
                 (is bluetoothd running and the adapter switched on?)"
                    .into(),
            )
        }
    }

    fn describe<E: std::fmt::Debug>(what: &str, e: WebAuthnError<E>) -> String {
        match e {
            WebAuthnError::Ctap(c) => format!("{what}: the phone said {c:?}"),
            other => format!("{what}: {other:?}"),
        }
    }

    fn status(u: &CableUxUpdate) -> Option<String> {
        match u {
            CableUxUpdate::CableUpdate(c) => Some(match c {
                CableUpdate::ProximityCheck => "Waiting for your phone (keep Bluetooth on)".into(),
                CableUpdate::Connecting => "Connecting to your phone".into(),
                CableUpdate::Authenticating => "Confirm on your phone".into(),
                CableUpdate::Connected => "Connected; confirm on your phone".into(),
                CableUpdate::Error(e) => format!("Phone connection failed: {e}"),
            }),
            CableUxUpdate::UvUpdate(_) => None,
        }
    }

    /// Show the QR code, then run `op` on the channel, forwarding progress.
    async fn with_phone<T, F>(
        hint: QrCodeOperationHint,
        events: &dyn Fn(PhoneEvent),
        op: F,
    ) -> HwResult<T>
    where
        F: AsyncFnOnce(&mut CableChannel) -> HwResult<T>,
    {
        // Cloud-assisted only: older Google Play services reject a QR code
        // that also offers the local channel.
        let mut device = CableQrCodeDevice::new_transient(hint, CableTransports::CloudAssistedOnly)
            .map_err(|e| format!("phone: {e:?}"))?;
        events(PhoneEvent::Qr(device.qr_code.to_string()));
        let mut channel = device
            .channel(ChannelSettings::default())
            .await
            .map_err(|e| describe("phone", e))?;
        let mut rx: Receiver<CableUxUpdate> = channel.get_ux_update_receiver();
        let fut = op(&mut channel);
        tokio::pin!(fut);
        loop {
            tokio::select! {
                r = &mut fut => return r,
                u = rx.recv() => match u {
                    Ok(u) => {
                        if let Some(s) = status(&u) {
                            events(PhoneEvent::Status(s));
                        }
                    }
                    // Closed or lagged: keep waiting for the result.
                    Err(_) => {
                        let r = (&mut fut).await;
                        return r;
                    }
                },
            }
        }
    }

    fn prf_value(input: &[u8; 32]) -> PrfInputValue {
        PrfInputValue {
            first: input.to_vec(),
            second: None,
        }
    }

    pub fn enroll(
        rp_id: &str,
        prf_input: &[u8; 32],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<Enrolled> {
        let request = MakeCredentialRequest {
            hints: vec![],
            authenticator_attachment: None,
            challenge: random::<32>().to_vec(),
            origin: origin(rp_id),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new(rp_id, "Secret Vault"),
            // A random user handle: nothing looks the user up by it.
            user: Ctap2PublicKeyCredentialUserEntity::new(&random::<16>(), USER_NAME, USER_NAME),
            // Phones keep only discoverable credentials.
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: UserVerificationRequirement::Required,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(MakeCredentialsRequestExtensions {
                prf: Some(MakeCredentialPrfInput {
                    eval: Some(prf_value(prf_input)),
                }),
                ..Default::default()
            }),
            attestation: None,
            timeout: timeout(),
        };
        runtime()?.block_on(with_phone(
            QrCodeOperationHint::MakeCredential,
            events,
            async |ch| {
                let r = ch
                    .webauthn_make_credential(&request)
                    .await
                    .map_err(|e| describe("creating the passkey", e))?;
                let cred: Ctap2PublicKeyCredentialDescriptor =
                    (&r.authenticator_data)
                        .try_into()
                        .map_err(|_| "the phone returned no credential")?;
                let prf = r.unsigned_extensions_output.prf.as_ref();
                if prf.is_some_and(|p| p.enabled == Some(false)) {
                    return Err("this phone's passkeys do not support PRF, which the vault \
                                needs; try a newer phone or password manager"
                        .into());
                }
                Ok(Enrolled {
                    credential_id: cred.id.to_vec(),
                    prf: prf
                        .and_then(|p| p.results.as_ref())
                        .map(|v| HwKey::new(v.first)),
                })
            },
        ))
    }

    pub fn prf(
        rp_id: &str,
        creds: &[PasskeyCred],
        events: &dyn Fn(PhoneEvent),
    ) -> HwResult<(Vec<u8>, HwKey)> {
        let eval_by_credential: HashMap<String, PrfInputValue> = creds
            .iter()
            .map(|c| {
                (
                    base64_url::encode(&c.credential_id),
                    prf_value(&c.prf_input),
                )
            })
            .collect();
        let allow = creds
            .iter()
            .map(|c| Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(c.credential_id.clone()),
                transports: None,
            })
            .collect();
        let request = GetAssertionRequest {
            hints: vec![],
            relying_party_id: rp_id.to_owned(),
            challenge: random::<32>().to_vec(),
            origin: origin(rp_id),
            top_origin: None,
            allow,
            user_verification: UserVerificationRequirement::Required,
            extensions: Some(GetAssertionRequestExtensions {
                prf: Some(PrfInput {
                    eval: None,
                    eval_by_credential,
                }),
                ..Default::default()
            }),
            timeout: timeout(),
        };
        runtime()?.block_on(with_phone(
            QrCodeOperationHint::GetAssertionRequest,
            events,
            async |ch| {
                let r = ch
                    .webauthn_get_assertion(&request)
                    .await
                    .map_err(|e| describe("phone", e))?;
                let a = r
                    .assertions
                    .first()
                    .ok_or("the phone returned no passkey")?;
                // With one allowed credential the phone may leave the ID out.
                let id = match &a.credential_id {
                    Some(d) => d.id.to_vec(),
                    None if creds.len() == 1 => creds[0].credential_id.clone(),
                    None => return Err("the phone did not say which passkey it used".into()),
                };
                if !creds.iter().any(|c| c.credential_id == id) {
                    return Err("the phone used a passkey this vault does not know".into());
                }
                if !a
                    .authenticator_data
                    .flags
                    .contains(AuthenticatorDataFlags::USER_VERIFIED)
                {
                    return Err(
                        "the phone did not verify you (screen lock, face or fingerprint)".into(),
                    );
                }
                let out = a
                    .unsigned_extensions_output
                    .as_ref()
                    .and_then(|u| u.prf.as_ref())
                    .and_then(|p| p.results.as_ref())
                    .ok_or("the phone returned no PRF output; its passkeys may not support PRF")?;
                Ok((id, HwKey::new(out.first)))
            },
        ))
    }
}
