//! FIDO2 security keys over USB HID (ctap-hid-fido2).
//!
//! Not exercised by automated tests: needs a physical key with hmac-secret.
//! Check one with `fido2-token -I <device>` (look for `hmac-secret`).

use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as Mext;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use vault_core::HwKey;

use super::{Fido2, HwResult, prf_salt};

pub struct HidFido2;

fn challenge() -> [u8; 32] {
    let mut c = [0u8; 32];
    getrandom_fill(&mut c);
    c
}

fn getrandom_fill(buf: &mut [u8]) {
    use vault_core::SecureRandom;
    vault_core::OsRandom.fill(buf).expect("OS RNG");
}

impl Fido2 for HidFido2 {
    fn enroll(&self, rp_id: &str, pin: Option<&str>, require_uv: bool) -> HwResult<Vec<u8>> {
        let dev =
            FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| format!("no security key: {e}"))?;
        let ch = challenge();
        let ext = [Mext::HmacSecret(Some(true))];
        let mut b = MakeCredentialArgsBuilder::new(rp_id, &ch).extensions(&ext);
        // A key with a PIN set may require it to register even a touch-only
        // credential (CTAP 2.1 without makeCredUvNotRqd). The PIN then only
        // gates registration; the slot's secret is still the without-UV one.
        b = match (require_uv, pin) {
            (_, Some(p)) => b.pin(p),
            (true, None) => return Err("this slot requires the security key PIN".into()),
            (false, None) => b.without_pin_and_uv(),
        };
        let att = dev.make_credential_with_args(&b.build()).map_err(|e| {
            let e = e.to_string();
            if e.contains("PIN_REQUIRED") {
                "this security key needs its PIN to register a credential; give the PIN".into()
            } else {
                format!("registration failed: {e}")
            }
        })?;
        if !att
            .extensions
            .iter()
            .any(|e| matches!(e, Mext::HmacSecret(Some(true))))
        {
            return Err("security key does not support hmac-secret".into());
        }
        Ok(att.credential_descriptor.id)
    }

    fn hmac_secret(
        &self,
        rp_id: &str,
        cred: &[u8],
        prf_input: &[u8; 32],
        pin: Option<&str>,
        require_uv: bool,
    ) -> HwResult<HwKey> {
        let dev =
            FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| format!("no security key: {e}"))?;
        let ch = challenge();
        let ext = [Gext::HmacSecret(Some(prf_salt(prf_input)))];
        let mut b = GetAssertionArgsBuilder::new(rp_id, &ch)
            .credential_id(cred)
            .extensions(&ext);
        b = match (require_uv, pin) {
            (true, Some(p)) => b.pin(p),
            (true, None) => return Err("this slot requires the security key PIN".into()),
            (false, _) => b.without_pin_and_uv(),
        };
        let assertions = dev
            .get_assertion_with_args(&b.build())
            .map_err(|e| format!("security key: {e}"))?;
        let out = assertions
            .first()
            .and_then(|a| {
                a.extensions.iter().find_map(|e| match e {
                    Gext::HmacSecret(Some(o)) => Some(*o),
                    _ => None,
                })
            })
            .ok_or("security key returned no hmac-secret output")?;
        Ok(HwKey::new(out))
    }
}
