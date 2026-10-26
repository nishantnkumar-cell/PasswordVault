//! TPM 2.0 sealing with `tss-esapi` (format.md 4.2, threat model A1).
//!
//! The secret is sealed as a keyed-hash data object under a transient ECC
//! P-256 storage primary key in the owner hierarchy, created from the standard
//! template on every use, so nothing persists in the TPM. Every command that
//! carries the secret or the PIN runs in a session salted to that primary key,
//! with parameter encryption both ways, against bus sniffing.
//!
//! Without a PCR binding the object's authValue is the PIN (empty if none).
//! With PCR 7 the object is policy-only: `PolicyPCR(sha256:7) + PolicyAuthValue`.
//!
//! Blob: u16 LE length || marshalled TPMT_PUBLIC || TPM2B_PRIVATE buffer.

use std::convert::TryFrom;

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme,
    PcrSelectionList, PcrSlot, Private, Public, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyedHashParameters, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, Error as TssError};
use vault_core::HwKey;
use zeroize::Zeroizing;

use super::{HwResult, Tpm, WIN_TPM_HINT, WIN_TPM_PREFIX};
#[cfg(test)]
use super::{WIN_TPM_MAGIC, WIN_TPM_SEALED};

/// The machine's TPM, via `TPM2TOOLS_TCTI` / `TCTI` if set, else `/dev/tpmrm0`.
pub struct SystemTpm;

fn err(what: &str) -> impl FnOnce(TssError) -> String + '_ {
    move |e| format!("TPM {what}: {e}")
}

fn context() -> HwResult<Context> {
    let tcti = std::env::var("TPM2TOOLS_TCTI")
        .or_else(|_| std::env::var("TCTI"))
        .ok()
        .and_then(|s| s.parse::<TctiNameConf>().ok())
        .unwrap_or_else(|| {
            TctiNameConf::Device("/dev/tpmrm0".parse::<DeviceConfig>().unwrap_or_default())
        });
    Context::new(tcti)
        .map_err(|e| format!("no usable TPM (is /dev/tpmrm0 present and readable?): {e}"))
}

/// The standard ECC P-256 storage key template (TCG EK/SRK profile shape).
fn srk_template() -> HwResult<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .with_no_da(true)
        .build()
        .map_err(err("srk attributes"))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .with_ecc_scheme(EccScheme::Null)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .map_err(err("srk parameters"))?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(err("srk template"))
}

fn pcr7() -> HwResult<PcrSelectionList> {
    PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
        .build()
        .map_err(err("pcr selection"))
}

fn auth(pin: Option<&str>) -> HwResult<Auth> {
    Auth::try_from(pin.unwrap_or("").as_bytes().to_vec()).map_err(err("pin"))
}

struct Session {
    ctx: Context,
    srk: KeyHandle,
}

impl Session {
    fn open() -> HwResult<Session> {
        let mut ctx = context()?;
        let template = srk_template()?;
        let srk = ctx
            .execute_with_nullauth_session(|c| {
                c.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .map_err(err("create primary"))?
            .key_handle;
        Ok(Session { ctx, srk })
    }

    /// A session salted to the SRK, with command and response encryption.
    fn salted(&mut self, kind: SessionType) -> HwResult<AuthSession> {
        let s = self
            .ctx
            .start_auth_session(
                Some(self.srk),
                None,
                None,
                kind,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(err("start session"))?
            .ok_or("TPM returned no session")?;
        let (a, m) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .with_continue_session(true)
            .build();
        self.ctx
            .tr_sess_set_attributes(s, a, m)
            .map_err(err("session attributes"))?;
        Ok(s)
    }

    /// Run PolicyPCR(7, current values) + PolicyAuthValue on `s`.
    fn pcr_policy(&mut self, s: AuthSession) -> HwResult<()> {
        let ps = PolicySession::try_from(s).map_err(err("policy session"))?;
        self.ctx
            .policy_pcr(ps, Digest::default(), pcr7()?)
            .map_err(err("policy pcr"))?;
        self.ctx
            .policy_auth_value(ps)
            .map_err(err("policy auth value"))
    }

    /// The policy digest the sealed object will require.
    fn trial_digest(&mut self) -> HwResult<Digest> {
        let trial = self
            .ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(err("trial session"))?
            .ok_or("TPM returned no session")?;
        self.pcr_policy(trial)?;
        let d = self
            .ctx
            .policy_get_digest(PolicySession::try_from(trial).map_err(err("policy session"))?)
            .map_err(err("policy digest"));
        self.flush(trial);
        d
    }

    fn flush(&mut self, s: AuthSession) {
        let _ =
            self.ctx
                .flush_context(ObjectHandle::from(tss_esapi::handles::SessionHandle::from(
                    s,
                )));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.ctx.flush_context(self.srk.into());
    }
}

/// Objects with a PIN are subject to the TPM's dictionary-attack lockout;
/// objects without one have nothing to guess, so they are exempt.
fn sealed_template(policy: Option<Digest>, has_pin: bool) -> HwResult<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(policy.is_none())
        .with_no_da(!has_pin)
        .build()
        .map_err(err("sealed attributes"))?;
    let mut b = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default());
    if let Some(p) = policy {
        b = b.with_auth_policy(p);
    }
    b.build().map_err(err("sealed template"))
}

impl Tpm for SystemTpm {
    fn seal(&self, secret: &[u8; 32], pin: Option<&str>, bind_pcr7: bool) -> HwResult<Vec<u8>> {
        let mut s = Session::open()?;
        let policy = if bind_pcr7 {
            Some(s.trial_digest()?)
        } else {
            None
        };
        let data = SensitiveData::try_from(secret.to_vec()).map_err(err("sensitive data"))?;
        let sess = s.salted(SessionType::Hmac)?;
        let template = sealed_template(policy, pin.is_some_and(|p| !p.is_empty()))?;
        let auth = auth(pin)?;
        let srk = s.srk;
        let created = s.ctx.execute_with_session(Some(sess), |c| {
            c.create(srk, template, Some(auth), Some(data), None, None)
        });
        s.flush(sess);
        let created = created.map_err(err("create sealed object"))?;
        let public = created
            .out_public
            .marshall()
            .map_err(err("marshall public"))?;
        let mut blob = Vec::with_capacity(2 + public.len() + created.out_private.len());
        blob.extend_from_slice(
            &u16::try_from(public.len())
                .map_err(|_| "TPM public too large")?
                .to_le_bytes(),
        );
        blob.extend_from_slice(&public);
        blob.extend_from_slice(created.out_private.value());
        Ok(blob)
    }

    fn unseal(&self, blob: &[u8], pin: Option<&str>, bind_pcr7: bool) -> HwResult<HwKey> {
        if blob.starts_with(WIN_TPM_PREFIX) {
            return Err(WIN_TPM_HINT.into());
        }
        let (len, rest) = blob.split_at_checked(2).ok_or("TPM blob truncated")?;
        let len = u16::from_le_bytes([len[0], len[1]]) as usize;
        let (public, private) = rest.split_at_checked(len).ok_or("TPM blob truncated")?;
        let public = Public::unmarshall(public).map_err(err("unmarshall public"))?;
        let private = Private::try_from(private.to_vec()).map_err(err("private"))?;

        let mut s = Session::open()?;
        let srk = s.srk;
        let obj = s
            .ctx
            .execute_with_nullauth_session(|c| c.load(srk, private, public))
            .map_err(err("load"))?;
        s.ctx
            .tr_set_auth(obj.into(), auth(pin)?)
            .map_err(err("set auth"))?;

        let sess = s.salted(if bind_pcr7 {
            SessionType::Policy
        } else {
            SessionType::Hmac
        })?;
        let res = (|| {
            if bind_pcr7 {
                s.pcr_policy(sess)?;
            }
            s.ctx
                .execute_with_session(Some(sess), |c| c.unseal(obj.into()))
                .map_err(err("unseal (wrong PIN or PCR 7 changed)"))
        })();
        s.flush(sess);
        let _ = s.ctx.flush_context(obj.into());
        let data = Zeroizing::new(res?.value().to_vec());
        let arr: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| "TPM secret has wrong length")?;
        Ok(HwKey::new(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs against a real or simulated TPM. Start one with
    /// `swtpm socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --tpmstate dir=/tmp/swtpm --flags startup-clear`
    /// and set `TCTI=swtpm:port=2321`.
    #[test]
    #[ignore = "needs a TPM; see doc comment"]
    fn seal_unseal_round_trip() {
        let _g = crate::TPM_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::tpm2::tests::reset_swtpm_lockout();
        let t = SystemTpm;
        let secret = [7u8; 32];
        for pcr in [false, true] {
            let blob = t.seal(&secret, Some("1234"), pcr).unwrap();
            assert!(t.unseal(&blob, Some("1234"), pcr).unwrap().ct_eq(&secret));
            assert!(t.unseal(&blob, Some("0000"), pcr).is_err());
        }
        let blob = t.seal(&secret, None, false).unwrap();
        assert!(t.unseal(&blob, None, false).unwrap().ct_eq(&secret));

        // A slot made on Windows is named as such, not reported as damaged.
        for magic in [WIN_TPM_MAGIC, WIN_TPM_SEALED] {
            let mut win = magic.to_vec();
            win.extend_from_slice(&[1, 0, 0]);
            let msg = t.unseal(&win, None, false).err().unwrap();
            assert!(msg.contains("made on Windows"), "{msg}");
        }

        // Changing PCR 7 (as a Secure Boot change would) breaks the PCR-bound blob only.
        let bound = t.seal(&secret, None, true).unwrap();
        let mut ctx = context().unwrap();
        let mut d = tss_esapi::structures::DigestValues::new();
        d.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![1u8; 32]).unwrap(),
        );
        ctx.execute_with_nullauth_session(|c| c.pcr_extend(tss_esapi::handles::PcrHandle::Pcr7, d))
            .unwrap();
        assert!(t.unseal(&bound, None, true).is_err());
        assert!(t.unseal(&blob, None, false).unwrap().ct_eq(&secret));
    }
}
