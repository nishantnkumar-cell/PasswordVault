//! What the phone apps can change besides items: unlock methods, imports
//! from other password managers, and SSH and OpenPGP keys.
//!
//! Every method here changes the vault in memory only. The app calls
//! [`VaultSession::to_bytes`] and saves the file afterwards, as for items.

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use vault_core::item::{ItemData, KeyData};
use vault_core::{Factor, OsRandom, ParsedVault, SlotId, Unlock, Vault};
use zeroize::Zeroizing;

use crate::{MobileError, R, VaultSession, hex, invalid, item_id, now, unhex};

/// What an import added.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImportResult {
    /// Items added to the vault.
    pub imported: u32,
    /// Entries the export held that the vault has no type for (Bitwarden
    /// SSH keys, for example).
    pub skipped: u32,
    /// "Bitwarden" or "CSV".
    pub format: String,
}

/// The public half of a key item, safe to show, copy and share.
#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyPublic {
    /// "SSH" or "OpenPGP".
    pub kind: String,
    /// The algorithm, such as "ssh-ed25519" or "EdDSALegacy".
    pub algorithm: String,
    /// `SHA256:...` for SSH, the hex fingerprint for OpenPGP.
    pub fingerprint: String,
    /// The `ssh-ed25519 AAAA... comment` line, or the ASCII-armored
    /// certificate.
    pub public_text: String,
    /// Each use needs approval on the computer.
    pub confirm: bool,
}

/// Which kind of SSH key to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshKeyKind {
    /// Ed25519, the default and what GitHub, GitLab and current servers
    /// suggest.
    Ed25519,
    /// ECDSA on P-256, for servers that don't take Ed25519.
    EcdsaP256,
}

fn check_new_password(password: &str) -> R<()> {
    if password.chars().count() < 8 {
        return Err(invalid(
            "Use at least 8 characters for the master password.",
        ));
    }
    Ok(())
}

fn slot_id(s: &str) -> R<SlotId> {
    unhex(s).ok_or_else(|| invalid("That unlock method no longer exists."))
}

fn slot_error(err: vault_core::Error) -> MobileError {
    match err {
        vault_core::Error::LastSlot => invalid(
            "The vault needs at least one password or security key to unlock with every day.",
        ),
        vault_core::Error::TooManySlots => {
            invalid("The vault has as many unlock methods as it can hold. Remove one first.")
        }
        other => other.into(),
    }
}

/// The password-only slots `password` opens, tried on an encoded copy (the
/// vault in memory has no way to test a credential).
fn password_slots(v: &mut Vault, password: &str) -> R<Vec<SlotId>> {
    let parsed = ParsedVault::parse(&v.to_bytes(&mut OsRandom)?)?;
    let cred = Unlock::Password {
        password,
        hw_key: None,
    };
    let ids: Vec<SlotId> = parsed
        .slots()
        .filter(|m| m.factor == Factor::PasswordOnly)
        .filter(|m| parsed.unlock(&m.id, &cred).is_ok())
        .map(|m| m.id)
        .collect();
    if ids.is_empty() {
        return Err(MobileError::WrongCredential);
    }
    Ok(ids)
}

/// Encode and open the new slot, as the desktop does after every enrollment
/// (format.md 6.2), so a slot that would not unlock is never saved.
fn test_unlock(v: &mut Vault, id: &SlotId, cred: &Unlock<'_>) -> R<()> {
    let parsed = ParsedVault::parse(&v.to_bytes(&mut OsRandom)?)?;
    parsed
        .unlock(id, cred)
        .map(|_| ())
        .map_err(|e| invalid(format!("The new unlock method failed its test: {e}")))
}

fn add_recovery(v: &mut Vault) -> R<String> {
    let (id, code) = v
        .add_recovery_slot(&mut OsRandom, "recovery code")
        .map_err(slot_error)?;
    test_unlock(
        v,
        &id,
        &Unlock::Recovery {
            code: code.as_str(),
        },
    )?;
    Ok(code.as_str().to_owned())
}

fn ssh_public(openssh: &str, confirm: bool) -> R<KeyPublic> {
    let k = PrivateKey::from_openssh(openssh)
        .map_err(|e| invalid(format!("The stored SSH key is unreadable: {e}")))?;
    let public = k
        .public_key()
        .to_openssh()
        .map_err(|e| invalid(e.to_string()))?;
    Ok(KeyPublic {
        kind: "SSH".into(),
        algorithm: k.algorithm().as_str().to_owned(),
        fingerprint: k.fingerprint(HashAlg::Sha256).to_string(),
        public_text: public,
        confirm,
    })
}

fn pgp_public(tsk: &[u8], confirm: bool) -> R<KeyPublic> {
    use pgp::composed::{ArmorOptions, Deserializable, SignedSecretKey};
    use pgp::types::KeyDetails;
    let (k, _) = SignedSecretKey::from_reader_single(tsk)
        .map_err(|e| invalid(format!("The stored OpenPGP key is unreadable: {e}")))?;
    let public = k
        .to_public_key()
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| invalid(e.to_string()))?;
    Ok(KeyPublic {
        kind: "OpenPGP".into(),
        algorithm: format!("{:?}", k.primary_key.algorithm()),
        fingerprint: format!("{}", k.fingerprint()).to_uppercase(),
        public_text: public,
        confirm,
    })
}

#[uniffi::export]
impl VaultSession {
    /// Replace the master password: checks `current`, adds a slot for `new`
    /// and removes the password slots `current` opened. Other passwords,
    /// security keys and the recovery code stay. Runs Argon2id several
    /// times: call it off the main thread.
    pub fn change_password(&self, current: String, new: String) -> R<()> {
        let current = Zeroizing::new(current);
        let new = Zeroizing::new(new);
        check_new_password(&new)?;
        let mut v = self.lock();
        let old = password_slots(&mut v, &current)?;
        let id = v
            .add_password_slot(
                &mut OsRandom,
                Factor::PasswordOnly,
                self.cost,
                &new,
                None,
                "password",
            )
            .map_err(slot_error)?;
        for o in &old {
            v.remove_slot(o).map_err(slot_error)?;
        }
        test_unlock(
            &mut v,
            &id,
            &Unlock::Password {
                password: &new,
                hw_key: None,
            },
        )
    }

    /// Make a new recovery code and remove every older one. Returns the code,
    /// to be shown once.
    pub fn new_recovery_code(&self) -> R<String> {
        let mut v = self.lock();
        let old: Vec<SlotId> = v
            .slots()
            .filter(|m| m.factor == Factor::Recovery)
            .map(|m| m.id)
            .collect();
        let code = add_recovery(&mut v)?;
        for o in &old {
            v.remove_slot(o).map_err(slot_error)?;
        }
        Ok(code)
    }

    /// Remove one unlock method without changing the vault key. The last
    /// password-only method can't be removed on a phone: it is how the phone
    /// unlocks.
    pub fn remove_slot(&self, id: String) -> R<()> {
        let id = slot_id(&id)?;
        let mut v = self.lock();
        let meta = v
            .slots()
            .find(|m| m.id == id)
            .cloned()
            .ok_or_else(|| invalid("That unlock method no longer exists."))?;
        let passwords = v
            .slots()
            .filter(|m| m.factor == Factor::PasswordOnly)
            .count();
        if meta.factor == Factor::PasswordOnly && passwords == 1 {
            return Err(invalid(
                "This is the vault's only master password, which this device unlocks with. \
                 Use Change Master Password instead.",
            ));
        }
        v.remove_slot(&id).map_err(slot_error)
    }

    /// For a lost or stolen device or key: give the vault a new key, keep
    /// only the password slots `password` opens, remove every other unlock
    /// method (security keys, TPMs, phone passkeys, other passwords, recovery
    /// codes) and make a new recovery code, which is returned. Old copies of
    /// the file stay readable with what opened them; new saves are not.
    /// Other devices need the master password once at their next sync.
    pub fn revoke_others(&self, password: String) -> R<String> {
        let password = Zeroizing::new(password);
        let mut v = self.lock();
        let keep = password_slots(&mut v, &password)?;
        let creds: Vec<(SlotId, Unlock<'_>)> = keep
            .iter()
            .map(|id| {
                (
                    *id,
                    Unlock::Password {
                        password: &password,
                        hw_key: None,
                    },
                )
            })
            .collect();
        v.revoke(&mut OsRandom, &creds).map_err(slot_error)?;
        add_recovery(&mut v)
    }

    /// Import an export from another password manager: Bitwarden's
    /// unencrypted JSON, or a CSV from Apple Passwords, Safari, Chrome,
    /// Edge or Firefox. Every entry becomes a new item.
    pub fn import_export(&self, data: String) -> R<ImportResult> {
        let data = Zeroizing::new(data);
        let text = data.trim_start_matches('\u{feff}').trim_start();
        let t = now();
        let (items, skipped, format) = if text.starts_with('{') {
            let (items, skipped) = vault_import::bitwarden_json(text, t)
                .map_err(|e| invalid(sentence(&e.to_string())))?;
            (items, skipped, "Bitwarden")
        } else {
            let items = vault_import::browser_csv(text, t)
                .map_err(|e| invalid(sentence(&e.to_string())))?;
            (items, 0, "CSV")
        };
        if items.is_empty() {
            return Err(invalid("The file has no items in it."));
        }
        let mut v = self.lock();
        for item in &items {
            let id = v.new_item_id(&mut OsRandom)?;
            v.put_item(&mut OsRandom, &id, &item.to_bytes())?;
        }
        Ok(ImportResult {
            imported: items.len() as u32,
            skipped: skipped as u32,
            format: format.into(),
        })
    }

    /// The public half of the item's SSH or OpenPGP key; `None` when the
    /// item holds no key.
    pub fn key_public(&self, id: String) -> R<Option<KeyPublic>> {
        let id = item_id(&id)?;
        let v = self.lock();
        let item = Self::read(&v, &id)?;
        item.key
            .as_ref()
            .map(|k| match k {
                KeyData::Ssh { openssh, confirm } => ssh_public(openssh, *confirm),
                KeyData::OpenPgp { tsk, confirm } => pgp_public(tsk, *confirm),
            })
            .transpose()
    }

    /// Make a new SSH key in a new item titled `title`. The private key
    /// never leaves the vault; the computer's daemon uses it for SSH and Git
    /// signing once the vault syncs. `confirm`: ask before each use there.
    pub fn generate_ssh_key(&self, title: String, kind: SshKeyKind, confirm: bool) -> R<String> {
        let title = title.trim();
        if title.is_empty() {
            return Err(invalid(
                "Give the key a name, such as the computer or site it's for.",
            ));
        }
        let alg = match kind {
            SshKeyKind::Ed25519 => Algorithm::Ed25519,
            SshKeyKind::EcdsaP256 => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        };
        let mut k = PrivateKey::random(&mut OsRng, alg).map_err(|e| invalid(e.to_string()))?;
        k.set_comment(title);
        let text = k
            .to_openssh(LineEnding::LF)
            .map_err(|e| invalid(e.to_string()))?;
        let t = now();
        let mut item = ItemData::default();
        item.title = title.to_owned();
        item.created = t;
        item.modified = t;
        item.key = Some(KeyData::Ssh {
            openssh: String::from(text.as_str()),
            confirm,
        });
        let mut v = self.lock();
        let id = v.new_item_id(&mut OsRandom)?;
        v.put_item(&mut OsRandom, &id, &item.to_bytes())?;
        Ok(hex(&id))
    }
}

/// "could not parse export: x" → "Could not read the file: x."
fn sentence(s: &str) -> String {
    let s = s.replace("could not parse export", "Could not read the file");
    let mut c = s.chars();
    let s = match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => s,
    };
    if s.ends_with('.') { s } else { s + "." }
}
