//! The vault for the iPhone/iPad and Android apps, exported over UniFFI.
//!
//! This crate is a thin layer over `vault-core`: the apps read and write the
//! vault file themselves (their storage APIs differ) and pass bytes in and
//! out. Every secret that crosses into Swift or Kotlin is a plain string
//! there; the apps keep such strings only while a screen shows them.

use std::sync::{Arc, Mutex, MutexGuard};

use vault_core::generator::{self, Charset};
use vault_core::item::{
    Card, CustomField, FieldKind, Identity, ItemData, ItemKind, ItemMerge, KeyData, UrlEntry,
};
use vault_core::origin::{self, MatchMode};
use vault_core::totp::TotpConfig;
use vault_core::{
    Factor, HwKey, ItemId, KdfCost, OsRandom, ParkedKey, ParsedVault, SlotId, Unlock, Vault,
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests;

/// What went wrong, in words the apps can show as they are.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MobileError {
    /// The password, recovery code or biometric key did not open the vault.
    #[error("That did not unlock the vault. Check it and try again.")]
    WrongCredential,
    /// The file is not a vault, or is damaged or half-synced.
    #[error("This file is not a vault, or it is damaged: {detail}")]
    BadFile {
        /// What `vault-core` reported.
        detail: String,
    },
    /// Two different vaults.
    #[error("The synced file belongs to a different vault.")]
    DifferentVault,
    /// The other copy's key was rotated: unlock it with a password to merge.
    #[error(
        "The synced copy was re-keyed on another device. Unlock with your master password to merge it."
    )]
    Rekeyed,
    /// No item with that ID.
    #[error("That item no longer exists.")]
    NotFound,
    /// The input was not accepted.
    #[error("{detail}")]
    Invalid {
        /// What to fix.
        detail: String,
    },
}

impl From<vault_core::Error> for MobileError {
    fn from(err: vault_core::Error) -> MobileError {
        use vault_core::Error as E;
        match err {
            E::WrongFactor | E::BadRecoveryCode => MobileError::WrongCredential,
            E::DifferentVault => MobileError::DifferentVault,
            E::DifferentKey => MobileError::Rekeyed,
            E::NotFound => MobileError::NotFound,
            other => MobileError::BadFile {
                detail: other.to_string(),
            },
        }
    }
}

type R<T> = Result<T, MobileError>;

fn invalid(detail: impl Into<String>) -> MobileError {
    MobileError::Invalid {
        detail: detail.into(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn item_id(s: &str) -> R<ItemId> {
    unhex(s).ok_or(MobileError::NotFound)
}

fn wrap_key(bytes: &[u8]) -> R<HwKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| invalid("the biometric key must be 32 bytes"))?;
    Ok(HwKey::new(arr))
}

// ---------------------------------------------------------------------------
// Records shared with the apps
// ---------------------------------------------------------------------------

/// What an item holds. Mirrors [`ItemKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Kind {
    /// Username, password, websites, one-time code.
    Login,
    /// Text only.
    Note,
    /// A payment card.
    Card,
    /// Name, address and contact details.
    Identity,
}

impl From<ItemKind> for Kind {
    fn from(k: ItemKind) -> Kind {
        match k {
            ItemKind::Login => Kind::Login,
            ItemKind::Note => Kind::Note,
            ItemKind::Card => Kind::Card,
            ItemKind::Identity => Kind::Identity,
        }
    }
}

impl From<Kind> for ItemKind {
    fn from(k: Kind) -> ItemKind {
        match k {
            Kind::Login => ItemKind::Login,
            Kind::Note => ItemKind::Note,
            Kind::Card => ItemKind::Card,
            Kind::Identity => ItemKind::Identity,
        }
    }
}

/// One keyslot, for the Unlock methods screen.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SlotInfo {
    /// Hex slot ID.
    pub id: String,
    /// The name given when it was added, such as "password" or "YubiKey".
    pub label: String,
    /// "password", "security key", "TPM", "recovery code" or "other".
    pub factor: String,
    /// Whether this phone can use it. Security key and TPM slots belong to
    /// the desktop that enrolled them.
    pub usable_here: bool,
}

fn slot_infos<'a>(
    slots: impl Iterator<Item = &'a vault_core::KeyslotMeta>,
    label: impl Fn(&SlotId) -> String,
) -> Vec<SlotInfo> {
    slots
        .map(|m| {
            let (factor, usable_here) = match m.factor {
                Factor::PasswordOnly => ("password", true),
                Factor::PasswordFido2 { .. } => ("security key", false),
                Factor::PasswordTpm { .. } => ("TPM", false),
                Factor::Recovery => ("recovery code", true),
                _ => ("other", false),
            };
            SlotInfo {
                id: hex(&m.id),
                label: label(&m.id),
                factor: factor.into(),
                usable_here,
            }
        })
        .collect()
}

/// One row of the item list. Never holds a secret.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemSummary {
    /// Hex item ID.
    pub id: String,
    /// What the item is.
    pub kind: Kind,
    /// Display name.
    pub title: String,
    /// Username, card network and last four digits, or the identity's name.
    pub subtitle: String,
    /// Has a one-time code seed.
    pub has_totp: bool,
    /// Holds an SSH or OpenPGP key (used by the desktop daemon).
    pub has_key: bool,
    /// Host of the first website, for the letter tile and search.
    pub host: Option<String>,
    /// Seconds since the Unix epoch.
    pub modified: u64,
}

fn summary(id: &ItemId, item: &ItemData) -> ItemSummary {
    ItemSummary {
        id: hex(id),
        kind: item.kind.into(),
        title: item.title.clone(),
        subtitle: if item.key.is_some() && item.kind == ItemKind::Note {
            key_label(item.key.as_ref()).unwrap_or_default()
        } else {
            item.subtitle()
        },
        has_totp: item.totp.is_some(),
        has_key: item.key.is_some(),
        host: item
            .urls
            .iter()
            .find_map(|u| origin::Origin::parse(&u.url).map(|o| o.host)),
        modified: item.modified,
    }
}

fn key_label(key: Option<&KeyData>) -> Option<String> {
    key.map(|k| match k {
        KeyData::Ssh { .. } => "SSH key".to_owned(),
        KeyData::OpenPgp { .. } => "OpenPGP key".to_owned(),
    })
}

/// A website a login may be filled on.
#[derive(Debug, Clone, uniffi::Record)]
pub struct UrlRecord {
    /// As entered.
    pub url: String,
    /// Match any subdomain of the same registrable domain, not only this
    /// exact origin.
    pub match_subdomains: bool,
    /// Allow filling over plain http.
    pub allow_http: bool,
}

/// Payment card details.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct CardRecord {
    /// Name on the card.
    pub holder: String,
    /// Digits only once saved.
    pub number: String,
    /// 1 to 12, or 0.
    pub exp_month: u8,
    /// Four digits, or 0.
    pub exp_year: u16,
    /// Security code.
    pub cvv: String,
    /// PIN.
    pub pin: String,
    /// "Visa", "Mastercard", ... (read only).
    pub brand: Option<String>,
    /// Whether the number passes the Luhn check (read only).
    pub number_valid: bool,
}

/// Name and address details. Field names follow [`Identity`].
#[derive(Debug, Clone, Default, uniffi::Record)]
#[allow(missing_docs)]
pub struct IdentityRecord {
    pub honorific: String,
    pub given_name: String,
    pub middle_name: String,
    pub family_name: String,
    pub company: String,
    pub email: String,
    pub phone: String,
    pub address1: String,
    pub address2: String,
    pub address3: String,
    pub city: String,
    pub region: String,
    pub postcode: String,
    pub country: String,
}

/// A field the user added.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FieldRecord {
    /// Label.
    pub name: String,
    /// Value.
    pub value: String,
    /// Hidden until revealed.
    pub hidden: bool,
    /// Shown as a link.
    pub link: bool,
}

/// Everything about one item, for the detail and edit screens.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemDetail {
    /// Hex item ID.
    pub id: String,
    /// What the item is.
    pub kind: Kind,
    /// Display name.
    pub title: String,
    /// Logins.
    pub username: String,
    /// Logins.
    pub password: String,
    /// Logins.
    pub urls: Vec<UrlRecord>,
    /// Logins: has a one-time code seed. The seed itself never leaves Rust.
    pub has_totp: bool,
    /// Cards.
    pub card: Option<CardRecord>,
    /// Identities.
    pub identity: Option<IdentityRecord>,
    /// Extra fields.
    pub fields: Vec<FieldRecord>,
    /// Free text.
    pub notes: String,
    /// Seconds since the Unix epoch.
    pub created: u64,
    /// Seconds since the Unix epoch.
    pub modified: u64,
    /// "SSH key" or "OpenPGP key" when the item holds one. Keys are used by
    /// the desktop daemon; the phone shows them but cannot use or edit them.
    pub key: Option<String>,
}

/// What to do with the one-time code seed when saving.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum TotpEdit {
    /// Leave it as it is.
    Keep,
    /// Delete it.
    Remove,
    /// Replace it with an `otpauth://` URI or a Base32 secret.
    Set {
        /// As pasted or scanned.
        input: String,
    },
}

/// The editable parts of an item.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemEdit {
    /// What the item is.
    pub kind: Kind,
    /// Display name; required.
    pub title: String,
    /// Logins.
    pub username: String,
    /// Logins.
    pub password: String,
    /// Logins. Empty URLs are dropped.
    pub urls: Vec<UrlRecord>,
    /// Logins.
    pub totp: TotpEdit,
    /// Cards.
    pub card: Option<CardRecord>,
    /// Identities.
    pub identity: Option<IdentityRecord>,
    /// Extra fields. Empty ones are dropped.
    pub fields: Vec<FieldRecord>,
    /// Free text.
    pub notes: String,
}

/// A current one-time code.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TotpCode {
    /// The digits.
    pub code: String,
    /// Seconds until it changes.
    pub remaining: u64,
    /// Seconds each code lasts.
    pub period: u32,
}

/// What a sync merge did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MergeOutcome {
    /// This vault changed: save it.
    pub changed: bool,
    /// The synced copy is missing something this vault has: write this vault
    /// over it.
    pub other_behind: bool,
    /// Items edited on both sides; the loser was kept as "... (conflict)".
    pub conflicts: u32,
    /// This vault took a key rotated on another device.
    pub rekeyed: bool,
}

/// Options for [`generate_password`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct GeneratorOptions {
    /// Number of characters, 4 to 128.
    pub length: u32,
    /// a to z.
    pub lower: bool,
    /// A to Z.
    pub upper: bool,
    /// 0 to 9.
    pub digits: bool,
    /// Punctuation.
    pub symbols: bool,
    /// Leave out characters that look alike (0 O, 1 l I).
    pub avoid_ambiguous: bool,
}

// ---------------------------------------------------------------------------
// Converting between the records and vault-core's item
// ---------------------------------------------------------------------------

fn detail(id: &ItemId, item: &ItemData) -> ItemDetail {
    ItemDetail {
        id: hex(id),
        kind: item.kind.into(),
        title: item.title.clone(),
        username: item.username.clone(),
        password: item.password.clone(),
        urls: item
            .urls
            .iter()
            .map(|u| UrlRecord {
                url: u.url.clone(),
                match_subdomains: u.mode == MatchMode::RegistrableDomain,
                allow_http: u.allow_http,
            })
            .collect(),
        has_totp: item.totp.is_some(),
        card: item.card.as_ref().map(|c| CardRecord {
            holder: c.holder.clone(),
            number: c.number.clone(),
            exp_month: c.exp_month,
            exp_year: c.exp_year,
            cvv: c.cvv.clone(),
            pin: c.pin.clone(),
            brand: c.brand().map(|b| b.name().to_owned()),
            number_valid: c.luhn_ok(),
        }),
        identity: item.identity.as_ref().map(|i| IdentityRecord {
            honorific: i.honorific.clone(),
            given_name: i.given_name.clone(),
            middle_name: i.middle_name.clone(),
            family_name: i.family_name.clone(),
            company: i.company.clone(),
            email: i.email.clone(),
            phone: i.phone.clone(),
            address1: i.address1.clone(),
            address2: i.address2.clone(),
            address3: i.address3.clone(),
            city: i.city.clone(),
            region: i.region.clone(),
            postcode: i.postcode.clone(),
            country: i.country.clone(),
        }),
        fields: item
            .fields
            .iter()
            .map(|f| FieldRecord {
                name: f.name.clone(),
                value: f.value.clone(),
                hidden: f.kind == FieldKind::Hidden,
                link: f.kind == FieldKind::Url,
            })
            .collect(),
        notes: item.notes.clone(),
        created: item.created,
        modified: item.modified,
        key: key_label(item.key.as_ref()),
    }
}

/// Apply `edit` over `item` (a new empty item, or the stored one so its
/// creation time, seed and key survive).
fn apply(item: &mut ItemData, edit: ItemEdit, now: u64) -> R<()> {
    let title = edit.title.trim();
    if title.is_empty() {
        return Err(invalid("Give the item a title."));
    }
    item.kind = edit.kind.into();
    item.title = title.to_owned();
    item.username = edit.username;
    item.password = edit.password;
    item.urls = edit
        .urls
        .into_iter()
        .filter(|u| !u.url.trim().is_empty())
        .map(|u| {
            let url = u.url.trim().to_owned();
            // Bare hosts as typed on a phone ("github.com") become https URLs.
            let url = if url.contains("://") {
                url
            } else {
                format!("https://{url}")
            };
            if origin::Origin::parse(&url).is_none() {
                return Err(invalid(format!("{url} is not a web address.")));
            }
            Ok(UrlEntry {
                url,
                mode: if u.match_subdomains {
                    MatchMode::RegistrableDomain
                } else {
                    MatchMode::Origin
                },
                allow_http: u.allow_http,
            })
        })
        .collect::<R<_>>()?;
    match edit.totp {
        TotpEdit::Keep => {}
        TotpEdit::Remove => item.totp = None,
        TotpEdit::Set { input } => {
            item.totp = Some(
                TotpConfig::parse(input.trim())
                    .map_err(|e| invalid(format!("One-time code: {e}")))?,
            );
        }
    }
    item.card = edit.card.map(|c| Card {
        holder: c.holder,
        number: c.number,
        exp_month: c.exp_month,
        exp_year: c.exp_year,
        cvv: c.cvv,
        pin: c.pin,
    });
    item.identity = edit.identity.map(|i| Identity {
        honorific: i.honorific,
        given_name: i.given_name,
        middle_name: i.middle_name,
        family_name: i.family_name,
        company: i.company,
        email: i.email,
        phone: i.phone,
        address1: i.address1,
        address2: i.address2,
        address3: i.address3,
        city: i.city,
        region: i.region,
        postcode: i.postcode,
        country: i.country,
    });
    item.fields = edit
        .fields
        .into_iter()
        .map(|f| CustomField {
            name: f.name,
            value: f.value,
            kind: if f.hidden {
                FieldKind::Hidden
            } else if f.link {
                FieldKind::Url
            } else {
                FieldKind::Text
            },
        })
        .collect();
    item.notes = edit.notes;
    if item.created == 0 {
        item.created = now;
    }
    item.modified = now;
    item.normalize();
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Locked vault
// ---------------------------------------------------------------------------

/// A vault file read from storage, not yet unlocked.
#[derive(uniffi::Object)]
pub struct LockedVault {
    parsed: ParsedVault,
}

#[uniffi::export]
impl LockedVault {
    /// Parse a vault file.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> R<Arc<LockedVault>> {
        Ok(Arc::new(LockedVault {
            parsed: ParsedVault::parse(&bytes)?,
        }))
    }

    /// Hex vault ID, the same on every device that shares the vault.
    pub fn vault_id(&self) -> String {
        hex(&self.parsed.vault_id())
    }

    /// The keyslots, without labels (labels are inside the encrypted body).
    pub fn slots(&self) -> Vec<SlotInfo> {
        slot_infos(self.parsed.slots(), |_| String::new())
    }

    /// Whether any slot accepts a password alone, the usual way to unlock on
    /// a phone.
    pub fn has_password_slot(&self) -> bool {
        self.parsed
            .slots()
            .any(|m| m.factor == Factor::PasswordOnly)
    }

    /// Unlock with the master password. Tries each password slot. Slow on
    /// purpose (Argon2id, 256 MiB by default): call it off the main thread.
    pub fn unlock_password(&self, password: String, device: u64) -> R<Arc<VaultSession>> {
        let password = Zeroizing::new(password);
        let ids: Vec<SlotId> = self
            .parsed
            .slots()
            .filter(|m| m.factor == Factor::PasswordOnly)
            .map(|m| m.id)
            .collect();
        if ids.is_empty() {
            return Err(invalid(
                "This vault has no password-only unlock method. Add one on your computer \
                 (Unlock methods), or use the recovery code.",
            ));
        }
        let cred = Unlock::Password {
            password: &password,
            hw_key: None,
        };
        let mut last = vault_core::Error::WrongFactor;
        for id in ids {
            match self.parsed.unlock(&id, &cred) {
                Ok(v) => return Ok(VaultSession::wrap(v, device)),
                Err(e) => last = e,
            }
        }
        Err(last.into())
    }

    /// Unlock with the recovery code.
    pub fn unlock_recovery(&self, code: String, device: u64) -> R<Arc<VaultSession>> {
        let code = Zeroizing::new(code);
        let cred = Unlock::Recovery { code: &code };
        let mut last = vault_core::Error::WrongFactor;
        for m in self.parsed.slots().filter(|m| m.factor == Factor::Recovery) {
            match self.parsed.unlock(&m.id, &cred) {
                Ok(v) => return Ok(VaultSession::wrap(v, device)),
                Err(e) => last = e,
            }
        }
        Err(last.into())
    }

    /// Unlock with a key from [`VaultSession::park`] and the wrap key the
    /// platform keystore released after Face ID, Touch ID or the fingerprint
    /// sensor. Fails with [`MobileError::Rekeyed`] or
    /// [`MobileError::WrongCredential`] when a full unlock is needed.
    pub fn resume(&self, parked: Vec<u8>, wrap: Vec<u8>, device: u64) -> R<Arc<VaultSession>> {
        let wrap = Zeroizing::new(wrap);
        let parked = ParkedKey::from_bytes(&parked)?;
        let v = self.parsed.resume(&parked, &wrap_key(&wrap)?)?;
        Ok(VaultSession::wrap(v, device))
    }
}

/// A new vault and its recovery code, shown once.
#[derive(uniffi::Record)]
pub struct NewVault {
    /// The unlocked vault. Save [`VaultSession::to_bytes`] right away.
    pub session: Arc<VaultSession>,
    /// Shown once; the user writes it down.
    pub recovery_code: String,
}

/// Create a vault with a master password and a recovery code, and check that
/// both open the encoded file before handing it back (format.md 6.1).
#[uniffi::export]
pub fn create_vault(password: String, device: u64) -> R<NewVault> {
    create_with_cost(password, device, KdfCost::DEFAULT)
}

fn create_with_cost(password: String, device: u64, cost: KdfCost) -> R<NewVault> {
    let password = Zeroizing::new(password);
    if password.chars().count() < 8 {
        return Err(invalid(
            "Use at least 8 characters for the master password.",
        ));
    }
    let rng = &mut OsRandom;
    let mut v = Vault::new(rng)?;
    let pw = v.add_password_slot(rng, Factor::PasswordOnly, cost, &password, None, "password")?;
    let (rc, code) = v.add_recovery_slot(rng, "recovery code")?;
    let bytes = v.to_bytes(rng)?;
    let parsed = ParsedVault::parse(&bytes)?;
    parsed.unlock(
        &pw,
        &Unlock::Password {
            password: &password,
            hw_key: None,
        },
    )?;
    parsed.unlock(
        &rc,
        &Unlock::Recovery {
            code: code.as_str(),
        },
    )?;
    Ok(NewVault {
        session: VaultSession::wrap(v, device),
        recovery_code: code.as_str().to_owned(),
    })
}

/// A random password.
#[uniffi::export]
pub fn generate_password(options: GeneratorOptions) -> R<String> {
    if !(4..=128).contains(&options.length) {
        return Err(invalid("Choose a length from 4 to 128."));
    }
    let cs = Charset {
        lower: options.lower,
        upper: options.upper,
        digits: options.digits,
        symbols: options.symbols,
        avoid_ambiguous: options.avoid_ambiguous,
    };
    let p = generator::generate_password(&mut OsRandom, options.length as usize, cs)
        .map_err(|_| invalid("Turn on at least one kind of character."))?;
    Ok(p.to_string())
}

/// Check a one-time code seed before saving it; returns the current code.
#[uniffi::export]
pub fn preview_totp(input: String, now: u64) -> R<TotpCode> {
    let cfg = TotpConfig::parse(input.trim()).map_err(|e| invalid(e.to_string()))?;
    code(&cfg, now)
}

fn code(cfg: &TotpConfig, now: u64) -> R<TotpCode> {
    Ok(TotpCode {
        code: cfg.code_at(now).map_err(|e| invalid(e.to_string()))?,
        remaining: cfg.remaining(now),
        period: cfg.period,
    })
}

/// The host of a URL or bare domain, lowercase, for display and matching;
/// `None` when it is not a web address.
#[uniffi::export]
pub fn host_of(url: String) -> Option<String> {
    let url = url.trim();
    let url = if url.contains("://") {
        url.to_owned()
    } else {
        format!("https://{url}")
    };
    origin::Origin::parse(&url).map(|o| o.host)
}

// ---------------------------------------------------------------------------
// Unlocked vault
// ---------------------------------------------------------------------------

/// An unlocked vault. Holds the vault key until the app drops it (on lock).
#[derive(uniffi::Object)]
pub struct VaultSession {
    vault: Mutex<Vault>,
}

impl VaultSession {
    fn wrap(mut v: Vault, device: u64) -> Arc<VaultSession> {
        v.set_device(device);
        Arc::new(VaultSession {
            vault: Mutex::new(v),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Vault> {
        // A panic while holding the lock leaves a valid vault; keep going.
        self.vault.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn read(v: &Vault, id: &ItemId) -> R<ItemData> {
        let bytes = v.get_item(id)?;
        Ok(ItemData::from_bytes(&bytes)?)
    }
}

#[uniffi::export]
impl VaultSession {
    /// Hex vault ID.
    pub fn vault_id(&self) -> String {
        hex(&self.lock().vault_id())
    }

    /// Increases with every save; a smaller number later means an old copy.
    pub fn generation(&self) -> u64 {
        self.lock().generation()
    }

    /// The keyslots with their labels.
    pub fn slots(&self) -> Vec<SlotInfo> {
        let v = self.lock();
        slot_infos(v.slots(), |id| v.slot_label(id).unwrap_or("").to_owned())
    }

    /// Every item, sorted by title. Items that fail to decode are skipped.
    pub fn items(&self) -> Vec<ItemSummary> {
        let v = self.lock();
        let mut out: Vec<ItemSummary> = v
            .item_ids()
            .filter_map(|id| Self::read(&v, id).ok().map(|i| summary(id, &i)))
            .collect();
        out.sort_by_cached_key(|s| (s.title.to_lowercase(), s.id.clone()));
        out
    }

    /// One item in full.
    pub fn item(&self, id: String) -> R<ItemDetail> {
        let id = item_id(&id)?;
        let v = self.lock();
        Ok(detail(&id, &Self::read(&v, &id)?))
    }

    /// Create (`id` = None) or update an item; returns its ID. Call
    /// [`Self::to_bytes`] and save the file afterwards.
    pub fn save_item(&self, id: Option<String>, edit: ItemEdit) -> R<String> {
        let mut v = self.lock();
        let (id, mut item) = match id {
            Some(s) => {
                let id = item_id(&s)?;
                let item = Self::read(&v, &id)?;
                (id, item)
            }
            None => (v.new_item_id(&mut OsRandom)?, ItemData::default()),
        };
        apply(&mut item, edit, now())?;
        v.put_item(&mut OsRandom, &id, &item.to_bytes())?;
        Ok(hex(&id))
    }

    /// Delete an item. Synced devices delete it too at their next merge.
    pub fn delete_item(&self, id: String) -> R<()> {
        let id = item_id(&id)?;
        self.lock().remove_item(&id)?;
        Ok(())
    }

    /// The item's current one-time code, if it has a seed.
    pub fn totp(&self, id: String, now: u64) -> R<Option<TotpCode>> {
        let id = item_id(&id)?;
        let v = self.lock();
        let item = Self::read(&v, &id)?;
        item.totp.as_ref().map(|c| code(c, now)).transpose()
    }

    /// Logins that may be filled on `page`: a URL or domain the platform's
    /// autofill API reported for the page (never one taken from page
    /// content). Uses the same origin policy as the browser extension.
    pub fn logins_for(&self, page: String) -> Vec<ItemSummary> {
        let page = page.trim();
        let page = if page.contains("://") {
            page.to_owned()
        } else {
            format!("https://{page}")
        };
        let v = self.lock();
        let mut out: Vec<ItemSummary> = v
            .item_ids()
            .filter_map(|id| {
                let item = Self::read(&v, id).ok()?;
                (item.kind == ItemKind::Login
                    && item.urls.iter().any(|u| origin::may_fill(u, &page)))
                .then(|| summary(id, &item))
            })
            .collect();
        out.sort_by_cached_key(|s| s.title.to_lowercase());
        out
    }

    /// The encrypted file to write to storage (and to the sync folder).
    pub fn to_bytes(&self) -> R<Vec<u8>> {
        Ok(self.lock().to_bytes(&mut OsRandom)?)
    }

    /// Wrap the vault key under `wrap` (32 random bytes the app keeps in the
    /// Keychain or Android Keystore behind a biometric check) for
    /// [`LockedVault::resume`]. The result may be stored in app storage.
    pub fn park(&self, wrap: Vec<u8>) -> R<Vec<u8>> {
        let wrap = Zeroizing::new(wrap);
        let parked = self.lock().park(&wrap_key(&wrap)?, &mut OsRandom)?;
        Ok(parked.to_bytes())
    }

    /// Merge a copy read from the sync folder (format.md 5.1). When the copy
    /// was re-keyed on another device, pass the master password to open it;
    /// without one this fails with [`MobileError::Rekeyed`].
    pub fn merge(&self, bytes: Vec<u8>, password: Option<String>) -> R<MergeOutcome> {
        let password = password.map(Zeroizing::new);
        let parsed = ParsedVault::parse(&bytes)?;
        let mut v = self.lock();
        let theirs = match parsed.open_with(&v) {
            Ok(t) => t,
            Err(vault_core::Error::DifferentKey) => {
                let Some(pw) = password.as_ref() else {
                    return Err(MobileError::Rekeyed);
                };
                let cred = Unlock::Password {
                    password: pw,
                    hw_key: None,
                };
                parsed
                    .slots()
                    .filter(|m| m.factor == Factor::PasswordOnly)
                    .find_map(|m| parsed.unlock(&m.id, &cred).ok())
                    .ok_or(MobileError::WrongCredential)?
            }
            Err(e) => return Err(e.into()),
        };
        let r = v.merge(&mut OsRandom, &theirs, &ItemMerge)?;
        Ok(MergeOutcome {
            changed: r.changed(),
            other_behind: r.other_behind,
            conflicts: r.conflicts as u32,
            rekeyed: r.rekeyed,
        })
    }
}
