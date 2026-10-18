//! Unlocking, editing and writing a vault (sections 4 to 6).

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::Error;
use crate::crypto::{self, NONCE_LEN, OpenError, TAG_LEN};
use crate::format::{
    self, AEAD_XCHACHA20POLY1305, Argon2Params, FORMAT_VERSION, Factor, Header, KdfCost, Keyslot,
    KeyslotMeta, MAX_HEADER_LEN, MAX_SLOTS, ParsedVault, SealedBody, SlotId, arr48,
};
use crate::recovery::RecoveryCode;
use crate::rng::{self, SecureRandom};
use crate::secret::{HwKey, Key};

/// Random 16-byte item identifier.
pub type ItemId = [u8; 16];

/// A credential for one keyslot.
pub enum Unlock<'a> {
    /// For daily-use slots. `hw_key` must be `Some` exactly for FIDO2 and TPM slots.
    Password {
        /// The password as typed. It is normalized to NFC (section 4.1).
        password: &'a str,
        /// The hardware factor's secret, if the slot has one.
        hw_key: Option<&'a HwKey>,
    },
    /// For the recovery slot: the recovery code as typed.
    Recovery {
        /// Recovery code, with or without hyphens.
        code: &'a str,
    },
}

#[derive(Serialize, Deserialize)]
struct Body {
    generation: u64,
    slot_labels: Vec<(SlotId, String)>,
    items: Vec<ItemRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ItemRecord {
    pub(crate) item_id: ItemId,
    pub(crate) version: u64,
    pub(crate) key_nonce: [u8; NONCE_LEN],
    pub(crate) key_commit: [u8; 32],
    #[serde(with = "arr48")]
    pub(crate) wrapped_item_key: [u8; 48],
    pub(crate) data_nonce: [u8; NONCE_LEN],
    pub(crate) data_commit: [u8; 32],
    pub(crate) data_ciphertext: Vec<u8>,
}

/// An unlocked vault. Holds the vault key in memory until dropped.
pub struct Vault {
    vault_id: [u8; 16],
    vault_key: Key,
    slots: Vec<Keyslot>,
    generation: u64,
    slot_labels: Vec<(SlotId, String)>,
    pub(crate) items: Vec<ItemRecord>,
}

fn slot_aad(vault_id: &[u8; 16], meta: &KeyslotMeta) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"vault/slot-aad/v1");
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    aad.extend_from_slice(&format::encode(meta));
    aad
}

fn item_key_aad(vault_id: &[u8; 16], item_id: &ItemId) -> Vec<u8> {
    [b"vault/item-key/v1".as_slice(), vault_id, item_id].concat()
}

fn item_data_aad(vault_id: &[u8; 16], item_id: &ItemId, version: u64) -> Vec<u8> {
    [
        b"vault/item-data/v1".as_slice(),
        vault_id,
        item_id,
        &version.to_le_bytes(),
        &FORMAT_VERSION.to_le_bytes(),
    ]
    .concat()
}

fn header_key(vault_key: &Key, vault_id: &[u8; 16]) -> Key {
    crypto::hkdf(
        vault_key.as_bytes(),
        Some(vault_id),
        &[b"vault/header-mac/v1"],
    )
}

fn body_key(vault_key: &Key, vault_id: &[u8; 16]) -> Key {
    crypto::hkdf(vault_key.as_bytes(), Some(vault_id), &[b"vault/body/v1"])
}

fn body_aad(vault_id: &[u8; 16], header_mac: &[u8; 32]) -> Vec<u8> {
    [
        b"vault/body-aad/v1".as_slice(),
        vault_id,
        &FORMAT_VERSION.to_le_bytes(),
        header_mac,
    ]
    .concat()
}

/// Padded plaintext size: next 4 KiB up to 64 KiB, then next 64 KiB (section 5).
fn padded_len(len: usize) -> usize {
    let bucket = if len <= 64 * 1024 { 4096 } else { 64 * 1024 };
    len.div_ceil(bucket).max(1) * bucket
}

/// Derive a slot's KEK (section 4.3).
fn derive_kek(meta: &KeyslotMeta, cred: &Unlock<'_>) -> Result<Key, Error> {
    match (cred, &meta.factor) {
        (Unlock::Password { password, hw_key }, f) if f.is_daily_use() => {
            if f.needs_hw_key() != hw_key.is_some() {
                return Err(Error::FactorMismatch);
            }
            let kdf = meta.kdf.as_ref().ok_or(Error::Malformed)?;
            let normalized = Zeroizing::new(password.nfc().collect::<String>());
            let pw_key = crypto::argon2id(normalized.as_bytes(), kdf)?;
            let mut ikm = Zeroizing::new([0u8; 64]);
            ikm[..32].copy_from_slice(pw_key.as_bytes());
            if let Some(hw) = hw_key {
                ikm[32..].copy_from_slice(hw.as_bytes());
            }
            Ok(crypto::hkdf(
                ikm.as_ref(),
                Some(&meta.salt),
                &[b"vault/kek/v1", &meta.id],
            ))
        }
        (Unlock::Recovery { code }, Factor::Recovery) => {
            let secret = RecoveryCode::decode(code)?;
            Ok(recovery_kek(&secret, meta))
        }
        _ => Err(Error::FactorMismatch),
    }
}

fn recovery_kek(secret: &Key, meta: &KeyslotMeta) -> Key {
    crypto::hkdf(
        secret.as_bytes(),
        Some(&meta.salt),
        &[b"vault/kek-recovery/v1", &meta.id],
    )
}

fn wrap_slot(
    rng: &mut dyn SecureRandom,
    vault_id: &[u8; 16],
    kek: &Key,
    meta: KeyslotMeta,
    vault_key: &Key,
) -> Result<Keyslot, Error> {
    let sealed = crypto::seal(rng, kek, &slot_aad(vault_id, &meta), vault_key.as_bytes())?;
    Ok(Keyslot {
        meta,
        nonce: sealed.nonce,
        commit: sealed.commit,
        wrapped_vault_key: sealed.ciphertext.try_into().map_err(|_| Error::Malformed)?,
    })
}

fn unwrap_slot(vault_id: &[u8; 16], kek: &Key, slot: &Keyslot) -> Result<Key, Error> {
    let aad = slot_aad(vault_id, &slot.meta);
    let pt = crypto::open(
        kek,
        &slot.nonce,
        &slot.commit,
        &slot.wrapped_vault_key,
        &aad,
    )
    .map_err(|e| match e {
        OpenError::WrongKey => Error::WrongFactor,
        OpenError::Corrupt => Error::CorruptSlot,
    })?;
    to_key(&pt).ok_or(Error::CorruptSlot)
}

fn to_key(bytes: &[u8]) -> Option<Key> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Key::from_bytes(arr))
}

impl ParsedVault {
    /// Unlock with one slot's credential, then verify the header MAC and
    /// decrypt the body (sections 4.4, 4.5 and 5).
    pub fn unlock(&self, slot_id: &SlotId, cred: &Unlock<'_>) -> Result<Vault, Error> {
        let vault_id = self.header.vault_id;
        let slot = self
            .header
            .slots
            .iter()
            .find(|s| &s.meta.id == slot_id)
            .ok_or(Error::NotFound)?;
        if !slot.meta.factor.is_supported() {
            return Err(Error::FactorMismatch);
        }
        let kek = derive_kek(&slot.meta, cred)?;
        let vault_key = unwrap_slot(&vault_id, &kek, slot)?;

        if !crypto::hmac_verify(
            &header_key(&vault_key, &vault_id),
            &[&self.mac_input],
            &self.header_mac,
        ) {
            return Err(Error::HeaderTampered);
        }

        let plain = crypto::open(
            &body_key(&vault_key, &vault_id),
            &self.body.nonce,
            &self.body.commit,
            &self.body.ciphertext,
            &body_aad(&vault_id, &self.header_mac),
        )
        .map_err(|_| Error::CorruptBody)?;
        if plain.len() < 8 {
            return Err(Error::CorruptBody);
        }
        let len = u64::from_le_bytes(plain[..8].try_into().unwrap());
        let rest = &plain[8..];
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l <= rest.len())
            .ok_or(Error::CorruptBody)?;
        if rest[len..].iter().any(|&b| b != 0) || plain.len() != padded_len(8 + len) {
            return Err(Error::CorruptBody);
        }
        let body: Body = format::decode_canonical(&rest[..len]).map_err(|_| Error::CorruptBody)?;

        Ok(Vault {
            vault_id,
            vault_key,
            slots: self.header.slots.clone(),
            generation: body.generation,
            slot_labels: body.slot_labels,
            items: body.items,
        })
    }
}

impl Vault {
    /// A new, empty vault with a fresh vault ID and vault key. Add a daily-use
    /// slot and a backup slot before writing it (section 6.1).
    pub fn new(rng: &mut dyn SecureRandom) -> Result<Vault, Error> {
        Ok(Vault {
            vault_id: rng::array(rng)?,
            vault_key: Key::from_bytes(rng::array(rng)?),
            slots: Vec::new(),
            generation: 0,
            slot_labels: Vec::new(),
            items: Vec::new(),
        })
    }

    /// The vault's permanent identifier.
    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    /// Write counter, for rollback detection by the caller (section 6.6).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Public metadata of every keyslot.
    pub fn slots(&self) -> impl Iterator<Item = &KeyslotMeta> {
        self.slots.iter().map(|s| &s.meta)
    }

    /// The label stored for a slot, if any.
    pub fn slot_label(&self, id: &SlotId) -> Option<&str> {
        self.slot_labels
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, l)| l.as_str())
    }

    fn check_room(&self) -> Result<(), Error> {
        if self.slots.len() >= MAX_SLOTS {
            Err(Error::TooManySlots)
        } else {
            Ok(())
        }
    }

    /// Enroll a daily-use slot (section 6.2). For FIDO2 the caller generates
    /// `prf_input`, runs hmac-secret with the matching UV mode, and passes the
    /// output as `hw_key`. For TPM it passes the unsealed secret.
    pub fn add_password_slot(
        &mut self,
        rng: &mut dyn SecureRandom,
        factor: Factor,
        cost: KdfCost,
        password: &str,
        hw_key: Option<&HwKey>,
        label: &str,
    ) -> Result<SlotId, Error> {
        if !factor.is_daily_use() {
            return Err(Error::FactorMismatch);
        }
        self.check_room()?;
        let meta = KeyslotMeta {
            id: rng::array(rng)?,
            kdf: Some(Argon2Params {
                m_kib: cost.m_kib,
                t: cost.t,
                p: cost.p,
                salt: rng::array(rng)?,
            }),
            salt: rng::array(rng)?,
            factor,
        };
        meta.validate()?;
        let kek = derive_kek(&meta, &Unlock::Password { password, hw_key })?;
        self.push_slot(rng, kek, meta, label)
    }

    /// Enroll a recovery slot and return its code, to be shown once.
    pub fn add_recovery_slot(
        &mut self,
        rng: &mut dyn SecureRandom,
        label: &str,
    ) -> Result<(SlotId, RecoveryCode), Error> {
        self.check_room()?;
        let secret = Key::from_bytes(rng::array(rng)?);
        let meta = KeyslotMeta {
            id: rng::array(rng)?,
            kdf: None,
            salt: rng::array(rng)?,
            factor: Factor::Recovery,
        };
        let kek = recovery_kek(&secret, &meta);
        let id = self.push_slot(rng, kek, meta, label)?;
        Ok((id, RecoveryCode::encode(&secret)))
    }

    fn push_slot(
        &mut self,
        rng: &mut dyn SecureRandom,
        kek: Key,
        meta: KeyslotMeta,
        label: &str,
    ) -> Result<SlotId, Error> {
        let id = meta.id;
        let slot = wrap_slot(rng, &self.vault_id, &kek, meta, &self.vault_key)?;
        self.slots.push(slot);
        if !label.is_empty() {
            self.slot_labels.push((id, label.to_owned()));
        }
        Ok(id)
    }

    /// Remove a slot without rotating the vault key (section 6.3). Use
    /// [`Vault::revoke`] when the factor may be compromised.
    pub fn remove_slot(&mut self, id: &SlotId) -> Result<(), Error> {
        let pos = self
            .slots
            .iter()
            .position(|s| &s.meta.id == id)
            .ok_or(Error::NotFound)?;
        let daily_left = self
            .slots
            .iter()
            .enumerate()
            .filter(|(i, s)| *i != pos && s.meta.factor.is_daily_use())
            .count();
        if daily_left == 0 {
            return Err(Error::LastSlot);
        }
        self.slots.remove(pos);
        self.slot_labels.retain(|(i, _)| i != id);
        Ok(())
    }

    /// Revoke factors by rotating the vault key (section 6.4). Every slot in
    /// `keep` is re-wrapped under the new key, after proving its credential
    /// still unwraps the current key; every other slot is removed. Returns the
    /// removed slot IDs, for the caller to list for re-enrollment.
    pub fn revoke(
        &mut self,
        rng: &mut dyn SecureRandom,
        keep: &[(SlotId, Unlock<'_>)],
    ) -> Result<Vec<SlotId>, Error> {
        let new_key = Key::from_bytes(rng::array(rng)?);
        let mut kept = Vec::with_capacity(keep.len());
        for (id, cred) in keep {
            let slot = self
                .slots
                .iter()
                .find(|s| &s.meta.id == id)
                .ok_or(Error::NotFound)?;
            let kek = derive_kek(&slot.meta, cred)?;
            unwrap_slot(&self.vault_id, &kek, slot)?;
            kept.push(wrap_slot(
                rng,
                &self.vault_id,
                &kek,
                slot.meta.clone(),
                &new_key,
            )?);
        }
        if !kept.iter().any(|s| s.meta.factor.is_daily_use()) {
            return Err(Error::LastSlot);
        }

        let mut items = Vec::with_capacity(self.items.len());
        for rec in &self.items {
            let item_key = self.unwrap_item_key(rec)?;
            let sealed = crypto::seal(
                rng,
                &new_key,
                &item_key_aad(&self.vault_id, &rec.item_id),
                item_key.as_bytes(),
            )?;
            let mut rec = rec.clone();
            rec.key_nonce = sealed.nonce;
            rec.key_commit = sealed.commit;
            rec.wrapped_item_key = sealed.ciphertext.try_into().map_err(|_| Error::Malformed)?;
            items.push(rec);
        }

        let removed: Vec<SlotId> = self
            .slots
            .iter()
            .map(|s| s.meta.id)
            .filter(|id| !kept.iter().any(|k| &k.meta.id == id))
            .collect();
        self.slot_labels.retain(|(i, _)| !removed.contains(i));
        self.slots = kept;
        self.items = items;
        self.vault_key = new_key;
        Ok(removed)
    }

    /// A fresh random item ID.
    pub fn new_item_id(&self, rng: &mut dyn SecureRandom) -> Result<ItemId, Error> {
        rng::array(rng)
    }

    /// IDs of all items.
    pub fn item_ids(&self) -> impl Iterator<Item = &ItemId> {
        self.items.iter().map(|r| &r.item_id)
    }

    fn unwrap_item_key(&self, rec: &ItemRecord) -> Result<Key, Error> {
        let pt = crypto::open(
            &self.vault_key,
            &rec.key_nonce,
            &rec.key_commit,
            &rec.wrapped_item_key,
            &item_key_aad(&self.vault_id, &rec.item_id),
        )
        .map_err(|_| Error::CorruptItem)?;
        to_key(&pt).ok_or(Error::CorruptItem)
    }

    /// Insert or replace an item's data. The data is opaque to this crate; its
    /// structure is specified separately (`docs/items.md`).
    pub fn put_item(
        &mut self,
        rng: &mut dyn SecureRandom,
        id: &ItemId,
        data: &[u8],
    ) -> Result<(), Error> {
        let existing = self.items.iter().position(|r| &r.item_id == id);
        let (item_key, version, key_part) = match existing {
            Some(i) => {
                let rec = &self.items[i];
                let key = self.unwrap_item_key(rec)?;
                (
                    key,
                    rec.version + 1,
                    (rec.key_nonce, rec.key_commit, rec.wrapped_item_key),
                )
            }
            None => {
                let key = Key::from_bytes(rng::array(rng)?);
                let s = crypto::seal(
                    rng,
                    &self.vault_key,
                    &item_key_aad(&self.vault_id, id),
                    key.as_bytes(),
                )?;
                let wrapped: [u8; 48] = s.ciphertext.try_into().map_err(|_| Error::Malformed)?;
                (key, 1, (s.nonce, s.commit, wrapped))
            }
        };
        let data = crypto::seal(
            rng,
            &item_key,
            &item_data_aad(&self.vault_id, id, version),
            data,
        )?;
        let rec = ItemRecord {
            item_id: *id,
            version,
            key_nonce: key_part.0,
            key_commit: key_part.1,
            wrapped_item_key: key_part.2,
            data_nonce: data.nonce,
            data_commit: data.commit,
            data_ciphertext: data.ciphertext,
        };
        match existing {
            Some(i) => self.items[i] = rec,
            None => self.items.push(rec),
        }
        Ok(())
    }

    /// Decrypt an item's data.
    pub fn get_item(&self, id: &ItemId) -> Result<Zeroizing<Vec<u8>>, Error> {
        let rec = self
            .items
            .iter()
            .find(|r| &r.item_id == id)
            .ok_or(Error::NotFound)?;
        let key = self.unwrap_item_key(rec)?;
        crypto::open(
            &key,
            &rec.data_nonce,
            &rec.data_commit,
            &rec.data_ciphertext,
            &item_data_aad(&self.vault_id, id, rec.version),
        )
        .map_err(|_| Error::CorruptItem)
    }

    /// Delete an item.
    pub fn remove_item(&mut self, id: &ItemId) -> Result<(), Error> {
        let pos = self
            .items
            .iter()
            .position(|r| &r.item_id == id)
            .ok_or(Error::NotFound)?;
        self.items.remove(pos);
        Ok(())
    }

    /// Encode the vault as file bytes, incrementing the generation counter.
    /// The caller writes them atomically (section 6.5) and should then
    /// test-unlock any slot it just enrolled.
    pub fn to_bytes(&mut self, rng: &mut dyn SecureRandom) -> Result<Vec<u8>, Error> {
        if !self.slots.iter().any(|s| s.meta.factor.is_daily_use()) {
            return Err(Error::LastSlot);
        }
        self.generation = self.generation.checked_add(1).ok_or(Error::Malformed)?;

        let header = Header {
            vault_id: self.vault_id,
            aead: AEAD_XCHACHA20POLY1305,
            slots: self.slots.clone(),
        };
        let header_bytes = format::encode(&header);
        if header_bytes.len() > MAX_HEADER_LEN {
            return Err(Error::Malformed);
        }
        let prefix = format::prefix(header_bytes.len());
        let header_mac = crypto::hmac(
            &header_key(&self.vault_key, &self.vault_id),
            &[&prefix, &header_bytes],
        );

        let body = Body {
            generation: self.generation,
            slot_labels: self.slot_labels.clone(),
            items: self.items.clone(),
        };
        let encoded = Zeroizing::new(format::encode(&body));
        let mut plain = Zeroizing::new(vec![0u8; padded_len(8 + encoded.len())]);
        plain[..8].copy_from_slice(&(encoded.len() as u64).to_le_bytes());
        plain[8..8 + encoded.len()].copy_from_slice(&encoded);
        let sealed = crypto::seal(
            rng,
            &body_key(&self.vault_key, &self.vault_id),
            &body_aad(&self.vault_id, &header_mac),
            &plain,
        )?;
        let body_bytes = format::encode(&SealedBody {
            nonce: sealed.nonce,
            commit: sealed.commit,
            ciphertext: sealed.ciphertext,
        });
        Ok(format::assemble(&header_bytes, &header_mac, &body_bytes))
    }
}

const _: () = assert!(32 + TAG_LEN == 48);
