//! Shared collections (format.md 3.2 and 5.3): a small vault of its own whose
//! key is wrapped for each member with X-Wing, and whose member list is
//! signed by the person who made it. Only that owner can add or remove
//! members; every reader checks the signature against the header.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::format::{self, Factor, KeyslotMeta, MAX_SLOTS, ParsedVault, SlotId};
use crate::identity::{Identity, PublicIdentity};
use crate::rng::{self, SecureRandom};
use crate::secret::Key;
use crate::vault::{Unlock, Vault, recipient_kek, wrap_slot};
use crate::xwing;

/// The setting that holds the signed member list.
pub const COLLECTION_SETTING: &str = "collection";
/// Prefix of the settings that hold each member's public identity, followed
/// by the first 16 bytes of the fingerprint in lowercase hex.
pub const MEMBER_SETTING_PREFIX: &str = "member/";
/// Most members, owner included.
pub const MAX_MEMBERS: usize = 16;
const MAX_NAME: usize = 64;
const SIGN_CONTEXT: &[u8] = b"secret-vault/collection/v1";

/// What the owner signs.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Signed {
    vault_id: [u8; 16],
    /// Fingerprint of the vault key this list is for (only key holders can
    /// compute it), so a list cannot be moved to a rotated key.
    key: [u8; 32],
    epoch: u64,
    name: String,
    owner: [u8; 32],
    /// (fingerprint, display name), owner first.
    members: Vec<([u8; 32], String)>,
    /// The header's slots, exactly: (slot id, member fingerprint).
    slots: Vec<(SlotId, [u8; 32])>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    signed: Signed,
    signature: Vec<u8>,
}

/// A member of a shared collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Display name, as the owner entered it.
    pub name: String,
    /// The member's public identity.
    pub identity: PublicIdentity,
}

/// A verified shared collection's details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    /// The collection's name.
    pub name: String,
    /// Fingerprint of the owner's identity. Readers compare it with the one
    /// they pinned when they joined.
    pub owner: [u8; 32],
    /// Every member, owner first.
    pub members: Vec<Member>,
    /// +1 on every change of the member list.
    pub epoch: u64,
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn member_setting(fp: &[u8; 32]) -> String {
    format!("{MEMBER_SETTING_PREFIX}{}", hex(&fp[..16]))
}

fn check_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() || name.len() > MAX_NAME {
        Err(Error::BadSetting)
    } else {
        Ok(())
    }
}

impl ParsedVault {
    /// Whether this file is a shared collection with a slot for `fp`.
    pub fn has_member(&self, fp: &[u8; 32]) -> bool {
        self.slots()
            .any(|s| matches!(&s.factor, Factor::RecipientHybrid { member, .. } if member == fp))
    }

    /// Open a shared collection with a member's identity. The caller then
    /// checks [`Vault::collection`] and that its owner is the one it pinned.
    pub fn unlock_member(&self, identity: &Identity) -> Result<Vault, Error> {
        let fp = identity.public().fingerprint();
        let id = self
            .slots()
            .find(|s| matches!(&s.factor, Factor::RecipientHybrid { member, .. } if *member == fp))
            .map(|s| s.id)
            .ok_or(Error::NotFound)?;
        self.unlock(&id, &Unlock::Member { identity })
    }
}

impl Vault {
    /// A new shared collection with `owner` as its first member.
    pub fn new_collection(
        rng: &mut dyn SecureRandom,
        owner: &Identity,
        owner_name: &str,
        name: &str,
    ) -> Result<Vault, Error> {
        check_name(name)?;
        check_name(owner_name)?;
        let mut v = Vault::new(rng)?;
        let pk = owner.public();
        let fp = pk.fingerprint();
        v.push_member_slot(rng, &pk)?;
        v.set_setting(&member_setting(&fp), Some(&pk.to_bytes()))?;
        v.sign_members(owner, name, 1, vec![(fp, owner_name.to_owned())])?;
        Ok(v)
    }

    /// Whether this vault is a shared collection (it has a member list).
    pub fn is_collection(&self) -> bool {
        self.setting(COLLECTION_SETTING).is_some()
    }

    fn stored(&self) -> Result<Stored, Error> {
        let raw = self.setting(COLLECTION_SETTING).ok_or(Error::NotFound)?;
        format::decode_canonical(raw).map_err(|_| Error::MembershipNotSigned)
    }

    fn member_identity(&self, fp: &[u8; 32]) -> Result<PublicIdentity, Error> {
        let raw = self
            .setting(&member_setting(fp))
            .ok_or(Error::MembershipNotSigned)?;
        let pk = PublicIdentity::from_bytes(raw).map_err(|_| Error::MembershipNotSigned)?;
        if &pk.fingerprint() != fp {
            return Err(Error::MembershipNotSigned);
        }
        Ok(pk)
    }

    /// The verified member list. Fails with [`Error::MembershipNotSigned`]
    /// unless the owner signed exactly this vault key and these slots: a
    /// member who adds a slot for someone else, or rotates the key, is
    /// caught here.
    pub fn collection(&self) -> Result<Collection, Error> {
        let st = self.stored()?;
        let s = &st.signed;
        let owner = self.member_identity(&s.owner)?;
        if !owner.verify(SIGN_CONTEXT, &format::encode(s), &st.signature) {
            return Err(Error::MembershipNotSigned);
        }
        let ok = s.vault_id == self.vault_id
            && s.key == self.key_fingerprint(&self.vault_key)
            && s.members.first().map(|m| m.0) == Some(s.owner)
            && s.members.len() <= MAX_MEMBERS;
        if !ok {
            return Err(Error::MembershipNotSigned);
        }
        let header: BTreeSet<(SlotId, [u8; 32])> = self
            .slots
            .iter()
            .map(|sl| match &sl.meta.factor {
                Factor::RecipientHybrid { member, .. } => Ok((sl.meta.id, *member)),
                _ => Err(Error::MembershipNotSigned),
            })
            .collect::<Result<_, _>>()?;
        let signed: BTreeSet<_> = s.slots.iter().copied().collect();
        let fps: BTreeSet<_> = s.members.iter().map(|m| m.0).collect();
        if header != signed
            || header.len() != s.slots.len()
            || fps.len() != s.members.len()
            || header.iter().map(|x| x.1).collect::<BTreeSet<_>>() != fps
        {
            return Err(Error::MembershipNotSigned);
        }
        let members = s
            .members
            .iter()
            .map(|(fp, name)| {
                Ok(Member {
                    name: name.clone(),
                    identity: self.member_identity(fp)?,
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Collection {
            name: s.name.clone(),
            owner: s.owner,
            members,
            epoch: s.epoch,
        })
    }

    /// [`Vault::collection`], also requiring that `owner` (the fingerprint
    /// pinned when this device joined) signed it. Without the pin, a member
    /// could sign a member list of their own and claim to be the owner.
    pub fn collection_owned_by(&self, owner: &[u8; 32]) -> Result<Collection, Error> {
        let c = self.collection()?;
        if &c.owner != owner {
            return Err(Error::MembershipNotSigned);
        }
        Ok(c)
    }

    fn owner_check(&self, owner: &Identity) -> Result<Collection, Error> {
        let c = self.collection()?;
        if owner.public().fingerprint() != c.owner {
            return Err(Error::NotOwner);
        }
        Ok(c)
    }

    fn push_member_slot(
        &mut self,
        rng: &mut dyn SecureRandom,
        pk: &PublicIdentity,
    ) -> Result<SlotId, Error> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::TooManySlots);
        }
        pk.check()?;
        let (ct, ss) = xwing::encapsulate(&pk.kem, rng)?;
        let meta = KeyslotMeta {
            id: rng::array(rng)?,
            kdf: None,
            salt: rng::array(rng)?,
            factor: Factor::RecipientHybrid {
                member: pk.fingerprint(),
                encapsulated: ct,
            },
        };
        meta.validate()?;
        let kek = recipient_kek(&ss, &meta);
        let id = meta.id;
        let slot = wrap_slot(rng, &self.vault_id, &kek, meta, &self.vault_key)?;
        self.slots.push(slot);
        Ok(id)
    }

    fn sign_members(
        &mut self,
        owner: &Identity,
        name: &str,
        epoch: u64,
        members: Vec<([u8; 32], String)>,
    ) -> Result<(), Error> {
        let slots = self
            .slots
            .iter()
            .filter_map(|s| match &s.meta.factor {
                Factor::RecipientHybrid { member, .. } => Some((s.meta.id, *member)),
                _ => None,
            })
            .collect();
        let signed = Signed {
            vault_id: self.vault_id,
            key: self.key_fingerprint(&self.vault_key),
            epoch,
            name: name.to_owned(),
            owner: owner.public().fingerprint(),
            members,
            slots,
        };
        let signature = owner.sign(SIGN_CONTEXT, &format::encode(&signed))?;
        let value = format::encode(&Stored { signed, signature });
        self.set_setting(COLLECTION_SETTING, Some(&value))
    }

    fn signed_members(&self) -> Result<Vec<([u8; 32], String)>, Error> {
        Ok(self.stored()?.signed.members)
    }

    /// Add `identity` as a member named `name`. Only the owner can.
    pub fn add_member(
        &mut self,
        rng: &mut dyn SecureRandom,
        owner: &Identity,
        name: &str,
        identity: &PublicIdentity,
    ) -> Result<(), Error> {
        check_name(name)?;
        let c = self.owner_check(owner)?;
        identity.check()?;
        let fp = identity.fingerprint();
        let mut members = self.signed_members()?;
        if members.iter().any(|m| m.0 == fp) {
            return Err(Error::AlreadyMember);
        }
        if members.len() >= MAX_MEMBERS {
            return Err(Error::TooManySlots);
        }
        self.push_member_slot(rng, identity)?;
        self.set_setting(&member_setting(&fp), Some(&identity.to_bytes()))?;
        members.push((fp, name.to_owned()));
        self.sign_members(owner, &c.name, c.epoch + 1, members)
    }

    /// Remove a member and rotate the collection's key, so that the removed
    /// person cannot open anything written from now on (section 6.4). Only
    /// the owner can, and the owner cannot remove themselves.
    pub fn remove_member(
        &mut self,
        rng: &mut dyn SecureRandom,
        owner: &Identity,
        fp: &[u8; 32],
    ) -> Result<(), Error> {
        let c = self.owner_check(owner)?;
        if *fp == c.owner {
            return Err(Error::LastSlot);
        }
        let mut members = self.signed_members()?;
        let before = members.len();
        members.retain(|m| &m.0 != fp);
        if members.len() == before {
            return Err(Error::NotFound);
        }
        let new_key = Key::from_bytes(rng::array(rng)?);
        let items = self.rewrap_items(rng, &new_key)?;
        let old_slots: Vec<SlotId> = self.slots.iter().map(|s| s.meta.id).collect();
        self.retire_key();
        self.vault_key = new_key;
        self.items = items;
        self.slots.clear();
        for m in &c.members {
            if &m.identity.fingerprint() != fp {
                self.push_member_slot(rng, &m.identity)?;
            }
        }
        self.note_removed(&old_slots);
        self.key_epoch = self.key_epoch.saturating_add(1);
        self.set_setting(&member_setting(fp), None)?;
        self.sign_members(owner, &c.name, c.epoch + 1, members)
    }

    /// Rename the collection. Only the owner can.
    pub fn rename_collection(&mut self, owner: &Identity, name: &str) -> Result<(), Error> {
        check_name(name)?;
        let c = self.owner_check(owner)?;
        let members = self.signed_members()?;
        self.sign_members(owner, name, c.epoch + 1, members)
    }
}

/// Check that `slot` is still unwrapped by `identity`, for tests and
/// diagnostics.
#[cfg(test)]
pub(crate) fn opens(v: &Vault, identity: &Identity) -> bool {
    let fp = identity.public().fingerprint();
    v.slots.iter().any(|s| match &s.meta.factor {
        Factor::RecipientHybrid {
            member,
            encapsulated,
        } if *member == fp => identity
            .kem()
            .decapsulate(encapsulated)
            .map(|ss| {
                crate::vault::unwrap_slot(&v.vault_id, &recipient_kek(&ss, &s.meta), s).is_ok()
            })
            .unwrap_or(false),
        _ => false,
    })
}

#[cfg(test)]
impl Vault {
    pub(crate) fn push_member_slot_for_test(
        &mut self,
        rng: &mut dyn SecureRandom,
        pk: &PublicIdentity,
    ) {
        self.push_member_slot(rng, pk).unwrap();
    }

    pub(crate) fn sign_as_for_test(&mut self, who: &Identity) {
        let c = self.stored().unwrap().signed;
        let fp = who.public().fingerprint();
        self.set_setting(&member_setting(&fp), Some(&who.public().to_bytes()))
            .unwrap();
        let mut members = c.members.clone();
        members.retain(|m| m.0 != fp);
        members.insert(0, (fp, "Me".into()));
        self.sign_members(who, &c.name, c.epoch + 1, members)
            .unwrap();
    }
}
