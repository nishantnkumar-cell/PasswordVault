//! Merging two copies of one vault (section 5.1).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;
use crate::clock::{Clock, Order};
use crate::crypto;
use crate::format::{self, MAX_SLOTS, SlotId};
use crate::rng::{self, SecureRandom};
use crate::secret::Key;
use crate::vault::{ItemId, ItemRecord, Vault, item_data_aad, item_key_aad, to_key};

/// What the caller knows about item data, which this crate treats as opaque.
pub trait Resolve {
    /// When two devices edited an item at the same time, the edit with the
    /// higher rank wins (ties go to the larger SHA-256 of the data). Usually
    /// the item's modified time.
    fn rank(&self, data: &[u8]) -> i64;
    /// The data for a new item that keeps the losing edit, such as the same
    /// item with " (conflict)" after its title. Must depend only on `data`,
    /// so every device makes the same copy.
    fn conflict_copy(&self, data: &[u8]) -> Zeroizing<Vec<u8>>;
}

/// What a merge changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MergeReport {
    /// Items that only the other copy had.
    pub added: usize,
    /// Items the other copy had a later edit of.
    pub updated: usize,
    /// Items the other copy deleted.
    pub deleted: usize,
    /// Items edited on both sides; the losing edit was kept as a new item.
    pub conflicts: usize,
    /// Slots enrolled on the other copy.
    pub slots_added: usize,
    /// Slots removed on the other copy.
    pub slots_removed: usize,
    /// The other copy's vault key was rotated more recently, so this copy
    /// took that key and its slots.
    pub rekeyed: bool,
    /// Slots this copy lost by taking the other key. Their factors must be
    /// enrolled again.
    pub slots_dropped: Vec<SlotId>,
    /// The other copy lacks something this one has and should be rewritten.
    pub other_behind: bool,
}

impl MergeReport {
    /// Whether this copy changed and should be written.
    pub fn changed(&self) -> bool {
        self.added + self.updated + self.deleted + self.conflicts > 0
            || self.slots_added + self.slots_removed > 0
            || self.rekeyed
    }
}

/// The ID of the copy that keeps a losing edit. Derived from what was lost,
/// so devices that resolve the same conflict make the same item.
fn conflict_id(id: &ItemId, clock: &Clock, data: &[u8]) -> ItemId {
    let d = Sha256::new()
        .chain_update(b"vault/conflict-id/v1")
        .chain_update(id)
        .chain_update(format::encode(clock))
        .chain_update(Sha256::digest(data))
        .finalize();
    d[..16].try_into().unwrap()
}

/// Orders two different vault keys: the later rotation wins, and between two
/// rotations of the same epoch a keyed hash decides, the same way on every
/// device.
fn key_order(v: &Vault) -> (u64, [u8; 32]) {
    let tag = crypto::hmac(&v.vault_key, &[b"vault/key-order/v1", &v.vault_id]);
    (v.key_epoch, tag)
}

/// Everything a merge compares, to tell whether a copy is behind.
#[derive(PartialEq, Eq)]
struct Shape {
    items: Vec<(ItemId, Clock)>,
    tombstones: Vec<(ItemId, Clock)>,
    removed_slots: Vec<SlotId>,
    slots: Vec<SlotId>,
    labels: Vec<(SlotId, String)>,
    key_epoch: u64,
}

impl Vault {
    fn clock(&self, id: &ItemId) -> Clock {
        self.clocks.get(id).cloned().unwrap_or_default()
    }

    fn shape(&self) -> Shape {
        let mut items: Vec<_> = self
            .items
            .iter()
            .map(|r| (r.item_id, self.clock(&r.item_id)))
            .collect();
        items.sort_unstable_by_key(|(id, _)| *id);
        let mut slots: Vec<_> = self.slots.iter().map(|s| s.meta.id).collect();
        slots.sort_unstable();
        let mut labels = self.slot_labels.clone();
        labels.sort_unstable();
        Shape {
            items,
            tombstones: self
                .tombstones
                .iter()
                .map(|(i, c)| (*i, c.clone()))
                .collect(),
            removed_slots: self.removed_slots.clone(),
            slots,
            labels,
            key_epoch: self.key_epoch,
        }
    }

    /// Wrap an item key under this vault's key.
    fn wrap_item_key(
        &self,
        rng: &mut dyn SecureRandom,
        key: &Key,
        rec: &mut ItemRecord,
    ) -> Result<(), Error> {
        let s = crypto::seal(
            rng,
            &self.vault_key,
            &item_key_aad(&self.vault_id, &rec.item_id),
            key.as_bytes(),
        )?;
        rec.key_nonce = s.nonce;
        rec.key_commit = s.commit;
        rec.wrapped_item_key = s.ciphertext.try_into().map_err(|_| Error::Malformed)?;
        Ok(())
    }

    /// The other copy's record, readable with this copy's key.
    fn import(
        &self,
        rng: &mut dyn SecureRandom,
        other: &Vault,
        rec: &ItemRecord,
    ) -> Result<ItemRecord, Error> {
        let mut rec = rec.clone();
        if !self.vault_key.ct_eq(&other.vault_key) {
            let key = other.unwrap_item_key(&rec)?;
            self.wrap_item_key(rng, &key, &mut rec)?;
        }
        Ok(rec)
    }

    /// Add the copy that keeps a losing edit, unless it is already here or
    /// was deleted since.
    fn add_conflict_copy(
        &mut self,
        rng: &mut dyn SecureRandom,
        id: ItemId,
        data: &[u8],
        clock: &Clock,
    ) -> Result<bool, Error> {
        if self.items.iter().any(|r| r.item_id == id)
            || self.tombstones.get(&id).is_some_and(|t| clock.le(t))
        {
            return Ok(false);
        }
        let key = Key::from_bytes(rng::array(rng)?);
        let sealed = crypto::seal(rng, &key, &item_data_aad(&self.vault_id, &id, 1), data)?;
        let mut rec = ItemRecord {
            item_id: id,
            version: 1,
            key_nonce: [0; 24],
            key_commit: [0; 32],
            wrapped_item_key: [0; 48],
            data_nonce: sealed.nonce,
            data_commit: sealed.commit,
            data_ciphertext: sealed.ciphertext,
        };
        self.wrap_item_key(rng, &key, &mut rec)?;
        self.items.push(rec);
        self.clocks.insert(id, clock.clone());
        Ok(true)
    }

    /// Take the other copy's vault key and slots, re-wrapping every item key.
    fn adopt_key(
        &mut self,
        rng: &mut dyn SecureRandom,
        other: &Vault,
        report: &mut MergeReport,
    ) -> Result<(), Error> {
        let mut items = Vec::with_capacity(self.items.len());
        for rec in &self.items {
            let key = self.unwrap_item_key(rec)?;
            let mut rec = rec.clone();
            // Wrap under the new key: other shares this vault ID.
            other.wrap_item_key(rng, &key, &mut rec)?;
            items.push(rec);
        }
        report.slots_dropped = self
            .slots
            .iter()
            .map(|s| s.meta.id)
            .filter(|id| !other.slots.iter().any(|s| &s.meta.id == id))
            .collect();
        let mut labels: Vec<_> = other.slot_labels.clone();
        for (id, l) in &self.slot_labels {
            if other.slots.iter().any(|s| &s.meta.id == id) && !labels.iter().any(|(i, _)| i == id)
            {
                labels.push((*id, l.clone()));
            }
        }
        self.items = items;
        self.slots = other.slots.clone();
        self.slot_labels = labels;
        self.vault_key = to_key(other.vault_key.as_bytes()).ok_or(Error::Malformed)?;
        report.rekeyed = true;
        Ok(())
    }

    fn merge_slots(
        &mut self,
        other: &Vault,
        import: bool,
        report: &mut MergeReport,
    ) -> Result<(), Error> {
        self.note_removed(&other.removed_slots);
        let removed = |id: &SlotId| self.removed_slots.binary_search(id).is_ok();
        let new: Vec<_> = if import {
            other
                .slots
                .iter()
                .filter(|s| {
                    !removed(&s.meta.id) && !self.slots.iter().any(|m| m.meta.id == s.meta.id)
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        // Two devices may each have removed a different last daily-use slot.
        let daily_left = self
            .slots
            .iter()
            .chain(&new)
            .any(|s| s.meta.factor.is_daily_use() && !removed(&s.meta.id));
        let before = self.slots.len();
        let keep: Vec<_> = self
            .slots
            .iter()
            .filter(|s| !removed(&s.meta.id) || (!daily_left && s.meta.factor.is_daily_use()))
            .cloned()
            .collect();
        if keep.len() + new.len() > MAX_SLOTS {
            return Err(Error::TooManySlots);
        }
        report.slots_removed = before - keep.len();
        report.slots_added = new.len();
        self.slots = keep;
        self.slots.extend(new);
        let slots = &self.slots;
        let mut labels: Vec<_> = self
            .slot_labels
            .iter()
            .filter(|(id, _)| slots.iter().any(|s| &s.meta.id == id))
            .cloned()
            .collect();
        for (id, l) in &other.slot_labels {
            if slots.iter().any(|s| &s.meta.id == id) && !labels.iter().any(|(i, _)| i == id) {
                labels.push((*id, l.clone()));
            }
        }
        self.slot_labels = labels;
        Ok(())
    }

    /// Merge another copy of this vault into this one, as when two devices
    /// edited copies of a synced file (section 5.1). Merging is commutative
    /// and idempotent: two devices that merge each other's copies hold the
    /// same items. Write this vault afterwards if [`MergeReport::changed`],
    /// and write it over the other copy if [`MergeReport::other_behind`].
    ///
    /// Open `other` with [`crate::ParsedVault::open_with`], or, when that
    /// fails with [`Error::DifferentKey`], by unlocking it. On error, this
    /// vault may hold part of the merge, which is still a valid state.
    pub fn merge(
        &mut self,
        rng: &mut dyn SecureRandom,
        other: &Vault,
        resolve: &dyn Resolve,
    ) -> Result<MergeReport, Error> {
        if self.vault_id != other.vault_id {
            return Err(Error::DifferentVault);
        }
        let mut report = MergeReport::default();
        if !self.vault_key.ct_eq(&other.vault_key) && key_order(other) > key_order(self) {
            self.adopt_key(rng, other, &mut report)?;
        }
        let same_key = self.vault_key.ct_eq(&other.vault_key);
        self.merge_slots(other, same_key, &mut report)?;

        for (id, t) in &other.tombstones {
            let joined = match self.tombstones.get(id) {
                Some(mine) => mine.join(t),
                None => t.clone(),
            };
            self.tombstones.insert(*id, joined);
        }

        for rec in &other.items {
            let id = rec.item_id;
            let theirs = other.clock(&id);
            let Some(i) = self.items.iter().position(|r| r.item_id == id) else {
                if !self.tombstones.get(&id).is_some_and(|t| theirs.le(t)) {
                    let rec = self.import(rng, other, rec)?;
                    self.items.push(rec);
                    self.clocks.insert(id, theirs);
                    report.added += 1;
                }
                continue;
            };
            let mine = self.clock(&id);
            match mine.compare(&theirs) {
                Order::Equal | Order::After => {}
                Order::Before => {
                    self.items[i] = self.import(rng, other, rec)?;
                    self.clocks.insert(id, theirs);
                    report.updated += 1;
                }
                Order::Concurrent => {
                    let a = self.get_item(&id)?;
                    let b = other.get_item(&id)?;
                    if *a != *b {
                        let rank = |d: &[u8]| (resolve.rank(d), Sha256::digest(d));
                        let theirs_win = rank(&b) > rank(&a);
                        let (lost, lost_clock) = if theirs_win {
                            (&a, &mine)
                        } else {
                            (&b, &theirs)
                        };
                        let copy = resolve.conflict_copy(lost);
                        let copy_id = conflict_id(&id, lost_clock, lost);
                        if theirs_win {
                            self.items[i] = self.import(rng, other, rec)?;
                            report.updated += 1;
                        }
                        if self.add_conflict_copy(rng, copy_id, &copy, lost_clock)? {
                            report.conflicts += 1;
                        }
                    }
                    self.clocks.insert(id, mine.join(&theirs));
                }
            }
        }

        let deleted: Vec<ItemId> = self
            .items
            .iter()
            .map(|r| r.item_id)
            .filter(|id| {
                self.tombstones
                    .get(id)
                    .is_some_and(|t| self.clock(id).le(t))
            })
            .collect();
        for id in &deleted {
            self.items.retain(|r| &r.item_id != id);
            self.clocks.remove(id);
        }
        report.deleted = deleted.len();

        self.generation = self.generation.max(other.generation);
        self.key_epoch = self.key_epoch.max(other.key_epoch);
        report.other_behind =
            !self.vault_key.ct_eq(&other.vault_key) || self.shape() != other.shape();
        Ok(report)
    }
}
