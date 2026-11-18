//! Shared collections (docs/sharing.md): small vaults of their own that a
//! family shares through cloud sync, opened with this person's sharing
//! identity next to their own vault.
//!
//! The person's own vault holds, in its settings, their sharing identity
//! ([`IDENTITY_SETTING`]) and the collections they belong to
//! ([`JOINED_SETTING`]), so every one of their devices opens the same ones.
//! Each collection lives in `shared/<id>/` next to the vault file:
//! `vault.svault` is this device's copy and `cloud/` is what `vault-sync`
//! mirrors to the collection's mailbox, exactly like the person's own
//! `cloud` folder.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vault_core::collection::Collection;
use vault_core::identity::{Identity, PublicIdentity};
use vault_core::item::ItemMerge;
use vault_core::{OsRandom, ParsedVault, Vault};
use vault_ipc::{CLOUD_COPY_FILE, CLOUD_DEVICE_FILE, CloudDevice, CollectionInfo, MemberInfo};

use crate::store::write_atomic;
use crate::sync::Folder;

type R<T> = Result<T, String>;

/// The person's own vault setting with their sharing identity.
pub const IDENTITY_SETTING: &str = "sharing-identity";
/// The person's own vault setting listing the collections they belong to.
pub const JOINED_SETTING: &str = "shared-collections";
/// Prefix of a sharing card.
pub const CARD_PREFIX: &str = "svcard1.";

#[derive(Serialize, Deserialize)]
pub struct IdentitySetting {
    pub seed: [u8; 32],
    pub name: String,
}

impl Drop for IdentitySetting {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

/// One collection this person belongs to, as kept in their own vault.
#[derive(Serialize, Deserialize, Clone)]
pub struct Joined {
    pub id: [u8; 16],
    /// The owner's identity fingerprint, pinned when joining.
    pub owner: [u8; 32],
    /// The collection's name when last opened, for listing it while it
    /// cannot be opened.
    pub name: String,
    /// This person's access to the collection's mailbox, shared by all of
    /// their devices.
    pub device: CloudDevice,
}

#[derive(Serialize, Deserialize)]
struct Card {
    name: String,
    identity: PublicIdentity,
}

/// A sharing card: the text a person sends to an owner to be added.
pub fn card(name: &str, identity: &PublicIdentity) -> String {
    let bytes = postcard::to_allocvec(&Card {
        name: name.to_owned(),
        identity: identity.clone(),
    })
    .expect("encoding to a Vec cannot fail");
    format!(
        "{CARD_PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&bytes)
    )
}

/// Read a sharing card: the name it suggests and the identity.
pub fn read_card(text: &str) -> R<(String, PublicIdentity)> {
    let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = t
        .strip_prefix(CARD_PREFIX)
        .ok_or("that is not a sharing card (it starts with svcard1.)")?;
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(body.as_bytes())
        .map_err(|_| "the sharing card is damaged; copy all of it again")?;
    let c: Card = postcard::from_bytes(&bytes)
        .map_err(|_| "the sharing card is damaged; copy all of it again")?;
    c.identity
        .check()
        .map_err(|_| "the sharing card is damaged; copy all of it again")?;
    Ok((c.name, c.identity))
}

pub fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

/// One open collection.
pub struct Open {
    pub joined: Joined,
    pub vault: Option<Vault>,
    pub folder: Folder,
    pub error: Option<String>,
    pub last_sync: Option<u64>,
    /// Write the local file and the cloud copy at the next save.
    pub dirty: bool,
}

/// Every collection this person belongs to, while their vault is unlocked.
pub struct Shared {
    root: PathBuf,
    pub open: BTreeMap<[u8; 16], Open>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mkdir(dir: &Path) -> R<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

impl Shared {
    /// `vault_dir` is the folder that holds the person's vault file.
    pub fn new(vault_dir: &Path) -> Shared {
        Shared {
            root: vault_dir.join("shared"),
            open: BTreeMap::new(),
        }
    }

    pub fn dir(&self, id: &[u8; 16]) -> PathBuf {
        self.root.join(hex(id))
    }

    fn local(&self, id: &[u8; 16]) -> PathBuf {
        self.dir(id).join("vault.svault")
    }

    fn cloud_copy(&self, id: &[u8; 16]) -> PathBuf {
        self.dir(id).join("cloud").join(CLOUD_COPY_FILE)
    }

    /// Open every collection in `joined` (the person's own vault's list).
    /// Collections no longer listed are closed and their folders removed.
    pub fn load(&mut self, joined: Vec<Joined>, me: &Identity) {
        let ids: Vec<[u8; 16]> = joined.iter().map(|j| j.id).collect();
        self.open.retain(|id, _| ids.contains(id));
        for j in joined {
            if let Some(o) = self.open.get_mut(&j.id) {
                o.joined = j;
                continue;
            }
            let id = j.id;
            let folder = Folder::new(self.cloud_copy(&id));
            let mut o = Open {
                joined: j,
                vault: None,
                folder,
                error: None,
                last_sync: None,
                dirty: false,
            };
            if let Err(m) = self.attach(&o.joined) {
                o.error = Some(m);
            }
            let local = std::fs::read(self.local(&id)).ok();
            match local {
                Some(bytes) => match open(&bytes, me, &o.joined) {
                    Ok(v) => o.vault = Some(v),
                    Err(m) => o.error = Some(m),
                },
                None => o.error = Some("waiting for the first copy from the server".into()),
            }
            self.open.insert(id, o);
        }
        // Folders of collections this person left.
        if let Ok(entries) = std::fs::read_dir(&self.root) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !ids.iter().any(|id| hex(id) == name) {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
    }

    /// Write the mailbox access for `vault-sync`.
    fn attach(&self, j: &Joined) -> R<()> {
        let cloud = self.dir(&j.id).join("cloud");
        mkdir(&cloud)?;
        write_atomic(
            &cloud.join(CLOUD_DEVICE_FILE),
            j.device.to_text().as_bytes(),
        )
        .map_err(|e| e.to_string())
    }

    /// Lay out a new collection's folder with its first copy.
    pub fn create(&mut self, j: Joined, v: Vault, bytes: &[u8]) -> R<()> {
        self.attach(&j)?;
        write_atomic(&self.local(&j.id), bytes).map_err(|e| e.to_string())?;
        let mut folder = Folder::new(self.cloud_copy(&j.id));
        folder.write(bytes).map_err(|e| e.to_string())?;
        self.open.insert(
            j.id,
            Open {
                joined: j,
                vault: Some(v),
                folder,
                error: None,
                last_sync: Some(now()),
                dirty: false,
            },
        );
        Ok(())
    }

    /// Take in what came from the server for every collection, then write
    /// what changed. Problems are kept per collection, never returned.
    pub fn sync(&mut self, me: &Identity, all: bool) {
        let ids: Vec<[u8; 16]> = self.open.keys().copied().collect();
        for id in ids {
            let local = self.local(&id);
            let Some(o) = self.open.get_mut(&id) else {
                continue;
            };
            let res = pull(o, me, all);
            match res {
                Ok(changed) => {
                    o.error = None;
                    o.dirty |= changed;
                }
                Err(m) => o.error = Some(m),
            }
            if o.dirty
                && let Some(v) = o.vault.as_mut()
            {
                match v.to_bytes(&mut OsRandom) {
                    Ok(bytes) => {
                        let r = write_atomic(&local, &bytes)
                            .map_err(|e| e.to_string())
                            .and_then(|()| o.folder.write(&bytes).map_err(|e| e.to_string()));
                        match r {
                            Ok(()) => o.dirty = false,
                            Err(m) => o.error = Some(format!("could not save: {m}")),
                        }
                    }
                    Err(e) => o.error = Some(e.to_string()),
                }
            }
        }
    }

    /// The collection holding item `id`, if any.
    pub fn holder(&self, id: &vault_core::ItemId) -> Option<[u8; 16]> {
        self.open
            .iter()
            .find(|(_, o)| {
                o.vault
                    .as_ref()
                    .is_some_and(|v| v.item_ids().any(|i| i == id))
            })
            .map(|(cid, _)| *cid)
    }

    pub fn vault_mut(&mut self, id: &[u8; 16]) -> R<&mut Vault> {
        let o = self.open.get_mut(id).ok_or("no such shared collection")?;
        match (&mut o.vault, &o.error) {
            (Some(v), _) => Ok(v),
            (None, Some(m)) => Err(format!("the shared collection cannot be opened: {m}")),
            (None, None) => Err("the shared collection is not open".into()),
        }
    }

    pub fn mark_dirty(&mut self, id: &[u8; 16]) {
        if let Some(o) = self.open.get_mut(id) {
            o.dirty = true;
        }
    }

    /// What `vault-sync` last said went wrong for this collection, if it
    /// said so in the last few minutes (for example that the owner removed
    /// this person, so the server no longer takes their access).
    fn helper_error(&self, id: &[u8; 16]) -> Option<String> {
        let text = std::fs::read_to_string(
            self.dir(id)
                .join("cloud")
                .join(vault_ipc::CLOUD_HELPER_FILE),
        )
        .ok()?;
        let h = vault_ipc::HelperStatus::from_text(&text)?;
        (now().saturating_sub(h.written) < 300)
            .then_some(h.error)
            .flatten()
    }

    pub fn info(&self, me: &[u8; 32]) -> Vec<CollectionInfo> {
        self.open
            .iter()
            .map(|(id, o)| {
                let c = o.vault.as_ref().and_then(|v| v.collection().ok());
                CollectionInfo {
                    id: *id,
                    name: c
                        .as_ref()
                        .map_or_else(|| o.joined.name.clone(), |c| c.name.clone()),
                    owner: &o.joined.owner == me,
                    members: c.as_ref().map(members).unwrap_or_default(),
                    items: o.vault.as_ref().map_or(0, |v| v.item_ids().count()),
                    device: Some(o.joined.device.clone()),
                    error: o.error.clone().or_else(|| self.helper_error(id)),
                    last_sync: o.last_sync,
                }
            })
            .collect()
    }
}

pub fn members(c: &Collection) -> Vec<MemberInfo> {
    c.members
        .iter()
        .map(|m| MemberInfo {
            name: m.name.clone(),
            fingerprint: m.identity.fingerprint(),
            safety: m.identity.safety_code(),
        })
        .collect()
}

/// Open a collection's file with this person's identity and check that its
/// pinned owner signed its member list.
pub fn open(bytes: &[u8], me: &Identity, j: &Joined) -> R<Vault> {
    let p = ParsedVault::parse(bytes).map_err(|e| e.to_string())?;
    if p.vault_id() != j.id {
        return Err("the copy is a different shared collection".into());
    }
    let v = p.unlock_member(me).map_err(|e| match e {
        vault_core::Error::NotFound => {
            "you are no longer a member of this shared collection".to_string()
        }
        e => e.to_string(),
    })?;
    v.collection_owned_by(&j.owner).map_err(|e| e.to_string())?;
    Ok(v)
}

/// Merge a changed server copy into `o`. Returns whether anything changed
/// that should be written.
fn pull(o: &mut Open, me: &Identity, all: bool) -> R<bool> {
    let mut write = !o.folder.exists() && o.vault.is_some();
    for c in o.folder.changed(all) {
        if !o.folder.is_main(&c.path) || c.too_big {
            o.folder.mark(c.path, c.stamp);
            continue;
        }
        let theirs = match open(&c.bytes, me, &o.joined) {
            Ok(t) => t,
            Err(m) => {
                o.folder.mark(c.path, c.stamp);
                return Err(m);
            }
        };
        match &mut o.vault {
            None => {
                o.vault = Some(theirs);
                write = true;
            }
            Some(v) => {
                let r = v.merge(&mut OsRandom, &theirs, &ItemMerge);
                match r {
                    Ok(r) => write |= r.changed() || r.other_behind,
                    Err(vault_core::Error::RetiredKey) => {}
                    Err(e) => return Err(e.to_string()),
                }
                // A merge never makes a list the owner did not sign valid,
                // but check what will be written all the same.
                v.collection_owned_by(&o.joined.owner)
                    .map_err(|e| e.to_string())?;
            }
        }
        o.folder.mark(c.path, c.stamp);
        o.last_sync = Some(now());
    }
    Ok(write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_round_trip() {
        let me = Identity::from_seed([5; 32]);
        let c = card("Sam Example", &me.public());
        let (name, pk) = read_card(&format!(" {c}\n")).unwrap();
        assert_eq!(name, "Sam Example");
        assert_eq!(pk, me.public());
        assert!(read_card("svcard1.AAAA").is_err());
        assert!(read_card("hello").is_err());
    }
}
