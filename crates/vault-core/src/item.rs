//! Item data model (`docs/items.md`). Stored as the opaque item payload of a
//! vault record, encoded with postcard.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::origin::MatchMode;
use crate::totp::TotpConfig;

/// Version tags of the item payload, so the schema can evolve independently
/// of the file format. Schema 2 added [`ItemData::key`]; schema 1 items are
/// still read.
const ITEM_SCHEMA_V1: u8 = 1;
const ITEM_SCHEMA_V2: u8 = 2;

/// One stored credential or note. Zeroized on drop.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ItemData {
    /// Display name.
    pub title: String,
    /// Account name.
    pub username: String,
    /// Password.
    pub password: String,
    /// Sites this login may be filled on.
    pub urls: Vec<UrlEntry>,
    /// TOTP seed and parameters, if any.
    pub totp: Option<TotpConfig>,
    /// Free-form notes.
    pub notes: String,
    /// Seconds since the Unix epoch.
    pub created: u64,
    /// Seconds since the Unix epoch.
    pub modified: u64,
    /// A private key the daemon uses on the user's behalf. Set only through
    /// the daemon's key requests, never returned to clients.
    pub key: Option<KeyData>,
}

/// A private key held in the vault. Stored unencrypted inside the item: the
/// vault's own encryption protects it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Zeroize)]
pub enum KeyData {
    /// An SSH key, in OpenSSH private key format without a passphrase.
    Ssh {
        /// The `-----BEGIN OPENSSH PRIVATE KEY-----` text.
        openssh: String,
        /// Ask the user before each use.
        confirm: bool,
    },
    /// An OpenPGP transferable secret key, binary, without a passphrase.
    OpenPgp {
        /// The secret key packets.
        tsk: Vec<u8>,
        /// Ask the user before each signature or decryption.
        confirm: bool,
    },
}

impl KeyData {
    /// Whether each use needs the user's approval.
    pub fn confirm(&self) -> bool {
        match self {
            KeyData::Ssh { confirm, .. } | KeyData::OpenPgp { confirm, .. } => *confirm,
        }
    }

    /// Change whether each use needs the user's approval.
    pub fn set_confirm(&mut self, on: bool) {
        match self {
            KeyData::Ssh { confirm, .. } | KeyData::OpenPgp { confirm, .. } => *confirm = on,
        }
    }
}

/// Schema 1 layout, for reading items written before keys existed.
#[derive(Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
struct ItemDataV1 {
    title: String,
    username: String,
    password: String,
    urls: Vec<UrlEntry>,
    totp: Option<TotpConfig>,
    notes: String,
    created: u64,
    modified: u64,
}

impl ItemDataV1 {
    fn upgrade(mut self) -> ItemData {
        ItemData {
            title: std::mem::take(&mut self.title),
            username: std::mem::take(&mut self.username),
            password: std::mem::take(&mut self.password),
            urls: std::mem::take(&mut self.urls),
            totp: self.totp.take(),
            notes: std::mem::take(&mut self.notes),
            created: self.created,
            modified: self.modified,
            key: None,
        }
    }
}

/// A URL an item is bound to, with its matching mode.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct UrlEntry {
    /// URL as entered; matched by origin, path ignored.
    pub url: String,
    /// How strictly to match.
    #[zeroize(skip)]
    pub mode: MatchMode,
    /// Permit filling over plain `http` for this entry (off by default).
    pub allow_http: bool,
}

impl ItemData {
    /// Encode for [`crate::Vault::put_item`].
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut out = zeroize::Zeroizing::new(vec![ITEM_SCHEMA_V2]);
        out.extend_from_slice(&crate::format::encode(self));
        out
    }

    /// Decode bytes from [`crate::Vault::get_item`].
    pub fn from_bytes(bytes: &[u8]) -> Result<ItemData, Error> {
        match bytes.split_first() {
            Some((&ITEM_SCHEMA_V2, rest)) => {
                crate::format::decode_canonical(rest).map_err(|_| Error::CorruptItem)
            }
            Some((&ITEM_SCHEMA_V1, rest)) => crate::format::decode_canonical::<ItemDataV1>(rest)
                .map(ItemDataV1::upgrade)
                .map_err(|_| Error::CorruptItem),
            _ => Err(Error::CorruptItem),
        }
    }
}
