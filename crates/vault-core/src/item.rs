//! Item data model (`docs/items.md`). Stored as the opaque item payload of a
//! vault record, encoded with postcard.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;
use crate::origin::MatchMode;
use crate::totp::TotpConfig;

/// Version tag of the item payload, so the schema can evolve independently of
/// the file format.
const ITEM_SCHEMA_V1: u8 = 1;

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
        let mut out = zeroize::Zeroizing::new(vec![ITEM_SCHEMA_V1]);
        out.extend_from_slice(&crate::format::encode(self));
        out
    }

    /// Decode bytes from [`crate::Vault::get_item`].
    pub fn from_bytes(bytes: &[u8]) -> Result<ItemData, Error> {
        match bytes.split_first() {
            Some((&ITEM_SCHEMA_V1, rest)) => {
                crate::format::decode_canonical(rest).map_err(|_| Error::CorruptItem)
            }
            _ => Err(Error::CorruptItem),
        }
    }
}
