//! Wire protocol between `vaultd` and its clients: length-prefixed postcard
//! frames over a Unix socket. One request, one response, per frame pair.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

pub use vault_core::item::ItemData;
pub use vault_core::{ItemId, SlotId};

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 16 << 20;

/// Secret text that is zeroized when dropped.
pub type Secret = Zeroizing<String>;

/// Token a paired client presents with each request.
pub type ClientToken = Zeroizing<[u8; 32]>;

/// What a client sends.
#[derive(Serialize, Deserialize)]
pub struct Envelope {
    /// Present for every request except `Status`, `Init` and `Pair`.
    pub token: Option<ClientToken>,
    /// The request.
    pub request: Request,
}

/// How to unlock (or prove a factor for pairing and revocation).
#[derive(Serialize, Deserialize)]
pub enum UnlockMethod {
    /// A password-only slot.
    Password { password: Secret },
    /// A password + FIDO2 slot. `pin` is required for slots with `require_uv`.
    Fido2 {
        password: Secret,
        pin: Option<Secret>,
    },
    /// A password + TPM slot. `pin` is the TPM object's authValue, if set.
    Tpm {
        password: Secret,
        pin: Option<Secret>,
    },
    /// The recovery slot.
    Recovery { code: Secret },
}

/// What a paired client may do.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientScope {
    /// Everything: the command-line client.
    Full,
    /// Status, unlock, lock, origin lookups, filling a matching item, TOTP
    /// for a matching item and generation: the browser's native host.
    Autofill,
}

/// Character classes for `Generate`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct GenerateOptions {
    /// Length in characters.
    pub length: u16,
    /// Include symbols.
    pub symbols: bool,
    /// Drop look-alike characters.
    pub avoid_ambiguous: bool,
}

/// Formats accepted by `Import`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportFormat {
    /// Bitwarden unencrypted JSON export.
    BitwardenJson,
    /// Chrome / Edge / Firefox password CSV export.
    BrowserCsv,
}

/// Requests a client can make.
#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Daemon and vault state. No token needed.
    Status,
    /// Create a new vault with a password slot and a recovery slot. Only when
    /// no vault exists. Returns the recovery code and a client token.
    Init {
        password: Secret,
        client_name: String,
    },
    /// Pair this client by proving a factor. Returns a client token.
    Pair {
        client_name: String,
        scope: ClientScope,
        method: UnlockMethod,
    },
    /// Unlock the vault.
    Unlock { method: UnlockMethod },
    /// Lock the vault and zeroize keys.
    Lock,
    /// List keyslots.
    ListSlots,
    /// Enroll another password-only slot.
    AddPasswordSlot { password: Secret, label: String },
    /// Enroll a FIDO2 security key (touch required).
    AddFido2Slot {
        password: Secret,
        pin: Option<Secret>,
        require_uv: bool,
        label: String,
    },
    /// Enroll this machine's TPM.
    AddTpmSlot {
        password: Secret,
        pin: Option<Secret>,
        bind_pcr7: bool,
        label: String,
    },
    /// Enroll a new recovery slot; returns its code.
    AddRecoverySlot { label: String },
    /// Remove a slot without rotating keys.
    RemoveSlot { slot: SlotId },
    /// Rotate the vault key, keeping only the listed slots (each re-proved).
    Revoke { keep: Vec<(SlotId, UnlockMethod)> },
    /// Summaries of all items.
    ListItems,
    /// One item in full.
    GetItem { id: ItemId },
    /// Create (id = None) or replace an item.
    PutItem { id: Option<ItemId>, item: ItemData },
    /// Delete an item.
    DeleteItem { id: ItemId },
    /// Items that may be filled on this origin. The caller must take the
    /// origin from the browser, never from page content.
    FindForOrigin { origin: String },
    /// One item for filling, only if one of its URLs may be filled on `origin`.
    GetForFill { id: ItemId, origin: String },
    /// TOTP code for filling, only if the item may be filled on `origin`.
    TotpForFill { id: ItemId, origin: String },
    /// Current TOTP code for an item.
    Totp { id: ItemId },
    /// Generate a password.
    Generate { options: GenerateOptions },
    /// Import items from an export file's contents.
    Import { format: ImportFormat, data: Secret },
}

/// Public slot information.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlotInfo {
    /// Slot ID.
    pub id: SlotId,
    /// `password`, `fido2`, `tpm`, `recovery` or `reserved`.
    pub kind: String,
    /// User label.
    pub label: String,
}

/// Item summary for listings: no password, no TOTP secret.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ItemSummary {
    /// Item ID.
    pub id: ItemId,
    /// Title.
    pub title: String,
    /// Username.
    pub username: String,
    /// URLs.
    pub urls: Vec<String>,
    /// Whether a TOTP seed is stored.
    pub has_totp: bool,
}

/// Daemon state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StatusInfo {
    /// A vault file exists.
    pub initialized: bool,
    /// The vault is unlocked.
    pub unlocked: bool,
    /// Write counter of the unlocked vault.
    pub generation: Option<u64>,
    /// The file on disk is older than one seen before: writes are refused.
    pub rollback_detected: bool,
    /// Seconds until auto-lock.
    pub idle_lock_in: Option<u64>,
}

/// Responses.
#[derive(Serialize, Deserialize)]
pub enum Response {
    /// Success with nothing to return.
    Ok,
    /// Failure, with a message safe to show.
    Error(String),
    /// Daemon state.
    Status(StatusInfo),
    /// Vault created.
    Initialized {
        recovery_code: Secret,
        token: ClientToken,
    },
    /// Client paired.
    Paired { token: ClientToken },
    /// Keyslots.
    Slots(Vec<SlotInfo>),
    /// A slot was added; recovery slots also return their code.
    SlotAdded {
        id: SlotId,
        recovery_code: Option<Secret>,
    },
    /// Slots removed by a revoke.
    Revoked { removed: Vec<SlotId> },
    /// Item summaries.
    Items(Vec<ItemSummary>),
    /// One item.
    Item { id: ItemId, item: ItemData },
    /// ID of a created or replaced item.
    ItemSaved { id: ItemId },
    /// TOTP code.
    Totp { code: Secret, remaining: u64 },
    /// Generated password.
    Generated(Secret),
    /// Number of items imported.
    Imported(usize),
}

/// Write one frame: u32 little-endian length, then postcard bytes.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> io::Result<()> {
    let bytes = Zeroizing::new(postcard::to_allocvec(value).map_err(io::Error::other)?);
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

/// Read one frame written by [`write_frame`].
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    postcard::from_bytes(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Hex encoding for IDs in user-facing tools.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 16-byte ID from hex.
pub fn parse_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_oversize() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Envelope {
                token: None,
                request: Request::Status,
            },
        )
        .unwrap();
        let env: Envelope = read_frame(&mut buf.as_slice()).unwrap();
        assert!(matches!(env.request, Request::Status));

        let mut big = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        big.extend_from_slice(&[0; 8]);
        assert!(read_frame::<_, Envelope>(&mut big.as_slice()).is_err());
    }

    #[test]
    fn ids_round_trip_as_hex() {
        let id = [0xab; 16];
        assert_eq!(parse_id(&hex(&id)), Some(id));
        assert_eq!(parse_id("zz"), None);
    }
}
