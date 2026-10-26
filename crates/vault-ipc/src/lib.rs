//! Wire protocol between `vaultd` and its clients: length-prefixed postcard
//! frames over a Unix socket or a Windows named pipe. One request, one
//! response, per frame pair.

#![deny(unsafe_code)]

pub mod local;
#[cfg(windows)]
pub mod win;

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

pub use vault_core::item::{ItemData, ItemKind};
pub use vault_core::{ItemId, SlotId};

/// Largest frame accepted in either direction.
pub const MAX_FRAME: usize = 16 << 20;

/// Secret text that is zeroized when dropped.
pub type Secret = Zeroizing<String>;

/// Bytes that are zeroized when dropped.
pub type SecretBytes = Zeroizing<Vec<u8>>;

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
    /// Quick unlock: re-open a vault this daemon locked, after Windows Hello
    /// confirms the user. Works only while quick unlock is on and within its
    /// time limit since the last unlock with another method; never for
    /// pairing, revoking or a vault this daemon has not unlocked.
    Hello,
    /// A password + phone passkey slot (or any FIDO2 slot that checks the
    /// PIN). The client ran the passkey itself, with the slot's
    /// `PasskeySlot::prf_input`, and sends the credential the phone used and
    /// its 32-byte PRF output.
    Passkey {
        password: Secret,
        credential_id: Vec<u8>,
        prf_output: SecretBytes,
    },
}

/// A slot a phone passkey can open, as `Request::PasskeySlots` lists it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PasskeySlot {
    /// The passkey's credential ID.
    pub credential_id: Vec<u8>,
    /// Relying party ID the passkey was made for.
    pub rp_id: String,
    /// PRF input to ask the passkey for.
    pub prf_input: [u8; 32],
}

/// What a paired client may do.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientScope {
    /// Everything: the command-line client.
    Full,
    /// Status, unlock, lock, origin lookups, filling a matching login, TOTP
    /// for a matching login, filling cards and identities into https pages
    /// (cards only after the user confirms in vaultd's own window) and
    /// generation: the browser's native host.
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

/// Keys `GenerateKey` can make.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// SSH Ed25519.
    SshEd25519,
    /// SSH ECDSA on NIST P-256.
    SshEcdsaP256,
}

/// Requests a client can make.
// Items are large, but a request lives for one round trip; boxing buys nothing.
#[allow(clippy::large_enum_variant)]
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
    /// Pair this client. Returns a client token. With a `method`, by proving
    /// that factor; without one, the daemon asks the user in an approval
    /// window it opens itself, so a client cannot approve its own pairing.
    Pair {
        client_name: String,
        scope: ClientScope,
        method: Option<UnlockMethod>,
    },
    /// Unlock the vault.
    Unlock { method: UnlockMethod },
    /// Lock the vault and zeroize keys. With quick unlock on, the daemon
    /// keeps the vault key wrapped in memory so Windows Hello can re-open it.
    Lock,
    /// Lock the vault and also forget the quick unlock key, so the next
    /// unlock needs a full method.
    LockFully,
    /// Turn quick unlock with Windows Hello on for `hours` after each full
    /// unlock (1 to 24), or off with 0. Turning it on asks for Windows Hello
    /// once, so a client cannot enable it without the user.
    SetQuickUnlock { hours: u32 },
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
    /// Cards and identities that may be offered on `origin`: any `https`
    /// page, since they are not bound to sites. Summaries only.
    FormItems { origin: String },
    /// An identity's details for filling into a form on the `https` `origin`.
    IdentityForFill { id: ItemId, origin: String },
    /// A card's details for filling on the `https` `origin`. The daemon first
    /// asks the user to confirm in a window of its own, so a client cannot
    /// read cards without the user knowing.
    CardForFill { id: ItemId, origin: String },
    /// Current TOTP code for an item.
    Totp { id: ItemId },
    /// Generate a password.
    Generate { options: GenerateOptions },
    /// Import items from an export file's contents.
    Import { format: ImportFormat, data: Secret },
    /// Keep the vault in sync with a copy at `path`, usually in a folder
    /// that OneDrive, Google Drive or Dropbox syncs; `None` stops syncing.
    /// Needs no token while no vault exists here, so a new device can join
    /// a vault from its synced copy (then pair with `Pair` and a method).
    SetSync { path: Option<String> },
    /// Merge the synced copy now instead of at the next check.
    SyncNow,
    /// Generate a key inside the daemon and store it as a new item.
    GenerateKey {
        title: String,
        kind: KeyKind,
        confirm: bool,
    },
    /// Store an SSH private key (OpenSSH format) as a new item.
    /// `passphrase` decrypts it if it is encrypted.
    ImportSshKey {
        title: String,
        private: Secret,
        passphrase: Option<Secret>,
        confirm: bool,
    },
    /// The public half of an item's key, in its usual text form.
    PublicKey { id: ItemId },
    /// Whether each use of an item's key needs the user's approval.
    SetKeyConfirm { id: ItemId, confirm: bool },
    /// The private key in its usual text form, only after proving an unlock
    /// factor again.
    ExportKey { id: ItemId, method: UnlockMethod },
    /// Generate an OpenPGP key for `user_id` ("Name <mail@example.com>"):
    /// classic (v4 Ed25519/Curve25519) or post-quantum (v6 ML-DSA/ML-KEM).
    GeneratePgpKey {
        title: String,
        user_id: String,
        post_quantum: bool,
        confirm: bool,
    },
    /// Store an OpenPGP secret key (armored or binary) as a new item.
    ImportPgpKey {
        title: String,
        key: SecretBytes,
        passphrase: Option<Secret>,
        confirm: bool,
    },
    /// Detached signature over `data` with an item's OpenPGP key.
    PgpSign {
        id: ItemId,
        data: Vec<u8>,
        armor: bool,
        /// A text signature (gpg's `--textmode`): line endings (LF or
        /// CRLF) do not change whether it verifies. Mail needs this.
        text: bool,
    },
    /// Decrypt a message with whichever OpenPGP key in the vault it is for.
    PgpDecrypt { message: Vec<u8> },
    /// Encrypt to the keys of the listed items and to the given certificates
    /// (armored or binary), optionally signing with an item's key.
    PgpEncrypt {
        to_items: Vec<ItemId>,
        to_certs: Vec<Vec<u8>>,
        data: SecretBytes,
        armor: bool,
        sign_with: Option<ItemId>,
    },
    /// Check a detached signature against the vault's OpenPGP keys and the
    /// given certificates.
    PgpVerify {
        data: Vec<u8>,
        signature: Vec<u8>,
        certs: Vec<Vec<u8>>,
    },
    /// The slots a phone passkey can open (security key slots that check the
    /// PIN included: the two are the same kind of slot), so the client can
    /// run the passkey before `Unlock` or `Pair` with `UnlockMethod::Passkey`.
    /// Only public header data, so no token needed.
    PasskeySlots,
    /// Enroll a phone passkey the client just created: its credential ID, the
    /// random PRF input it was asked for, and the PRF output.
    AddPasskeySlot {
        password: Secret,
        credential_id: Vec<u8>,
        prf_input: [u8; 32],
        prf_output: SecretBytes,
        label: String,
    },
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

/// Item summary for listings: no password, card number or TOTP secret.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ItemSummary {
    /// Item ID.
    pub id: ItemId,
    /// What the item is.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// [`ItemData::subtitle`]: username, card network and last four digits,
    /// or identity name.
    pub subtitle: String,
    /// URLs.
    pub urls: Vec<String>,
    /// Whether a TOTP seed is stored.
    pub has_totp: bool,
    /// The item's key, if any: algorithm and fingerprint.
    pub key: Option<String>,
    /// Whether each use of the item's key needs the user's approval.
    pub key_confirm: bool,
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
    /// Folder sync, if it is on.
    pub sync: Option<SyncInfo>,
    /// Quick unlock with Windows Hello.
    pub quick_unlock: QuickUnlockInfo,
}

/// Quick unlock state.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct QuickUnlockInfo {
    /// This daemon can use Windows Hello.
    pub supported: bool,
    /// Hours quick unlock lasts after a full unlock; 0 means off.
    pub hours: u32,
    /// While the vault is locked: quick unlock can open it until this time
    /// (Unix seconds). `None` when it cannot.
    pub until: Option<u64>,
}

/// Folder sync state.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SyncInfo {
    /// The synced copy.
    pub path: String,
    /// When the copies were last merged (Unix seconds), if they were.
    pub last_sync: Option<u64>,
    /// Why the last attempt failed, if it did.
    pub error: Option<String>,
    /// Items edited on two devices at once since the daemon started; each
    /// losing edit was kept as a copy titled "(conflict)".
    pub conflicts: u64,
    /// Other copies next to the synced one (such as a cloud service's
    /// conflict copies) that were merged in and can be deleted.
    pub other_copies: Vec<String>,
}

/// Responses.
#[allow(clippy::large_enum_variant)]
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
    /// A public key.
    PublicKey(String),
    /// An exported private key.
    ExportedKey(Secret),
    /// Output that is not secret: a signature or ciphertext.
    Bytes(Vec<u8>),
    /// Decrypted data, and the title of the key that decrypted it.
    Decrypted { plaintext: SecretBytes, key: String },
    /// A good signature, by this key (fingerprint and user ID).
    Verified(String),
    /// Slots a phone passkey can open.
    PasskeySlots(Vec<PasskeySlot>),
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
