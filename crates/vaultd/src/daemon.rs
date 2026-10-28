//! Request handling: authorization, unlock with rate limiting, the vault
//! operations, rollback refusal and idle lock.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vault_core::generator;
use vault_core::item::{ItemData, ItemKind, ItemMerge, KeyData};
use vault_core::origin::may_fill;
use vault_core::{
    Factor, HwKey, ItemId, KdfCost, KeyslotMeta, OsRandom, ParkedKey, ParsedVault, PcrPolicy,
    SecureRandom, SlotId, Unlock, Vault,
};
use vault_hw::protect::ProtectedKey;
use vault_ipc::{
    ClientScope, ClientToken, Envelope, ImportFormat, ItemSummary, PasskeySlot, PasswordStyle,
    QuickUnlockInfo, Request, Response, Secret, SlotInfo, StatusInfo, SyncInfo, UnlockMethod,
};
use zeroize::Zeroizing;

use crate::approve::{Approver, PairPrompt};
use crate::hw::Hardware;
use crate::store::Store;
use crate::sync::Folder;
use crate::{pgp, ssh};

/// Relying party ID for FIDO2 credentials created by this daemon.
pub const RP_ID: &str = vault_hw::RP_ID;

/// Failed attempts allowed before backoff starts.
const FREE_ATTEMPTS: u32 = 3;
/// Longest wait between attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Longest quick unlock window after a full unlock.
const MAX_QUICK_HOURS: u32 = 24;
/// Failed Windows Hello or Touch ID attempts before the quick unlock key is forgotten.
const QUICK_ATTEMPTS: u32 = 3;

pub struct Daemon {
    store: Store,
    hw: Hardware,
    cost: KdfCost,
    idle: Duration,
    vault: Option<Vault>,
    last_activity: Instant,
    rollback: bool,
    failures: u32,
    next_attempt: Option<Instant>,
    approver: Option<Arc<dyn Approver>>,
    prompting: bool,
    next_prompt: Option<Instant>,
    device: u64,
    sync: Option<SyncState>,
    /// Set by a request that used a key marked `confirm`: its title and the
    /// purpose. The server asks the user before releasing the response.
    pending_use: Option<(String, String)>,
    /// Quick unlock window in hours; 0 is off.
    quick_hours: u32,
    /// When quick unlock stops working: the last full unlock plus
    /// `quick_hours`. Wall clock, so time asleep counts.
    quick_until: Option<SystemTime>,
    /// While locked with quick unlock on: the vault key, wrapped.
    parked: Option<Parked>,
}

/// A locked vault's key kept for quick unlock (format.md section 4.6). The
/// wrap key is protected in memory where the OS can (Windows).
struct Parked {
    key: ParkedKey,
    wrap: ProtectedKey,
    failures: u32,
}

/// Folder sync and what to report about it.
struct SyncState {
    folder: Folder,
    last_sync: Option<u64>,
    error: Option<String>,
    /// The synced copy changed but could not be merged, so it must not be
    /// overwritten yet.
    blocked: bool,
    /// The last write to the synced copy failed (a cloud client may have
    /// held it open); try again at the next check.
    pending: bool,
    conflicts: u64,
    other_copies: BTreeSet<String>,
}

impl SyncState {
    fn new(path: PathBuf) -> SyncState {
        SyncState {
            folder: Folder::new(path),
            last_sync: None,
            error: None,
            blocked: false,
            pending: false,
            conflicts: 0,
            other_copies: BTreeSet::new(),
        }
    }
}

/// Why a synced copy could not be merged when it was re-keyed elsewhere.
const REKEYED: &str = "the synced copy was re-keyed on another device (a factor was revoked there); lock and unlock to merge it";

/// Wait after a declined or unanswered prompt before showing another.
const PROMPT_COOLDOWN: Duration = Duration::from_secs(10);

type R<T> = Result<T, String>;

/// An OpenPGP key item: title, secret key, confirm flag.
type PgpKey = (String, Zeroizing<Vec<u8>>, bool);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn e(err: vault_core::Error) -> String {
    err.to_string()
}

/// A credential for one slot, owned so it can be borrowed as [`Unlock`].
enum Cred {
    Password(Secret, Option<HwKey>),
    Recovery(Secret),
}

impl Cred {
    fn as_unlock(&self) -> Unlock<'_> {
        match self {
            Cred::Password(p, hw) => Unlock::Password {
                password: p,
                hw_key: hw.as_ref(),
            },
            Cred::Recovery(c) => Unlock::Recovery { code: c },
        }
    }
}

fn kind(f: &Factor) -> &'static str {
    match f {
        Factor::PasswordOnly => "password",
        Factor::PasswordFido2 { .. } => "fido2",
        Factor::PasswordTpm { .. } => "tpm",
        Factor::Recovery => "recovery",
        _ => "reserved",
    }
}

/// See [`SlotInfo::warning`].
fn slot_warning(f: &Factor) -> Option<String> {
    match f {
        Factor::PasswordTpm { blob, .. } if vault_hw::tpm_blob_is_classical(blob) => Some(
            "made with an RSA key a future quantum computer could break; add the TPM again \
             and remove this one for post-quantum protection"
                .into(),
        ),
        _ => None,
    }
}

fn token(rng: &mut OsRandom) -> R<ClientToken> {
    let mut t = Zeroizing::new([0u8; 32]);
    rng.fill(&mut t[..]).map_err(e)?;
    Ok(t)
}

impl Daemon {
    pub fn new(store: Store, hw: Hardware, cost: KdfCost, idle: Duration) -> Daemon {
        let device = store.device_id().unwrap_or_else(|err| {
            eprintln!(
                "vaultd: warning: could not keep a device ID ({err}); using one for this run"
            );
            let mut b = [0u8; 8];
            let _ = OsRandom.fill(&mut b);
            u64::from_le_bytes(b)
        });
        let sync = store.sync_path().map(SyncState::new);
        let mut d = Daemon {
            store,
            hw,
            cost,
            idle,
            vault: None,
            last_activity: Instant::now(),
            rollback: false,
            failures: 0,
            next_attempt: None,
            approver: None,
            prompting: false,
            next_prompt: None,
            device,
            sync,
            pending_use: None,
            quick_hours: 0,
            quick_until: None,
            parked: None,
        };
        d.quick_hours = d.store.quick_unlock_hours().min(MAX_QUICK_HOURS);
        d.join_from_sync();
        d
    }

    /// Lock if idle for longer than the timeout, and merge the synced copy
    /// if it changed. Called periodically.
    pub fn tick(&mut self) {
        if self.vault.is_some() && self.last_activity.elapsed() >= self.idle {
            self.lock();
        }
        if self.parked.is_some() && !self.quick_open() {
            self.parked = None;
        }
        if self.vault.is_some()
            && let Some(all) = self.sync.as_mut().and_then(|s| s.folder.due())
        {
            self.sync_now(None, all);
        }
    }

    /// On a device with no vault yet, take the synced copy as the vault.
    fn join_from_sync(&mut self) {
        if self.store.exists() {
            return;
        }
        let Some(s) = &mut self.sync else { return };
        let Ok(bytes) = std::fs::read(s.folder.path()) else {
            return;
        };
        let res = ParsedVault::parse(&bytes)
            .map_err(e)
            .and_then(|_| self.store.write(&bytes).map_err(|e| e.to_string()));
        s.error = res
            .err()
            .map(|m| format!("could not copy the synced vault: {m}"));
    }

    /// Merge changed synced copies into the unlocked vault, then write both
    /// files if either is behind. `method`, from an unlock just now, opens a
    /// copy whose vault key was rotated on another device. `all` reads
    /// every copy even if it looks unchanged. Problems are reported in the
    /// status, not returned: syncing never blocks using the vault.
    fn sync_now(&mut self, method: Option<&UnlockMethod>, all: bool) {
        let Ok(write) = self.pull(method, all) else {
            return;
        };
        if write {
            let _ = self.save();
        }
    }

    /// The merge half of [`Self::sync_now`]. Returns whether anything
    /// should be written.
    fn pull(&mut self, method: Option<&UnlockMethod>, all: bool) -> Result<bool, ()> {
        if self.sync.is_none() || self.vault.is_none() {
            return Err(());
        }
        let (Some(mut st), Some(mut v)) = (self.sync.take(), self.vault.take()) else {
            unreachable!("checked above")
        };
        let res = self.pull_into(&mut st, &mut v, method, all);
        if let Err(m) = &res {
            st.error = Some(m.clone());
        }
        self.sync = Some(st);
        self.vault = Some(v);
        res.map_err(|_| ())
    }

    fn pull_into(
        &self,
        st: &mut SyncState,
        v: &mut Vault,
        method: Option<&UnlockMethod>,
        all: bool,
    ) -> R<bool> {
        let mut write = st.pending || !st.folder.exists();
        st.blocked = false;
        st.error = None;
        for c in st.folder.changed(all) {
            let main = st.folder.is_main(&c.path);
            let parsed = match ParsedVault::parse(&c.bytes) {
                Ok(p) => p,
                // Possibly still being downloaded: look again next time.
                Err(_) if main => {
                    st.blocked = true;
                    return Err("the synced copy is incomplete or damaged; trying again".into());
                }
                Err(_) => continue,
            };
            if parsed.vault_id() != v.vault_id() {
                if main {
                    st.blocked = true;
                    return Err("the synced copy is a different vault".into());
                }
                st.folder.mark(c.path, c.stamp);
                continue;
            }
            let theirs = match parsed.open_with(v) {
                Ok(t) => t,
                Err(vault_core::Error::DifferentKey) => {
                    let opened = method.map(|m| self.open_parsed(&parsed, m).map_err(|(m, _)| m));
                    match opened {
                        Some(Ok(t)) => t,
                        Some(Err(m)) if main => {
                            st.blocked = true;
                            return Err(format!("{REKEYED} ({m})"));
                        }
                        None if main => {
                            st.blocked = true;
                            return Err(REKEYED.into());
                        }
                        _ => continue,
                    }
                }
                Err(err) if main => {
                    st.blocked = true;
                    return Err(format!("could not open the synced copy: {err}"));
                }
                Err(_) => continue,
            };
            let r = v.merge(&mut OsRandom, &theirs, &ItemMerge).map_err(e)?;
            st.conflicts += r.conflicts as u64;
            write |= r.changed() || (main && r.other_behind);
            if !main {
                st.other_copies.insert(
                    c.path
                        .file_name()
                        .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                );
            }
            if r.rekeyed {
                eprintln!(
                    "vaultd: took the vault key rotated on another device; {} slot(s) of this copy were dropped",
                    r.slots_dropped.len()
                );
            }
            st.folder.mark(c.path, c.stamp);
        }
        st.last_sync = Some(now());
        Ok(write)
    }

    /// Drop the vault and its keys. With quick unlock on and its window
    /// open, keep the vault key wrapped under a fresh random key first.
    pub fn lock(&mut self) {
        let Some(v) = self.vault.take() else {
            return;
        };
        if self.hw.presence.is_none() || !self.quick_open() {
            return;
        }
        let mut wrap = Zeroizing::new([0u8; 32]);
        if OsRandom.fill(&mut wrap[..]).is_err() {
            return;
        }
        if let Ok(key) = v.park(&HwKey::new(*wrap), &mut OsRandom) {
            self.parked = Some(Parked {
                key,
                wrap: ProtectedKey::new(*wrap),
                failures: 0,
            });
        }
    }

    /// Lock, and forget the quick unlock key too.
    pub fn lock_fully(&mut self) {
        self.vault = None;
        self.parked = None;
        self.quick_until = None;
    }

    /// Whether quick unlock is on and within its window.
    fn quick_open(&self) -> bool {
        self.quick_hours > 0 && self.quick_until.is_some_and(|t| SystemTime::now() < t)
    }

    /// Re-open the parked vault after Windows Hello or Touch ID confirms the user.
    fn quick_unlock(&mut self) -> R<Vault> {
        const NOT_NOW: &str = "quick unlock is not available now: unlock with your password \
                               (or another method) first";
        if self.parked.is_none() || !self.quick_open() {
            self.parked = None;
            return Err(NOT_NOW.into());
        }
        let hello = self.hw.presence.as_ref().ok_or(NOT_NOW)?;
        if let Err(m) = hello.verify("Unlock Secret Vault") {
            let p = self.parked.as_mut().ok_or(NOT_NOW)?;
            p.failures += 1;
            if p.failures >= QUICK_ATTEMPTS {
                self.parked = None;
                return Err(format!(
                    "{m}; quick unlock is off until you unlock with your password"
                ));
            }
            return Err(m);
        }
        let bytes = self
            .store
            .read()
            .map_err(|_| "no vault; run `vault init`")?;
        let parsed = ParsedVault::parse(&bytes).map_err(e)?;
        let p = self.parked.as_mut().ok_or(NOT_NOW)?;
        let opened = p.wrap.with(|w| parsed.resume(&p.key, w));
        match opened {
            Ok(v) => {
                self.parked = None;
                self.check_rollback(&v);
                Ok(v)
            }
            Err(err) => {
                // The key was rotated (a revoke synced in) or the file was
                // replaced: a full unlock is needed.
                self.parked = None;
                Err(format!("{}; unlock with your password", e(err)))
            }
        }
    }

    fn set_quick_unlock(&mut self, hours: u32) -> R<Response> {
        if hours > MAX_QUICK_HOURS {
            return Err(format!(
                "quick unlock lasts at most {MAX_QUICK_HOURS} hours after a full unlock"
            ));
        }
        if hours > 0 {
            let hello = self.hw.presence.as_ref().ok_or(
                "quick unlock needs Windows Hello or Touch ID, which this system does not have",
            )?;
            hello.check_available()?;
            hello.verify("Turn on quick unlock for Secret Vault")?;
        }
        self.store
            .set_quick_unlock_hours(hours)
            .map_err(|e| e.to_string())?;
        self.quick_hours = hours;
        // The window counts from now, for the unlock that is open.
        self.quick_until = (hours > 0 && self.vault.is_some())
            .then(|| SystemTime::now() + Duration::from_secs(u64::from(hours) * 3600));
        if hours == 0 {
            self.parked = None;
        }
        Ok(Response::Status(self.status()))
    }

    /// Let clients pair by asking the user through `approver`.
    pub fn set_approver(&mut self, approver: Arc<dyn Approver>) {
        self.approver = Some(approver);
    }

    /// The key use the last response depends on approval for, if any.
    pub fn take_pending_use(&mut self) -> Option<(String, String)> {
        self.pending_use.take()
    }

    /// An item's OpenPGP key: its title, secret key and confirm flag.
    fn pgp_key(&mut self, id: &ItemId) -> R<PgpKey> {
        let it = self.item(id)?;
        match &it.key {
            Some(KeyData::OpenPgp { tsk, confirm }) => {
                Ok((it.title.clone(), Zeroizing::new(tsk.clone()), *confirm))
            }
            _ => Err(format!("\u{201c}{}\u{201d} has no OpenPGP key", it.title)),
        }
    }

    /// All OpenPGP keys in the vault, as `pgp_key` returns them, those that
    /// need no approval first.
    fn pgp_keys(&mut self) -> R<Vec<PgpKey>> {
        let ids: Vec<ItemId> = self.vault()?.item_ids().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            if let Ok(k) = self.pgp_key(&id) {
                out.push(k);
            }
        }
        out.sort_by_key(|k| k.2);
        Ok(out)
    }

    /// Record that the response depends on the user approving this use.
    fn needs_approval(&mut self, confirm: bool, title: &str, purpose: &str) {
        if confirm {
            self.pending_use = Some((title.to_owned(), purpose.to_owned()));
        }
    }

    /// The approval window, for key-use prompts.
    pub fn approver(&self) -> Option<Arc<dyn Approver>> {
        self.approver.clone()
    }

    /// SSH keys the agent may offer: none while locked.
    pub fn ssh_identities(&mut self) -> Vec<ssh::Identity> {
        let Some(v) = self.vault.as_ref() else {
            return Vec::new();
        };
        let ids: Vec<ItemId> = v.item_ids().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            let Ok(it) = self.item(&id) else { continue };
            if let Some(KeyData::Ssh { openssh, confirm }) = &it.key
                && let Ok(blob) = ssh::public_blob(openssh)
            {
                out.push(ssh::Identity {
                    id,
                    title: it.title.clone(),
                    blob,
                    confirm: *confirm,
                });
            }
        }
        out.sort_by_key(|i| i.title.to_lowercase());
        out
    }

    /// Sign with the SSH key of item `id`, if it is still the key with
    /// public blob `blob` (the vault may have changed during a prompt).
    pub fn ssh_sign(&mut self, id: &ItemId, blob: &[u8], data: &[u8]) -> R<Vec<u8>> {
        match &self.item(id)?.key {
            Some(KeyData::Ssh { openssh, .. }) if ssh::public_blob(openssh)? == blob => {
                ssh::sign(openssh, data)
            }
            _ => Err("that key is no longer in the vault".into()),
        }
    }

    /// Whether the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Every item `keep` selects, with its ID. Fails while locked. Does not
    /// count as activity: an application polling the Secret Service must
    /// not keep the vault unlocked.
    pub fn items_where(&mut self, keep: impl Fn(&ItemData) -> bool) -> R<Vec<(ItemId, ItemData)>> {
        let ids: Vec<ItemId> = self.vault()?.item_ids().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            let Ok(it) = self.item(&id) else { continue };
            if keep(&it) {
                out.push((id, it));
            }
        }
        Ok(out)
    }

    /// Save `item` under `id`, or as a new item, and write the vault. Keeps
    /// an edited item's key and creation time; a new item gets no key.
    pub fn put_item(&mut self, id: Option<ItemId>, mut item: ItemData) -> R<ItemId> {
        let t = now();
        let id = match id {
            Some(id) => {
                let old = self.item(&id)?;
                item.created = old.created;
                item.key = old.key.clone();
                id
            }
            None => {
                item.created = t;
                item.key = None;
                self.vault()?.new_item_id(&mut OsRandom).map_err(e)?
            }
        };
        item.modified = t;
        item.normalize();
        self.vault()?
            .put_item(&mut OsRandom, &id, &item.to_bytes())
            .map_err(e)?;
        self.save()?;
        Ok(id)
    }

    /// Delete item `id` and write the vault.
    pub fn delete_item(&mut self, id: &ItemId) -> R<()> {
        self.vault()?.remove_item(id).map_err(e)?;
        self.save()
    }

    /// Claim the prompt to ask about an application using the Secret
    /// Service. Finish with [`Self::end_app_prompt`].
    pub fn begin_app_prompt(&mut self) -> R<Arc<dyn Approver>> {
        self.claim_prompt(
            "vaultd cannot show the approval window, so no application can use the Secret Service",
        )
    }

    /// Release the prompt from [`Self::begin_app_prompt`].
    pub fn end_app_prompt(&mut self, answer: &Result<bool, String>) {
        self.finish_prompt(answer);
    }

    /// Claim the one prompt that may be open at a time. The caller asks
    /// without holding the daemon lock, then calls [`Self::finish_prompt`].
    fn claim_prompt(&mut self, cannot: &str) -> R<Arc<dyn Approver>> {
        let a = self.approver.clone().ok_or(cannot)?;
        if self.prompting {
            return Err("another request is waiting for your approval".into());
        }
        if self.next_prompt.is_some_and(|t| Instant::now() < t) {
            return Err("a request was just declined; try again in a few seconds".into());
        }
        self.prompting = true;
        Ok(a)
    }

    /// Release the prompt; anything but an approval holds off the next one.
    fn finish_prompt(&mut self, answer: &Result<bool, String>) {
        self.prompting = false;
        if !matches!(answer, Ok(true)) {
            self.next_prompt = Some(Instant::now() + PROMPT_COOLDOWN);
        }
    }

    /// Claim the prompt for pairing. Finish with [`Self::end_prompt`].
    pub fn begin_prompt(&mut self) -> R<Arc<dyn Approver>> {
        if !self.store.exists() {
            return Err("no vault exists yet".into());
        }
        self.claim_prompt(
            "this daemon cannot show an approval prompt; pair by proving an unlock method instead",
        )
    }

    /// Finish a prompt from [`Self::begin_prompt`]: pair if approved.
    pub fn end_prompt(&mut self, prompt: &PairPrompt, answer: Result<bool, String>) -> Response {
        self.finish_prompt(&answer);
        let r = match answer {
            Ok(true) => token(&mut OsRandom).and_then(|t| {
                self.store
                    .add_client(&prompt.client_name, prompt.scope, &t)
                    .map_err(|e| e.to_string())?;
                Ok(Response::Paired { token: t })
            }),
            Ok(false) => Err("pairing was declined".into()),
            Err(m) => Err(format!("could not show the approval prompt: {m}")),
        };
        r.unwrap_or_else(Response::Error)
    }

    /// Start releasing a card for filling: check the client and the page,
    /// then claim the prompt. Returns the approver, the client's name and
    /// the card. Finish with [`Self::end_card_fill`].
    pub fn begin_card_fill(
        &mut self,
        token: Option<&ClientToken>,
        id: &ItemId,
        origin: &str,
    ) -> R<(Arc<dyn Approver>, String, ItemData)> {
        let t = token.ok_or("this client is not paired; run `vault pair`")?;
        let (name, _) = self
            .store
            .client(t)
            .ok_or("unknown client token; pair again")?;
        self.last_activity = Instant::now();
        form_origin(origin)?;
        let item = self.item(id)?;
        if item.kind != ItemKind::Card {
            return Err("that item is not a card".into());
        }
        let a = self.claim_prompt(
            "filling a card needs vaultd's confirmation window, which this daemon cannot show",
        )?;
        Ok((a, name, item.for_form_fill()))
    }

    /// Finish [`Self::begin_card_fill`]: release the card if approved.
    pub fn end_card_fill(
        &mut self,
        id: ItemId,
        item: ItemData,
        answer: Result<bool, String>,
    ) -> Response {
        self.finish_prompt(&answer);
        match answer {
            Ok(true) if self.vault.is_some() => Response::Item { id, item },
            Ok(true) => Response::Error("the vault was locked while you were asked".into()),
            Ok(false) => Response::Error("filling the card was declined".into()),
            Err(m) => Response::Error(format!("could not show the confirmation window: {m}")),
        }
    }

    /// Handle one request. If it used a key that needs approval, the
    /// response must not be released until [`Self::take_pending_use`] has
    /// been asked and the user allowed it.
    pub fn handle(&mut self, env: Envelope) -> Response {
        self.pending_use = None;
        match self.dispatch(env) {
            Ok(r) => r,
            Err(m) => Response::Error(m),
        }
    }

    fn dispatch(&mut self, env: Envelope) -> R<Response> {
        let scope = match &env.request {
            Request::Status
            | Request::Init { .. }
            | Request::Pair { .. }
            | Request::PasskeySlots => None,
            Request::SetSync { .. } if !self.store.exists() => None,
            _ => {
                let t = env
                    .token
                    .as_ref()
                    .ok_or("this client is not paired; run `vault pair`")?;
                Some(
                    self.store
                        .client_scope(t)
                        .ok_or("unknown client token; pair again")?,
                )
            }
        };
        if scope == Some(ClientScope::Autofill)
            && !matches!(
                env.request,
                Request::Unlock { .. }
                    | Request::PasskeySlots
                    | Request::Lock
                    | Request::LockFully
                    | Request::FindForOrigin { .. }
                    | Request::GetForFill { .. }
                    | Request::TotpForFill { .. }
                    | Request::FormItems { .. }
                    | Request::IdentityForFill { .. }
                    | Request::CardForFill { .. }
                    | Request::Generate { .. }
                    | Request::GenerateStyled { .. }
            )
        {
            return Err("not allowed for an autofill client".into());
        }
        if scope.is_some() {
            self.last_activity = Instant::now();
        }

        match env.request {
            Request::Status => Ok(Response::Status(self.status())),
            Request::Init {
                password,
                client_name,
            } => self.init(&password, &client_name),
            Request::Pair {
                method: Some(UnlockMethod::Hello),
                ..
            } => Err("pair with your password or another full unlock method".into()),
            Request::Pair {
                client_name,
                scope,
                method: Some(method),
            } => {
                let v = self.prove(&method)?;
                self.opened(v, &method);
                let t = token(&mut OsRandom)?;
                self.store
                    .add_client(&client_name, scope, &t)
                    .map_err(|e| e.to_string())?;
                Ok(Response::Paired { token: t })
            }
            Request::Pair { method: None, .. } => {
                Err("pairing without a factor goes through the server's approval prompt".into())
            }
            Request::Unlock {
                method: UnlockMethod::Hello,
            } => {
                if self.vault.is_none() {
                    let mut v = self.quick_unlock()?;
                    v.set_device(self.device);
                    self.vault = Some(v);
                    self.sync_now(None, true);
                }
                Ok(Response::Ok)
            }
            Request::Unlock { method } => {
                let v = self.prove(&method)?;
                self.opened(v, &method);
                Ok(Response::Ok)
            }
            Request::SetSync { path } => self.set_sync(path),
            Request::Lock => {
                self.lock();
                Ok(Response::Ok)
            }
            Request::LockFully => {
                self.lock_fully();
                Ok(Response::Ok)
            }
            Request::Generate { options } => {
                let style = PasswordStyle::Random(options).to_core();
                Ok(Response::Generated(
                    generator::generate(&mut OsRandom, &style).map_err(e)?,
                ))
            }
            Request::GenerateStyled { style: s } => Ok(Response::Generated(
                generator::generate(&mut OsRandom, &s.to_core())
                    .map_err(|_| "choose 3 to 10 words and a separator of up to 3 characters")?,
            )),
            Request::PasskeySlots => self.passkey_slots(),
            other => self.unlocked(other),
        }
    }

    /// Slots a phone passkey can open: FIDO2 slots that check the PIN.
    fn passkey_slots(&mut self) -> R<Response> {
        let parsed;
        let metas: Vec<&KeyslotMeta> = match &self.vault {
            Some(v) => v.slots().collect(),
            None => {
                self.join_from_sync();
                let bytes = self
                    .store
                    .read()
                    .map_err(|_| "no vault; run `vault init`")?;
                parsed = ParsedVault::parse(&bytes).map_err(e)?;
                parsed.slots().collect()
            }
        };
        Ok(Response::PasskeySlots(
            metas
                .into_iter()
                .filter_map(|m| match &m.factor {
                    Factor::PasswordFido2 {
                        credential_id,
                        rp_id,
                        prf_input,
                        require_uv: true,
                    } => Some(PasskeySlot {
                        credential_id: credential_id.clone(),
                        rp_id: rp_id.clone(),
                        prf_input: *prf_input,
                    }),
                    _ => None,
                })
                .collect(),
        ))
    }

    /// Hold a vault just unlocked with `method`, and catch up with the
    /// synced copy. A full unlock starts a new quick unlock window.
    fn opened(&mut self, mut v: Vault, method: &UnlockMethod) {
        v.set_device(self.device);
        self.vault = Some(v);
        self.parked = None;
        self.quick_until = (self.quick_hours > 0)
            .then(|| SystemTime::now() + Duration::from_secs(u64::from(self.quick_hours) * 3600));
        self.sync_now(Some(method), true);
    }

    fn set_sync(&mut self, path: Option<String>) -> R<Response> {
        let path = path.map(PathBuf::from);
        if let Some(p) = &path {
            if p.file_name().is_none() {
                return Err("give the path of a file, such as ~/OneDrive/vault.svault".into());
            }
            let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
            if dir.is_some_and(|d| !d.is_dir()) {
                return Err(format!("{} is not a folder", dir.unwrap_or(p).display()));
            }
            if p == self.store.vault_path() {
                return Err(
                    "that is the vault file itself; choose a file in a synced folder".into(),
                );
            }
        }
        self.store
            .set_sync_path(path.as_deref())
            .map_err(|e| e.to_string())?;
        self.sync = path.map(SyncState::new);
        self.join_from_sync();
        if self.vault.is_some() {
            self.sync_now(None, true);
        }
        Ok(Response::Status(self.status()))
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            initialized: self.store.exists(),
            unlocked: self.vault.is_some(),
            generation: self.vault.as_ref().map(Vault::generation),
            rollback_detected: self.rollback,
            idle_lock_in: self.vault.as_ref().map(|_| {
                self.idle
                    .saturating_sub(self.last_activity.elapsed())
                    .as_secs()
            }),
            quick_unlock: QuickUnlockInfo {
                supported: self.hw.presence.is_some(),
                hours: self.quick_hours,
                until: self
                    .parked
                    .as_ref()
                    .filter(|_| self.vault.is_none() && self.quick_open())
                    .and(self.quick_until)
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            },
            sync: self.sync.as_ref().map(|s| SyncInfo {
                path: s.folder.path().display().to_string(),
                last_sync: s.last_sync,
                error: s.error.clone(),
                conflicts: s.conflicts,
                other_copies: s.other_copies.iter().cloned().collect(),
            }),
        }
    }

    fn init(&mut self, password: &str, client_name: &str) -> R<Response> {
        if self.store.exists() {
            return Err("a vault already exists".into());
        }
        check_password(password)?;
        let rng = &mut OsRandom;
        let mut v = Vault::new(rng).map_err(e)?;
        let pw_slot = v
            .add_password_slot(
                rng,
                Factor::PasswordOnly,
                self.cost,
                password,
                None,
                "password",
            )
            .map_err(e)?;
        let (rc_slot, code) = v.add_recovery_slot(rng, "recovery code").map_err(e)?;
        let bytes = v.to_bytes(rng).map_err(e)?;
        // Test-unlock both slots from the encoded bytes before writing (6.1).
        let parsed = ParsedVault::parse(&bytes).map_err(e)?;
        parsed
            .unlock(
                &pw_slot,
                &Unlock::Password {
                    password,
                    hw_key: None,
                },
            )
            .map_err(e)?;
        parsed
            .unlock(
                &rc_slot,
                &Unlock::Recovery {
                    code: code.as_str(),
                },
            )
            .map_err(e)?;
        self.store.write(&bytes).map_err(|e| e.to_string())?;
        self.store
            .record_generation(&v.vault_id(), v.generation())
            .map_err(|e| e.to_string())?;
        let t = token(rng)?;
        self.store
            .add_client(client_name, ClientScope::Full, &t)
            .map_err(|e| e.to_string())?;
        v.set_device(self.device);
        self.vault = Some(v);
        self.rollback = false;
        if let Some(s) = &mut self.sync
            && let Err(err) = s.folder.write(&bytes)
        {
            s.error = Some(format!("could not write the synced copy: {err}"));
            s.pending = true;
        }
        Ok(Response::Initialized {
            recovery_code: Zeroizing::new(code.as_str().to_owned()),
            token: t,
        })
    }

    /// Unlock with the first slot the method fits. Rate limited.
    fn prove(&mut self, method: &UnlockMethod) -> R<Vault> {
        if matches!(method, UnlockMethod::Hello) {
            return Err(format!(
                "{} only re-opens a vault locked on this computer; \
                 use your password or another full unlock method here",
                vault_hw::PRESENCE_NAME
            ));
        }
        if let Some(t) = self.next_attempt
            && Instant::now() < t
        {
            return Err(format!(
                "too many failed attempts; try again in {} s",
                (t - Instant::now()).as_secs() + 1
            ));
        }
        self.join_from_sync();
        let parsed = ParsedVault::parse(
            &self
                .store
                .read()
                .map_err(|_| "no vault; run `vault init`")?,
        )
        .map_err(e)?;
        let last = match self.open_parsed(&parsed, method) {
            Ok(v) => {
                self.failures = 0;
                self.next_attempt = None;
                self.check_rollback(&v);
                return Ok(v);
            }
            Err((m, false)) => return Err(m),
            Err((m, true)) => m,
        };
        self.failures += 1;
        if self.failures > FREE_ATTEMPTS {
            let wait =
                Duration::from_secs(1 << (self.failures - FREE_ATTEMPTS).min(9)).min(MAX_BACKOFF);
            self.next_attempt = Some(Instant::now() + wait);
        }
        Err(last)
    }

    /// Unlock with the first slot `method` fits. On failure, also says
    /// whether it counts as a wrong guess.
    fn open_parsed(
        &self,
        parsed: &ParsedVault,
        method: &UnlockMethod,
    ) -> Result<Vault, (String, bool)> {
        let candidates: Vec<KeyslotMeta> = parsed
            .slots()
            .filter(|m| fits(&m.factor, method))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err(("no slot of that kind is enrolled".into(), false));
        }
        let mut last = String::from("wrong password or factor");
        for meta in &candidates {
            let cred = match self.credential(&meta.factor, method) {
                Ok(c) => c,
                Err(m) => {
                    last = m;
                    continue;
                }
            };
            match parsed.unlock(&meta.id, &cred.as_unlock()) {
                Ok(v) => return Ok(v),
                Err(vault_core::Error::WrongFactor) => {}
                Err(err) => return Err((e(err), false)),
            }
        }
        Err((last, true))
    }

    fn check_rollback(&mut self, v: &Vault) {
        let seen = self.store.last_generation(&v.vault_id());
        self.rollback = v.generation() < seen;
        if !self.rollback {
            let _ = self.store.record_generation(&v.vault_id(), v.generation());
        }
    }

    /// Build the credential for one slot, running the hardware factor.
    fn credential(&self, factor: &Factor, method: &UnlockMethod) -> R<Cred> {
        Ok(match (factor, method) {
            (Factor::PasswordOnly, UnlockMethod::Password { password }) => {
                Cred::Password(password.clone(), None)
            }
            (
                Factor::PasswordFido2 {
                    credential_id,
                    rp_id,
                    prf_input,
                    require_uv,
                },
                UnlockMethod::Fido2 { password, pin },
            ) => {
                // Every slot's password has 8 or more characters, so a
                // shorter one can't open it: don't ask for a PIN and touch.
                check_password(password)?;
                let dev = self
                    .hw
                    .fido2
                    .as_ref()
                    .ok_or("FIDO2 support is not built in")?;
                let hw = dev.hmac_secret(
                    rp_id,
                    credential_id,
                    prf_input,
                    pin.as_deref().map(|s| s.as_str()),
                    *require_uv,
                )?;
                Cred::Password(password.clone(), Some(hw))
            }
            (
                Factor::PasswordTpm {
                    blob, pcr_policy, ..
                },
                UnlockMethod::Tpm { password, pin },
            ) => {
                let dev = self.hw.tpm.as_ref().ok_or("TPM support is not built in")?;
                let hw = dev.unseal(
                    blob,
                    pin.as_deref().map(|s| s.as_str()),
                    pcr_policy.is_some(),
                )?;
                Cred::Password(password.clone(), Some(hw))
            }
            (
                Factor::PasswordFido2 { .. },
                UnlockMethod::Passkey {
                    password,
                    prf_output,
                    ..
                },
            ) => {
                check_password(password)?;
                Cred::Password(password.clone(), Some(prf_key(prf_output)?))
            }
            (Factor::Recovery, UnlockMethod::Recovery { code }) => Cred::Recovery(code.clone()),
            _ => return Err("that method does not fit this slot".into()),
        })
    }

    fn vault(&mut self) -> R<&mut Vault> {
        self.vault
            .as_mut()
            .ok_or_else(|| "vault is locked; run `vault unlock`".into())
    }

    /// Encode and write the unlocked vault. Refused after a rollback.
    fn save(&mut self) -> R<()> {
        if self.rollback {
            return Err("the vault file is older than one this daemon saw before (possible rollback); writes are refused".into());
        }
        // Take in what other devices wrote first, so it is not overwritten.
        let _ = self.pull(None, false);
        let v = self.vault.as_mut().ok_or("vault is locked")?;
        let bytes = v.to_bytes(&mut OsRandom).map_err(e)?;
        self.store.write(&bytes).map_err(|e| e.to_string())?;
        self.store
            .record_generation(&v.vault_id(), v.generation())
            .map_err(|e| e.to_string())?;
        if let Some(s) = &mut self.sync
            && !s.blocked
        {
            match s.folder.write(&bytes) {
                Ok(()) => {
                    s.last_sync = Some(now());
                    s.pending = false;
                }
                Err(err) => {
                    s.error = Some(format!("could not write the synced copy: {err}"));
                    s.pending = true;
                }
            }
        }
        Ok(())
    }

    /// After adding a slot: re-read the file and unlock it with the new slot.
    fn test_unlock(&self, id: &SlotId, cred: &Unlock<'_>) -> R<()> {
        let parsed =
            ParsedVault::parse(&self.store.read().map_err(|e| e.to_string())?).map_err(e)?;
        parsed
            .unlock(id, cred)
            .map(|_| ())
            .map_err(|err| format!("new slot failed its test unlock: {err}"))
    }

    fn item(&mut self, id: &ItemId) -> R<ItemData> {
        let bytes = self.vault()?.get_item(id).map_err(e)?;
        ItemData::from_bytes(&bytes).map_err(e)
    }

    fn fillable(&mut self, id: &ItemId, origin: &str) -> R<ItemData> {
        let item = self.item(id)?;
        if item.kind == ItemKind::Login && item.urls.iter().any(|u| may_fill(u, origin)) {
            Ok(item)
        } else {
            Err("this item is not bound to that site".into())
        }
    }

    fn summaries(&mut self, keep: impl Fn(&ItemData) -> bool) -> R<Vec<ItemSummary>> {
        let ids: Vec<ItemId> = self.vault()?.item_ids().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            let it = self.item(&id)?;
            if keep(&it) {
                out.push(ItemSummary {
                    id,
                    kind: it.kind,
                    title: it.title.clone(),
                    subtitle: it.subtitle(),
                    urls: it.urls.iter().map(|u| u.url.clone()).collect(),
                    has_totp: it.totp.is_some(),
                    key: it.key.as_ref().map(describe_key),
                    key_confirm: it.key.as_ref().is_some_and(KeyData::confirm),
                });
            }
        }
        out.sort_by_key(|s| s.title.to_lowercase());
        Ok(out)
    }

    fn unlocked(&mut self, req: Request) -> R<Response> {
        let rng = &mut OsRandom;
        match req {
            Request::ListSlots => {
                let v = self.vault()?;
                Ok(Response::Slots(
                    v.slots()
                        .map(|m| SlotInfo {
                            id: m.id,
                            kind: kind(&m.factor).into(),
                            label: v.slot_label(&m.id).unwrap_or("").into(),
                            warning: slot_warning(&m.factor),
                        })
                        .collect(),
                ))
            }
            Request::AddPasswordSlot { password, label } => {
                check_password(&password)?;
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, Factor::PasswordOnly, cost, &password, None, &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: None,
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddFido2Slot {
                password,
                pin,
                require_uv,
                label,
            } => {
                check_password(&password)?;
                self.vault()?;
                let dev = self
                    .hw
                    .fido2
                    .as_ref()
                    .ok_or("FIDO2 support is not built in")?;
                let pin = pin.as_deref().map(|s| s.as_str());
                let credential_id = dev.enroll(RP_ID, pin, require_uv)?;
                let mut prf_input = [0u8; 32];
                rng.fill(&mut prf_input).map_err(e)?;
                let hw = dev.hmac_secret(RP_ID, &credential_id, &prf_input, pin, require_uv)?;
                let factor = Factor::PasswordFido2 {
                    credential_id,
                    rp_id: RP_ID.into(),
                    prf_input,
                    require_uv,
                };
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, factor, cost, &password, Some(&hw), &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: Some(&hw),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddPasskeySlot {
                password,
                credential_id,
                prf_input,
                prf_output,
                label,
            } => {
                check_password(&password)?;
                if credential_id.is_empty() {
                    return Err("the passkey has no credential ID".into());
                }
                let hw = prf_key(&prf_output)?;
                // Phones always verify the user, so the slot checks UV.
                let factor = Factor::PasswordFido2 {
                    credential_id,
                    rp_id: RP_ID.into(),
                    prf_input,
                    require_uv: true,
                };
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, factor, cost, &password, Some(&hw), &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: Some(&hw),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddTpmSlot {
                password,
                pin,
                bind_pcr7,
                label,
            } => {
                check_password(&password)?;
                self.vault()?;
                let dev = self.hw.tpm.as_ref().ok_or("TPM support is not built in")?;
                let pin = pin.as_deref().map(|s| s.as_str());
                let mut secret = Zeroizing::new([0u8; 32]);
                rng.fill(&mut secret[..]).map_err(e)?;
                let blob = dev.seal(&secret, pin, bind_pcr7)?;
                let hw = dev.unseal(&blob, pin, bind_pcr7)?;
                if !hw.ct_eq(&secret) {
                    return Err("TPM returned a different secret than it sealed".into());
                }
                let factor = Factor::PasswordTpm {
                    blob,
                    pcr_policy: bind_pcr7.then(|| PcrPolicy {
                        bank: 1,
                        pcrs: vec![7],
                    }),
                    has_pin: pin.is_some_and(|p| !p.is_empty()),
                };
                let cost = self.cost;
                let id = self
                    .vault()?
                    .add_password_slot(rng, factor, cost, &password, Some(&hw), &label)
                    .map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Password {
                        password: &password,
                        hw_key: Some(&hw),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: None,
                })
            }
            Request::AddRecoverySlot { label } => {
                let (id, code) = self.vault()?.add_recovery_slot(rng, &label).map_err(e)?;
                self.save()?;
                self.test_unlock(
                    &id,
                    &Unlock::Recovery {
                        code: code.as_str(),
                    },
                )?;
                Ok(Response::SlotAdded {
                    id,
                    recovery_code: Some(Zeroizing::new(code.as_str().to_owned())),
                })
            }
            Request::RemoveSlot { slot } => {
                self.vault()?.remove_slot(&slot).map_err(e)?;
                self.save()?;
                Ok(Response::Ok)
            }
            Request::Revoke { keep } => {
                let metas: Vec<KeyslotMeta> = self.vault()?.slots().cloned().collect();
                let mut creds = Vec::with_capacity(keep.len());
                for (id, method) in &keep {
                    let meta = metas.iter().find(|m| &m.id == id).ok_or("no such slot")?;
                    creds.push((*id, self.credential(&meta.factor, method)?));
                }
                let pairs: Vec<(SlotId, Unlock<'_>)> =
                    creds.iter().map(|(id, c)| (*id, c.as_unlock())).collect();
                let v = self.vault.as_mut().ok_or("vault is locked")?;
                let removed = v.revoke(rng, &pairs).map_err(e)?;
                drop(pairs);
                self.save()?;
                Ok(Response::Revoked { removed })
            }
            Request::ListItems => Ok(Response::Items(self.summaries(|_| true)?)),
            Request::GetItem { id } => Ok(Response::Item {
                item: without_key(self.item(&id)?),
                id,
            }),
            // Keys change only through the key requests: an edited item
            // keeps its key, and a new one starts without.
            Request::PutItem { id, item } => Ok(Response::ItemSaved {
                id: self.put_item(id, item)?,
            }),
            Request::DeleteItem { id } => {
                self.delete_item(&id)?;
                Ok(Response::Ok)
            }
            Request::FindForOrigin { origin } => Ok(Response::Items(self.summaries(|it| {
                it.kind == ItemKind::Login && it.urls.iter().any(|u| may_fill(u, &origin))
            })?)),
            Request::FormItems { origin } => {
                form_origin(&origin)?;
                Ok(Response::Items(self.summaries(|it| {
                    matches!(it.kind, ItemKind::Card | ItemKind::Identity)
                })?))
            }
            Request::IdentityForFill { id, origin } => {
                form_origin(&origin)?;
                let item = self.item(&id)?;
                if item.kind != ItemKind::Identity {
                    return Err("that item is not an identity".into());
                }
                Ok(Response::Item {
                    item: item.for_form_fill(),
                    id,
                })
            }
            Request::CardForFill { .. } => {
                Err("filling a card goes through the server's confirmation prompt".into())
            }
            Request::GetForFill { id, origin } => Ok(Response::Item {
                item: without_key(self.fillable(&id, &origin)?),
                id,
            }),
            Request::Totp { id } => totp(&self.item(&id)?),
            Request::TotpForFill { id, origin } => totp(&self.fillable(&id, &origin)?),
            Request::Import { format, data } => {
                let t = now();
                let items = match format {
                    ImportFormat::BitwardenJson => {
                        vault_import::bitwarden_json(&data, t).map(|(i, _)| i)
                    }
                    ImportFormat::BrowserCsv => vault_import::browser_csv(&data, t),
                }
                .map_err(|err| err.to_string())?;
                let v = self.vault()?;
                for item in &items {
                    let id = v.new_item_id(rng).map_err(e)?;
                    v.put_item(rng, &id, &item.to_bytes()).map_err(e)?;
                }
                self.save()?;
                Ok(Response::Imported(items.len()))
            }
            Request::SyncNow => {
                self.vault()?;
                if self.sync.is_none() {
                    return Err("sync is off; turn it on with `vault sync on PATH`".into());
                }
                self.sync_now(None, true);
                Ok(Response::Status(self.status()))
            }
            Request::GenerateKey {
                title,
                kind,
                confirm,
            } => {
                let key = ssh::generate(kind, &title, confirm)?;
                self.new_key_item(title, key)
            }
            Request::ImportSshKey {
                title,
                private,
                passphrase,
                confirm,
            } => {
                let key =
                    ssh::import(&private, passphrase.as_deref().map(|s| s.as_str()), confirm)?;
                self.new_key_item(title, key)
            }
            Request::PublicKey { id } => match &self.item(&id)?.key {
                Some(KeyData::Ssh { openssh, .. }) => {
                    Ok(Response::PublicKey(ssh::public_line(openssh)?))
                }
                Some(KeyData::OpenPgp { tsk, .. }) => {
                    Ok(Response::PublicKey(pgp::public_armored(tsk)?))
                }
                None => Err("this item has no key".into()),
            },
            Request::SetKeyConfirm { id, confirm } => {
                let mut item = self.item(&id)?;
                item.key
                    .as_mut()
                    .ok_or("this item has no key")?
                    .set_confirm(confirm);
                item.modified = now();
                self.vault()?
                    .put_item(rng, &id, &item.to_bytes())
                    .map_err(e)?;
                self.save()?;
                Ok(Response::Ok)
            }
            Request::ExportKey { id, method } => {
                self.vault()?;
                // Prove a factor again: an unlocked vault alone is not enough.
                self.prove(&method)?;
                match &self.item(&id)?.key {
                    Some(KeyData::Ssh { openssh, .. }) => {
                        Ok(Response::ExportedKey(ssh::private_text(openssh)?))
                    }
                    Some(KeyData::OpenPgp { tsk, .. }) => {
                        Ok(Response::ExportedKey(pgp::secret_armored(tsk)?))
                    }
                    None => Err("this item has no key".into()),
                }
            }
            Request::GeneratePgpKey {
                title,
                user_id,
                post_quantum,
                confirm,
            } => {
                let key = pgp::generate(&user_id, post_quantum, confirm)?;
                self.new_key_item(title, key)
            }
            Request::ImportPgpKey {
                title,
                key,
                passphrase,
                confirm,
            } => {
                let key = pgp::import(&key, passphrase.as_deref().map(|s| s.as_str()), confirm)?;
                self.new_key_item(title, key)
            }
            Request::PgpSign {
                id,
                data,
                armor,
                text,
            } => {
                let (title, tsk, confirm) = self.pgp_key(&id)?;
                let sig = pgp::sign(&tsk, &data, armor, text)?;
                self.needs_approval(confirm, &title, "sign data with OpenPGP");
                Ok(Response::Bytes(sig))
            }
            Request::PgpDecrypt { message } => {
                for (title, tsk, confirm) in self.pgp_keys()? {
                    if let Ok(plaintext) = pgp::decrypt(&tsk, &message) {
                        self.needs_approval(confirm, &title, "decrypt an OpenPGP message");
                        return Ok(Response::Decrypted {
                            plaintext,
                            key: title,
                        });
                    }
                }
                Err("no OpenPGP key in the vault can decrypt this message".into())
            }
            Request::PgpEncrypt {
                to_items,
                to_certs,
                data,
                armor,
                sign_with,
            } => {
                let mut certs = Vec::new();
                for id in &to_items {
                    certs.push(pgp::certificate(&self.pgp_key(id)?.1)?);
                }
                for c in &to_certs {
                    certs.push(pgp::certificate(c)?);
                }
                let signer = sign_with.map(|id| self.pgp_key(&id)).transpose()?;
                let out = pgp::encrypt(&certs, &data, armor, signer.as_ref().map(|s| &s.1[..]))?;
                if let Some((title, _, confirm)) = &signer {
                    self.needs_approval(*confirm, title, "sign an encrypted OpenPGP message");
                }
                Ok(Response::Bytes(out))
            }
            Request::PgpVerify {
                data,
                signature,
                certs,
            } => {
                let mut all = Vec::new();
                for (_, tsk, _) in self.pgp_keys()? {
                    all.push(pgp::certificate(&tsk)?);
                }
                for c in &certs {
                    all.push(pgp::certificate(c)?);
                }
                Ok(Response::Verified(pgp::verify(&all, &data, &signature)?))
            }
            Request::Status
            | Request::Init { .. }
            | Request::Pair { .. }
            | Request::PasskeySlots
            | Request::Unlock { .. }
            | Request::SetSync { .. }
            | Request::Lock
            | Request::LockFully
            | Request::Generate { .. }
            | Request::GenerateStyled { .. } => {
                unreachable!("handled in dispatch")
            }
            Request::SetQuickUnlock { hours } => {
                self.vault()?;
                self.set_quick_unlock(hours)
            }
        }
    }
}

impl Daemon {
    fn new_key_item(&mut self, title: String, key: KeyData) -> R<Response> {
        if title.trim().is_empty() {
            return Err("give the key a title".into());
        }
        let t = now();
        let mut item = ItemData::default();
        item.title = title;
        item.created = t;
        item.modified = t;
        item.key = Some(key);
        let rng = &mut OsRandom;
        let v = self.vault()?;
        let id = v.new_item_id(rng).map_err(e)?;
        v.put_item(rng, &id, &item.to_bytes()).map_err(e)?;
        self.save()?;
        Ok(Response::ItemSaved { id })
    }
}

/// An item as clients see it: private keys stay in the daemon.
fn without_key(mut item: ItemData) -> ItemData {
    item.key = None;
    item
}

fn describe_key(k: &KeyData) -> String {
    match k {
        KeyData::Ssh { openssh, .. } => {
            ssh::describe(openssh).unwrap_or_else(|_| "unreadable SSH key".into())
        }
        KeyData::OpenPgp { tsk, .. } => {
            pgp::describe(tsk).unwrap_or_else(|_| "unreadable OpenPGP key".into())
        }
    }
}

fn totp(item: &ItemData) -> R<Response> {
    let cfg = item.totp.as_ref().ok_or("this item has no TOTP seed")?;
    let t = now();
    Ok(Response::Totp {
        code: Zeroizing::new(cfg.code_at(t).map_err(e)?),
        remaining: cfg.remaining(t),
    })
}

/// Cards and identities are not bound to sites, so they are filled only into
/// `https` pages (and the extension fills only the top frame).
fn form_origin(origin: &str) -> R<()> {
    if origin.starts_with("https://") && origin.len() > "https://".len() {
        Ok(())
    } else {
        Err("cards and addresses are filled only on https pages".into())
    }
}

fn fits(f: &Factor, m: &UnlockMethod) -> bool {
    matches!(
        (f, m),
        (Factor::PasswordOnly, UnlockMethod::Password { .. })
            | (Factor::PasswordFido2 { .. }, UnlockMethod::Fido2 { .. })
            | (Factor::PasswordTpm { .. }, UnlockMethod::Tpm { .. })
            | (Factor::Recovery, UnlockMethod::Recovery { .. })
    ) || matches!(
        (f, m),
        (
            Factor::PasswordFido2 { credential_id: c, require_uv: true, .. },
            UnlockMethod::Passkey { credential_id, .. },
        ) if c == credential_id
    )
}

/// A PRF output from a client as a hardware key.
fn prf_key(out: &[u8]) -> R<HwKey> {
    let b: [u8; 32] = out
        .try_into()
        .map_err(|_| "a passkey PRF output is 32 bytes")?;
    Ok(HwKey::new(b))
}

fn check_password(p: &str) -> R<()> {
    if p.chars().count() < 8 {
        Err("the password must be at least 8 characters".into())
    } else {
        Ok(())
    }
}
