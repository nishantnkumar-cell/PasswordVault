//! The freedesktop Secret Service (`org.freedesktop.secrets`) on the
//! session bus, so apps that keep passwords through libsecret (mail and chat
//! clients, NetworkManager applets, `secret-tool`) keep them in the vault.
//!
//! One collection, "Vault", also reachable as the `default` alias. Only items
//! created through this API are visible here; the user's own logins, cards
//! and keys never are. Each program must be allowed once in the approval
//! window before it can list, read, change or delete them, and nothing is
//! readable while the vault is locked: an `Unlock` prompt opens the desktop
//! app and waits for the user to unlock there. As the brief says, a D-Bus
//! sender is identified by its process's executable only, so the approval
//! is advisory against programs running as the same user.
//!
//! Sessions: `plain`, and `dh-ietf1024-sha256-aes128-cbc-pkcs7`, which
//! libsecret prefers and which keeps secrets out of a bus monitor's view.
//!
//! Storage: an app password is a login whose password is the secret and
//! whose custom fields carry the metadata, so the desktop app shows it like
//! any other login and folder sync carries it: [`MARKER`] holds the content
//! type, [`ATTR_PREFIX`]`name` each attribute.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vault_core::item::{CustomField, FieldKind, ItemData, ItemKind};
use vault_core::{ItemId, OsRandom, SecureRandom};
use zbus::blocking::{Connection, MessageIterator, fdo::DBusProxy};
use zbus::fdo::RequestNameFlags;
use zbus::fdo::RequestNameReply;
use zbus::message::{Header, Type};
use zbus::names::BusName;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{MatchRule, Message};
use zeroize::Zeroizing;

use crate::approve::{self, AppPrompt, Prompt};
use crate::server::Shared;

/// The bus name.
pub const NAME: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
/// The one collection.
pub const COLLECTION: &str = "/org/freedesktop/secrets/collection/vault";
const ALIAS: &str = "/org/freedesktop/secrets/aliases/default";
const SESSIONS: &str = "/org/freedesktop/secrets/session/";
const PROMPTS: &str = "/org/freedesktop/secrets/prompt/";

const I_SERVICE: &str = "org.freedesktop.Secret.Service";
const I_COLLECTION: &str = "org.freedesktop.Secret.Collection";
const I_ITEM: &str = "org.freedesktop.Secret.Item";
const I_SESSION: &str = "org.freedesktop.Secret.Session";
const I_PROMPT: &str = "org.freedesktop.Secret.Prompt";
const I_PROPS: &str = "org.freedesktop.DBus.Properties";

const P_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const P_ATTRS: &str = "org.freedesktop.Secret.Item.Attributes";

/// Custom field marking an app password; its value is the content type.
pub const MARKER: &str = "Secret Service";
/// Custom field present, with value `base64`, when the secret was not text.
pub const ENCODING: &str = "Secret Service encoding";
/// Prefix of the custom fields holding the attributes.
pub const ATTR_PREFIX: &str = "ss:";

/// Largest secret accepted.
const MAX_SECRET: usize = 256 * 1024;
/// Most open sessions per bus connection.
const MAX_SESSIONS: usize = 64;
/// How long an unlock prompt waits for the user.
const UNLOCK_WAIT: Duration = Duration::from_secs(300);
/// How long a program declined in the approval window is refused without
/// asking again.
const DECLINE_HOLD: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Items

/// Whether `item` is an app password stored through this API.
pub fn is_app_secret(item: &ItemData) -> bool {
    item.kind == ItemKind::Login && item.fields.iter().any(|f| f.name == MARKER)
}

/// An app password's attributes.
pub fn attributes(item: &ItemData) -> HashMap<String, String> {
    item.fields
        .iter()
        .filter_map(|f| {
            f.name
                .strip_prefix(ATTR_PREFIX)
                .map(|n| (n.to_owned(), f.value.clone()))
        })
        .collect()
}

fn content_type(item: &ItemData) -> String {
    item.fields
        .iter()
        .find(|f| f.name == MARKER)
        .map(|f| f.value.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "text/plain".into())
}

/// The stored secret's bytes.
pub fn secret_of(item: &ItemData) -> Zeroizing<Vec<u8>> {
    use base64::Engine;
    let b64 = item
        .fields
        .iter()
        .any(|f| f.name == ENCODING && f.value == "base64");
    if b64 && let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(&item.password) {
        return Zeroizing::new(raw);
    }
    Zeroizing::new(item.password.as_bytes().to_vec())
}

/// Store `secret` (text where it is UTF-8, else base64) and its type.
pub fn set_secret(item: &mut ItemData, secret: &[u8], content_type: &str) {
    use base64::Engine;
    use zeroize::Zeroize;
    item.password.zeroize();
    item.fields
        .retain(|f| f.name != MARKER && f.name != ENCODING);
    match std::str::from_utf8(secret) {
        Ok(s) => item.password = s.to_owned(),
        Err(_) => {
            item.password = base64::engine::general_purpose::STANDARD.encode(secret);
            item.fields.push(field(ENCODING, "base64"));
        }
    }
    let ct: String = content_type
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    item.fields.insert(0, field(MARKER, &ct));
}

/// Replace the attributes.
pub fn set_attributes(item: &mut ItemData, attrs: &HashMap<String, String>) {
    item.fields.retain(|f| !f.name.starts_with(ATTR_PREFIX));
    let mut sorted: Vec<_> = attrs.iter().collect();
    sorted.sort();
    for (k, v) in sorted {
        item.fields.push(field(&format!("{ATTR_PREFIX}{k}"), v));
    }
}

/// A new app password.
pub fn new_app_secret(
    label: &str,
    attrs: &HashMap<String, String>,
    secret: &[u8],
    content_type: &str,
) -> ItemData {
    let mut item = ItemData::new(ItemKind::Login, label_or_default(label));
    set_secret(&mut item, secret, content_type);
    set_attributes(&mut item, attrs);
    item
}

fn label_or_default(label: &str) -> String {
    let l = label.trim();
    if l.is_empty() {
        "App password".into()
    } else {
        l.into()
    }
}

fn field(name: &str, value: &str) -> CustomField {
    CustomField {
        name: name.into(),
        value: value.into(),
        kind: FieldKind::Text,
    }
}

fn matches(item: &ItemData, want: &HashMap<String, String>) -> bool {
    let have = attributes(item);
    want.iter().all(|(k, v)| have.get(k) == Some(v))
}

fn item_path(id: &ItemId) -> OwnedObjectPath {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    OwnedObjectPath::try_from(format!("{COLLECTION}/{hex}")).expect("hex is a valid path element")
}

/// The item ID in an item's object path.
fn item_id(path: &str) -> Option<ItemId> {
    let hex = path
        .strip_prefix(COLLECTION)
        .or_else(|| path.strip_prefix(ALIAS))?
        .strip_prefix('/')?;
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

fn is_collection(path: &str) -> bool {
    path == COLLECTION || path == ALIAS
}

// ---------------------------------------------------------------------------
// Sessions

/// RFC 2409 section 6.2, the Second Oakley Group (1024-bit MODP), generator 2.
const MODP1024: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE65381FFFFFFFFFFFFFFFF";

/// How secrets travel in a session.
pub enum Cipher {
    Plain,
    /// AES-128-CBC with PKCS#7 padding and a fresh IV per secret.
    Aes(Zeroizing<[u8; 16]>),
}

/// The `dh-ietf1024-sha256-aes128-cbc-pkcs7` exchange: from the client's
/// public value, our public value and the session key. Also used by tests,
/// as the client side.
pub fn dh_exchange(peer: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), String> {
    use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
    use crypto_bigint::{Encoding, U1024};
    let peer = peer.strip_prefix(&[0u8][..]).unwrap_or(peer);
    if peer.is_empty() || peer.len() > 128 {
        return Err("bad public key".into());
    }
    let mut padded = [0u8; 128];
    padded[128 - peer.len()..].copy_from_slice(peer);
    let y = U1024::from_be_slice(&padded);
    let p = U1024::from_be_hex(MODP1024);
    // 1 < y < p - 1, so the shared value is not trivially known.
    if y <= U1024::ONE || y >= p.wrapping_sub(&U1024::ONE) {
        return Err("bad public key".into());
    }
    let mut priv_bytes = Zeroizing::new([0u8; 128]);
    OsRandom
        .fill(&mut priv_bytes[..])
        .map_err(|_| "no randomness")?;
    let x = U1024::from_be_slice(&priv_bytes[..]);
    let params = DynResidueParams::new(&p);
    let ours = DynResidue::new(&U1024::from_u8(2), params)
        .pow(&x)
        .retrieve();
    let shared = Zeroizing::new(DynResidue::new(&y, params).pow(&x).retrieve().to_be_bytes());
    let mut key = Zeroizing::new([0u8; 16]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, &shared[..])
        .expand(&[], &mut key[..])
        .map_err(|_| "key derivation failed")?;
    Ok((ours.to_be_bytes().to_vec(), key))
}

impl Cipher {
    /// (parameters, value) for a secret struct.
    pub fn seal(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
        match self {
            Cipher::Plain => Ok((Vec::new(), secret.to_vec())),
            Cipher::Aes(key) => {
                let mut iv = [0u8; 16];
                OsRandom.fill(&mut iv).map_err(|_| "no randomness")?;
                let ct = cbc::Encryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(secret);
                Ok((iv.to_vec(), ct))
            }
        }
    }

    /// The secret in a secret struct's parameters and value.
    pub fn open(&self, params: &[u8], value: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
        match self {
            Cipher::Plain => Ok(Zeroizing::new(value.to_vec())),
            Cipher::Aes(key) => {
                let iv: [u8; 16] = params.try_into().map_err(|_| "bad IV")?;
                cbc::Decryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| "the secret could not be decrypted".into())
            }
        }
    }
}

struct Session {
    /// The bus connection that opened it; nobody else may use it.
    owner: String,
    cipher: Cipher,
}

// ---------------------------------------------------------------------------
// The service

/// A secret struct: session, parameters, value, content type.
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

enum Fail {
    Locked,
    NoSession,
    NoObject,
    Denied(String),
    NotSupported(&'static str),
    UnknownMethod,
    Invalid(String),
    Failed(String),
}

type Res = Result<(), Fail>;

impl From<zbus::Error> for Fail {
    fn from(e: zbus::Error) -> Fail {
        Fail::Invalid(e.to_string())
    }
}

impl From<zbus::fdo::Error> for Fail {
    fn from(e: zbus::fdo::Error) -> Fail {
        Fail::Failed(e.to_string())
    }
}

impl From<zbus::zvariant::Error> for Fail {
    fn from(e: zbus::zvariant::Error) -> Fail {
        Fail::Invalid(e.to_string())
    }
}

struct PendingPrompt {
    owner: String,
    objects: Vec<OwnedObjectPath>,
    started: bool,
    dismissed: Arc<AtomicBool>,
}

#[derive(Default)]
struct State {
    next: u64,
    sessions: HashMap<String, Session>,
    prompts: HashMap<String, PendingPrompt>,
    /// Executables the user allowed, until vaultd restarts.
    allowed: HashSet<String>,
    declined: HashMap<String, Instant>,
}

/// The Secret Service on one bus connection.
pub struct Service {
    conn: Connection,
    daemon: Shared,
    owner: u32,
    unlock_ui: Option<PathBuf>,
    state: Mutex<State>,
    /// One approval window for this service at a time, so a program's
    /// burst of calls waits for one answer instead of failing.
    asking: Mutex<()>,
}

/// Why [`serve`] stopped.
#[derive(Debug)]
pub enum Stop {
    /// Another Secret Service (GNOME Keyring, KWallet) owns the name.
    NameTaken,
    Bus(zbus::Error),
}

impl From<zbus::Error> for Stop {
    fn from(e: zbus::Error) -> Stop {
        Stop::Bus(e)
    }
}

impl From<zbus::fdo::Error> for Stop {
    fn from(e: zbus::fdo::Error) -> Stop {
        Stop::Bus(e.into())
    }
}

/// The desktop app, started by an unlock prompt: `VAULT_GUI`, else
/// `vault-gui` next to this executable.
pub fn find_unlock_ui() -> Option<PathBuf> {
    let exe = match std::env::var_os("VAULT_GUI") {
        Some(p) => PathBuf::from(p),
        None => std::env::current_exe().ok()?.with_file_name("vault-gui"),
    };
    exe.is_file().then_some(exe)
}

/// Serve the Secret Service on `conn` for `daemon`, admitting only callers
/// running as `owner`. Returns only if the name is taken or the bus fails.
pub fn serve(
    conn: Connection,
    daemon: Shared,
    owner: u32,
    unlock_ui: Option<PathBuf>,
) -> Result<(), Stop> {
    // Listen before taking the name, so no call is missed.
    let messages = MessageIterator::from(&conn);
    let bus = DBusProxy::new(&conn)?;
    bus.add_match_rule(
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender("org.freedesktop.DBus")?
            .member("NameOwnerChanged")?
            .build(),
    )?;
    match conn.request_name_with_flags(NAME, RequestNameFlags::DoNotQueue.into()) {
        Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => {}
        Ok(_) | Err(zbus::Error::NameTaken) => return Err(Stop::NameTaken),
        Err(e) => return Err(e.into()),
    }
    let svc = Arc::new(Service {
        conn: conn.clone(),
        daemon,
        owner,
        unlock_ui,
        state: Mutex::new(State::default()),
        asking: Mutex::new(()),
    });
    for msg in messages {
        let msg = msg?;
        match msg.message_type() {
            Type::MethodCall => {
                let svc = svc.clone();
                std::thread::spawn(move || svc.call(&msg));
            }
            Type::Signal => svc.signal(&msg),
            _ => {}
        }
    }
    Ok(())
}

/// Serve on the session bus. Runs on its own thread; logs and gives up if
/// there is no session bus or another Secret Service is running.
pub fn run(daemon: Shared, owner: u32) {
    let conn = match Connection::session() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vaultd: warning: no session bus, not serving the Secret Service: {e}");
            return;
        }
    };
    eprintln!("vaultd: Secret Service on the session bus");
    match serve(conn, daemon, owner, find_unlock_ui()) {
        Ok(()) => {}
        Err(Stop::NameTaken) => eprintln!(
            "vaultd: warning: another Secret Service (GNOME Keyring or KWallet?) is running; \
             not serving it. Stop that one and restart vaultd."
        ),
        Err(Stop::Bus(e)) => eprintln!("vaultd: warning: lost the Secret Service bus: {e}"),
    }
}

impl Service {
    fn lock(&self) -> std::sync::MutexGuard<'_, crate::daemon::Daemon> {
        self.daemon.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A bus connection went away: drop its sessions and prompts.
    fn signal(&self, msg: &Message) {
        let h = msg.header();
        if h.member().map(|m| m.as_str()) != Some("NameOwnerChanged") {
            return;
        }
        if let Ok((name, _old, new)) = msg.body().deserialize::<(String, String, String)>()
            && new.is_empty()
        {
            let mut st = self.state();
            st.sessions.retain(|_, s| s.owner != name);
            st.prompts.retain(|_, p| {
                let keep = p.owner != name;
                if !keep {
                    p.dismissed.store(true, Ordering::SeqCst);
                }
                keep
            });
        }
    }

    fn call(&self, msg: &Message) {
        let h = msg.header();
        let r = self.dispatch(msg, &h);
        if let Err(f) = r {
            let (name, text) = match f {
                Fail::Locked => (
                    "org.freedesktop.Secret.Error.IsLocked",
                    "the vault is locked".to_owned(),
                ),
                Fail::NoSession => (
                    "org.freedesktop.Secret.Error.NoSession",
                    "no such session".to_owned(),
                ),
                Fail::NoObject => (
                    "org.freedesktop.Secret.Error.NoSuchObject",
                    "no such object".to_owned(),
                ),
                Fail::Denied(m) => ("org.freedesktop.DBus.Error.AccessDenied", m),
                Fail::NotSupported(m) => ("org.freedesktop.DBus.Error.NotSupported", m.to_owned()),
                Fail::UnknownMethod => (
                    "org.freedesktop.DBus.Error.UnknownMethod",
                    "unknown method".to_owned(),
                ),
                Fail::Invalid(m) => ("org.freedesktop.DBus.Error.InvalidArgs", m),
                Fail::Failed(m) => ("org.freedesktop.DBus.Error.Failed", m),
            };
            let _ = self.conn.reply_error(&h, name, &text);
        }
    }

    fn reply<B>(&self, h: &Header<'_>, body: &B) -> Res
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        let _ = self.conn.reply(h, body);
        Ok(())
    }

    fn dispatch(&self, msg: &Message, h: &Header<'_>) -> Res {
        let path = h.path().map(|p| p.as_str()).unwrap_or("");
        let iface = h.interface().map(|i| i.as_str()).unwrap_or("");
        let member = h.member().map(|m| m.as_str()).unwrap_or("");
        let sender = h.sender().map(|s| s.to_string()).unwrap_or_default();
        match (iface, member) {
            ("org.freedesktop.DBus.Peer", "Ping") => return self.reply(h, &()),
            ("org.freedesktop.DBus.Introspectable", "Introspect") => {
                return self.reply(h, &introspect(path));
            }
            (I_PROPS, _) => return self.properties(msg, h, path, member, &sender),
            _ => {}
        }
        if path == SERVICE {
            return self.service(msg, h, iface, member, &sender);
        }
        if is_collection(path) {
            return self.collection(msg, h, iface, member, &sender);
        }
        if path.starts_with(SESSIONS) {
            if (iface, member) != (I_SESSION, "Close") && member != "Close" {
                return Err(Fail::UnknownMethod);
            }
            let mut st = self.state();
            match st.sessions.get(path) {
                Some(s) if s.owner == sender => {
                    st.sessions.remove(path);
                }
                _ => return Err(Fail::NoSession),
            }
            drop(st);
            return self.reply(h, &());
        }
        if path.starts_with(PROMPTS) {
            return self.prompt(msg, h, member, path, &sender);
        }
        if let Some(id) = item_id(path) {
            return self.item(msg, h, iface, member, &sender, &id);
        }
        Err(Fail::NoObject)
    }

    // -- approval

    /// Let `sender` at the vault's app passwords, asking the user the first
    /// time its program does.
    fn allow(&self, sender: &str) -> Res {
        let bus = DBusProxy::new(&self.conn)?;
        let name = BusName::try_from(sender).map_err(|e| Fail::Invalid(e.to_string()))?;
        let uid = bus.get_connection_unix_user(name.clone())?;
        if uid != self.owner {
            return Err(Fail::Denied("this vault belongs to another user".into()));
        }
        let pid = bus.get_connection_unix_process_id(name).ok();
        let program = pid.and_then(approve::program_of);
        if let Some(p) = &program {
            let st = self.state();
            if st.allowed.contains(p) {
                return Ok(());
            }
            if st
                .declined
                .get(p)
                .is_some_and(|t| t.elapsed() < DECLINE_HOLD)
            {
                return Err(Fail::Denied("declined in the approval window".into()));
            }
        }
        let _one = self.asking.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(p) = &program
            && self.state().allowed.contains(p)
        {
            return Ok(());
        }
        let approver = self.lock().begin_app_prompt().map_err(Fail::Denied)?;
        let prompt = Prompt::App(AppPrompt {
            program: program.clone(),
            command: pid.and_then(approve::command_of),
        });
        let answer = approver.approve(&prompt);
        self.lock().end_app_prompt(&answer);
        match answer {
            Ok(true) => {
                // An unknown program is allowed this once only.
                if let Some(p) = program {
                    self.state().allowed.insert(p);
                }
                Ok(())
            }
            Ok(false) => {
                if let Some(p) = program {
                    self.state().declined.insert(p, Instant::now());
                }
                Err(Fail::Denied("declined in the approval window".into()))
            }
            Err(m) => Err(Fail::Failed(format!(
                "could not show the approval window: {m}"
            ))),
        }
    }

    /// Allowed and unlocked.
    fn open_for(&self, sender: &str) -> Res {
        if !self.lock().is_unlocked() {
            return Err(Fail::Locked);
        }
        self.allow(sender)
    }

    // -- data

    fn items(&self, want: &HashMap<String, String>) -> Result<Vec<(ItemId, ItemData)>, Fail> {
        let mut found = self
            .lock()
            .items_where(|it| is_app_secret(it) && matches(it, want))
            .map_err(|_| Fail::Locked)?;
        found.sort_by_key(|(_, it)| std::cmp::Reverse(it.modified));
        Ok(found)
    }

    fn get(&self, id: &ItemId) -> Result<ItemData, Fail> {
        let mut d = self.lock();
        if !d.is_unlocked() {
            return Err(Fail::Locked);
        }
        d.items_where(is_app_secret)
            .map_err(|_| Fail::Locked)?
            .into_iter()
            .find(|(i, _)| i == id)
            .map(|(_, it)| it)
            .ok_or(Fail::NoObject)
    }

    fn put(&self, id: Option<ItemId>, item: ItemData) -> Result<ItemId, Fail> {
        self.lock().put_item(id, item).map_err(Fail::Failed)
    }

    fn secret_struct(
        &self,
        session: &str,
        sender: &str,
        item: &ItemData,
    ) -> Result<SecretStruct, Fail> {
        let st = self.state();
        let s = st
            .sessions
            .get(session)
            .filter(|s| s.owner == sender)
            .ok_or(Fail::NoSession)?;
        let (params, value) = s.cipher.seal(&secret_of(item)).map_err(Fail::Failed)?;
        Ok((path(session)?, params, value, content_type(item)))
    }

    fn read_secret(
        &self,
        sender: &str,
        secret: &SecretStruct,
    ) -> Result<(Zeroizing<Vec<u8>>, String), Fail> {
        let (session, params, value, ct) = secret;
        if value.len() > MAX_SECRET {
            return Err(Fail::Invalid("the secret is too large".into()));
        }
        let st = self.state();
        let s = st
            .sessions
            .get(session.as_str())
            .filter(|s| s.owner == sender)
            .ok_or(Fail::NoSession)?;
        let plain = s.cipher.open(params, value).map_err(Fail::Invalid)?;
        Ok((plain, ct.clone()))
    }

    fn signal_item(&self, member: &str, id: &ItemId) {
        let _ = self.conn.emit_signal(
            None::<&str>,
            COLLECTION,
            I_COLLECTION,
            member,
            &item_path(id),
        );
    }

    fn next_path(&self, base: &str) -> String {
        let mut st = self.state();
        st.next += 1;
        format!("{base}s{}", st.next)
    }

    // -- org.freedesktop.Secret.Service

    fn service(
        &self,
        msg: &Message,
        h: &Header<'_>,
        iface: &str,
        member: &str,
        sender: &str,
    ) -> Res {
        if !iface.is_empty() && iface != I_SERVICE {
            return Err(Fail::UnknownMethod);
        }
        match member {
            "OpenSession" => {
                let (alg, input): (String, OwnedValue) = msg.body().deserialize()?;
                let (output, cipher) = match alg.as_str() {
                    "plain" => (Value::from(""), Cipher::Plain),
                    "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                        let peer: Vec<u8> = input
                            .try_into()
                            .map_err(|_| Fail::Invalid("expected a byte array".into()))?;
                        let (ours, key) = dh_exchange(&peer).map_err(Fail::Invalid)?;
                        (Value::from(ours), Cipher::Aes(key))
                    }
                    _ => return Err(Fail::NotSupported("unsupported session algorithm")),
                };
                let p = self.next_path(SESSIONS);
                {
                    let mut st = self.state();
                    if st.sessions.values().filter(|s| s.owner == sender).count() >= MAX_SESSIONS {
                        return Err(Fail::Failed("too many open sessions".into()));
                    }
                    st.sessions.insert(
                        p.clone(),
                        Session {
                            owner: sender.to_owned(),
                            cipher,
                        },
                    );
                }
                self.reply(h, &(output, path(&p)?))
            }
            "SearchItems" => {
                let want: HashMap<String, String> = msg.body().deserialize()?;
                let none: Vec<OwnedObjectPath> = Vec::new();
                if !self.lock().is_unlocked() {
                    return self.reply(h, &(none.clone(), none));
                }
                self.allow(sender)?;
                let found = self.items(&want)?;
                let paths: Vec<_> = found.iter().map(|(id, _)| item_path(id)).collect();
                self.reply(h, &(paths, none))
            }
            "GetSecrets" => {
                let (items, session): (Vec<OwnedObjectPath>, OwnedObjectPath) =
                    msg.body().deserialize()?;
                self.open_for(sender)?;
                let mut out: HashMap<OwnedObjectPath, SecretStruct> = HashMap::new();
                for p in items {
                    let Some(id) = item_id(p.as_str()) else {
                        continue;
                    };
                    let Ok(item) = self.get(&id) else { continue };
                    out.insert(p, self.secret_struct(session.as_str(), sender, &item)?);
                }
                self.reply(h, &out)
            }
            "Unlock" => {
                let objects: Vec<OwnedObjectPath> = msg.body().deserialize()?;
                let ours: Vec<OwnedObjectPath> = objects
                    .into_iter()
                    .filter(|p| is_collection(p.as_str()) || item_id(p.as_str()).is_some())
                    .collect();
                if self.lock().is_unlocked() {
                    return self.reply(h, &(ours, path("/")?));
                }
                let p = self.next_path(PROMPTS);
                self.state().prompts.insert(
                    p.clone(),
                    PendingPrompt {
                        owner: sender.to_owned(),
                        objects: ours,
                        started: false,
                        dismissed: Arc::new(AtomicBool::new(false)),
                    },
                );
                self.reply(h, &(Vec::<OwnedObjectPath>::new(), path(&p)?))
            }
            "Lock" => {
                let objects: Vec<OwnedObjectPath> = msg.body().deserialize()?;
                self.lock().lock();
                let ours: Vec<OwnedObjectPath> = objects
                    .into_iter()
                    .filter(|p| is_collection(p.as_str()) || item_id(p.as_str()).is_some())
                    .collect();
                self.reply(h, &(ours, path("/")?))
            }
            "ReadAlias" => {
                let name: String = msg.body().deserialize()?;
                let p = if name == "default" { COLLECTION } else { "/" };
                self.reply(h, &path(p)?)
            }
            "SetAlias" => {
                let (name, target): (String, OwnedObjectPath) = msg.body().deserialize()?;
                if name == "default" && is_collection(target.as_str()) {
                    return self.reply(h, &());
                }
                Err(Fail::NotSupported(
                    "this vault has one collection, the default",
                ))
            }
            "CreateCollection" => {
                let (_props, alias): (HashMap<String, OwnedValue>, String) =
                    msg.body().deserialize()?;
                if alias == "default" {
                    return self.reply(h, &(path(COLLECTION)?, path("/")?));
                }
                Err(Fail::NotSupported(
                    "this vault has one collection, the default",
                ))
            }
            _ => Err(Fail::UnknownMethod),
        }
    }

    // -- org.freedesktop.Secret.Collection

    fn collection(
        &self,
        msg: &Message,
        h: &Header<'_>,
        iface: &str,
        member: &str,
        sender: &str,
    ) -> Res {
        if !iface.is_empty() && iface != I_COLLECTION {
            return Err(Fail::UnknownMethod);
        }
        match member {
            "SearchItems" => {
                let want: HashMap<String, String> = msg.body().deserialize()?;
                if !self.lock().is_unlocked() {
                    return self.reply(h, &Vec::<OwnedObjectPath>::new());
                }
                self.allow(sender)?;
                let found = self.items(&want)?;
                let paths: Vec<_> = found.iter().map(|(id, _)| item_path(id)).collect();
                self.reply(h, &paths)
            }
            "CreateItem" => {
                let (props, secret, replace): (HashMap<String, OwnedValue>, SecretStruct, bool) =
                    msg.body().deserialize()?;
                self.open_for(sender)?;
                let label = match props.get(P_LABEL) {
                    Some(v) => String::try_from(v.try_clone()?)?,
                    None => String::new(),
                };
                let attrs: HashMap<String, String> = match props.get(P_ATTRS) {
                    Some(v) => HashMap::try_from(v.try_clone()?)?,
                    None => HashMap::new(),
                };
                let (plain, ct) = self.read_secret(sender, &secret)?;
                let existing = if replace {
                    self.items(&attrs)?
                        .into_iter()
                        .find(|(_, it)| attributes(it) == attrs)
                } else {
                    None
                };
                let (id, created) = match existing {
                    Some((id, mut item)) => {
                        item.title = label_or_default(&label);
                        set_secret(&mut item, &plain, &ct);
                        (self.put(Some(id), item)?, false)
                    }
                    None => (
                        self.put(None, new_app_secret(&label, &attrs, &plain, &ct))?,
                        true,
                    ),
                };
                self.signal_item(
                    if created {
                        "ItemCreated"
                    } else {
                        "ItemChanged"
                    },
                    &id,
                );
                self.reply(h, &(item_path(&id), path("/")?))
            }
            "Delete" => Err(Fail::NotSupported(
                "the vault's collection cannot be deleted over the Secret Service",
            )),
            _ => Err(Fail::UnknownMethod),
        }
    }

    // -- org.freedesktop.Secret.Item

    fn item(
        &self,
        msg: &Message,
        h: &Header<'_>,
        iface: &str,
        member: &str,
        sender: &str,
        id: &ItemId,
    ) -> Res {
        if !iface.is_empty() && iface != I_ITEM {
            return Err(Fail::UnknownMethod);
        }
        self.open_for(sender)?;
        let item = self.get(id)?;
        match member {
            "GetSecret" => {
                let session: OwnedObjectPath = msg.body().deserialize()?;
                let s = self.secret_struct(session.as_str(), sender, &item)?;
                self.reply(h, &(s,))
            }
            "SetSecret" => {
                let secret: SecretStruct = msg.body().deserialize()?;
                let (plain, ct) = self.read_secret(sender, &secret)?;
                let mut item = item;
                set_secret(&mut item, &plain, &ct);
                self.put(Some(*id), item)?;
                self.signal_item("ItemChanged", id);
                self.reply(h, &())
            }
            "Delete" => {
                self.lock().delete_item(id).map_err(Fail::Failed)?;
                self.signal_item("ItemDeleted", id);
                self.reply(h, &path("/")?)
            }
            _ => Err(Fail::UnknownMethod),
        }
    }

    // -- org.freedesktop.Secret.Prompt

    fn prompt(&self, _msg: &Message, h: &Header<'_>, member: &str, p: &str, sender: &str) -> Res {
        let mut st = self.state();
        let Some(pending) = st.prompts.get_mut(p).filter(|x| x.owner == sender) else {
            return Err(Fail::NoObject);
        };
        match member {
            "Prompt" => {
                if pending.started {
                    return Err(Fail::Failed("this prompt was already shown".into()));
                }
                pending.started = true;
                let dismissed = pending.dismissed.clone();
                drop(st);
                if let Some(ui) = &self.unlock_ui {
                    let _ = std::process::Command::new(ui)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .spawn()
                        .map(|mut c| std::thread::spawn(move || c.wait()));
                }
                self.reply(h, &())?;
                self.wait_for_unlock(p, &dismissed);
                Ok(())
            }
            "Dismiss" => {
                let started = pending.started;
                pending.dismissed.store(true, Ordering::SeqCst);
                if !started {
                    st.prompts.remove(p);
                    drop(st);
                    self.complete(p, true, Vec::new());
                }
                self.reply(h, &())
            }
            _ => Err(Fail::UnknownMethod),
        }
    }

    /// Wait for the user to unlock the vault anywhere (the desktop app, the
    /// CLI), then complete the prompt.
    fn wait_for_unlock(&self, p: &str, dismissed: &AtomicBool) {
        let start = Instant::now();
        let unlocked = loop {
            if self.lock().is_unlocked() {
                break true;
            }
            if dismissed.load(Ordering::SeqCst) || start.elapsed() >= UNLOCK_WAIT {
                break false;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        let objects = self
            .state()
            .prompts
            .remove(p)
            .map(|x| x.objects)
            .unwrap_or_default();
        if unlocked {
            self.complete(p, false, objects);
        } else {
            self.complete(p, true, Vec::new());
        }
    }

    fn complete(&self, p: &str, dismissed: bool, objects: Vec<OwnedObjectPath>) {
        let result = Value::from(objects);
        let _ = self
            .conn
            .emit_signal(None::<&str>, p, I_PROMPT, "Completed", &(dismissed, result));
    }

    // -- org.freedesktop.DBus.Properties

    fn properties(
        &self,
        msg: &Message,
        h: &Header<'_>,
        p: &str,
        member: &str,
        sender: &str,
    ) -> Res {
        match member {
            "Get" => {
                let (iface, name): (String, String) = msg.body().deserialize()?;
                let all = self.props(p, &iface, sender, Some(&name))?;
                let v = all
                    .into_iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v)
                    .ok_or_else(|| Fail::Invalid(format!("no property {name}")))?;
                self.reply(h, &v)
            }
            "GetAll" => {
                let iface: String = msg.body().deserialize()?;
                let all: HashMap<&str, Value<'static>> =
                    self.props(p, &iface, sender, None)?.into_iter().collect();
                self.reply(h, &all)
            }
            "Set" => {
                let (iface, name, value): (String, String, OwnedValue) =
                    msg.body().deserialize()?;
                let id = item_id(p)
                    .filter(|_| iface == I_ITEM)
                    .ok_or_else(|| Fail::Denied(format!("{name} cannot be changed")))?;
                self.open_for(sender)?;
                let mut item = self.get(&id)?;
                match name.as_str() {
                    "Label" => item.title = label_or_default(&String::try_from(value)?),
                    "Attributes" => set_attributes(&mut item, &HashMap::try_from(value)?),
                    _ => return Err(Fail::Denied(format!("{name} cannot be changed"))),
                }
                self.put(Some(id), item)?;
                self.signal_item("ItemChanged", &id);
                self.reply(h, &())
            }
            _ => Err(Fail::UnknownMethod),
        }
    }

    /// The properties of the object at `p`. `only` names the one wanted, so
    /// that reading `Locked` needs no approval.
    fn props(
        &self,
        p: &str,
        iface: &str,
        sender: &str,
        only: Option<&str>,
    ) -> Result<Vec<(&'static str, Value<'static>)>, Fail> {
        let locked = !self.lock().is_unlocked();
        let wants = |n: &str| only.is_none_or(|o| o == n);
        if p == SERVICE && iface == I_SERVICE {
            return Ok(vec![("Collections", Value::from(vec![path(COLLECTION)?]))]);
        }
        if is_collection(p) && iface == I_COLLECTION {
            let mut out = vec![
                ("Label", Value::from("Vault")),
                ("Locked", Value::from(locked)),
                ("Created", Value::from(0u64)),
                ("Modified", Value::from(0u64)),
            ];
            if wants("Items") {
                let items: Vec<OwnedObjectPath> = if locked {
                    Vec::new()
                } else {
                    self.allow(sender)?;
                    self.items(&HashMap::new())?
                        .iter()
                        .map(|(id, _)| item_path(id))
                        .collect()
                };
                out.push(("Items", Value::from(items)));
            }
            return Ok(out);
        }
        if let Some(id) = item_id(p)
            && iface == I_ITEM
        {
            if only == Some("Locked") {
                return Ok(vec![("Locked", Value::from(locked))]);
            }
            self.open_for(sender)?;
            let item = self.get(&id)?;
            return Ok(vec![
                ("Locked", Value::from(false)),
                ("Label", Value::from(item.title.clone())),
                ("Attributes", Value::from(attributes(&item))),
                ("Created", Value::from(item.created)),
                ("Modified", Value::from(item.modified)),
            ]);
        }
        if p.starts_with(SESSIONS) || p.starts_with(PROMPTS) {
            return Ok(Vec::new());
        }
        Err(Fail::Invalid(format!("no interface {iface} here")))
    }
}

fn path(p: &str) -> Result<OwnedObjectPath, Fail> {
    ObjectPath::try_from(p)
        .map(OwnedObjectPath::from)
        .map_err(|e| Fail::Invalid(e.to_string()))
}

/// Introspection data, for tools such as `busctl` and D-Spy.
fn introspect(p: &str) -> String {
    const HEAD: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.freedesktop.DBus.Introspectable"><method name="Introspect"><arg name="xml" type="s" direction="out"/></method></interface>
 <interface name="org.freedesktop.DBus.Properties">
  <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
  <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
  <method name="Set"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/></method>
 </interface>
"#;
    let body = if p == SERVICE {
        r#" <interface name="org.freedesktop.Secret.Service">
  <method name="OpenSession"><arg name="algorithm" type="s" direction="in"/><arg name="input" type="v" direction="in"/><arg name="output" type="v" direction="out"/><arg name="result" type="o" direction="out"/></method>
  <method name="CreateCollection"><arg name="properties" type="a{sv}" direction="in"/><arg name="alias" type="s" direction="in"/><arg name="collection" type="o" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
  <method name="SearchItems"><arg name="attributes" type="a{ss}" direction="in"/><arg name="unlocked" type="ao" direction="out"/><arg name="locked" type="ao" direction="out"/></method>
  <method name="Unlock"><arg name="objects" type="ao" direction="in"/><arg name="unlocked" type="ao" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
  <method name="Lock"><arg name="objects" type="ao" direction="in"/><arg name="locked" type="ao" direction="out"/><arg name="Prompt" type="o" direction="out"/></method>
  <method name="GetSecrets"><arg name="items" type="ao" direction="in"/><arg name="session" type="o" direction="in"/><arg name="secrets" type="a{o(oayays)}" direction="out"/></method>
  <method name="ReadAlias"><arg name="name" type="s" direction="in"/><arg name="collection" type="o" direction="out"/></method>
  <method name="SetAlias"><arg name="name" type="s" direction="in"/><arg name="collection" type="o" direction="in"/></method>
  <property name="Collections" type="ao" access="read"/>
 </interface>
 <node name="collection"/><node name="aliases"/>
"#
    } else if is_collection(p) {
        r#" <interface name="org.freedesktop.Secret.Collection">
  <method name="Delete"><arg name="prompt" type="o" direction="out"/></method>
  <method name="SearchItems"><arg name="attributes" type="a{ss}" direction="in"/><arg name="results" type="ao" direction="out"/></method>
  <method name="CreateItem"><arg name="properties" type="a{sv}" direction="in"/><arg name="secret" type="(oayays)" direction="in"/><arg name="replace" type="b" direction="in"/><arg name="item" type="o" direction="out"/><arg name="prompt" type="o" direction="out"/></method>
  <signal name="ItemCreated"><arg name="item" type="o"/></signal>
  <signal name="ItemDeleted"><arg name="item" type="o"/></signal>
  <signal name="ItemChanged"><arg name="item" type="o"/></signal>
  <property name="Items" type="ao" access="read"/>
  <property name="Label" type="s" access="read"/>
  <property name="Locked" type="b" access="read"/>
  <property name="Created" type="t" access="read"/>
  <property name="Modified" type="t" access="read"/>
 </interface>
"#
    } else if item_id(p).is_some() {
        r#" <interface name="org.freedesktop.Secret.Item">
  <method name="Delete"><arg name="Prompt" type="o" direction="out"/></method>
  <method name="GetSecret"><arg name="session" type="o" direction="in"/><arg name="secret" type="(oayays)" direction="out"/></method>
  <method name="SetSecret"><arg name="secret" type="(oayays)" direction="in"/></method>
  <property name="Locked" type="b" access="read"/>
  <property name="Attributes" type="a{ss}" access="readwrite"/>
  <property name="Label" type="s" access="readwrite"/>
  <property name="Created" type="t" access="read"/>
  <property name="Modified" type="t" access="read"/>
 </interface>
"#
    } else if p.starts_with(SESSIONS) {
        r#" <interface name="org.freedesktop.Secret.Session"><method name="Close"/></interface>
"#
    } else if p.starts_with(PROMPTS) {
        r#" <interface name="org.freedesktop.Secret.Prompt">
  <method name="Prompt"><arg name="window-id" type="s" direction="in"/></method>
  <method name="Dismiss"/>
  <signal name="Completed"><arg name="dismissed" type="b"/><arg name="result" type="v"/></signal>
 </interface>
"#
    } else {
        let child = ["/", "/org", "/org/freedesktop"]
            .iter()
            .position(|x| *x == p)
            .map(|i| ["org", "freedesktop", "secrets"][i]);
        return match child {
            Some(c) => format!("{HEAD} <node name=\"{c}\"/>\n</node>\n"),
            None => format!("{HEAD}</node>\n"),
        };
    };
    format!("{HEAD}{body}</node>\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_secrets_round_trip_through_items() {
        let attrs: HashMap<String, String> = [("service", "mail"), ("user", "alex@example.com")]
            .into_iter()
            .map(|(a, b)| (a.into(), b.into()))
            .collect();
        let item = new_app_secret("Mail", &attrs, b"hunter22", "text/plain");
        assert!(is_app_secret(&item));
        assert_eq!(attributes(&item), attrs);
        assert_eq!(&secret_of(&item)[..], b"hunter22");
        assert_eq!(item.password, "hunter22");
        let mut user = ItemData::new(ItemKind::Login, "Mine");
        user.password = "x".into();
        assert!(!is_app_secret(&user));

        // Binary secrets are kept as base64.
        let mut bin = new_app_secret(
            "",
            &HashMap::new(),
            &[0xff, 0, 1],
            "application/octet-stream",
        );
        assert_eq!(bin.title, "App password");
        assert_eq!(&secret_of(&bin)[..], &[0xff, 0, 1]);
        assert_eq!(content_type(&bin), "application/octet-stream");
        set_secret(&mut bin, b"text again", "text/plain");
        assert_eq!(&secret_of(&bin)[..], b"text again");
        assert!(!bin.fields.iter().any(|f| f.name == ENCODING));

        // Surviving a save: normalize keeps login passwords and the fields.
        let mut saved = ItemData::from_bytes(&item.to_bytes()).unwrap();
        saved.normalize();
        assert!(is_app_secret(&saved) && attributes(&saved) == attrs);
    }

    #[test]
    fn matching_needs_every_attribute() {
        let attrs: HashMap<String, String> = [
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "2".to_owned()),
        ]
        .into();
        let item = new_app_secret("x", &attrs, b"s", "text/plain");
        assert!(matches(&item, &HashMap::new()));
        assert!(matches(&item, &[("a".to_owned(), "1".to_owned())].into()));
        assert!(!matches(&item, &[("a".to_owned(), "2".to_owned())].into()));
        assert!(!matches(&item, &[("c".to_owned(), "1".to_owned())].into()));
    }

    #[test]
    fn item_paths_round_trip() {
        let id = [0xab; 16];
        let p = item_path(&id);
        assert_eq!(item_id(p.as_str()), Some(id));
        assert_eq!(item_id(&format!("{ALIAS}/{}", "ab".repeat(16))), Some(id));
        assert_eq!(item_id(COLLECTION), None);
        assert_eq!(item_id(&format!("{COLLECTION}/zz")), None);
        assert_eq!(item_id("/elsewhere/abababababababababababababababab"), None);
    }

    #[test]
    fn dh_sessions_agree_and_encrypt() {
        use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
        use crypto_bigint::{Encoding, U1024};
        // A client with private value 12345.
        let p = U1024::from_be_hex(MODP1024);
        let params = DynResidueParams::new(&p);
        let x = U1024::from_u32(12345);
        let client = DynResidue::new(&U1024::from_u8(2), params)
            .pow(&x)
            .retrieve();
        let (server, key) = dh_exchange(&client.to_be_bytes()).unwrap();
        let shared = DynResidue::new(&U1024::from_be_slice(&server), params)
            .pow(&x)
            .retrieve()
            .to_be_bytes();
        let mut ckey = [0u8; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &shared)
            .expand(&[], &mut ckey)
            .unwrap();
        assert_eq!(ckey, *key);

        let c = Cipher::Aes(key);
        let (iv, ct) = c.seal(b"correct horse").unwrap();
        assert_eq!((iv.len(), ct.len()), (16, 16));
        assert_eq!(&c.open(&iv, &ct).unwrap()[..], b"correct horse");
        assert!(c.open(&iv[..8], &ct).is_err());

        assert!(dh_exchange(&[1]).is_err());
        assert!(dh_exchange(&p.to_be_bytes()).is_err());
        assert!(dh_exchange(&[]).is_err());
    }

    #[test]
    fn introspection_names_the_interfaces() {
        assert!(introspect(SERVICE).contains(I_SERVICE));
        assert!(introspect(COLLECTION).contains(I_COLLECTION));
        assert!(introspect(&item_path(&[1; 16])).contains(I_ITEM));
        assert!(introspect("/org").contains("<node name=\"freedesktop\"/>"));
    }
}
