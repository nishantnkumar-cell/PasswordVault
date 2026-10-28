//! The window: create, pair, unlock, then browse and edit items.
//!
//! All vault data comes from `vaultd`; the app keeps only what is on screen
//! and drops it (and clears a password it put on the clipboard) when the
//! vault locks.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, CornerRadius, Key, Margin, Rect, RichText, Stroke, TextEdit, Ui, Vec2};
use vault_core::item::{Card, CustomField, FieldKind, Identity, ItemData, ItemKind, UrlEntry};
use vault_core::origin::MatchMode;
use vault_core::totp::TotpConfig;
use vault_ipc::{
    ClientScope, ClientToken, GenerateOptions, ImportFormat, ItemId, ItemSummary, KeyKind,
    PasswordStyle, Request, Response, Secret, SlotId, SlotInfo, StatusInfo, UnlockMethod,
};
use zeroize::Zeroizing;

use crate::client::{Backend, Failure, Paths, Phone, SystemPhone, Work};
use crate::theme::{self, Icon};

mod keys;
mod setup;

/// How long a copied secret stays on the clipboard.
pub const CLIPBOARD_CLEAR: Duration = Duration::from_secs(30);
const STATUS_EVERY: Duration = Duration::from_secs(2);
const CLIENT_NAME: &str = "desktop app";
/// Height of the bar across the top of the unlocked window.
const TOP_BAR: f32 = 60.0;
/// Width of the sidebar, and of the app's name above it.
const SIDEBAR: f32 = 236.0;

/// The system clipboard, or a stand-in for tests.
pub trait Clip {
    fn set(&mut self, text: &str) -> Result<(), String>;
    fn get(&mut self) -> Option<String>;
    fn clear(&mut self);
}

/// What this system calls its quick unlock check (vault_hw::PRESENCE_NAME).
pub(crate) const HELLO: &str = if cfg!(target_os = "macos") {
    "Touch ID"
} else {
    "Windows Hello"
};
/// The ways the quick unlock check accepts, as a sentence start.
pub(crate) const HELLO_WAYS: &str = if cfg!(target_os = "macos") {
    "Your fingerprint, Apple Watch or Mac password"
} else {
    "Face, fingerprint or your Windows PIN"
};
/// What to show while the quick unlock check waits for the person.
pub(crate) const HELLO_CONFIRM: &str = if cfg!(target_os = "macos") {
    "Confirm it's you with Touch ID…"
} else {
    "Confirm it's you in the Windows Security window…"
};

/// The command palette's shortcut as this system writes it.
const PALETTE_KEY: &str = if cfg!(target_os = "macos") {
    "Cmd K"
} else {
    "Ctrl K"
};

/// The OS clipboard. On Windows and macOS copied secrets are marked so
/// clipboard history and sync skip them.
#[derive(Default)]
pub struct SystemClip(Option<arboard::Clipboard>);

impl SystemClip {
    fn board(&mut self) -> Result<&mut arboard::Clipboard, String> {
        if self.0.is_none() {
            self.0 = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        Ok(self.0.as_mut().expect("set above"))
    }
}

impl Clip for SystemClip {
    fn set(&mut self, text: &str) -> Result<(), String> {
        let set = self.board()?.set();
        #[cfg(target_os = "windows")]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_history().exclude_from_cloud()
        };
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        set.text(text).map_err(|e| e.to_string())
    }
    fn get(&mut self) -> Option<String> {
        self.board().ok()?.get_text().ok()
    }
    fn clear(&mut self) {
        if let Ok(b) = self.board() {
            let _ = b.clear();
        }
    }
}

/// What an answer from the daemon is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Status,
    Init,
    Pair,
    Unlock,
    Lock,
    ListItems,
    OpenItem(ItemId),
    Totp(ItemId),
    Save,
    Delete(ItemId),
    Generate,
    GenerateForEdit,
    Import,
    ListSlots,
    AddSlot,
    RemoveSlot(SlotId),
    PublicKey(ItemId),
    KeyConfirm,
    NewKey,
    ImportKey,
    ExportKey(ItemId),
    /// Encrypt, decrypt, sign or verify on the OpenPGP page.
    Pgp,
    Sync,
    QuickUnlock,
    /// An unlock method added from the first-run wizard.
    SetupSlot(setup::Extra),
    /// Windows Hello or Touch ID quick unlock turned on from the wizard.
    SetupHello,
}

/// Which screen is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Connecting,
    Unreachable(String),
    /// No vault yet: the first-run wizard.
    Create,
    /// The wizard's steps after the vault is made.
    Setup,
    Pair,
    Locked,
    Unlocked,
}

/// Pages of the unlocked window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Items,
    Generator,
    Import,
    Slots,
    Sync,
    /// Encrypt, decrypt, sign and verify with OpenPGP keys.
    Pgp,
}

/// Which items the list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    Kind(ItemKind),
    Codes,
    Keys,
}

impl Filter {
    /// The sidebar's item categories, in order, with their names.
    const NAV: [(Filter, &'static str); 7] = [
        (Filter::All, "All items"),
        (Filter::Kind(ItemKind::Login), "Logins"),
        (Filter::Kind(ItemKind::Note), "Secure notes"),
        (Filter::Kind(ItemKind::Card), "Cards"),
        (Filter::Kind(ItemKind::Identity), "Identities"),
        (Filter::Codes, "One-time codes"),
        (Filter::Keys, "SSH and PGP keys"),
    ];

    fn name(self) -> &'static str {
        Self::NAV
            .iter()
            .find(|(f, _)| *f == self)
            .map_or("Items", |(_, name)| name)
    }

    /// What the list says when this category has nothing in it.
    fn empty(self) -> &'static str {
        match self {
            Filter::All => "No items yet.",
            Filter::Kind(ItemKind::Login) => "No logins yet.",
            Filter::Kind(ItemKind::Note) => "No secure notes yet.",
            Filter::Kind(ItemKind::Card) => "No cards yet.",
            Filter::Kind(ItemKind::Identity) => "No identities yet.",
            Filter::Codes => {
                "No one-time codes yet. Edit a login and paste its 2FA setup key to add one."
            }
            Filter::Keys => "No SSH or PGP keys yet.",
        }
    }

    /// A short name for the search field: "Search keys", "in Keys".
    fn short(self) -> &'static str {
        match self {
            Filter::All => "All items",
            Filter::Kind(ItemKind::Login) => "Logins",
            Filter::Kind(ItemKind::Note) => "Notes",
            Filter::Kind(ItemKind::Card) => "Cards",
            Filter::Kind(ItemKind::Identity) => "Identities",
            Filter::Codes => "Codes",
            Filter::Keys => "Keys",
        }
    }

    fn icon(self) -> Icon {
        match self {
            Filter::All => Icon::Grid,
            Filter::Kind(k) => kind_icon(k),
            Filter::Codes => Icon::Clock,
            Filter::Keys => Icon::Terminal,
        }
    }

    /// The top bar's New button in this category: its label and what it
    /// starts. All items has a menu instead.
    fn new_button(self) -> Option<(&'static str, Quick)> {
        Some(match self {
            Filter::All => return None,
            Filter::Kind(ItemKind::Login) | Filter::Codes => {
                ("New login", Quick::Item(ItemKind::Login))
            }
            Filter::Kind(ItemKind::Note) => ("New secure note", Quick::Item(ItemKind::Note)),
            Filter::Kind(ItemKind::Card) => ("New card", Quick::Item(ItemKind::Card)),
            Filter::Kind(ItemKind::Identity) => ("New identity", Quick::Item(ItemKind::Identity)),
            Filter::Keys => ("New SSH key", Quick::Key(false)),
        })
    }

    fn admits(self, i: &ItemSummary) -> bool {
        match self {
            Filter::All => true,
            // Keys are stored as logins but listed on their own.
            Filter::Kind(k) => i.kind == k && i.key.is_none(),
            Filter::Codes => i.has_totp,
            Filter::Keys => i.key.is_some(),
        }
    }
}

/// The icon for a kind of item.
fn kind_icon(k: ItemKind) -> Icon {
    match k {
        ItemKind::Login => Icon::Key,
        ItemKind::Note => Icon::Note,
        ItemKind::Card => Icon::Card,
        ItemKind::Identity => Icon::Identity,
    }
}

/// What a New button starts.
#[derive(Clone, Copy)]
enum Quick {
    Item(ItemKind),
    Key(bool),
    /// Import an SSH key (`false`) or an OpenPGP key (`true`).
    Import(bool),
}

/// A secret to copy once the daemon sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Password,
    Code,
}

/// The Ctrl K palette: one box to find an item or run an action.
#[derive(Default)]
struct Palette {
    query: String,
    sel: usize,
    focused: bool,
}

/// What a palette row does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Copy(ItemId, Field),
    CopyUsername(ItemId),
    Open(ItemId),
    NewItem,
    /// Make an SSH key (`false`) or an OpenPGP key (`true`).
    NewKey(bool),
    /// Import an SSH key (`false`) or an OpenPGP key (`true`).
    ImportKey(bool),
    Pgp(keys::Task),
    Generate,
    Go(View),
    Lock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Method {
    #[default]
    Password,
    SecurityKey,
    Phone,
    Tpm,
    Recovery,
}

#[derive(Default)]
struct UnlockForm {
    method: Method,
    password: Secret,
    pin: Secret,
    code: Secret,
}

/// On Windows vaultd uses Windows' security key service, which asks for the
/// key's PIN in its own window and ignores one sent by the app.
const WINDOWS_ASKS_KEY_PIN: bool = cfg!(windows);

/// Phone passkeys work on Linux and Windows; macOS comes later.
const PHONE: bool = cfg!(any(target_os = "linux", windows));

/// What to do on the phone, once the app shows the QR code (Linux) or
/// Windows shows its window.
const PHONE_HOW: &str = if cfg!(windows) {
    "In the Windows window, choose \"iPhone, iPad or Android device\", scan the QR code with \
     your phone's camera and confirm on the phone. Bluetooth must be on on both."
} else {
    "Scan the QR code with your phone's camera and confirm on the phone. Bluetooth must be on \
     on both, and the phone needs an internet connection."
};

fn opt(s: &Secret) -> Option<Secret> {
    (!s.is_empty()).then(|| s.clone())
}

impl UnlockForm {
    fn to_method(&self) -> UnlockMethod {
        match self.method {
            Method::Password => UnlockMethod::Password {
                password: self.password.clone(),
            },
            Method::SecurityKey => UnlockMethod::Fido2 {
                password: self.password.clone(),
                pin: opt(&self.pin),
            },
            Method::Phone => unreachable!("the phone runs as `Work::PhoneUnlock`"),
            Method::Tpm => UnlockMethod::Tpm {
                password: self.password.clone(),
                pin: opt(&self.pin),
            },
            Method::Recovery => UnlockMethod::Recovery {
                code: self.code.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum SlotKind {
    #[default]
    Password,
    SecurityKey,
    Phone,
    Tpm,
    Recovery,
}

#[derive(Default)]
struct SlotForm {
    kind: SlotKind,
    label: String,
    password: Secret,
    password2: Secret,
    pin: Secret,
    require_uv: bool,
    bind_pcr7: bool,
}

/// An item being created or edited.
struct Edit {
    id: Option<ItemId>,
    kind: ItemKind,
    title: String,
    username: String,
    password: Secret,
    reveal: bool,
    urls: Vec<UrlEntry>,
    totp: Option<TotpConfig>,
    totp_input: Secret,
    holder: String,
    number: Secret,
    expiry: String,
    cvv: Secret,
    pin: Secret,
    identity: Identity,
    fields: Vec<FieldEdit>,
    notes: Secret,
}

/// A custom field in the edit form.
struct FieldEdit {
    name: String,
    value: Secret,
    hidden: bool,
}

impl Edit {
    fn new(kind: ItemKind) -> Edit {
        Edit {
            id: None,
            kind,
            title: String::new(),
            username: String::new(),
            password: Secret::default(),
            reveal: false,
            urls: vec![blank_url()],
            totp: None,
            totp_input: Secret::default(),
            holder: String::new(),
            number: Secret::default(),
            expiry: String::new(),
            cvv: Secret::default(),
            pin: Secret::default(),
            identity: Identity::default(),
            fields: Vec::new(),
            notes: Secret::default(),
        }
    }

    fn from_item(id: ItemId, item: &ItemData) -> Edit {
        let card = item.card.clone().unwrap_or_default();
        Edit {
            id: Some(id),
            kind: item.kind,
            title: item.title.clone(),
            username: item.username.clone(),
            password: Zeroizing::new(item.password.clone()),
            reveal: false,
            urls: item.urls.clone(),
            totp: item.totp.clone(),
            totp_input: Secret::default(),
            holder: card.holder.clone(),
            number: Zeroizing::new(card.number.clone()),
            expiry: card.expiry(),
            cvv: Zeroizing::new(card.cvv.clone()),
            pin: Zeroizing::new(card.pin.clone()),
            identity: item.identity.clone().unwrap_or_default(),
            fields: item
                .fields
                .iter()
                .map(|f| FieldEdit {
                    name: f.name.clone(),
                    value: Zeroizing::new(f.value.clone()),
                    hidden: f.kind == FieldKind::Hidden,
                })
                .collect(),
            notes: Zeroizing::new(item.notes.clone()),
        }
    }

    fn to_item(&self) -> Result<ItemData, String> {
        if self.title.trim().is_empty() {
            return Err("Give the item a title.".into());
        }
        let mut item = ItemData::new(self.kind, self.title.trim());
        match self.kind {
            ItemKind::Login => {
                item.totp = if self.totp_input.trim().is_empty() {
                    self.totp.clone()
                } else {
                    Some(TotpConfig::parse(&self.totp_input).map_err(|e| format!("TOTP: {e}"))?)
                };
                item.username = self.username.clone();
                item.password = self.password.to_string();
                item.urls = self
                    .urls
                    .iter()
                    .filter(|u| !u.url.trim().is_empty())
                    .map(|u| UrlEntry {
                        url: u.url.trim().to_owned(),
                        ..u.clone()
                    })
                    .collect();
            }
            ItemKind::Note => {}
            ItemKind::Card => {
                let (exp_month, exp_year) = if self.expiry.trim().is_empty() {
                    (0, 0)
                } else {
                    Card::parse_expiry(&self.expiry)
                        .ok_or("Type the expiry as MM/YY, for example 07/31.")?
                };
                item.card = Some(Card {
                    holder: self.holder.trim().to_owned(),
                    number: Card::clean_number(&self.number),
                    exp_month,
                    exp_year,
                    cvv: self.cvv.trim().to_owned(),
                    pin: self.pin.trim().to_owned(),
                });
            }
            ItemKind::Identity => item.identity = Some(self.identity.clone()),
        }
        item.fields = self
            .fields
            .iter()
            .filter(|f| !f.name.trim().is_empty() || !f.value.is_empty())
            .map(|f| CustomField {
                name: f.name.trim().to_owned(),
                value: f.value.to_string(),
                kind: if f.hidden {
                    FieldKind::Hidden
                } else {
                    FieldKind::Text
                },
            })
            .collect();
        item.notes = self.notes.to_string();
        Ok(item)
    }
}

/// The form for making a new SSH or OpenPGP key inside `vaultd`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyForm {
    pgp: bool,
    title: String,
    /// SSH: ECDSA P-256 instead of Ed25519.
    ecdsa: bool,
    /// OpenPGP: the name and email the key is made for.
    name: String,
    email: String,
    /// OpenPGP: v6 ML-DSA/ML-KEM instead of v4 Ed25519/Curve25519.
    post_quantum: bool,
    confirm: bool,
}

impl KeyForm {
    fn new(pgp: bool) -> KeyForm {
        KeyForm {
            pgp,
            title: String::new(),
            ecdsa: false,
            name: String::new(),
            email: String::new(),
            post_quantum: false,
            confirm: true,
        }
    }

    /// The OpenPGP user ID, "Name <mail@example.com>" or just "Name".
    fn user_id(&self) -> Result<String, String> {
        let name = self.name.trim();
        let email = self.email.trim();
        if name.is_empty() {
            return Err("Type the name the key is for.".into());
        }
        if name.contains(['<', '>']) {
            return Err("The name can't contain < or >.".into());
        }
        if email.is_empty() {
            return Ok(name.to_owned());
        }
        let ok = email.split_once('@').is_some_and(|(user, host)| {
            !user.is_empty() && host.contains('.') && !host.ends_with('.')
        }) && !email.contains(['<', '>', ' ']);
        if !ok {
            return Err("That email address doesn't look right.".into());
        }
        Ok(format!("{name} <{email}>"))
    }

    fn to_request(&self) -> Result<Request, String> {
        let title = self.title.trim().to_owned();
        let confirm = self.confirm;
        if self.pgp {
            let user_id = self.user_id()?;
            let title = if title.is_empty() {
                self.name.trim().to_owned()
            } else {
                title
            };
            Ok(Request::GeneratePgpKey {
                title,
                user_id,
                post_quantum: self.post_quantum,
                confirm,
            })
        } else {
            if title.is_empty() {
                return Err(
                    "Give the key a title, such as the computer or service it is for.".into(),
                );
            }
            let kind = if self.ecdsa {
                KeyKind::SshEcdsaP256
            } else {
                KeyKind::SshEd25519
            };
            Ok(Request::GenerateKey {
                title,
                kind,
                confirm,
            })
        }
    }
}

fn blank_url() -> UrlEntry {
    UrlEntry {
        url: String::new(),
        mode: MatchMode::Origin,
        allow_http: false,
    }
}

/// The desktop app.
pub struct App {
    paths: Paths,
    backend: Backend<Op>,
    token: Option<ClientToken>,
    clip: Box<dyn Clip>,

    screen: Screen,
    status: Option<(StatusInfo, Instant)>,
    status_sent: Option<Instant>,
    busy: Option<&'static str>,
    error: Option<String>,
    notice: Option<String>,

    unlock: UnlockForm,
    new_password: Secret,
    new_password2: Secret,
    setup: Option<setup::Setup>,

    view: View,
    search: String,
    items: Vec<ItemSummary>,
    selected: Option<ItemId>,
    open: Option<(ItemId, ItemData)>,
    reveal: bool,
    totp: Option<(ItemId, Secret, Instant)>,
    totp_pending: bool,
    edit: Option<Edit>,
    new_key: Option<KeyForm>,
    import_key: Option<keys::KeyImport>,
    export: Option<keys::Export>,
    pgp: keys::PgpTools,
    confirm_delete: bool,
    /// The open key item's public half, to show and copy.
    public_key: Option<(ItemId, String)>,

    generator: Generator,
    generated: Option<Secret>,

    import_format: ImportFormat,
    import_path: String,

    slots: Vec<SlotInfo>,
    slot_form: SlotForm,
    new_recovery: Option<Secret>,
    confirm_remove: Option<SlotId>,

    sync_path: String,
    /// Hours picked on the quick unlock form; `None` until first shown.
    quick_hours: Option<u32>,

    copied: Option<(Secret, Instant)>,

    styled: bool,
    filter: Filter,
    palette: Option<Palette>,
    pending_copy: Option<(ItemId, Field)>,
}

impl App {
    /// Connect to the daemon at `paths`. `wake` repaints the window when an
    /// answer arrives.
    pub fn new(paths: Paths, clip: Box<dyn Clip>, wake: impl Fn() + Send + 'static) -> App {
        App::with_phone(paths, clip, wake, Arc::new(SystemPhone))
    }

    /// Like [`App::new`], with `phone` standing in for the phone (tests).
    pub fn with_phone(
        paths: Paths,
        clip: Box<dyn Clip>,
        wake: impl Fn() + Send + 'static,
        phone: Arc<dyn Phone>,
    ) -> App {
        let backend = Backend::start(paths.socket.clone(), wake, phone);
        let token = paths.load_token();
        App {
            paths,
            backend,
            token,
            clip,
            screen: Screen::Connecting,
            status: None,
            status_sent: None,
            busy: None,
            error: None,
            notice: None,
            unlock: UnlockForm::default(),
            new_password: Secret::default(),
            new_password2: Secret::default(),
            setup: None,
            view: View::Items,
            search: String::new(),
            items: Vec::new(),
            selected: None,
            open: None,
            reveal: false,
            totp: None,
            totp_pending: false,
            edit: None,
            new_key: None,
            import_key: None,
            export: None,
            pgp: keys::PgpTools::default(),
            confirm_delete: false,
            public_key: None,
            generator: Generator::default(),
            generated: None,
            import_format: ImportFormat::BitwardenJson,
            import_path: String::new(),
            slots: Vec::new(),
            slot_form: SlotForm::default(),
            new_recovery: None,
            confirm_remove: None,
            sync_path: String::new(),
            quick_hours: None,
            copied: None,
            styled: false,
            filter: Filter::All,
            palette: None,
            pending_copy: None,
        }
    }

    /// The current screen.
    pub fn screen(&self) -> &Screen {
        &self.screen
    }

    /// Calls to the daemon not yet answered.
    pub fn pending(&self) -> usize {
        self.backend.in_flight()
    }

    /// The error shown at the top of the window, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Item summaries currently held.
    pub fn items(&self) -> &[ItemSummary] {
        &self.items
    }

    fn send(&mut self, op: Op, request: Request) {
        if op == Op::Status {
            self.status_sent = Some(Instant::now());
        }
        self.backend.send(op, self.token.clone(), request);
    }

    fn act(&mut self, busy: &'static str, op: Op, request: Request) {
        self.error = None;
        self.notice = None;
        self.busy = Some(busy);
        self.send(op, request);
    }

    fn act_work(&mut self, busy: &'static str, op: Op, work: Work) {
        self.error = None;
        self.notice = None;
        self.busy = Some(busy);
        self.backend.send_work(op, self.token.clone(), work);
    }

    fn refresh(&mut self) {
        self.send(Op::Status, Request::Status);
    }

    /// Drop everything read from the vault.
    fn wipe(&mut self) {
        self.items.clear();
        self.selected = None;
        self.open = None;
        self.reveal = false;
        self.totp = None;
        self.edit = None;
        self.confirm_delete = false;
        self.public_key = None;
        self.import_key = None;
        self.export = None;
        self.pgp = keys::PgpTools::default();
        self.generated = None;
        self.slots.clear();
        self.slot_form = SlotForm::default();
        self.new_recovery = None;
        self.confirm_remove = None;
        self.palette = None;
        self.pending_copy = None;
        self.clear_clipboard();
    }

    fn clear_clipboard(&mut self) {
        if let Some((text, _)) = self.copied.take()
            && self.clip.get().as_deref() == Some(text.as_str())
        {
            self.clip.clear();
        }
    }

    fn copy(&mut self, text: &str, what: &str) {
        match self.clip.set(text) {
            Ok(()) => {
                self.copied = Some((Zeroizing::new(text.to_owned()), Instant::now()));
                self.notice = Some(format!(
                    "{what} copied. The clipboard clears in {} seconds.",
                    CLIPBOARD_CLEAR.as_secs()
                ));
            }
            Err(e) => self.error = Some(format!("Couldn't copy: {e}")),
        }
    }

    fn go_unpaired(&mut self, msg: &str) {
        self.paths.forget_token();
        self.token = None;
        self.wipe();
        self.screen = Screen::Pair;
        self.error = Some(msg.into());
    }

    fn on_status(&mut self, s: StatusInfo) {
        let next = if let Some(screen) = self.setup_screen(&s) {
            screen
        } else if self.token.is_none() {
            Screen::Pair
        } else if !s.unlocked {
            Screen::Locked
        } else {
            Screen::Unlocked
        };
        if matches!(self.screen, Screen::Unlocked | Screen::Setup)
            && !matches!(next, Screen::Unlocked | Screen::Setup)
        {
            self.wipe();
            if next == Screen::Locked {
                self.notice = Some("The vault locked.".into());
            }
        }
        if next == Screen::Unlocked && !matches!(self.screen, Screen::Unlocked | Screen::Setup) {
            self.view = View::Items;
            self.send(Op::ListItems, Request::ListItems);
        } else if next == Screen::Unlocked
            && self.status.as_ref().map(|(o, _)| o.generation) != Some(s.generation)
        {
            // Written since the last look, perhaps by a sync from another device.
            self.send(Op::ListItems, Request::ListItems);
        }
        self.screen = next;
        self.status = Some((s, Instant::now()));
    }

    fn on_result(&mut self, op: Op, r: Result<Response, Failure>) {
        if !matches!(op, Op::Status | Op::Totp(_)) {
            self.busy = None;
        }
        if let Op::Totp(_) = op {
            self.totp_pending = false;
        }
        let r = match r {
            Ok(r) => r,
            Err(Failure::Unreachable(m)) => {
                self.wipe();
                self.screen = Screen::Unreachable(m);
                return;
            }
            Err(Failure::Daemon(m)) if m.contains("unknown client token") => {
                self.go_unpaired("The vault no longer knows this app. Pair it again.");
                return;
            }
            Err(Failure::Daemon(m)) => {
                self.on_key_error(op, &m);
                if m.contains("locked") && self.screen == Screen::Unlocked {
                    self.refresh();
                }
                self.error = Some(m);
                return;
            }
        };
        match (op, r) {
            (Op::Status, Response::Status(s)) => self.on_status(s),
            (op @ (Op::Init | Op::SetupSlot(_) | Op::SetupHello), r) => self.on_setup_result(op, r),
            (op @ (Op::ImportKey | Op::ExportKey(_) | Op::Pgp), r) => self.on_key_result(op, r),
            (Op::Pair, Response::Paired { token }) => {
                if let Err(e) = self.paths.save_token(&token) {
                    self.error = Some(format!("Couldn't save this app's pairing: {e}"));
                }
                self.token = Some(token);
                self.unlock = UnlockForm::default();
                self.refresh();
            }
            (Op::Unlock, Response::Ok) => {
                self.unlock = UnlockForm {
                    method: self.unlock.method,
                    ..UnlockForm::default()
                };
                self.refresh();
            }
            (Op::Lock, Response::Ok) => {
                self.wipe();
                self.screen = Screen::Locked;
                self.refresh();
            }
            (Op::ListItems, Response::Items(mut items)) => {
                items.sort_by_key(|i| i.title.to_lowercase());
                self.items = items;
            }
            (Op::OpenItem(_), Response::Item { id, item }) => {
                if self.selected == Some(id) {
                    if item.totp.is_some() {
                        self.totp_pending = true;
                        self.send(Op::Totp(id), Request::Totp { id });
                    }
                    if self.pending_copy == Some((id, Field::Password)) {
                        self.pending_copy = None;
                        let pw = Zeroizing::new(item.password.clone());
                        self.copy(&pw, "Password");
                    }
                    if self.items.iter().any(|i| i.id == id && i.key.is_some())
                        && self.public_key.as_ref().is_none_or(|(k, _)| *k != id)
                    {
                        self.send(Op::PublicKey(id), Request::PublicKey { id });
                    }
                    self.open = Some((id, item));
                    self.reveal = false;
                    self.confirm_delete = false;
                }
            }
            (Op::Totp(id), Response::Totp { code, remaining }) => {
                if self.pending_copy == Some((id, Field::Code)) {
                    self.pending_copy = None;
                    self.copy(&code, "Code");
                }
                self.totp = Some((id, code, Instant::now() + Duration::from_secs(remaining)));
            }
            (Op::Save, Response::ItemSaved { id }) => {
                self.edit = None;
                self.notice = Some("Saved.".into());
                self.select(id);
                self.send(Op::ListItems, Request::ListItems);
            }
            (Op::Delete(id), Response::Ok) => {
                if self.selected == Some(id) {
                    self.selected = None;
                    self.open = None;
                }
                self.notice = Some("Deleted.".into());
                self.send(Op::ListItems, Request::ListItems);
            }
            (Op::Generate, Response::Generated(p)) => self.generated = Some(p),
            (Op::GenerateForEdit, Response::Generated(p)) => {
                if let Some(e) = &mut self.edit {
                    e.password = p;
                }
            }
            (Op::Import, Response::Imported(n)) => {
                self.notice = Some(format!(
                    "Imported {n} items. Delete the export file now: it is not encrypted."
                ));
                self.import_path.clear();
                self.send(Op::ListItems, Request::ListItems);
            }
            (Op::ListSlots, Response::Slots(s)) => self.slots = s,
            (Op::AddSlot, Response::SlotAdded { recovery_code, .. }) => {
                self.slot_form = SlotForm::default();
                self.new_recovery = recovery_code;
                self.notice = Some("Unlock method added.".into());
                self.send(Op::ListSlots, Request::ListSlots);
            }
            (Op::PublicKey(id), Response::PublicKey(text)) => {
                self.public_key = Some((id, text));
            }
            (Op::NewKey, Response::ItemSaved { id }) => {
                self.new_key = None;
                self.notice = Some(
                    "Key made. Copy its public key below and give it to the server, git host \
                     or people who need it."
                        .into(),
                );
                if !matches!(self.filter, Filter::All | Filter::Keys) {
                    self.filter = Filter::Keys;
                }
                // Answers come back in order, so the list knows it is a key
                // by the time the item opens and fetches its public half.
                self.send(Op::ListItems, Request::ListItems);
                self.select(id);
            }
            (Op::KeyConfirm, Response::Ok) => {
                self.send(Op::ListItems, Request::ListItems);
            }
            (Op::RemoveSlot(_), Response::Ok) => {
                self.confirm_remove = None;
                self.notice = Some("Unlock method removed.".into());
                self.send(Op::ListSlots, Request::ListSlots);
            }
            (Op::QuickUnlock, Response::Status(s)) => {
                self.notice = Some(if s.quick_unlock.hours == 0 {
                    "Quick unlock is off.".into()
                } else {
                    format!(
                        "Quick unlock is on: {HELLO} can unlock for {} hours after each \
                         unlock with your password.",
                        s.quick_unlock.hours
                    )
                });
                self.quick_hours = Some(s.quick_unlock.hours);
                self.on_status(s);
            }
            (Op::Sync, Response::Status(s)) => {
                self.notice = Some(match &s.sync {
                    Some(sync) if sync.error.is_none() => "Synced.".into(),
                    Some(_) => "Sync is on, but there is a problem (see below).".into(),
                    None => "Sync is off.".into(),
                });
                self.on_status(s);
            }
            _ => self.error = Some("Unexpected answer from vaultd.".into()),
        }
    }

    fn select(&mut self, id: ItemId) {
        self.selected = Some(id);
        self.open = None;
        self.totp = None;
        self.edit = None;
        self.new_key = None;
        self.import_key = None;
        self.export = None;
        self.send(Op::OpenItem(id), Request::GetItem { id });
    }

    /// Answers, polling and timers. Runs every frame.
    fn tick(&mut self, ctx: &egui::Context) {
        for (op, r) in self.backend.poll() {
            self.on_result(op, r);
        }
        let every = match self.screen {
            Screen::Unreachable(_) => STATUS_EVERY * 2,
            _ => STATUS_EVERY,
        };
        if self.backend.in_flight() == 0 && self.status_sent.is_none_or(|t| t.elapsed() >= every) {
            self.refresh();
        }
        if let Some((_, at)) = &self.copied
            && at.elapsed() >= CLIPBOARD_CLEAR
        {
            self.clear_clipboard();
            self.notice = None;
        }
        if let Some((id, _)) = &self.open {
            let id = *id;
            let stale = self
                .totp
                .as_ref()
                .is_none_or(|(tid, _, until)| *tid != id || Instant::now() >= *until);
            if self.open.as_ref().is_some_and(|(_, i)| i.totp.is_some())
                && stale
                && !self.totp_pending
            {
                self.totp_pending = true;
                self.send(Op::Totp(id), Request::Totp { id });
            }
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    /// Draw the window.
    pub fn show(&mut self, ui: &mut Ui) {
        if !self.styled {
            theme::apply(ui.ctx());
            self.styled = true;
        }
        self.tick(ui.ctx());
        if self.screen == Screen::Unlocked {
            self.unlocked(ui);
            return;
        }
        if matches!(self.screen, Screen::Create | Screen::Setup) {
            self.setup_window(ui);
            return;
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::SIDEBAR))
            .show(ui, |ui| {
                // Roughly centered on tall windows, near the top on short ones.
                let top = ((ui.available_height() - 520.0) / 2.0).clamp(24.0, 120.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(top);
                        if matches!(self.screen, Screen::Locked | Screen::Pair) {
                            self.unlock_card(ui);
                        } else {
                            theme::card().inner_margin(Margin::same(32)).show(ui, |ui| {
                                ui.set_width(440.0);
                                ui.vertical(|ui| self.front(ui));
                            });
                        }
                        ui.add_space(24.0);
                    });
                });
            });
    }

    /// The locked screen: the ways to unlock on the left, the chosen one's
    /// form on the right.
    fn unlock_card(&mut self, ui: &mut Ui) {
        const LEFT: f32 = 248.0;
        // 800 wide, less in a narrow window so the card keeps a margin.
        let width = (ui.available_width() - 48.0).clamp(640.0, 800.0);
        let pair = self.screen == Screen::Pair;
        let shadow = egui::Shadow {
            offset: [0, 12],
            blur: 40,
            spread: 0,
            color: egui::Color32::from_black_alpha(18),
        };
        theme::card()
            .inner_margin(Margin::ZERO)
            .corner_radius(16)
            .shadow(shadow)
            .show(ui, |ui| {
                ui.set_width(width);
                ui.spacing_mut().item_spacing = Vec2::ZERO;
                ui.horizontal_top(|ui| {
                    let left = egui::Frame::new()
                        .fill(theme::GROUND)
                        .corner_radius(egui::CornerRadius {
                            nw: 16,
                            sw: 16,
                            ne: 0,
                            se: 0,
                        })
                        .inner_margin(Margin::symmetric(16, 26))
                        .show(ui, |ui| {
                            ui.set_width(LEFT - 32.0);
                            ui.set_min_height(460.0 - 52.0);
                            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                                self.unlock_methods(ui, pair);
                            });
                        });
                    let r = left.response.rect;
                    ui.painter()
                        .vline(r.right(), r.y_range(), Stroke::new(1.0, theme::DIVIDER));
                    egui::Frame::new()
                        .inner_margin(Margin::symmetric(44, 40))
                        .show(ui, |ui| {
                            ui.set_width(width - LEFT - 88.0);
                            ui.spacing_mut().item_spacing = Vec2::new(8.0, 8.0);
                            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                                self.messages(ui);
                                self.pair_or_unlock(ui, pair);
                            });
                        });
                });
            });
    }

    /// The left column of the locked screen.
    fn unlock_methods(&mut self, ui: &mut Ui, pair: bool) {
        ui.horizontal(|ui| {
            ui.add_space(4.0);
            theme::lock_tile(ui, 36.0, false);
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.add_space(1.0);
                ui.label(theme::title("Secret Vault", 15.0));
                ui.label(
                    RichText::new(if pair {
                        "Not paired with this app"
                    } else {
                        "Locked"
                    })
                    .small()
                    .color(theme::MUTED),
                );
            });
        });
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            theme::caption(ui, "Unlock with");
        });
        ui.spacing_mut().item_spacing.y = 4.0;
        for (m, name, how) in [
            (
                Method::Password,
                "Master password",
                "The password you chose",
            ),
            (
                Method::SecurityKey,
                "Security key",
                "Password, then touch the key",
            ),
            (
                Method::Phone,
                "Phone",
                "Password, then a passkey on your phone",
            ),
            (
                Method::Tpm,
                "This device",
                "Password and this computer's chip",
            ),
            (Method::Recovery, "Recovery code", "From your printed sheet"),
        ] {
            if m == Method::Phone && !PHONE {
                continue;
            }
            if theme::choice_row(ui, self.unlock.method == m, name, how).clicked() {
                self.unlock.method = m;
                self.error = None;
            }
        }
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Any one of these unlocks the vault. Each keeps its own locked \
                         copy of the vault key.",
                    )
                    .small()
                    .color(theme::MUTED),
                )
                .wrap(),
            );
        });
    }

    /// The card shown before the vault is unlocked.
    fn front(&mut self, ui: &mut Ui) {
        let sub = match &self.screen {
            Screen::Connecting | Screen::Unreachable(_) => "Connecting",
            Screen::Create | Screen::Setup => "New vault",
            Screen::Pair => "Not paired with this app",
            Screen::Locked | Screen::Unlocked => "Locked",
        };
        ui.horizontal(|ui| {
            theme::lock_tile(ui, 40.0, false);
            ui.add_space(2.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.add_space(2.0);
                ui.label(theme::title("Secret Vault", 17.0));
                ui.label(RichText::new(sub).small().color(theme::MUTED));
            });
        });
        ui.add_space(16.0);
        self.messages(ui);
        match self.screen.clone() {
            Screen::Connecting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting to vaultd…");
                });
            }
            Screen::Unreachable(m) => {
                ui.label(m);
                ui.label(if cfg!(windows) {
                    "Start vaultd.exe, or sign out and in if it starts at login."
                } else {
                    "Start it with `systemctl --user start vaultd`."
                });
                if theme::primary(ui, true, "Try again").clicked() {
                    self.screen = Screen::Connecting;
                    self.refresh();
                }
            }
            Screen::Create | Screen::Setup => {}
            Screen::Pair => self.pair_or_unlock(ui, true),
            Screen::Locked => self.pair_or_unlock(ui, false),
            Screen::Unlocked => {}
        }
    }

    fn messages(&mut self, ui: &mut Ui) {
        let pill = |fill| {
            egui::Frame::new()
                .fill(fill)
                .corner_radius(10)
                .inner_margin(Margin::symmetric(14, 10))
        };
        if let Some(e) = &self.error {
            pill(theme::ERROR_WEAK).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add(egui::Label::new(RichText::new(e).color(theme::ERROR)).wrap());
            });
            ui.add_space(4.0);
        }
        if let Some(n) = &self.notice {
            pill(theme::INK).show(ui, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(n).size(13.0).color(egui::Color32::WHITE))
                        .wrap(),
                );
            });
            ui.add_space(4.0);
        }
        if let Some(b) = self.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(b);
            });
            self.phone_panel(ui);
        }
    }

    /// The QR code and progress of a phone passkey that is running.
    fn phone_panel(&self, ui: &mut Ui) {
        let view = self
            .backend
            .phone
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default();
        if let Some(uri) = view.qr.as_deref() {
            ui.add_space(6.0);
            qr_code(ui, uri);
            ui.label(
                RichText::new("Scan with your phone's camera, then confirm on the phone.")
                    .small()
                    .color(theme::MUTED),
            );
        }
        if let Some(s) = &view.status {
            ui.label(RichText::new(s).small().color(theme::TEXT));
        }
    }

    /// The synced file's path and a button. Returns whether it was pressed
    /// with a path filled in.
    fn sync_form(&mut self, ui: &mut Ui, button: &str) -> bool {
        egui::Grid::new("sync-path").num_columns(2).show(ui, |ui| {
            text_field(ui, "File in the synced folder", &mut self.sync_path);
            ui.end_row();
        });
        ui.label(RichText::new(sync_example()).weak());
        let ok = self.busy.is_none() && !self.sync_path.trim().is_empty();
        ui.add_enabled(ok, egui::Button::new(button)).clicked() && ok
    }

    fn sync_page(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Sync",
            "Keep this vault in step with your other devices through a folder that \
             OneDrive, Google Drive or Dropbox syncs. The file there is encrypted like \
             this one, and changes from each device are merged.",
        );
        let sync = self.status.as_ref().and_then(|(s, _)| s.sync.clone());
        let ok = self.busy.is_none();
        let Some(sync) = sync else {
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    status_dot(ui, theme::MUTED);
                    ui.label(
                        RichText::new("Sync is off")
                            .family(theme::semibold())
                            .color(theme::INK)
                            .color(theme::INK),
                    );
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Pick a file inside the folder your sync app keeps up to date. If it \
                         doesn't exist yet, the vault is copied there.",
                    )
                    .color(theme::MUTED),
                );
                ui.add_space(8.0);
                egui::Grid::new("sync-path").num_columns(2).show(ui, |ui| {
                    text_field(ui, "File in the synced folder", &mut self.sync_path);
                    ui.end_row();
                });
                ui.label(RichText::new(sync_example()).small().color(theme::MUTED));
                ui.add_space(8.0);
                let ready = ok && !self.sync_path.trim().is_empty();
                if theme::primary(ui, ready, "Turn on").clicked() && ready {
                    let path = self.sync_path.trim().to_owned();
                    self.act("Syncing…", Op::Sync, Request::SetSync { path: Some(path) });
                }
            });
            return;
        };
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (colour, state) = if sync.error.is_some() {
                (theme::ERROR, "Sync is on, with a problem")
            } else {
                (theme::OK, "Sync is on")
            };
            ui.horizontal(|ui| {
                status_dot(ui, colour);
                ui.label(
                    RichText::new(state)
                        .family(theme::semibold())
                        .color(theme::INK)
                        .color(theme::INK),
                );
            });
            ui.add_space(10.0);
            egui::Grid::new("sync")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("File").color(theme::MUTED));
                    ui.add(
                        egui::Label::new(RichText::new(&sync.path).monospace().color(theme::INK))
                            .wrap(),
                    );
                    ui.end_row();
                    ui.label(RichText::new("Last synced").color(theme::MUTED));
                    ui.label(
                        RichText::new(match sync.last_sync {
                            Some(t) => ago(SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs())
                                .saturating_sub(t)),
                            None => "not yet".into(),
                        })
                        .color(theme::INK),
                    );
                    ui.end_row();
                });
            if let Some(e) = &sync.error {
                ui.add_space(8.0);
                ui.colored_label(theme::ERROR, format!("Problem: {e}"));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if theme::primary_icon(ui, ok, Icon::Sync, "Sync now").clicked() && ok {
                    self.act("Syncing…", Op::Sync, Request::SyncNow);
                }
                if ui.add_enabled(ok, egui::Button::new("Turn off")).clicked() {
                    self.act("Turning off…", Op::Sync, Request::SetSync { path: None });
                }
            });
        });
        if sync.conflicts > 0 || !sync.other_copies.is_empty() {
            ui.add_space(12.0);
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                theme::caption(ui, "Needs a look");
                if sync.conflicts > 0 {
                    ui.label(format!(
                        "{} item(s) were changed on two devices at once. Both versions are \
                         kept; the older one has \"(conflict)\" after its title.",
                        sync.conflicts
                    ));
                }
                if !sync.other_copies.is_empty() {
                    ui.label(format!(
                        "These copies next to the synced file were merged in and can be \
                         deleted: {}",
                        sync.other_copies.join(", ")
                    ));
                }
            });
        }
    }

    fn pair_or_unlock(&mut self, ui: &mut Ui, pair: bool) {
        let quick = self
            .status
            .as_ref()
            .and_then(|(s, _)| s.quick_unlock.until)
            .filter(|_| !pair);
        if quick.is_some() {
            let ok = self.busy.is_none();
            if wide_primary(ui, ok, &format!("Unlock with {HELLO}")).clicked() && ok {
                self.act(
                    HELLO_CONFIRM,
                    Op::Unlock,
                    Request::Unlock {
                        method: UnlockMethod::Hello,
                    },
                );
            }
            ui.label(
                RichText::new(format!("{HELLO_WAYS}. Or use another method:"))
                    .small()
                    .color(theme::MUTED),
            );
            ui.add_space(8.0);
            theme::divider(ui);
            ui.add_space(16.0);
        }
        // Pairing needs a full unlock, so quick unlock waits until afterwards.
        let quick_later = pair
            && self
                .status
                .as_ref()
                .is_some_and(|(s, _)| s.quick_unlock.supported && s.quick_unlock.hours > 0);
        let f = &mut self.unlock;
        let (heading, about) = match f.method {
            Method::Password => (
                "Enter your master password",
                "The password you chose when you made the vault.",
            ),
            Method::SecurityKey => (
                "Use your security key",
                "Type your master password, then touch the key when it blinks.",
            ),
            Method::Phone => ("Use your phone", PHONE_HOW),
            Method::Tpm => (
                "Unlock with this device",
                "Your master password together with this computer's security chip.",
            ),
            Method::Recovery => (
                "Enter your recovery code",
                "The code from the sheet you printed or wrote down when you made the vault.",
            ),
        };
        ui.label(theme::title(heading, 22.0));
        ui.add(egui::Label::new(RichText::new(about).color(theme::TEXT)).wrap());
        if pair {
            ui.add(
                egui::Label::new(
                    RichText::new("This app isn't paired yet: unlocking once pairs it.")
                        .color(theme::MUTED),
                )
                .wrap(),
            );
            if quick_later {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{HELLO} unlock shows here from the next time the vault locks."
                        ))
                        .color(theme::MUTED),
                    )
                    .wrap(),
                );
            }
        }
        ui.add_space(12.0);
        let mut submit = false;
        if f.method == Method::Recovery {
            submit |= stacked_secret(ui, "Recovery code", &mut f.code);
        } else {
            submit |= stacked_secret(ui, "Master password", &mut f.password);
        }
        if f.method == Method::Tpm || f.method == Method::SecurityKey && !WINDOWS_ASKS_KEY_PIN {
            submit |= stacked_secret(ui, "PIN (if set)", &mut f.pin);
        }
        if f.method == Method::SecurityKey && WINDOWS_ASKS_KEY_PIN {
            ui.label(
                RichText::new(
                    "Windows asks for the touch, and the key's PIN if needed, in its own window.",
                )
                .small()
                .color(theme::MUTED),
            );
        }
        ui.add_space(8.0);
        let ok = self.busy.is_none();
        let label = if pair { "Pair" } else { "Unlock" };
        submit |= wide_primary(ui, ok, label).clicked();
        if submit && ok {
            // Nothing typed yet: don't start a security key or TPM check.
            let f = &self.unlock;
            let empty = if f.method == Method::Recovery {
                f.code.trim().is_empty()
            } else {
                f.password.is_empty()
            };
            if empty {
                self.error = Some(if f.method == Method::Recovery {
                    "Type the recovery code first.".into()
                } else {
                    "Type your master password first.".into()
                });
                return;
            }
            let busy = match self.unlock.method {
                Method::SecurityKey => "Touch your security key when it blinks…",
                Method::Phone => "Waiting for your phone…",
                _ if pair => "Pairing…",
                _ => "Unlocking…",
            };
            if self.unlock.method == Method::Phone {
                let work = Work::PhoneUnlock {
                    password: self.unlock.password.clone(),
                    pair: pair.then(|| (CLIENT_NAME.into(), ClientScope::Full)),
                };
                self.act_work(busy, if pair { Op::Pair } else { Op::Unlock }, work);
                return;
            }
            let method = self.unlock.to_method();
            if pair {
                self.act(
                    busy,
                    Op::Pair,
                    Request::Pair {
                        client_name: CLIENT_NAME.into(),
                        scope: ClientScope::Full,
                        method: Some(method),
                    },
                );
            } else {
                self.act(busy, Op::Unlock, Request::Unlock { method });
            }
        }
        if pair {
            ui.add_space(16.0);
            theme::divider(ui);
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Or approve this app in a window vaultd opens, without typing \
                         anything here.",
                    )
                    .color(theme::TEXT),
                )
                .wrap(),
            );
            if ui
                .add_enabled(ok, egui::Button::new("Ask for approval"))
                .clicked()
            {
                self.act(
                    "Approve the request in the window vaultd opened…",
                    Op::Pair,
                    Request::Pair {
                        client_name: CLIENT_NAME.into(),
                        scope: ClientScope::Full,
                        method: None,
                    },
                );
            }
        }
    }

    fn unlocked(&mut self, ui: &mut Ui) {
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::L)) {
            self.act("Locking…", Op::Lock, Request::Lock);
        }
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, Key::K)) {
            self.palette = match self.palette.take() {
                Some(_) => None,
                None => Some(Palette::default()),
            };
        }
        egui::Panel::top("top")
            .resizable(false)
            .exact_size(TOP_BAR)
            .frame(egui::Frame::new().fill(theme::SURFACE))
            .show(ui, |ui| self.top_bar(ui));
        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(SIDEBAR)
            .frame(
                egui::Frame::new()
                    .fill(theme::SIDEBAR)
                    .inner_margin(Margin::symmetric(12, 16)),
            )
            .show(ui, |ui| self.sidebar(ui));
        let page = egui::Frame::new()
            .fill(theme::GROUND)
            .inner_margin(Margin::symmetric(32, 26));
        match self.view {
            View::Items => {
                // The list gives way in a narrow window, so the item beside
                // it keeps room to show its text.
                let most = (ui.available_width() - 360.0).clamp(240.0, 480.0);
                egui::Panel::left("list")
                    .resizable(true)
                    .default_size(340.0)
                    .size_range(240.0..=most)
                    .frame(
                        egui::Frame::new()
                            .fill(theme::SURFACE)
                            .inner_margin(Margin::symmetric(12, 18)),
                    )
                    .show(ui, |ui| self.item_list(ui));
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if self.import_key.is_some() {
                            theme::card().show(ui, |ui| self.import_key_form(ui));
                        } else if self.new_key.is_some() {
                            theme::card().show(ui, |ui| self.key_form(ui));
                        } else if self.edit.is_some() {
                            theme::card().show(ui, |ui| self.edit_form(ui));
                        } else {
                            self.item_detail(ui);
                        }
                    });
                });
            }
            View::Generator => {
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    self.generator(ui);
                });
            }
            View::Import => {
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    self.import(ui);
                });
            }
            View::Slots => {
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.slots_page(ui);
                    });
                });
            }
            View::Sync => {
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.sync_page(ui);
                    });
                });
            }
            View::Pgp => {
                egui::CentralPanel::default().frame(page).show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.pgp_page(ui);
                    });
                });
            }
        }
        if self.palette.is_some() {
            self.palette(ui);
        }
    }

    /// Switch pages, dropping the last page's messages.
    fn go(&mut self, v: View) {
        if self.view == v {
            return;
        }
        self.view = v;
        self.error = None;
        self.notice = None;
        if v == View::Slots {
            self.send(Op::ListSlots, Request::ListSlots);
        }
    }

    /// The bar across the top: the app's name over the sidebar, one search
    /// field for the whole window, and on the right the lock timer, the New
    /// button for the open category, and Lock.
    fn top_bar(&mut self, ui: &mut Ui) {
        let full = ui.max_rect();
        let brand = Rect::from_min_size(full.min, Vec2::new(SIDEBAR, full.height()));
        ui.painter().rect_filled(brand, 0.0, theme::SIDEBAR);
        ui.painter().vline(
            brand.right(),
            brand.y_range(),
            Stroke::new(1.0, theme::BORDER),
        );
        let mut idle = None;
        if let Some((s, at)) = &self.status
            && let Some(left) = s.idle_lock_in
        {
            let left = left.saturating_sub(at.elapsed().as_secs());
            idle = Some(format!("Locks in {}:{:02}", left / 60, left % 60));
        }
        let mut lock = false;
        let mut start = None;
        let mut search_changed = false;
        let mut widen = false;
        ui.horizontal_centered(|ui| {
            ui.add_space(18.0);
            theme::lock_tile(ui, 30.0, true);
            ui.add_space(2.0);
            ui.label(theme::title("Secret Vault", 15.0));
            let used = ui.cursor().left() - full.left();
            ui.add_space(SIDEBAR - used + 20.0);

            // Search: as wide as the room the buttons on the right leave.
            // In a narrow window the lock timer goes, then the shortcut
            // hint, so nothing overlaps.
            let avail = ui.available_width();
            let show_timer = avail - 430.0 >= 240.0;
            let room = if show_timer {
                (avail - 430.0).min(640.0)
            } else {
                (avail - 290.0).max(150.0)
            };
            let show_kbd = room >= 260.0;
            let scoped = self.filter != Filter::All;
            egui::Frame::new()
                .fill(theme::GROUND)
                .stroke(Stroke::new(1.0, theme::BORDER))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(10, 0))
                .show(ui, |ui| {
                    ui.set_width(room - 20.0);
                    ui.set_height(38.0);
                    ui.horizontal_centered(|ui| {
                        ui.spacing_mut().item_spacing.x = 8.0;
                        Icon::Search.show(ui, 16.0, theme::MUTED);
                        if scoped {
                            let chip = egui::Button::new((
                                RichText::new(format!("in {}", self.filter.short()))
                                    .family(theme::semibold())
                                    .size(12.0)
                                    .color(theme::ACCENT),
                                RichText::new("×").size(13.0).color(theme::ACCENT),
                            ))
                            .fill(theme::ACCENT_WEAK)
                            .stroke(Stroke::NONE)
                            .corner_radius(6)
                            .min_size(Vec2::new(0.0, 24.0));
                            let r = ui.add(chip).on_hover_text("Search all items instead");
                            if r.clicked() {
                                widen = true;
                            }
                        }
                        let hint = if scoped {
                            format!("Search {}", self.filter.short().to_lowercase())
                        } else {
                            "Search all items".to_owned()
                        };
                        let kbd = if show_kbd { 54.0 } else { 0.0 };
                        let r = ui.add(
                            TextEdit::singleline(&mut self.search)
                                .hint_text(hint)
                                .frame(egui::Frame::NONE)
                                .align(egui::Align2::LEFT_CENTER)
                                .min_size(Vec2::new(0.0, 36.0))
                                .desired_width((ui.available_width() - kbd).max(60.0)),
                        );
                        ui.ctx()
                            .accesskit_node_builder(r.id, |n| n.set_label("Search"));
                        search_changed = r.changed();
                        if show_kbd {
                            ui.label(
                                RichText::new(PALETTE_KEY)
                                    .monospace()
                                    .size(11.0)
                                    .color(theme::MUTED),
                            )
                            .on_hover_text("Find items and actions");
                        }
                    });
                });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(16.0);
                lock = theme::button(ui, Icon::Lock, "Lock").clicked();
                ui.add_space(2.0);
                start = self.new_buttons(ui);
                if let Some(t) = idle.filter(|_| show_timer) {
                    ui.add_space(6.0);
                    ui.label(RichText::new(t).small().color(theme::MUTED));
                    status_dot(ui, theme::OK);
                }
            });
        });
        if widen {
            self.show_category(Filter::All);
            self.go(View::Items);
        }
        if search_changed && self.view != View::Items {
            self.go(View::Items);
        }
        match start {
            Some(Quick::Item(k)) => {
                self.go(View::Items);
                self.selected = None;
                self.open = None;
                self.new_key = None;
                self.import_key = None;
                self.edit = Some(Edit::new(k));
            }
            Some(Quick::Key(pgp)) => {
                self.go(View::Items);
                self.start_key(pgp);
            }
            Some(Quick::Import(pgp)) => {
                self.go(View::Items);
                self.start_import(pgp);
            }
            None => {}
        }
        if lock {
            self.act("Locking…", Op::Lock, Request::Lock);
        }
    }

    /// The blue New button, named for the open category. All items gets a
    /// menu of every kind; keys get a small menu beside it for OpenPGP.
    fn new_buttons(&self, ui: &mut Ui) -> Option<Quick> {
        let mut start = None;
        let blue = |b: egui::Button<'static>| b.fill(theme::ACCENT).stroke(Stroke::NONE);
        let white = |t: &str| {
            RichText::new(t)
                .family(theme::semibold())
                .color(egui::Color32::WHITE)
        };
        let entry = |ui: &mut Ui, icon: Icon, text: &str| {
            ui.add(
                egui::Button::new((icon.atom(15.0), RichText::new(text).color(theme::INK)))
                    .frame(false)
                    .min_size(Vec2::new(200.0, 32.0)),
            )
            .clicked()
        };
        match self.filter.new_button() {
            None => {
                let b = blue(
                    egui::Button::new((
                        Icon::Plus.atom_in(15.0, egui::Color32::WHITE),
                        white("New item"),
                        Icon::ChevronDown.atom_in(12.0, egui::Color32::WHITE),
                    ))
                    .min_size(Vec2::new(0.0, 36.0)),
                );
                egui::containers::menu::MenuButton::from_button(b).ui(ui, |ui| {
                    for k in ItemKind::ALL {
                        if entry(ui, kind_icon(k), k.label()) {
                            start = Some(Quick::Item(k));
                        }
                    }
                    ui.separator();
                    if entry(ui, Icon::Terminal, "SSH key") {
                        start = Some(Quick::Key(false));
                    }
                    if entry(ui, Icon::Terminal, "OpenPGP key") {
                        start = Some(Quick::Key(true));
                    }
                    ui.separator();
                    if entry(ui, Icon::Import, "Import SSH key") {
                        start = Some(Quick::Import(false));
                    }
                    if entry(ui, Icon::Import, "Import OpenPGP key") {
                        start = Some(Quick::Import(true));
                    }
                });
            }
            Some((label, quick)) => {
                // Right to left: the menu half first, then the main button.
                if matches!(quick, Quick::Key(_)) {
                    let more = blue(
                        egui::Button::new(Icon::ChevronDown.atom_in(12.0, egui::Color32::WHITE))
                            .corner_radius(CornerRadius {
                                nw: 0,
                                sw: 0,
                                ne: 8,
                                se: 8,
                            })
                            .min_size(Vec2::new(30.0, 36.0)),
                    );
                    let (r, _) =
                        egui::containers::menu::MenuButton::from_button(more).ui(ui, |ui| {
                            if entry(ui, Icon::Terminal, "New OpenPGP key") {
                                start = Some(Quick::Key(true));
                            }
                            ui.separator();
                            if entry(ui, Icon::Import, "Import SSH key") {
                                start = Some(Quick::Import(false));
                            }
                            if entry(ui, Icon::Import, "Import OpenPGP key") {
                                start = Some(Quick::Import(true));
                            }
                        });
                    ui.ctx()
                        .accesskit_node_builder(r.id, |n| n.set_label("More kinds of key"));
                    ui.add_space(-ui.spacing().item_spacing.x + 1.0);
                }
                let mut b = blue(
                    egui::Button::new((
                        Icon::Plus.atom_in(15.0, egui::Color32::WHITE),
                        white(label),
                    ))
                    .min_size(Vec2::new(0.0, 36.0)),
                );
                if matches!(quick, Quick::Key(_)) {
                    b = b.corner_radius(CornerRadius {
                        nw: 8,
                        sw: 8,
                        ne: 0,
                        se: 0,
                    });
                }
                if ui.add(b).clicked() {
                    start = Some(quick);
                }
            }
        }
        start
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        let mut rollback = false;
        let mut sync = None;
        if let Some((s, _)) = &self.status {
            sync = s.sync.as_ref().map(|y| {
                if y.error.is_some() {
                    ("Sync has a problem", theme::WARN)
                } else if y.last_sync.is_some() {
                    ("Synced", theme::MUTED)
                } else {
                    ("Sync is on", theme::MUTED)
                }
            });
            rollback = s.rollback_detected;
        }
        if rollback {
            ui.colored_label(
                theme::WARN,
                "WARNING: the vault file is older than one seen before, so saving is off.",
            );
        }
        let mut go = None;
        // The version and hints at the bottom keep their room; on a short
        // window the categories and tools scroll instead of running under them.
        let footer = if sync.is_some() { 84.0 } else { 64.0 };
        egui::ScrollArea::vertical()
            .id_salt("sidebar")
            .max_height((ui.available_height() - footer).max(80.0))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for (f, name) in Filter::NAV {
                    let on = self.view == View::Items && self.filter == f;
                    let count = self.items.iter().filter(|i| f.admits(i)).count();
                    if theme::nav_row(ui, on, f.icon(), name, Some(count)).clicked() {
                        go = Some((View::Items, f));
                    }
                }
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    theme::caption(ui, "Tools");
                });
                ui.add_space(2.0);
                for (v, icon, name) in [
                    (View::Generator, Icon::Dice, "Generator"),
                    (View::Import, Icon::Import, "Import"),
                    (View::Slots, Icon::Shield, "Unlock methods"),
                    (View::Sync, Icon::Sync, "Sync"),
                    (View::Pgp, Icon::Mail, "Encrypt and sign"),
                ] {
                    if theme::nav_row(ui, self.view == v, icon, name, None).clicked() {
                        go = Some((v, self.filter));
                    }
                }
            });
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("Version {}", vault_ipc::VERSION))
                        .small()
                        .color(theme::MUTED),
                );
            });
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("{PALETTE_KEY} finds items and actions"))
                        .small()
                        .color(theme::MUTED),
                );
            });
            if let Some((text, color)) = sync {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    Icon::Sync.show(ui, 13.0, color);
                    ui.label(RichText::new(text).small().color(color));
                });
            }
        });
        if let Some((v, f)) = go {
            self.show_category(f);
            self.go(v);
        }
    }

    /// Switch the list to another category. An open item that isn't in it
    /// is closed, so the right-hand pane follows the list; a form being
    /// filled in stays, so no typing is lost.
    fn show_category(&mut self, f: Filter) {
        self.filter = f;
        if self.edit.is_some() || self.new_key.is_some() || self.import_key.is_some() {
            return;
        }
        let inside = self
            .selected
            .and_then(|id| self.items.iter().find(|i| i.id == id))
            .is_some_and(|i| f.admits(i));
        if !inside {
            self.selected = None;
            self.open = None;
            self.totp = None;
            self.reveal = false;
            self.confirm_delete = false;
        }
    }

    fn matches(i: &ItemSummary, q: &str) -> bool {
        q.is_empty()
            || i.title.to_lowercase().contains(q)
            || i.subtitle.to_lowercase().contains(q)
            || i.urls.iter().any(|u| u.to_lowercase().contains(q))
    }

    fn item_list(&mut self, ui: &mut Ui) {
        let q = self.search.to_lowercase();
        let shown: Vec<&ItemSummary> = self
            .items
            .iter()
            .filter(|i| self.filter.admits(i) && Self::matches(i, &q))
            .collect();
        let in_category = self.items.iter().filter(|i| self.filter.admits(i)).count();
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            self.filter.icon().show(ui, 18.0, theme::MUTED);
            ui.label(theme::title(self.filter.name(), 17.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(6.0);
                let count = if q.is_empty() {
                    format!("{in_category}")
                } else {
                    format!("{} of {in_category}", shown.len())
                };
                ui.label(RichText::new(count).color(theme::MUTED));
            });
        });
        ui.add_space(2.0);
        theme::divider(ui);
        let mut pick = None;
        let mut widen = false;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add_space(4.0);
                for i in &shown {
                    let mut tags = Vec::new();
                    if i.has_totp {
                        tags.push("2FA");
                    }
                    if i.key.is_some() {
                        tags.push("Key");
                    }
                    let on = self.selected == Some(i.id);
                    if theme::item_row(ui, on, &i.title, &i.subtitle, &tags).clicked() {
                        pick = Some(i.id);
                    }
                }
                if in_category == 0 && q.is_empty() {
                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.add_space(6.0);
                        ui.label(RichText::new(self.filter.empty()).color(theme::MUTED));
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.add_space(6.0);
                        let button = self.filter.new_button().map_or("New item", |(l, _)| l);
                        ui.label(
                            RichText::new(format!("Use {button} at the top to add one."))
                                .small()
                                .color(theme::MUTED),
                        );
                    });
                } else if shown.is_empty() {
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Nothing matches.").color(theme::MUTED));
                    });
                    if self.filter != Filter::All
                        && self.items.iter().any(|i| Self::matches(i, &q))
                        && ui
                            .horizontal(|ui| {
                                ui.add_space(6.0);
                                theme::button(ui, Icon::Search, "Search all items").clicked()
                            })
                            .inner
                    {
                        widen = true;
                    }
                }
            });
        });
        if widen {
            self.show_category(Filter::All);
        }
        if let Some(id) = pick {
            self.select(id);
        }
    }

    fn item_detail(&mut self, ui: &mut Ui) {
        let Some((id, item)) = &self.open else {
            if self.selected.is_some() {
                ui.spinner();
            } else {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "Pick an item on the left, make a new one, or press {PALETTE_KEY}."
                        ))
                        .color(theme::MUTED),
                    );
                });
            }
            return;
        };
        let id = *id;
        let (key, key_confirm) = self
            .items
            .iter()
            .find(|i| i.id == id)
            .map_or((None, false), |i| (i.key.clone(), i.key_confirm));
        let public_key = self
            .public_key
            .as_ref()
            .filter(|(k, _)| *k == id)
            .map(|(_, text)| text.clone());
        let reveal = self.reveal;
        let mut copy: Option<(Secret, String)> = None;
        let mut copy_code: Option<Secret> = None;
        let mut toggle_reveal = false;
        let mut edit = false;
        let mut delete = false;
        let mut set_confirm = None;
        let mut export_pgp = None;

        // Edit and Delete sit right of the title when there is room, and
        // under it in a narrow window, so a long title wraps in readable lines.
        let mut buttons = |ui: &mut Ui| {
            if self.confirm_delete {
                if ui.button("Cancel").clicked() {
                    self.confirm_delete = false;
                }
                if ui
                    .add(
                        egui::Button::new(RichText::new("Yes, delete").color(egui::Color32::WHITE))
                            .fill(theme::ERROR),
                    )
                    .clicked()
                {
                    delete = true;
                }
                ui.label("Delete this item for good?");
            } else {
                if theme::danger(ui, Icon::Trash, "Delete").clicked() {
                    self.confirm_delete = true;
                }
                if theme::button(ui, Icon::Pencil, "Edit").clicked() {
                    edit = true;
                }
            }
        };
        let w = ui.available_width();
        let (tile, size) = if w < 400.0 {
            (40.0, 18.0)
        } else {
            (56.0, 22.0)
        };
        let title = |ui: &mut Ui| {
            theme::monogram(ui, &item.title, tile);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add_space(6.0);
                ui.add(egui::Label::new(theme::title(&item.title, size)).wrap());
                let kind = if let Some(k) = &key {
                    if k.starts_with("OpenPGP") {
                        "OpenPGP key"
                    } else {
                        "SSH key"
                    }
                } else {
                    item.kind.label()
                };
                ui.label(RichText::new(kind).size(13.0).color(theme::MUTED));
            });
        };
        if w < 560.0 {
            ui.allocate_ui_with_layout(
                Vec2::new(w, 0.0),
                egui::Layout::left_to_right(egui::Align::Min),
                title,
            );
            ui.add_space(10.0);
            ui.allocate_ui_with_layout(
                Vec2::new(w, 0.0),
                egui::Layout::right_to_left(egui::Align::Min),
                buttons,
            );
        } else {
            ui.allocate_ui_with_layout(
                Vec2::new(w, 0.0),
                egui::Layout::right_to_left(egui::Align::Min),
                |ui| {
                    buttons(ui);
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), title);
                },
            );
        }
        ui.add_space(18.0);

        // A row: the label over the value, and on the right a Copy button.
        // Rows are split by soft lines; empty values are left out. Secret
        // values stay dotted until shown.
        let first = std::cell::Cell::new(true);
        let line = |ui: &mut Ui| {
            if !first.replace(false) {
                theme::divider(ui);
            }
        };
        let mut row = |ui: &mut Ui, label: &str, value: &str, secret: bool| {
            if value.is_empty() {
                return;
            }
            line(ui);
            detail_row(
                ui,
                |ui| {
                    ui.label(RichText::new(label).size(12.0).color(theme::MUTED));
                    // Code font only for secrets, where telling 0 from O matters.
                    if secret && !reveal {
                        ui.add(
                            egui::Label::new(RichText::new("••••••••").monospace().size(15.0))
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                    } else if secret {
                        ui.add(
                            egui::Label::new(
                                RichText::new(value)
                                    .monospace()
                                    .size(15.0)
                                    .color(theme::INK),
                            )
                            .wrap(),
                        );
                    } else {
                        ui.add(
                            egui::Label::new(RichText::new(value).size(15.0).color(theme::INK))
                                .wrap(),
                        );
                    }
                },
                |ui| {
                    let text = format!("Copy {}", label.to_lowercase());
                    let clicked = if secret {
                        theme::primary_small(ui, Icon::Copy, &text).clicked()
                    } else {
                        theme::soft_icon(ui, Icon::Copy, &text).clicked()
                    };
                    if clicked {
                        copy = Some((Zeroizing::new(value.to_owned()), label.to_owned()));
                    }
                    if secret && show_button(ui, reveal).clicked() {
                        toggle_reveal = true;
                    }
                },
            );
        };
        // Keys and secure notes keep their content in cards of their own.
        let has_rows = match item.kind {
            _ if key.is_some() => !item.fields.is_empty(),
            ItemKind::Note => !item.fields.is_empty(),
            _ => true,
        };
        if has_rows {
            theme::card()
                .inner_margin(Margin::symmetric(20, 4))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 0.0;
                    {
                        match item.kind {
                            ItemKind::Login => {
                                row(ui, "Username", &item.username, false);
                                row(ui, "Password", &item.password, true);
                                if let Some(cfg) = &item.totp {
                                    line(ui);
                                    let now = match &self.totp {
                                        Some((tid, code, until)) if *tid == id => Some((
                                            code,
                                            until.saturating_duration_since(Instant::now()),
                                        )),
                                        _ => None,
                                    };
                                    detail_row(
                                        ui,
                                        |ui| {
                                            ui.label(
                                                RichText::new(format!(
                                                    "One-time code ({} s)",
                                                    cfg.period
                                                ))
                                                .size(12.0)
                                                .color(theme::MUTED),
                                            );
                                            match now {
                                                Some((code, left)) => {
                                                    ui.horizontal(|ui| {
                                                        theme::countdown(
                                                            ui,
                                                            left.as_secs_f32(),
                                                            cfg.period as f32,
                                                        );
                                                        ui.label(
                                                            RichText::new(spaced(code))
                                                                .monospace()
                                                                .size(22.0)
                                                                .extra_letter_spacing(1.5)
                                                                .color(theme::INK),
                                                        );
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "{} s left",
                                                                left.as_secs()
                                                            ))
                                                            .small()
                                                            .color(theme::MUTED),
                                                        );
                                                    });
                                                }
                                                None => {
                                                    ui.spinner();
                                                }
                                            }
                                        },
                                        |ui| {
                                            if let Some((code, _)) = now
                                                && theme::soft_icon(ui, Icon::Copy, "Copy code")
                                                    .clicked()
                                            {
                                                copy_code = Some(code.clone());
                                            }
                                        },
                                    );
                                }
                            }
                            ItemKind::Note => {}
                            ItemKind::Card => {
                                let c = item.card.clone().unwrap_or_default();
                                row(ui, "Name on card", &c.holder, false);
                                line(ui);
                                detail_row(
                                    ui,
                                    |ui| {
                                        ui.label(
                                            RichText::new("Card").size(12.0).color(theme::MUTED),
                                        );
                                        ui.label(
                                            RichText::new(c.describe())
                                                .size(15.0)
                                                .color(theme::INK),
                                        );
                                    },
                                    |_| {},
                                );
                                row(ui, "Number", &c.number, true);
                                row(ui, "Expires", &c.expiry(), false);
                                row(ui, "Security code", &c.cvv, true);
                                row(ui, "PIN", &c.pin, true);
                            }
                            ItemKind::Identity => {
                                let i = item.identity.clone().unwrap_or_default();
                                let name = [i.honorific.as_str(), &i.full_name()]
                                    .iter()
                                    .filter(|s| !s.is_empty())
                                    .copied()
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                row(ui, "Name", &name, false);
                                row(ui, "Company", &i.company, false);
                                row(ui, "Email", &i.email, false);
                                row(ui, "Phone", &i.phone, false);
                                let address = [
                                    &i.address1,
                                    &i.address2,
                                    &i.address3,
                                    &i.city,
                                    &i.region,
                                    &i.postcode,
                                    &i.country,
                                ]
                                .into_iter()
                                .map(String::as_str)
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                                .join("\n");
                                row(ui, "Address", &address, false);
                            }
                        }
                        for f in &item.fields {
                            row(ui, &f.name, &f.value, f.kind == FieldKind::Hidden);
                        }
                    }
                });
        }

        if item.kind == ItemKind::Login && key.is_none() {
            ui.add_space(12.0);
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                theme::caption(ui, "Autofill is bound to");
                if item.urls.is_empty() {
                    ui.label(
                        RichText::new("No websites, so this item is never offered for autofill.")
                            .color(theme::MUTED),
                    );
                }
                for u in &item.urls {
                    let mut how = match u.mode {
                        MatchMode::Origin => "this site only".to_owned(),
                        MatchMode::RegistrableDomain => "the whole domain".to_owned(),
                    };
                    if u.allow_http {
                        how += ", http allowed";
                    }
                    // Long addresses wrap inside the card.
                    ui.add(
                        egui::Label::new(RichText::new(&u.url).monospace().color(theme::INK))
                            .wrap(),
                    );
                    ui.label(RichText::new(how).small().color(theme::MUTED));
                    ui.add_space(4.0);
                }
            });
        }

        if let Some(k) = &key {
            if has_rows {
                ui.add_space(12.0);
            }
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                theme::caption(ui, "Key");
                ui.add(egui::Label::new(RichText::new(k).monospace().color(theme::INK)).wrap());
                ui.add_space(10.0);
                theme::caption(ui, "Public key");
                match &public_key {
                    Some(text) => {
                        // An SSH key is one line; an OpenPGP one is a block
                        // of base64 that tells a reader nothing.
                        if text.starts_with("-----BEGIN") {
                            ui.label(
                                RichText::new(
                                    "An armored OpenPGP public key, ready to send to others \
                                     or publish.",
                                )
                                .color(theme::TEXT),
                            );
                        } else {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(text.trim()).monospace().color(theme::TEXT),
                                )
                                .truncate(),
                            );
                        }
                        ui.add_space(4.0);
                        if theme::primary_small(ui, Icon::Copy, "Copy public key").clicked() {
                            copy = Some((Zeroizing::new(text.clone()), "Public key".to_owned()));
                        }
                    }
                    None => {
                        ui.spinner();
                    }
                }
                ui.add_space(10.0);
                let mut ask = key_confirm;
                let enabled = self.busy.is_none();
                if ui
                    .add_enabled(enabled, egui::Checkbox::new(&mut ask, "Ask before each use"))
                    .changed()
                {
                    set_confirm = Some(ask);
                }
                ui.label(
                    RichText::new(if key_confirm {
                        "vaultd opens a window to approve every signature or decryption."
                    } else {
                        "Programs you run can use this key without asking while the vault is unlocked."
                    })
                    .small()
                    .color(theme::MUTED),
                );
                ui.add_space(6.0);
                ui.label(
                    RichText::new(
                        "vaultd signs and decrypts for you, so programs never see the private \
                         key. Export it only to move it to a device without this vault.",
                    )
                    .color(theme::MUTED),
                );
                export_pgp = Some(k.starts_with("OpenPGP"));
            });
        }

        if !item.notes.is_empty() {
            ui.add_space(12.0);
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                theme::caption(ui, "Notes");
                // A secure note's text is its secret: hidden until shown.
                if item.kind == ItemKind::Note {
                    if reveal {
                        ui.label(RichText::new(&item.notes).color(theme::INK));
                    } else {
                        ui.label("••••••••••••");
                    }
                    ui.horizontal(|ui| {
                        if show_button(ui, reveal).clicked() {
                            toggle_reveal = true;
                        }
                        if theme::primary_small(ui, Icon::Copy, "Copy note").clicked() {
                            copy = Some((Zeroizing::new(item.notes.clone()), "Note".to_owned()));
                        }
                    });
                } else {
                    ui.label(&item.notes);
                }
            });
        }

        // Keys rarely have notes, so the export card can come last; it needs
        // the whole app, which the item borrowed above no longer holds.
        if let Some(pgp) = export_pgp {
            ui.add_space(12.0);
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                self.export_section(ui, id, pgp);
            });
        }
        if toggle_reveal {
            self.reveal = !self.reveal;
        }
        if let Some(confirm) = set_confirm {
            self.act(
                "Saving…",
                Op::KeyConfirm,
                Request::SetKeyConfirm { id, confirm },
            );
        }
        if edit {
            self.edit = self.open.as_ref().map(|(id, i)| Edit::from_item(*id, i));
        }
        if delete {
            self.act("Deleting…", Op::Delete(id), Request::DeleteItem { id });
        }
        if let Some(code) = copy_code {
            copy = Some((code, "Code".into()));
        }
        if let Some((text, what)) = copy {
            self.copy(&text, &what);
        }
    }

    /// Rows for the palette: matching items, actions on the best match, then
    /// the vault's own actions.
    fn palette_rows(&self, q: &str) -> Vec<(&'static str, String, Action)> {
        let q = q.trim().to_lowercase();
        let mut rows = Vec::new();
        let hits: Vec<&ItemSummary> = self
            .items
            .iter()
            .filter(|i| Self::matches(i, &q))
            .take(if q.is_empty() { 4 } else { 6 })
            .collect();
        for i in &hits {
            let label = if i.subtitle.is_empty() {
                i.title.clone()
            } else {
                format!("{}\n{}", i.title, i.subtitle)
            };
            let action = if i.key.is_some() || i.kind != ItemKind::Login {
                Action::Open(i.id)
            } else {
                Action::Copy(i.id, Field::Password)
            };
            rows.push(("Items", label, action));
        }
        if let Some(top) = hits.first().filter(|_| !q.is_empty()) {
            let t = &top.title;
            let login = top.kind == ItemKind::Login;
            if login && top.key.is_none() {
                rows.push((
                    "Actions",
                    format!("Copy password for {t}"),
                    Action::Copy(top.id, Field::Password),
                ));
            }
            if login && !top.subtitle.is_empty() {
                rows.push((
                    "Actions",
                    format!("Copy username for {t}"),
                    Action::CopyUsername(top.id),
                ));
            }
            if top.has_totp {
                rows.push((
                    "Actions",
                    format!("Copy one-time code for {t}"),
                    Action::Copy(top.id, Field::Code),
                ));
            }
            rows.push(("Actions", format!("Show {t}"), Action::Open(top.id)));
        }
        for (label, action) in [
            ("New item", Action::NewItem),
            ("New SSH key", Action::NewKey(false)),
            ("New OpenPGP key", Action::NewKey(true)),
            ("Import SSH key", Action::ImportKey(false)),
            ("Import OpenPGP key", Action::ImportKey(true)),
            ("Encrypt with OpenPGP", Action::Pgp(keys::Task::Encrypt)),
            ("Decrypt with OpenPGP", Action::Pgp(keys::Task::Decrypt)),
            ("Sign with OpenPGP", Action::Pgp(keys::Task::Sign)),
            (
                "Verify an OpenPGP signature",
                Action::Pgp(keys::Task::Verify),
            ),
            ("Generate a password", Action::Generate),
            ("Import items", Action::Go(View::Import)),
            ("Unlock methods", Action::Go(View::Slots)),
            ("Sync devices", Action::Go(View::Sync)),
            ("Lock now", Action::Lock),
        ] {
            if q.is_empty() || label.to_lowercase().contains(&q) {
                rows.push(("Vault", label.to_owned(), action));
            }
        }
        rows
    }

    fn palette(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let query = self
            .palette
            .as_ref()
            .map(|p| p.query.clone())
            .unwrap_or_default();
        let rows = self.palette_rows(&query);
        let (down, up, enter, esc) = ctx.input_mut(|i| {
            (
                i.consume_key(egui::Modifiers::NONE, Key::ArrowDown),
                i.consume_key(egui::Modifiers::NONE, Key::ArrowUp),
                i.consume_key(egui::Modifiers::NONE, Key::Enter),
                i.consume_key(egui::Modifiers::NONE, Key::Escape),
            )
        });
        let Some(p) = self.palette.as_mut() else {
            return;
        };
        let last = rows.len().saturating_sub(1);
        if down {
            p.sel = (p.sel + 1).min(last);
        }
        if up {
            p.sel = p.sel.saturating_sub(1);
        }
        p.sel = p.sel.min(last);
        let mut run = None;
        if enter {
            run = rows.get(p.sel).map(|r| r.2);
        }
        // Pinned near the top so the box stays put as the list shrinks.
        let id = egui::Id::unique("palette");
        let area = egui::Modal::default_area(id).anchor(egui::Align2::CENTER_TOP, [0.0, 72.0]);
        let modal = egui::Modal::new(id)
            .area(area)
            .backdrop_color(egui::Color32::from_rgba_unmultiplied(21, 23, 28, 90))
            .frame(
                theme::card()
                    .inner_margin(Margin::symmetric(8, 8))
                    .corner_radius(14)
                    .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
                    .shadow(egui::Shadow {
                        offset: [0, 24],
                        blur: 64,
                        spread: 0,
                        color: egui::Color32::from_black_alpha(60),
                    }),
            )
            .show(&ctx, |ui| {
                ui.set_width(620.0);
                let r = ui.add(
                    TextEdit::singleline(&mut p.query)
                        .hint_text("Search items and actions")
                        .font(egui::FontId::proportional(17.0))
                        .frame(egui::Frame::NONE)
                        .margin(Margin::symmetric(12, 10))
                        .desired_width(f32::INFINITY),
                );
                ui.ctx()
                    .accesskit_node_builder(r.id, |n| n.set_label("Find an item or action"));
                if !p.focused {
                    r.request_focus();
                    p.focused = true;
                }
                if r.changed() {
                    // The rows were built from the old query; draw again.
                    p.sel = 0;
                    ui.ctx().request_repaint();
                }
                theme::divider(ui);
                if rows.is_empty() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.label(RichText::new("Nothing matches.").color(theme::MUTED));
                    });
                }
                egui::ScrollArea::vertical()
                    .max_height(380.0)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        let mut group = "";
                        for (n, (g, text, action)) in rows.iter().enumerate() {
                            if *g != group {
                                group = g;
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.add_space(10.0);
                                    theme::caption(ui, g);
                                });
                            }
                            if theme::palette_row(ui, n == p.sel, text).clicked() {
                                run = Some(*action);
                            }
                        }
                        ui.add_space(4.0);
                    });
                theme::divider(ui);
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("Up and down to move · Enter to run · Esc to close")
                            .monospace()
                            .size(11.0)
                            .color(theme::MUTED),
                    );
                });
            });
        if esc || modal.should_close() {
            self.palette = None;
        }
        if let Some(a) = run {
            self.palette = None;
            self.run(a);
        }
    }

    fn run(&mut self, a: Action) {
        match a {
            Action::Copy(id, field) => {
                self.go(View::Items);
                let open = self.open.as_ref().is_some_and(|(o, _)| *o == id);
                match field {
                    Field::Password if open => {
                        let pw = self
                            .open
                            .as_ref()
                            .map(|(_, i)| Zeroizing::new(i.password.clone()))
                            .unwrap_or_default();
                        self.copy(&pw, "Password");
                    }
                    Field::Code if open && self.totp.as_ref().is_some_and(|t| t.0 == id) => {
                        let code = self.totp.as_ref().map(|t| t.1.clone()).unwrap_or_default();
                        self.copy(&code, "Code");
                    }
                    _ => {
                        self.pending_copy = Some((id, field));
                        if !open {
                            self.select(id);
                        }
                    }
                }
            }
            Action::CopyUsername(id) => {
                if let Some(u) = self
                    .items
                    .iter()
                    .find(|i| i.id == id)
                    .map(|i| i.subtitle.clone())
                {
                    self.copy(&u, "Username");
                }
            }
            Action::Open(id) => {
                self.go(View::Items);
                // Show the item in the list too, even if it's in another category.
                if !self
                    .items
                    .iter()
                    .any(|i| i.id == id && self.filter.admits(i))
                {
                    self.filter = Filter::All;
                }
                self.select(id);
            }
            Action::NewItem => {
                self.go(View::Items);
                self.selected = None;
                self.open = None;
                self.new_key = None;
                self.import_key = None;
                self.edit = Some(Edit::new(ItemKind::Login));
            }
            Action::NewKey(pgp) => {
                self.go(View::Items);
                self.start_key(pgp);
            }
            Action::ImportKey(pgp) => {
                self.go(View::Items);
                self.start_import(pgp);
            }
            Action::Pgp(task) => self.open_pgp(task),
            Action::Generate => {
                self.go(View::Generator);
                let style = self.generator.style();
                self.send(Op::Generate, Request::GenerateStyled { style });
            }
            Action::Go(v) => self.go(v),
            Action::Lock => self.act("Locking…", Op::Lock, Request::Lock),
        }
    }
    fn edit_form(&mut self, ui: &mut Ui) {
        let Some(e) = &mut self.edit else { return };
        let mut generate = false;
        ui.label(theme::title(
            match (e.id.is_some(), e.kind) {
                (true, _) => "Edit item".to_owned(),
                (false, k) => format!("New {}", k.label().to_lowercase()),
            },
            20.0,
        ));
        ui.add_space(10.0);
        egui::Grid::new("edit")
            .num_columns(2)
            .spacing([16.0, 10.0])
            .show(ui, |ui| {
                text_field(ui, "Title", &mut e.title);
                ui.end_row();
                match e.kind {
                    ItemKind::Login => generate = login_fields(ui, e),
                    ItemKind::Note => {}
                    ItemKind::Card => {
                        text_field(ui, "Name on card", &mut e.holder);
                        ui.end_row();
                        let l = ui.label("Card number");
                        ui.horizontal(|ui| {
                            ui.add(
                                TextEdit::singleline(&mut *e.number)
                                    .password(!e.reveal)
                                    .desired_width(300.0),
                            )
                            .labelled_by(l.id);
                            ui.checkbox(&mut e.reveal, "Show");
                        });
                        ui.end_row();
                        let typed = Card {
                            number: Card::clean_number(&e.number),
                            ..Card::default()
                        };
                        if typed.number.len() >= 12 {
                            ui.label("");
                            ui.label(if typed.luhn_ok() {
                                typed.describe()
                            } else {
                                "This number fails the card checksum; check it for typos."
                                    .to_owned()
                            });
                            ui.end_row();
                        }
                        let l = ui.label("Expires");
                        ui.add(
                            TextEdit::singleline(&mut e.expiry)
                                .hint_text("MM/YY")
                                .desired_width(80.0),
                        )
                        .labelled_by(l.id);
                        ui.end_row();
                        secret_field(ui, "Security code", &mut e.cvv);
                        ui.end_row();
                        secret_field(ui, "PIN", &mut e.pin);
                        ui.end_row();
                    }
                    ItemKind::Identity => {
                        let i = &mut e.identity;
                        for (label, field) in [
                            ("Title (Mr, Ms, Dr…)", &mut i.honorific),
                            ("First name", &mut i.given_name),
                            ("Middle name", &mut i.middle_name),
                            ("Last name", &mut i.family_name),
                            ("Company", &mut i.company),
                            ("Email", &mut i.email),
                            ("Phone", &mut i.phone),
                            ("Address line 1", &mut i.address1),
                            ("Address line 2", &mut i.address2),
                            ("Address line 3", &mut i.address3),
                            ("City", &mut i.city),
                            ("State / region", &mut i.region),
                            ("Postcode", &mut i.postcode),
                            ("Country", &mut i.country),
                        ] {
                            text_field(ui, label, field);
                            ui.end_row();
                        }
                    }
                }

                let mut remove = None;
                for (n, f) in e.fields.iter_mut().enumerate() {
                    ui.label(if n == 0 { "Custom fields" } else { "" });
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                TextEdit::singleline(&mut f.name)
                                    .hint_text("Name")
                                    .desired_width(110.0),
                            );
                            ui.add(
                                TextEdit::singleline(&mut *f.value)
                                    .hint_text("Value")
                                    .password(f.hidden && !e.reveal)
                                    .desired_width(182.0),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut f.hidden, "Hidden");
                            if ui.button("Remove").clicked() {
                                remove = Some(n);
                            }
                        });
                    });
                    ui.end_row();
                }
                if let Some(n) = remove {
                    e.fields.remove(n);
                }
                ui.label(if e.fields.is_empty() {
                    "Custom fields"
                } else {
                    ""
                });
                if ui.button("Add field").clicked() {
                    e.fields.push(FieldEdit {
                        name: String::new(),
                        value: Secret::default(),
                        hidden: false,
                    });
                }
                ui.end_row();

                let l = ui.label("Notes");
                ui.add(TextEdit::multiline(&mut *e.notes).desired_rows(4))
                    .labelled_by(l.id);
                ui.end_row();
            });
        ui.add_space(12.0);
        let ok = self.busy.is_none();
        let (mut save, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            save = theme::primary_icon(ui, ok, Icon::Check, "Save").clicked();
            cancel = ui.button("Cancel").clicked();
        });
        if generate {
            let style = self.generator.style();
            self.send(Op::GenerateForEdit, Request::GenerateStyled { style });
        }
        if cancel {
            self.edit = None;
            self.error = None;
        } else if save && ok {
            let e = self.edit.as_ref().expect("checked above");
            match e.to_item() {
                Ok(item) => {
                    let id = e.id;
                    self.act("Saving…", Op::Save, Request::PutItem { id, item });
                }
                Err(m) => self.error = Some(m),
            }
        }
    }

    /// Open the new key form in place of the item details.
    fn start_key(&mut self, pgp: bool) {
        self.selected = None;
        self.open = None;
        self.edit = None;
        self.import_key = None;
        self.export = None;
        self.error = None;
        self.notice = None;
        self.new_key = Some(KeyForm::new(pgp));
    }

    fn key_form(&mut self, ui: &mut Ui) {
        let Some(f) = &mut self.new_key else { return };
        ui.heading(if f.pgp {
            "New OpenPGP key"
        } else {
            "New SSH key"
        });
        ui.label(
            RichText::new(if f.pgp {
                "For encrypting and signing files and email, and signing git commits. \
                 The key is made inside the vault and its secret half never leaves it."
            } else {
                "For logging in to servers and git hosts, and signing git commits. \
                 The key is made inside the vault and its private half never leaves it."
            })
            .color(theme::MUTED),
        );
        ui.add_space(10.0);
        egui::Grid::new("new-key")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                if f.pgp {
                    let l = ui.label("Name");
                    ui.add(
                        TextEdit::singleline(&mut f.name)
                            .hint_text("Alex Example")
                            .desired_width(280.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                    let l = ui.label("Email");
                    ui.add(
                        TextEdit::singleline(&mut f.email)
                            .hint_text("alex@example.com")
                            .desired_width(280.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                    let l = ui.label("Title");
                    ui.add(
                        TextEdit::singleline(&mut f.title)
                            .hint_text("The name, if left empty")
                            .desired_width(280.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                } else {
                    let l = ui.label("Title");
                    ui.add(
                        TextEdit::singleline(&mut f.title)
                            .hint_text("Laptop, GitHub, deploy key…")
                            .desired_width(280.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                }
            });
        ui.add_space(10.0);
        theme::caption(ui, "Kind of key");
        let choices: [(bool, &str, &str); 2] = if f.pgp {
            [
                (
                    false,
                    "Classic (recommended)",
                    "Ed25519 and Curve25519 (OpenPGP v4). Works with GnuPG, Thunderbird \
                     and every current OpenPGP program.",
                ),
                (
                    true,
                    "Post-quantum",
                    "ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519 (OpenPGP v6). Protects \
                     secrets against future quantum computers, but GnuPG 2.4 and most \
                     mail programs can't use it yet.",
                ),
            ]
        } else {
            [
                (
                    false,
                    "Ed25519 (recommended)",
                    "Short, fast and accepted by GitHub, GitLab and any OpenSSH \
                     server from the last ten years.",
                ),
                (
                    true,
                    "ECDSA P-256",
                    "Only for a server or device that refuses Ed25519.",
                ),
            ]
        };
        let picked = if f.pgp {
            &mut f.post_quantum
        } else {
            &mut f.ecdsa
        };
        for (value, name, about) in choices {
            ui.radio_value(picked, value, name);
            ui.indent(name, |ui| {
                ui.label(RichText::new(about).small().color(theme::MUTED));
            });
        }
        ui.add_space(10.0);
        ui.checkbox(&mut f.confirm, "Ask before each use");
        ui.label(
            RichText::new(
                "vaultd opens a window to approve every signature or decryption. Untick \
                 it only for a key a program must use unattended. You can change this later.",
            )
            .small()
            .color(theme::MUTED),
        );
        ui.add_space(12.0);
        let ok = self.busy.is_none();
        let (mut make, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            make = theme::primary(ui, ok, "Make key").clicked();
            cancel = ui.button("Cancel").clicked();
        });
        if cancel {
            self.new_key = None;
            self.error = None;
        } else if make && ok {
            match self.new_key.as_ref().expect("checked above").to_request() {
                Ok(request) => self.act("Making the key…", Op::NewKey, request),
                Err(m) => self.error = Some(m),
            }
        }
    }

    fn generator(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Password generator",
            "Pick a style and make a password. New items use these settings when you press \
             Generate there.",
        );
        let mut copy = None;
        let mut generate = false;
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            if let Some(p) = &self.generated {
                detail_row(
                    ui,
                    |ui| {
                        ui.label(RichText::new("Password").size(12.0).color(theme::MUTED));
                        ui.add(
                            egui::Label::new(
                                RichText::new(p.as_str())
                                    .monospace()
                                    .size(18.0)
                                    .color(theme::INK),
                            )
                            .wrap_mode(egui::TextWrapMode::Wrap)
                            .selectable(true),
                        );
                    },
                    |ui| {
                        if theme::primary_small(ui, Icon::Copy, "Copy password").clicked() {
                            copy = Some(p.clone());
                        }
                        if theme::soft_icon(ui, Icon::Dice, "New").clicked() {
                            generate = true;
                        }
                    },
                );
                theme::divider(ui);
                ui.add_space(12.0);
            }
            let g = &mut self.generator;
            for (kind, name, about) in [
                (
                    GenKind::Random,
                    "Random characters",
                    "Strongest for its length. Best when you never type it.",
                ),
                (
                    GenKind::Words,
                    "Three random words",
                    "The UK NCSC's advice: easy to remember and type, like CupFishBiscuit.",
                ),
                (
                    GenKind::Apple,
                    "Apple style",
                    "Three groups of six letters, like fokjyb-Xewpud-hamu4s. Easy to type on a phone.",
                ),
            ] {
                if theme::choice_row(ui, g.kind == kind, name, about).clicked() && g.kind != kind {
                    g.kind = kind;
                    generate = true;
                }
                ui.add_space(4.0);
            }
            ui.add_space(6.0);
            match g.kind {
                GenKind::Random => {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().slider_width = 260.0;
                        ui.add(egui::Slider::new(&mut g.options.length, 8..=64).text("characters"));
                    });
                    ui.checkbox(&mut g.options.symbols, "Symbols");
                    ui.checkbox(&mut g.options.avoid_ambiguous, "Avoid look-alike characters");
                }
                GenKind::Words => {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().slider_width = 200.0;
                        ui.add(egui::Slider::new(&mut g.words, 3..=10).text("words"));
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label("Between words");
                        for (sep, name) in [("", "Nothing"), ("-", "-"), (".", "."), (" ", "Space")] {
                            ui.selectable_value(&mut g.separator, sep.to_owned(), name);
                        }
                    });
                    ui.checkbox(&mut g.capitalize, "Capital letter at the start of each word");
                    ui.checkbox(
                        &mut g.number_and_symbol,
                        "Add a number and a symbol at the end, for sites that demand them",
                    );
                }
                GenKind::Apple => {}
            }
            let bits = g.style().to_core().strength_bits();
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    RichText::new(strength_text(g.kind, bits))
                        .size(12.5)
                        .color(theme::MUTED),
                )
                .wrap(),
            );
            ui.add_space(4.0);
            if self.generated.is_none()
                && theme::primary_icon(ui, true, Icon::Dice, "Generate").clicked()
            {
                generate = true;
            }
        });
        if generate {
            let style = self.generator.style();
            self.send(Op::Generate, Request::GenerateStyled { style });
        }
        if let Some(p) = copy {
            self.copy(&p, "Password");
        }
    }

    fn import(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Import",
            "Bring in logins from another password manager or your browser. Delete the \
             export file afterwards: it holds your passwords in plain text.",
        );
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::caption(ui, "Format");
            ui.radio_value(
                &mut self.import_format,
                ImportFormat::BitwardenJson,
                "Bitwarden export (unencrypted .json)",
            );
            ui.radio_value(
                &mut self.import_format,
                ImportFormat::BrowserCsv,
                "Chrome, Edge or Firefox passwords (.csv)",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let l = ui.label("File");
                ui.add(TextEdit::singleline(&mut self.import_path).desired_width(360.0))
                    .labelled_by(l.id);
            });
            ui.add_space(4.0);
            let ok = self.busy.is_none() && !self.import_path.trim().is_empty();
            if theme::primary_icon(ui, ok, Icon::Import, "Import").clicked() {
                match std::fs::read_to_string(self.import_path.trim()) {
                    Ok(data) => {
                        let format = self.import_format;
                        self.act(
                            "Importing…",
                            Op::Import,
                            Request::Import {
                                format,
                                data: Zeroizing::new(data),
                            },
                        );
                    }
                    Err(e) => self.error = Some(format!("{}: {e}", self.import_path.trim())),
                }
            }
        });
    }

    fn slots_page(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Unlock methods",
            "Each method holds its own locked copy of the vault key, so any one of them \
             opens the vault. Removing one never touches your items.",
        );
        let mut remove = None;
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            for (n, s) in self.slots.iter().enumerate() {
                if n > 0 {
                    ui.separator();
                }
                let (name, about) = slot_text(&s.kind);
                ui.horizontal(|ui| {
                    theme::monogram(ui, name, 36.0);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.spacing_mut().interact_size.y = 0.0;
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(name)
                                    .family(theme::semibold())
                                    .color(theme::INK)
                                    .color(theme::INK),
                            );
                            if !s.label.is_empty() && !s.label.eq_ignore_ascii_case(name) {
                                ui.label(RichText::new(&s.label).color(theme::MUTED));
                            }
                        });
                        ui.label(RichText::new(about).small().color(theme::MUTED));
                        if let Some(w) = &s.warning {
                            ui.label(
                                RichText::new(format!("Not post-quantum: {w}"))
                                    .small()
                                    .color(theme::WARN),
                            );
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.confirm_remove == Some(s.id) {
                            if ui.button("Cancel").clicked() {
                                self.confirm_remove = None;
                            }
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Yes, remove").color(egui::Color32::WHITE),
                                    )
                                    .fill(theme::ERROR),
                                )
                                .clicked()
                            {
                                remove = Some(s.id);
                            }
                        } else if ui.button("Remove").clicked() {
                            self.confirm_remove = Some(s.id);
                        }
                    });
                });
            }
        });
        if let Some(slot) = remove {
            self.act(
                "Removing…",
                Op::RemoveSlot(slot),
                Request::RemoveSlot { slot },
            );
        }
        ui.add_space(8.0);
        match self.slots.len() {
            0 => {}
            1 => {
                ui.colored_label(
                    theme::WARN,
                    "You have only one way to unlock. If you lose it, nothing can open the \
                     vault: add a recovery code or a second method below.",
                );
            }
            n => {
                ui.colored_label(
                    theme::OK,
                    format!("You have {n} ways to unlock, so losing one won't lock you out."),
                );
            }
        }
        ui.label(
            RichText::new(
                "Removing a method doesn't change the vault key. To shut out a lost key or a \
                 leaked password, also run vault revoke.",
            )
            .small()
            .color(theme::MUTED),
        );
        if let Some(code) = &self.new_recovery {
            ui.add_space(12.0);
            let mut done = false;
            theme::card().fill(theme::ACCENT_WEAK).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(
                        "New recovery code, shown only once. Write it down and keep it offline:",
                    )
                    .color(theme::INK),
                );
                ui.label(RichText::new(code.as_str()).monospace().size(18.0));
                done = theme::primary(ui, true, "I've written it down").clicked();
            });
            if done {
                self.new_recovery = None;
            }
        }
        self.quick_unlock_form(ui);
        ui.add_space(12.0);
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            self.add_slot_form(ui);
        });
    }

    fn add_slot_form(&mut self, ui: &mut Ui) {
        ui.label(
            RichText::new("Add a method")
                .family(theme::semibold())
                .color(theme::INK)
                .size(16.0)
                .color(theme::INK),
        );
        ui.add_space(6.0);
        let f = &mut self.slot_form;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut f.kind, SlotKind::Password, "Password");
            ui.selectable_value(&mut f.kind, SlotKind::SecurityKey, "Security key");
            if PHONE {
                ui.selectable_value(&mut f.kind, SlotKind::Phone, "Phone");
            }
            ui.selectable_value(&mut f.kind, SlotKind::Tpm, "TPM");
            ui.selectable_value(&mut f.kind, SlotKind::Recovery, "Recovery code");
        });
        ui.label(
            RichText::new(match f.kind {
                SlotKind::Password => {
                    "Another master password, for example one to give a family member."
                }
                SlotKind::SecurityKey => {
                    "A FIDO2 security key (YubiKey, Nitrokey, Titan and others) that you touch \
                     after typing the password. Plug it in before you press Add."
                }
                SlotKind::Phone => {
                    "A passkey on your iPhone or Android phone, saved in its password manager \
                     (iCloud Keychain, Google Password Manager or another), together with the \
                     password. The app shows a QR code to scan; Bluetooth must be on on both."
                }
                SlotKind::Tpm => {
                    "The TPM chip in this computer, together with the password. It works only \
                     on this computer and this operating system."
                }
                SlotKind::Recovery => {
                    "A code to print and keep offline. It opens the vault on its own if you \
                     lose everything else."
                }
            })
            .small()
            .color(theme::MUTED),
        );
        ui.add_space(6.0);
        let mut submit = false;
        egui::Grid::new("add-slot").num_columns(2).show(ui, |ui| {
            text_field(ui, "Name", &mut f.label);
            ui.end_row();
            if f.kind != SlotKind::Recovery {
                let what = if f.kind == SlotKind::Password {
                    "New password"
                } else {
                    "Password to use with it"
                };
                secret_field(ui, what, &mut f.password);
                ui.end_row();
                submit |= secret_field(ui, "Repeat it", &mut f.password2);
                ui.end_row();
            }
            if f.kind == SlotKind::Tpm || f.kind == SlotKind::SecurityKey && !WINDOWS_ASKS_KEY_PIN {
                secret_field(ui, "PIN (optional)", &mut f.pin);
                ui.end_row();
            }
        });
        match f.kind {
            SlotKind::SecurityKey => {
                ui.checkbox(&mut f.require_uv, "Also ask for the key's PIN every time");
                if WINDOWS_ASKS_KEY_PIN {
                    ui.label(
                        RichText::new(
                            "Windows asks for the touch and the PIN in its own window. If your \
                             key has a PIN, tick the box: Windows always checks that PIN, so a \
                             touch-only method can't work with such a key here.",
                        )
                        .small()
                        .color(theme::MUTED),
                    );
                }
            }
            SlotKind::Tpm => {
                ui.checkbox(
                    &mut f.bind_pcr7,
                    "Stop working if Secure Boot settings change (PCR 7)",
                );
            }
            _ => {}
        }
        ui.add_space(6.0);
        let ok = self.busy.is_none();
        submit |= theme::primary(ui, ok, "Add").clicked();
        if !(submit && ok) {
            return;
        }
        let f = &self.slot_form;
        let label = f.label.trim().to_owned();
        if f.kind != SlotKind::Recovery {
            if f.password.chars().count() < 8 {
                self.error = Some("The password needs at least 8 characters.".into());
                return;
            }
            if *f.password != *f.password2 {
                self.error = Some("The passwords don't match.".into());
                return;
            }
        }
        let (busy, request) = match f.kind {
            SlotKind::Password => (
                "Adding…",
                Request::AddPasswordSlot {
                    password: f.password.clone(),
                    label,
                },
            ),
            SlotKind::SecurityKey => (
                "Touch your security key when it blinks…",
                Request::AddFido2Slot {
                    password: f.password.clone(),
                    pin: opt(&f.pin),
                    require_uv: f.require_uv,
                    label,
                },
            ),
            SlotKind::Tpm => (
                "Adding…",
                Request::AddTpmSlot {
                    password: f.password.clone(),
                    pin: opt(&f.pin),
                    bind_pcr7: f.bind_pcr7,
                    label,
                },
            ),
            SlotKind::Phone => {
                let work = Work::PhoneEnroll {
                    password: f.password.clone(),
                    label,
                };
                self.act_work("Creating a passkey on your phone…", Op::AddSlot, work);
                return;
            }
            SlotKind::Recovery => ("Adding…", Request::AddRecoverySlot { label }),
        };
        self.act(busy, Op::AddSlot, request);
    }
}

impl App {
    /// Quick unlock with Windows Hello or Touch ID, where vaultd supports it.
    fn quick_unlock_form(&mut self, ui: &mut Ui) {
        let Some(q) = self.status.as_ref().map(|(s, _)| s.quick_unlock.clone()) else {
            return;
        };
        if !q.supported {
            return;
        }
        ui.add_space(12.0);
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(format!("Quick unlock with {HELLO}"))
                    .family(theme::semibold())
                    .color(theme::INK)
                    .size(16.0)
                    .color(theme::INK),
            );
            ui.label(format!(
                "After you unlock with your password (or another method), {HELLO} can \
             unlock the vault again when it locks, until the time below runs out or the \
             computer restarts. Then the password is needed again."
            ));
            let hours = self
                .quick_hours
                .get_or_insert(if q.hours == 0 { 8 } else { q.hours });
            let name = |h: u32| match h {
                0 => "Off".to_string(),
                1 => "1 hour".to_string(),
                h => format!("{h} hours"),
            };
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("quick-hours")
                    .selected_text(name(*hours))
                    .show_ui(ui, |ui| {
                        for h in [0, 1, 2, 4, 8, 12, 24] {
                            ui.selectable_value(hours, h, name(h));
                        }
                    });
            });
            let picked = *hours;
            let ok = self.busy.is_none() && picked != q.hours;
            if theme::primary(ui, ok, "Apply").clicked() && ok {
                let busy = if picked == 0 {
                    "Turning quick unlock off…"
                } else {
                    HELLO_CONFIRM
                };
                self.act(
                    busy,
                    Op::QuickUnlock,
                    Request::SetQuickUnlock { hours: picked },
                );
            }
        });
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.clear_clipboard();
    }
}

/// A labelled password box. True when Enter was pressed in it.
/// A label over a full-width password box. True when Enter was pressed in it.
/// Show or Hide for a secret value, with an eye.
fn show_button(ui: &mut Ui, reveal: bool) -> egui::Response {
    if reveal {
        theme::soft_icon(ui, Icon::EyeOff, "Hide")
    } else {
        theme::soft_icon(ui, Icon::Eye, "Show")
    }
}

fn stacked_secret(ui: &mut Ui, label: &str, text: &mut Secret) -> bool {
    ui.spacing_mut().item_spacing.y = 6.0;
    let l = ui.label(theme::bold(label).size(13.0));
    let r = ui
        .add(
            TextEdit::singleline(&mut **text)
                .password(true)
                .margin(Margin::symmetric(12, 11))
                .desired_width(f32::INFINITY),
        )
        .labelled_by(l.id);
    ui.spacing_mut().item_spacing.y = 8.0;
    ui.add_space(6.0);
    r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// The main action of a form, as wide as the form.
fn wide_primary(ui: &mut Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new((
            egui::Atom::grow(),
            RichText::new(text)
                .family(theme::semibold())
                .size(15.0)
                .color(egui::Color32::WHITE),
            egui::Atom::grow(),
        ))
        .fill(theme::ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(10)
        .min_size(Vec2::new(ui.available_width(), 44.0)),
    )
}

fn secret_field(ui: &mut Ui, label: &str, text: &mut Secret) -> bool {
    let l = ui.label(label);
    let r = ui
        .add(
            TextEdit::singleline(&mut **text)
                .password(true)
                .desired_width(300.0),
        )
        .labelled_by(l.id);
    r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// The login part of the edit form. True when Generate was clicked.
fn login_fields(ui: &mut Ui, e: &mut Edit) -> bool {
    let mut generate = false;
    text_field(ui, "Username", &mut e.username);
    ui.end_row();
    let l = ui.label("Password");
    ui.vertical(|ui| {
        ui.add(
            TextEdit::singleline(&mut *e.password)
                .password(!e.reveal)
                .font(egui::TextStyle::Monospace)
                .desired_width(300.0),
        )
        .labelled_by(l.id);
        ui.horizontal(|ui| {
            ui.checkbox(&mut e.reveal, "Show");
            generate = ui.button("Generate").clicked();
        });
    });
    ui.end_row();

    let mut remove = None;
    for (n, u) in e.urls.iter_mut().enumerate() {
        let l = ui.label(if n == 0 { "Websites" } else { "" });
        ui.vertical(|ui| {
            ui.add(
                TextEdit::singleline(&mut u.url)
                    .hint_text("https://example.com")
                    .desired_width(300.0),
            )
            .labelled_by(l.id);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt(("mode", n))
                    .selected_text(match u.mode {
                        MatchMode::Origin => "This site only",
                        MatchMode::RegistrableDomain => "Whole domain",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut u.mode, MatchMode::Origin, "This site only");
                        ui.selectable_value(
                            &mut u.mode,
                            MatchMode::RegistrableDomain,
                            "Whole domain",
                        );
                    });
                ui.checkbox(&mut u.allow_http, "Allow http");
                if ui.button("Remove").clicked() {
                    remove = Some(n);
                }
            });
        });
        ui.end_row();
    }
    if let Some(n) = remove {
        e.urls.remove(n);
    }
    ui.label("");
    if ui.button("Add website").clicked() {
        e.urls.push(blank_url());
    }
    ui.end_row();

    let l = ui.label("One-time codes");
    ui.vertical(|ui| {
        if e.totp.is_some() {
            ui.horizontal(|ui| {
                ui.label("Set up.");
                if ui.button("Remove").clicked() {
                    e.totp = None;
                }
            });
        }
        ui.add(
            TextEdit::singleline(&mut *e.totp_input)
                .password(true)
                .hint_text("secret or otpauth:// link"),
        )
        .labelled_by(l.id);
    });
    ui.end_row();
    generate
}

/// A row of the details card: `left` stacks a label over its value, `right`
/// adds buttons from the right edge.
fn detail_row(ui: &mut Ui, left: impl FnOnce(&mut Ui), right: impl FnOnce(&mut Ui)) {
    ui.add_space(12.0);
    let w = ui.available_width();
    // In a narrow pane the buttons go under the value, which then has the
    // whole width to wrap in.
    if w < 480.0 {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            left(ui);
        });
        ui.add_space(6.0);
        ui.allocate_ui_with_layout(
            Vec2::new(w, 0.0),
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                right(ui);
            },
        );
        ui.add_space(12.0);
        return;
    }
    ui.allocate_ui_with_layout(
        Vec2::new(w, 0.0),
        egui::Layout::right_to_left(egui::Align::Center),
        |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            right(ui);
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                left(ui);
            });
        },
    );
    ui.add_space(12.0);
}

/// The generator's chosen style and the settings of each.
struct Generator {
    kind: GenKind,
    options: GenerateOptions,
    words: u8,
    separator: String,
    capitalize: bool,
    number_and_symbol: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GenKind {
    Random,
    Words,
    Apple,
}

impl Default for Generator {
    fn default() -> Self {
        Generator {
            kind: GenKind::Random,
            options: GenerateOptions::default(),
            words: 3,
            separator: String::new(),
            capitalize: true,
            number_and_symbol: false,
        }
    }
}

impl Generator {
    fn style(&self) -> PasswordStyle {
        match self.kind {
            GenKind::Random => PasswordStyle::Random(self.options),
            GenKind::Words => PasswordStyle::Words {
                words: self.words,
                separator: self.separator.clone(),
                capitalize: self.capitalize,
                number_and_symbol: self.number_and_symbol,
            },
            GenKind::Apple => PasswordStyle::Apple,
        }
    }
}

/// How strong a style is, in words.
fn strength_text(kind: GenKind, bits: f64) -> String {
    let rating = match bits {
        b if b >= 100.0 => "Very strong",
        b if b >= 70.0 => "Strong",
        b if b >= 50.0 => "Good for a website that limits guesses",
        _ => {
            "Fine for a website that limits guesses; use 4 or more words for anything that matters"
        }
    };
    let words = if kind == GenKind::Words {
        " Each word is one of 7,772 (the EFF word list)."
    } else {
        ""
    };
    format!("{rating}: about {bits:.0} bits.{words}")
}

/// A one-time code with a space in the middle, as sites print them.
fn spaced(code: &str) -> String {
    let mid = code.len() / 2;
    if code.len() >= 6 && code.is_char_boundary(mid) {
        format!("{} {}", &code[..mid], &code[mid..])
    } else {
        code.to_owned()
    }
}

fn text_field(ui: &mut Ui, label: &str, text: &mut String) {
    let l = ui.label(label);
    ui.add(TextEdit::singleline(text).desired_width(300.0))
        .labelled_by(l.id);
}

/// A page's title and what the page is for.
fn page_header(ui: &mut Ui, title: &str, about: &str) {
    ui.label(theme::title(title, 22.0));
    ui.add(egui::Label::new(RichText::new(about).size(13.5).color(theme::MUTED)).wrap());
    ui.add_space(16.0);
}

/// A small filled circle, as in the sidebar's lock status.
fn status_dot(ui: &mut Ui, colour: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, colour);
}

/// An example path for the synced file on this system.
fn sync_example() -> &'static str {
    if cfg!(windows) {
        r"For example C:\Users\you\OneDrive\vault.svault"
    } else if cfg!(target_os = "macos") {
        "For example /Users/you/Dropbox/vault.svault"
    } else {
        "For example /home/you/Dropbox/vault.svault"
    }
}

/// "12 seconds ago", "5 minutes ago", "3 hours ago".
fn ago(secs: u64) -> String {
    let (n, unit) = match secs {
        0..60 => (secs, "second"),
        60..3600 => (secs / 60, "minute"),
        3600..86400 => (secs / 3600, "hour"),
        _ => (secs / 86400, "day"),
    };
    if n == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{n} {unit}s ago")
    }
}

/// Draw `uri` as a QR code, dark on white with a quiet zone, as phones expect.
fn qr_code(ui: &mut Ui, uri: &str) {
    let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) else {
        ui.colored_label(theme::ERROR, "Could not draw the QR code.");
        return;
    };
    let n = code.width();
    let quiet = 4;
    let cell = 4.0;
    let side = (n + 2 * quiet) as f32 * cell;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Image, true, "Phone QR code"));
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 4.0, egui::Color32::WHITE);
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (x, y) = ((i % n + quiet) as f32, (i / n + quiet) as f32);
            let min = rect.min + egui::vec2(x * cell, y * cell);
            p.rect_filled(
                egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                0.0,
                egui::Color32::BLACK,
            );
        }
    }
}

/// A slot kind's name and what it needs.
fn slot_text(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "password" => ("Password", "Your master password"),
        "fido2" => (
            "Security key or phone",
            "Your master password, then a touch on the key (and its PIN if set), or a \
             passkey on your phone",
        ),
        "tpm" => (
            "This device (TPM)",
            "Your master password and this computer's TPM chip; works only on this computer",
        ),
        "recovery" => (
            "Recovery code",
            "The code on your printed recovery sheet; keep it somewhere safe and offline",
        ),
        _ => ("Other", "A method this app doesn't know yet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_form_builds_the_request() {
        let mut f = KeyForm::new(false);
        assert!(f.to_request().is_err(), "an SSH key needs a title");
        f.title = " Laptop ".into();
        f.ecdsa = true;
        assert!(matches!(
            f.to_request(),
            Ok(Request::GenerateKey { title, kind: KeyKind::SshEcdsaP256, confirm: true })
                if title == "Laptop"
        ));

        let mut f = KeyForm::new(true);
        assert!(f.to_request().is_err(), "an OpenPGP key needs a name");
        f.name = "Alex Example".into();
        assert_eq!(f.user_id().unwrap(), "Alex Example");
        f.email = "alex@example.com".into();
        f.post_quantum = true;
        f.confirm = false;
        assert!(matches!(
            f.to_request(),
            Ok(Request::GeneratePgpKey { title, user_id, post_quantum: true, confirm: false })
                if title == "Alex Example" && user_id == "Alex Example <alex@example.com>"
        ));
        for bad in [
            "alex",
            "alex@",
            "@example.com",
            "alex@example",
            "a b@example.com",
            "a@x.com>",
        ] {
            f.email = bad.into();
            assert!(f.user_id().is_err(), "{bad}");
        }
        f.email.clear();
        f.name = "Alex <x>".into();
        assert!(f.user_id().is_err());
    }
}
