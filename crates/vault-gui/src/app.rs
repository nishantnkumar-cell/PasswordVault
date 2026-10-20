//! The window: create, pair, unlock, then browse and edit items.
//!
//! All vault data comes from `vaultd`; the app keeps only what is on screen
//! and drops it (and clears a password it put on the clipboard) when the
//! vault locks.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Key, RichText, TextEdit, Ui};
use vault_core::item::{Card, CustomField, FieldKind, Identity, ItemData, ItemKind, UrlEntry};
use vault_core::origin::MatchMode;
use vault_core::totp::TotpConfig;
use vault_ipc::{
    ClientScope, ClientToken, GenerateOptions, ImportFormat, ItemId, ItemSummary, Request,
    Response, Secret, SlotId, SlotInfo, StatusInfo, UnlockMethod, hex,
};
use zeroize::Zeroizing;

use crate::client::{Backend, Failure, Paths};

/// How long a copied secret stays on the clipboard.
pub const CLIPBOARD_CLEAR: Duration = Duration::from_secs(30);
const STATUS_EVERY: Duration = Duration::from_secs(2);
const CLIENT_NAME: &str = "desktop app";

/// The system clipboard, or a stand-in for tests.
pub trait Clip {
    fn set(&mut self, text: &str) -> Result<(), String>;
    fn get(&mut self) -> Option<String>;
    fn clear(&mut self);
}

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
    Sync,
}

/// Which screen is showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Connecting,
    Unreachable(String),
    Create,
    ShowRecovery,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Method {
    #[default]
    Password,
    SecurityKey,
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
    recovery_code: Option<Secret>,

    view: View,
    search: String,
    kind_filter: Option<ItemKind>,
    items: Vec<ItemSummary>,
    selected: Option<ItemId>,
    open: Option<(ItemId, ItemData)>,
    reveal: bool,
    totp: Option<(ItemId, Secret, Instant)>,
    totp_pending: bool,
    edit: Option<Edit>,
    confirm_delete: bool,

    gen_options: GenerateOptions,
    generated: Option<Secret>,

    import_format: ImportFormat,
    import_path: String,

    slots: Vec<SlotInfo>,
    slot_form: SlotForm,
    new_recovery: Option<Secret>,
    confirm_remove: Option<SlotId>,

    sync_path: String,

    copied: Option<(Secret, Instant)>,
}

impl App {
    /// Connect to the daemon at `paths`. `wake` repaints the window when an
    /// answer arrives.
    pub fn new(paths: Paths, clip: Box<dyn Clip>, wake: impl Fn() + Send + 'static) -> App {
        let backend = Backend::start(paths.socket.clone(), wake);
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
            recovery_code: None,
            view: View::Items,
            search: String::new(),
            kind_filter: None,
            items: Vec::new(),
            selected: None,
            open: None,
            reveal: false,
            totp: None,
            totp_pending: false,
            edit: None,
            confirm_delete: false,
            gen_options: GenerateOptions {
                length: 24,
                symbols: true,
                avoid_ambiguous: false,
            },
            generated: None,
            import_format: ImportFormat::BitwardenJson,
            import_path: String::new(),
            slots: Vec::new(),
            slot_form: SlotForm::default(),
            new_recovery: None,
            confirm_remove: None,
            sync_path: String::new(),
            copied: None,
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
        self.generated = None;
        self.slots.clear();
        self.slot_form = SlotForm::default();
        self.new_recovery = None;
        self.confirm_remove = None;
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
        let next = if !s.initialized {
            Screen::Create
        } else if self.token.is_none() {
            Screen::Pair
        } else if !s.unlocked {
            Screen::Locked
        } else if self.screen == Screen::ShowRecovery {
            Screen::ShowRecovery
        } else {
            Screen::Unlocked
        };
        if self.screen == Screen::Unlocked && next != Screen::Unlocked {
            self.wipe();
            if next == Screen::Locked {
                self.notice = Some("The vault locked.".into());
            }
        }
        if next == Screen::Unlocked && self.screen != Screen::Unlocked {
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
                if m.contains("locked") && self.screen == Screen::Unlocked {
                    self.refresh();
                }
                self.error = Some(m);
                return;
            }
        };
        match (op, r) {
            (Op::Status, Response::Status(s)) => self.on_status(s),
            (
                Op::Init,
                Response::Initialized {
                    recovery_code,
                    token,
                },
            ) => {
                if let Err(e) = self.paths.save_token(&token) {
                    self.error = Some(format!("Couldn't save this app's pairing: {e}"));
                }
                self.token = Some(token);
                self.new_password = Secret::default();
                self.new_password2 = Secret::default();
                self.recovery_code = Some(recovery_code);
                self.screen = Screen::ShowRecovery;
            }
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
                    self.open = Some((id, item));
                    self.reveal = false;
                    self.confirm_delete = false;
                }
            }
            (Op::Totp(id), Response::Totp { code, remaining }) => {
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
            (Op::RemoveSlot(_), Response::Ok) => {
                self.confirm_remove = None;
                self.notice = Some("Unlock method removed.".into());
                self.send(Op::ListSlots, Request::ListSlots);
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
        self.tick(ui.ctx());
        if self.screen == Screen::Unlocked {
            self.unlocked(ui);
            return;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(380.0);
                ui.add_space(32.0);
                ui.heading("Secret Vault");
                ui.add_space(16.0);
                self.messages(ui);
                match self.screen.clone() {
                    Screen::Connecting => {
                        ui.spinner();
                        ui.label("Connecting to vaultd…");
                    }
                    Screen::Unreachable(m) => {
                        ui.label(m);
                        ui.label(if cfg!(windows) {
                            "Start vaultd.exe, or sign out and in if it starts at login."
                        } else {
                            "Start it with `systemctl --user start vaultd`."
                        });
                        if ui.button("Try again").clicked() {
                            self.screen = Screen::Connecting;
                            self.refresh();
                        }
                    }
                    Screen::Create => self.create(ui),
                    Screen::ShowRecovery => self.show_recovery(ui),
                    Screen::Pair => self.pair_or_unlock(ui, true),
                    Screen::Locked => self.pair_or_unlock(ui, false),
                    Screen::Unlocked => {}
                }
            });
        });
    }

    fn messages(&mut self, ui: &mut Ui) {
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        if let Some(n) = &self.notice {
            ui.label(n);
        }
        if let Some(b) = self.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(b);
            });
        }
    }

    fn create(&mut self, ui: &mut Ui) {
        ui.label("No vault yet. Choose a master password of at least 8 characters.");
        ui.add_space(8.0);
        let mut submit = false;
        egui::Grid::new("create").num_columns(2).show(ui, |ui| {
            secret_field(ui, "Master password", &mut self.new_password);
            ui.end_row();
            submit |= secret_field(ui, "Repeat it", &mut self.new_password2);
            ui.end_row();
        });
        let ok = self.busy.is_none();
        submit |= ui
            .add_enabled(ok, egui::Button::new("Create vault"))
            .clicked();
        if submit && ok {
            if self.new_password.chars().count() < 8 {
                self.error = Some("The password needs at least 8 characters.".into());
            } else if *self.new_password != *self.new_password2 {
                self.error = Some("The passwords don't match.".into());
            } else {
                let password = self.new_password.clone();
                self.act(
                    "Creating the vault…",
                    Op::Init,
                    Request::Init {
                        password,
                        client_name: CLIENT_NAME.into(),
                    },
                );
            }
        }
        ui.add_space(16.0);
        ui.separator();
        ui.label(
            "Already use the vault on another device and sync it through OneDrive, \
             Google Drive or Dropbox? Join it instead:",
        );
        if self.sync_form(ui, "Join") {
            let path = self.sync_path.trim().to_owned();
            self.act("Joining…", Op::Sync, Request::SetSync { path: Some(path) });
        }
    }

    /// The synced file's path and a button. Returns whether it was pressed
    /// with a path filled in.
    fn sync_form(&mut self, ui: &mut Ui, button: &str) -> bool {
        egui::Grid::new("sync-path").num_columns(2).show(ui, |ui| {
            text_field(ui, "File in the synced folder", &mut self.sync_path);
            ui.end_row();
        });
        ui.label(
            RichText::new(if cfg!(windows) {
                r"For example C:\Users\you\OneDrive\vault.svault"
            } else {
                "For example /home/you/Dropbox/vault.svault"
            })
            .weak(),
        );
        let ok = self.busy.is_none() && !self.sync_path.trim().is_empty();
        ui.add_enabled(ok, egui::Button::new(button)).clicked() && ok
    }

    fn sync_page(&mut self, ui: &mut Ui) {
        ui.heading("Sync");
        ui.add_space(8.0);
        ui.label(
            "Keep this vault in step with your other devices through a folder that \
             OneDrive, Google Drive or Dropbox syncs. The file there is encrypted like \
             this one, and changes from each device are merged.",
        );
        ui.add_space(8.0);
        let sync = self.status.as_ref().and_then(|(s, _)| s.sync.clone());
        let ok = self.busy.is_none();
        match sync {
            Some(sync) => {
                egui::Grid::new("sync").num_columns(2).show(ui, |ui| {
                    ui.label("File");
                    ui.label(RichText::new(&sync.path).monospace());
                    ui.end_row();
                    ui.label("Last synced");
                    ui.label(match sync.last_sync {
                        Some(t) => {
                            let ago = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_or(0, |d| d.as_secs())
                                .saturating_sub(t);
                            format!("{ago} s ago")
                        }
                        None => "not yet".into(),
                    });
                    ui.end_row();
                });
                if let Some(e) = &sync.error {
                    ui.colored_label(ui.visuals().error_fg_color, format!("Problem: {e}"));
                }
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
                ui.horizontal(|ui| {
                    if ui.add_enabled(ok, egui::Button::new("Sync now")).clicked() {
                        self.act("Syncing…", Op::Sync, Request::SyncNow);
                    }
                    if ui.add_enabled(ok, egui::Button::new("Turn off")).clicked() {
                        self.act("Turning off…", Op::Sync, Request::SetSync { path: None });
                    }
                });
            }
            None => {
                if self.sync_form(ui, "Turn on") {
                    let path = self.sync_path.trim().to_owned();
                    self.act("Syncing…", Op::Sync, Request::SetSync { path: Some(path) });
                }
            }
        }
    }

    fn show_recovery(&mut self, ui: &mut Ui) {
        ui.label("Your vault is ready. This is its recovery code. It is shown only once.");
        ui.add_space(8.0);
        if let Some(code) = &self.recovery_code {
            ui.label(RichText::new(code.as_str()).monospace().size(18.0));
        }
        ui.add_space(8.0);
        ui.label(
            "Write it down and keep it offline. It unlocks the vault on its own, \
             so anyone who has it can read your passwords.",
        );
        ui.add_space(8.0);
        if ui.button("I've written it down").clicked() {
            self.recovery_code = None;
            self.screen = Screen::Connecting;
            self.refresh();
        }
    }

    fn pair_or_unlock(&mut self, ui: &mut Ui, pair: bool) {
        if pair {
            ui.label("Pair this app with your vault by unlocking it once.");
        }
        let f = &mut self.unlock;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut f.method, Method::Password, "Password");
            ui.selectable_value(&mut f.method, Method::SecurityKey, "Security key");
            ui.selectable_value(&mut f.method, Method::Tpm, "TPM");
            ui.selectable_value(&mut f.method, Method::Recovery, "Recovery code");
        });
        ui.add_space(8.0);
        let mut submit = false;
        egui::Grid::new("unlock").num_columns(2).show(ui, |ui| {
            if f.method == Method::Recovery {
                submit |= secret_field(ui, "Recovery code", &mut f.code);
                ui.end_row();
            } else {
                submit |= secret_field(ui, "Master password", &mut f.password);
                ui.end_row();
            }
            if matches!(f.method, Method::SecurityKey | Method::Tpm) {
                submit |= secret_field(ui, "PIN (if set)", &mut f.pin);
                ui.end_row();
            }
        });
        let ok = self.busy.is_none();
        let label = if pair { "Pair" } else { "Unlock" };
        submit |= ui.add_enabled(ok, egui::Button::new(label)).clicked();
        if submit && ok {
            let busy = match self.unlock.method {
                Method::SecurityKey => "Touch your security key when it blinks…",
                _ if pair => "Pairing…",
                _ => "Unlocking…",
            };
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
            ui.add_space(12.0);
            ui.label("Or approve this app in a window vaultd opens, without typing anything here.");
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
        egui::Panel::top("bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (v, name) in [
                    (View::Items, "Items"),
                    (View::Generator, "Generator"),
                    (View::Import, "Import"),
                    (View::Slots, "Unlock methods"),
                    (View::Sync, "Sync"),
                ] {
                    if ui.selectable_label(self.view == v, name).clicked() && self.view != v {
                        self.view = v;
                        self.error = None;
                        self.notice = None;
                        if v == View::Slots {
                            self.send(Op::ListSlots, Request::ListSlots);
                        }
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Lock").clicked() {
                        self.act("Locking…", Op::Lock, Request::Lock);
                    }
                });
            });
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            let mut line = "Unlocked".to_owned();
            if let Some((s, at)) = &self.status {
                if let Some(left) = s.idle_lock_in {
                    let left = left.saturating_sub(at.elapsed().as_secs());
                    line += &format!(". Locks after {}:{:02} idle", left / 60, left % 60);
                }
                if let Some(sync) = &s.sync {
                    line += if sync.error.is_some() {
                        ". Sync has a problem (see Sync)"
                    } else if sync.last_sync.is_some() {
                        ". Synced"
                    } else {
                        ". Sync is on"
                    };
                }
                if s.rollback_detected {
                    line +=
                        ". WARNING: the vault file is older than one seen before, so saving is off";
                }
            }
            ui.label(line);
        });
        match self.view {
            View::Items => {
                egui::Panel::left("list")
                    .resizable(true)
                    .default_size(260.0)
                    .show(ui, |ui| self.item_list(ui));
                egui::CentralPanel::default().show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if self.edit.is_some() {
                            self.edit_form(ui);
                        } else {
                            self.item_detail(ui);
                        }
                    });
                });
            }
            View::Generator => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.messages(ui);
                    self.generator(ui);
                });
            }
            View::Import => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.messages(ui);
                    self.import(ui);
                });
            }
            View::Slots => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| self.slots_page(ui));
                });
            }
            View::Sync => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.messages(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| self.sync_page(ui));
                });
            }
        }
    }

    fn item_list(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let l = ui.label("Search");
            ui.add(TextEdit::singleline(&mut self.search).desired_width(f32::INFINITY))
                .labelled_by(l.id);
        });
        ui.horizontal_wrapped(|ui| {
            if ui
                .selectable_label(self.kind_filter.is_none(), "All")
                .clicked()
            {
                self.kind_filter = None;
            }
            for (k, name) in [
                (ItemKind::Login, "Logins"),
                (ItemKind::Note, "Notes"),
                (ItemKind::Card, "Cards"),
                (ItemKind::Identity, "Identities"),
            ] {
                if ui
                    .selectable_label(self.kind_filter == Some(k), name)
                    .clicked()
                {
                    self.kind_filter = Some(k);
                }
            }
        });
        ui.horizontal(|ui| {
            let mut new = None;
            ui.menu_button("New item", |ui| {
                for k in ItemKind::ALL {
                    if ui.button(k.label()).clicked() {
                        new = Some(k);
                    }
                }
            });
            if let Some(k) = new {
                self.selected = None;
                self.open = None;
                self.edit = Some(Edit::new(k));
            }
        });
        ui.separator();
        let q = self.search.to_lowercase();
        let mut pick = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                for i in &self.items {
                    if self.kind_filter.is_some_and(|k| k != i.kind) {
                        continue;
                    }
                    let hit = q.is_empty()
                        || i.title.to_lowercase().contains(&q)
                        || i.subtitle.to_lowercase().contains(&q)
                        || i.urls.iter().any(|u| u.to_lowercase().contains(&q));
                    if !hit {
                        continue;
                    }
                    let text = if i.subtitle.is_empty() {
                        i.title.clone()
                    } else {
                        format!("{}\n{}", i.title, i.subtitle)
                    };
                    if ui
                        .selectable_label(self.selected == Some(i.id), text)
                        .clicked()
                    {
                        pick = Some(i.id);
                    }
                }
                if self.items.is_empty() {
                    ui.label("No items yet.");
                }
            });
        });
        if let Some(id) = pick {
            self.select(id);
        }
    }

    fn item_detail(&mut self, ui: &mut Ui) {
        let Some((id, item)) = &self.open else {
            if self.selected.is_some() {
                ui.spinner();
            } else {
                ui.label("Pick an item on the left, or make a new one.");
            }
            return;
        };
        let id = *id;
        let reveal = self.reveal;
        let mut copy: Option<(Secret, String)> = None;
        let mut copy_code: Option<Secret> = None;
        let mut toggle_reveal = false;
        let mut edit = false;
        let mut delete = false;
        ui.heading(&item.title);
        ui.label(RichText::new(item.kind.label()).small());
        ui.add_space(8.0);
        // A row: label, value, and a Copy button when the value is not empty.
        let mut row = |ui: &mut Ui, label: &str, value: &str, secret: bool| {
            if value.is_empty() {
                return;
            }
            ui.label(label);
            if secret && !reveal {
                ui.label("••••••••••••");
            } else {
                ui.label(RichText::new(value).monospace());
            }
            ui.horizontal(|ui| {
                if ui
                    .button(format!("Copy {}", label.to_lowercase()))
                    .clicked()
                {
                    copy = Some((Zeroizing::new(value.to_owned()), label.to_owned()));
                }
                if secret && ui.button(if reveal { "Hide" } else { "Show" }).clicked() {
                    toggle_reveal = true;
                }
            });
            ui.end_row();
        };
        egui::Grid::new("detail")
            .num_columns(3)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                match item.kind {
                    ItemKind::Login => {
                        row(ui, "Username", &item.username, false);
                        row(ui, "Password", &item.password, true);
                        if item.totp.is_some() {
                            ui.label("One-time code");
                            match &self.totp {
                                Some((tid, code, until)) if *tid == id => {
                                    let left =
                                        until.saturating_duration_since(Instant::now()).as_secs();
                                    ui.label(
                                        RichText::new(format!("{}  ({left}s)", code.as_str()))
                                            .monospace(),
                                    );
                                    if ui.button("Copy code").clicked() {
                                        copy_code = Some(code.clone());
                                    }
                                }
                                _ => {
                                    ui.spinner();
                                    ui.label("");
                                }
                            }
                            ui.end_row();
                        }
                        for (n, u) in item.urls.iter().enumerate() {
                            ui.label(if n == 0 { "Websites" } else { "" });
                            ui.label(&u.url);
                            let mut how = match u.mode {
                                MatchMode::Origin => "this site only".to_owned(),
                                MatchMode::RegistrableDomain => "whole domain".to_owned(),
                            };
                            if u.allow_http {
                                how += ", http allowed";
                            }
                            ui.label(how);
                            ui.end_row();
                        }
                    }
                    ItemKind::Note => {}
                    ItemKind::Card => {
                        let c = item.card.clone().unwrap_or_default();
                        row(ui, "Name on card", &c.holder, false);
                        ui.label("Card");
                        ui.label(c.describe());
                        ui.label("");
                        ui.end_row();
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
            });
        if !item.notes.is_empty() {
            ui.add_space(8.0);
            ui.label("Notes");
            ui.label(&item.notes);
        }
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Edit").clicked() {
                edit = true;
            }
            if self.confirm_delete {
                ui.label("Delete this item for good?");
                if ui.button("Yes, delete").clicked() {
                    delete = true;
                }
                if ui.button("Cancel").clicked() {
                    self.confirm_delete = false;
                }
            } else if ui.button("Delete").clicked() {
                self.confirm_delete = true;
            }
        });
        if toggle_reveal {
            self.reveal = !self.reveal;
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

    fn edit_form(&mut self, ui: &mut Ui) {
        let Some(e) = &mut self.edit else { return };
        let mut generate = false;
        ui.heading(match (e.id.is_some(), e.kind) {
            (true, _) => "Edit item".to_owned(),
            (false, k) => format!("New {}", k.label().to_lowercase()),
        });
        ui.add_space(8.0);
        egui::Grid::new("edit")
            .num_columns(2)
            .spacing([12.0, 8.0])
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
                                    .desired_width(240.0),
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
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut f.name)
                                .hint_text("Name")
                                .desired_width(120.0),
                        );
                        ui.add(
                            TextEdit::singleline(&mut *f.value)
                                .hint_text("Value")
                                .password(f.hidden && !e.reveal)
                                .desired_width(180.0),
                        );
                        ui.checkbox(&mut f.hidden, "Hidden");
                        if ui.button("Remove").clicked() {
                            remove = Some(n);
                        }
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
            save = ui.add_enabled(ok, egui::Button::new("Save")).clicked();
            cancel = ui.button("Cancel").clicked();
        });
        if generate {
            let options = self.gen_options;
            self.send(Op::GenerateForEdit, Request::Generate { options });
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

    fn generator(&mut self, ui: &mut Ui) {
        ui.heading("Password generator");
        ui.add_space(8.0);
        let o = &mut self.gen_options;
        ui.add(egui::Slider::new(&mut o.length, 8..=64).text("characters"));
        ui.checkbox(&mut o.symbols, "Symbols");
        ui.checkbox(&mut o.avoid_ambiguous, "Avoid look-alike characters");
        if ui.button("Generate").clicked() {
            let options = *o;
            self.send(Op::Generate, Request::Generate { options });
        }
        let mut copy = None;
        if let Some(p) = &self.generated {
            ui.add_space(8.0);
            ui.label(RichText::new(p.as_str()).monospace().size(16.0));
            if ui.button("Copy password").clicked() {
                copy = Some(p.clone());
            }
        }
        ui.add_space(8.0);
        ui.label("New items use these settings when you press Generate there.");
        if let Some(p) = copy {
            self.copy(&p, "Password");
        }
    }

    fn import(&mut self, ui: &mut Ui) {
        ui.heading("Import");
        ui.add_space(8.0);
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
        let ok = self.busy.is_none() && !self.import_path.trim().is_empty();
        if ui.add_enabled(ok, egui::Button::new("Import")).clicked() {
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
    }

    fn slots_page(&mut self, ui: &mut Ui) {
        ui.heading("Unlock methods");
        ui.add_space(8.0);
        let mut remove = None;
        egui::Grid::new("slots")
            .num_columns(4)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                for s in &self.slots {
                    ui.label(match s.kind.as_str() {
                        "password" => "Password",
                        "fido2" => "Password + security key",
                        "tpm" => "Password + TPM",
                        "recovery" => "Recovery code",
                        k => k,
                    });
                    ui.label(&s.label);
                    ui.label(RichText::new(&hex(&s.id)[..8]).monospace());
                    if self.confirm_remove == Some(s.id) {
                        ui.horizontal(|ui| {
                            if ui.button("Yes, remove").clicked() {
                                remove = Some(s.id);
                            }
                            if ui.button("Cancel").clicked() {
                                self.confirm_remove = None;
                            }
                        });
                    } else if ui.button("Remove").clicked() {
                        self.confirm_remove = Some(s.id);
                    }
                    ui.end_row();
                }
            });
        if let Some(slot) = remove {
            self.act(
                "Removing…",
                Op::RemoveSlot(slot),
                Request::RemoveSlot { slot },
            );
        }
        ui.label(
            "Removing a method doesn't change the vault key. To shut out a lost key or a \
             leaked password, use `vault revoke` as well.",
        );
        if let Some(code) = &self.new_recovery {
            ui.add_space(8.0);
            ui.label("New recovery code, shown only once. Write it down and keep it offline:");
            ui.label(RichText::new(code.as_str()).monospace().size(18.0));
            if ui.button("I've written it down").clicked() {
                self.new_recovery = None;
            }
        }
        ui.separator();
        ui.heading("Add a method");
        let f = &mut self.slot_form;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut f.kind, SlotKind::Password, "Password");
            ui.selectable_value(&mut f.kind, SlotKind::SecurityKey, "Security key");
            ui.selectable_value(&mut f.kind, SlotKind::Tpm, "TPM");
            ui.selectable_value(&mut f.kind, SlotKind::Recovery, "Recovery code");
        });
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
            if matches!(f.kind, SlotKind::SecurityKey | SlotKind::Tpm) {
                secret_field(ui, "PIN (optional)", &mut f.pin);
                ui.end_row();
            }
        });
        match f.kind {
            SlotKind::SecurityKey => {
                ui.checkbox(&mut f.require_uv, "Also ask for the key's PIN every time");
            }
            SlotKind::Tpm => {
                ui.checkbox(
                    &mut f.bind_pcr7,
                    "Stop working if Secure Boot settings change (PCR 7)",
                );
            }
            _ => {}
        }
        let ok = self.busy.is_none();
        submit |= ui.add_enabled(ok, egui::Button::new("Add")).clicked();
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
            SlotKind::Recovery => ("Adding…", Request::AddRecoverySlot { label }),
        };
        self.act(busy, Op::AddSlot, request);
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.clear_clipboard();
    }
}

/// A labelled password box. True when Enter was pressed in it.
fn secret_field(ui: &mut Ui, label: &str, text: &mut Secret) -> bool {
    let l = ui.label(label);
    let r = ui
        .add(
            TextEdit::singleline(&mut **text)
                .password(true)
                .desired_width(240.0),
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
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(&mut *e.password)
                .password(!e.reveal)
                .desired_width(240.0),
        )
        .labelled_by(l.id);
        ui.checkbox(&mut e.reveal, "Show");
        generate = ui.button("Generate").clicked();
    });
    ui.end_row();

    let mut remove = None;
    for (n, u) in e.urls.iter_mut().enumerate() {
        let l = ui.label(if n == 0 { "Websites" } else { "" });
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut u.url)
                    .hint_text("https://example.com")
                    .desired_width(240.0),
            )
            .labelled_by(l.id);
            egui::ComboBox::from_id_salt(("mode", n))
                .selected_text(match u.mode {
                    MatchMode::Origin => "This site only",
                    MatchMode::RegistrableDomain => "Whole domain",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut u.mode, MatchMode::Origin, "This site only");
                    ui.selectable_value(&mut u.mode, MatchMode::RegistrableDomain, "Whole domain");
                });
            ui.checkbox(&mut u.allow_http, "Allow http");
            if ui.button("Remove").clicked() {
                remove = Some(n);
            }
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

fn text_field(ui: &mut Ui, label: &str, text: &mut String) {
    let l = ui.label(label);
    ui.add(TextEdit::singleline(text).desired_width(240.0))
        .labelled_by(l.id);
}
