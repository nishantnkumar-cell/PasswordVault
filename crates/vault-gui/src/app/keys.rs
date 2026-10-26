//! Key tools: import an SSH or OpenPGP key, export a private key after
//! proving an unlock factor again, and the OpenPGP page that encrypts,
//! decrypts, signs and verifies with the vault's keys.
//!
//! Secret keys never come to the app except on export. Plaintext from a
//! decryption and an exported key are held here, zeroized on drop, and go
//! when the vault locks.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Margin, RichText, TextEdit, Ui};
use vault_ipc::{ItemId, ItemSummary, Request, Response, Secret, SecretBytes, local};
use zeroize::Zeroizing;

use super::{
    App, Filter, Method, Op, UnlockForm, View, WINDOWS_ASKS_KEY_PIN, detail_row, page_header,
    show_button,
};
use crate::theme::{self, Icon};

/// The most a message or file can be: one request frame, less room for the
/// rest of the request.
const MAX_INPUT: u64 = (vault_ipc::MAX_FRAME - (64 << 10)) as u64;

/// Whether a listed key is an OpenPGP one (the rest are SSH keys).
pub(super) fn is_pgp(i: &ItemSummary) -> bool {
    i.key.as_deref().is_some_and(|k| k.starts_with("OpenPGP"))
}

/// Read a file the user named, refusing ones too big to send to vaultd.
fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let path = &expand(path);
    let shown = |e: std::io::Error| format!("{path}: {e}");
    let len = std::fs::metadata(path).map_err(shown)?.len();
    if len > MAX_INPUT {
        return Err(format!(
            "{path} is {} MiB; the vault handles files up to {} MiB.",
            len >> 20,
            MAX_INPUT >> 20
        ));
    }
    std::fs::read(path).map_err(shown)
}

/// Write `bytes` to a new file. An existing file is never replaced, so a
/// slip can't overwrite the message being decrypted or a key. Secrets are
/// readable only by this user.
fn write_new(path: &str, bytes: &[u8], secret: bool) -> Result<(), String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("Type where to save it.".into());
    }
    let shown = |e: std::io::Error| format!("{path}: {e}");
    if Path::new(path).exists() {
        return Err(format!(
            "{path} already exists. Pick another name, or move that file first."
        ));
    }
    if secret {
        local::write_private(Path::new(path), bytes).map_err(shown)
    } else {
        std::fs::write(path, bytes).map_err(shown)
    }
}

/// The form for bringing in an SSH or OpenPGP key someone already has.
#[derive(Default)]
pub(super) struct KeyImport {
    pub(super) pgp: bool,
    title: String,
    path: String,
    pasted: Secret,
    passphrase: Secret,
    confirm: bool,
    /// vaultd said the key is encrypted, so the passphrase box is shown.
    pub(super) needs_passphrase: bool,
}

impl KeyImport {
    pub(super) fn new(pgp: bool) -> KeyImport {
        KeyImport {
            pgp,
            confirm: true,
            ..KeyImport::default()
        }
    }

    /// The key's bytes, from the file if one is named, or as pasted.
    fn key(&self) -> Result<SecretBytes, String> {
        if !self.path.trim().is_empty() {
            return Ok(Zeroizing::new(read_file(&self.path)?));
        }
        if self.pasted.trim().is_empty() {
            return Err("Pick the key file, or paste the key.".into());
        }
        Ok(Zeroizing::new(self.pasted.trim().as_bytes().to_vec()))
    }

    /// The title typed, or the file's name without its extension.
    fn title(&self) -> Result<String, String> {
        let t = self.title.trim();
        if !t.is_empty() {
            return Ok(t.to_owned());
        }
        Path::new(self.path.trim())
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "Give the key a title.".into())
    }

    pub(super) fn to_request(&self) -> Result<Request, String> {
        let title = self.title()?;
        let key = self.key()?;
        let passphrase = (!self.passphrase.is_empty()).then(|| self.passphrase.clone());
        Ok(if self.pgp {
            Request::ImportPgpKey {
                title,
                key,
                passphrase,
                confirm: self.confirm,
            }
        } else {
            let text = String::from_utf8(key.to_vec())
                .map_err(|_| "That isn't an OpenSSH private key file.")?;
            Request::ImportSshKey {
                title,
                private: Zeroizing::new(text),
                passphrase,
                confirm: self.confirm,
            }
        })
    }
}

/// Exporting the open key's private half.
pub(super) struct Export {
    pub(super) id: ItemId,
    pub(super) form: UnlockForm,
    /// The exported key, once vaultd sends it.
    pub(super) key: Option<Secret>,
    reveal: bool,
    path: String,
}

impl Export {
    fn new(id: ItemId) -> Export {
        Export {
            id,
            form: UnlockForm::default(),
            key: None,
            reveal: false,
            path: String::new(),
        }
    }
}

/// What the OpenPGP page does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Task {
    #[default]
    Encrypt,
    Decrypt,
    Sign,
    Verify,
}

impl Task {
    const ALL: [(Task, Icon, &'static str); 4] = [
        (Task::Encrypt, Icon::Lock, "Encrypt"),
        (Task::Decrypt, Icon::Unlocked, "Decrypt"),
        (Task::Sign, Icon::Signature, "Sign"),
        (Task::Verify, Icon::Shield, "Verify"),
    ];
}

/// Text typed or pasted into the page, or a file.
#[derive(Default)]
struct Source {
    file: bool,
    text: Secret,
    path: String,
}

impl Source {
    fn read(&self, what: &str) -> Result<Vec<u8>, String> {
        if self.file {
            if self.path.trim().is_empty() {
                return Err(format!("Type the path of the {what}."));
            }
            read_file(&self.path)
        } else if self.text.is_empty() {
            Err(format!("Type or paste the {what}."))
        } else {
            Ok(self.text.as_bytes().to_vec())
        }
    }

    /// A text box or a path box, with a switch between them.
    fn show(&mut self, ui: &mut Ui, id: &str, label: &str, hint: &str, rows: usize) {
        ui.horizontal(|ui| {
            ui.label(theme::bold(label).size(13.0));
            ui.add_space(8.0);
            ui.selectable_value(&mut self.file, false, "Text");
            ui.selectable_value(&mut self.file, true, "File");
        });
        if self.file {
            let r = ui.add(
                TextEdit::singleline(&mut self.path)
                    .hint_text(file_example())
                    .desired_width(f32::INFINITY),
            );
            ui.ctx()
                .accesskit_node_builder(r.id, |n| n.set_label(format!("{label} file")));
        } else {
            let r = ui.add(
                TextEdit::multiline(&mut *self.text)
                    .id_salt(id)
                    .hint_text(hint)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(rows)
                    .desired_width(f32::INFINITY),
            );
            ui.ctx()
                .accesskit_node_builder(r.id, |n| n.set_label(label.to_owned()));
        }
    }
}

/// What came back from vaultd.
pub(super) enum Output {
    /// Ciphertext or a signature: not secret.
    Public(Vec<u8>),
    /// Decrypted data, and the title of the key that opened it.
    Plain(SecretBytes, String),
    /// A good signature, by this key.
    Good(String),
}

/// The OpenPGP page.
#[derive(Default)]
pub(super) struct PgpTools {
    pub(super) task: Task,
    input: Source,
    /// Verify: the detached signature.
    signature: Source,
    /// Encrypt: the vault's own keys to encrypt to.
    to_items: Vec<ItemId>,
    /// Encrypt and verify: other people's public keys, pasted or as paths.
    others: String,
    /// Encrypt (optional) and sign: whose key signs.
    signer: Option<ItemId>,
    binary: bool,
    pub(super) output: Option<Output>,
    reveal: bool,
    save_path: String,
    /// A result just arrived: bring it into view.
    scroll: bool,
}

impl PgpTools {
    /// Drop the input and the result, keeping the choices.
    pub(super) fn clear(&mut self) {
        self.input = Source {
            file: self.input.file,
            ..Source::default()
        };
        self.signature = Source {
            file: self.signature.file,
            ..Source::default()
        };
        self.output = None;
        self.reveal = false;
        self.save_path.clear();
    }

    fn request(&self, keys: &[&ItemSummary]) -> Result<Request, String> {
        let armor = !self.binary;
        let live = |id: &ItemId| keys.iter().any(|k| k.id == *id);
        match self.task {
            Task::Encrypt => {
                let to_items: Vec<ItemId> = self
                    .to_items
                    .iter()
                    .filter(|id| live(id))
                    .copied()
                    .collect();
                let to_certs = certificates(&self.others)?;
                if to_items.is_empty() && to_certs.is_empty() {
                    return Err(
                        "Pick who can read it: one of your keys, or paste someone's public key."
                            .into(),
                    );
                }
                Ok(Request::PgpEncrypt {
                    to_items,
                    to_certs,
                    data: Zeroizing::new(self.input.read("message")?),
                    armor,
                    sign_with: self.signer.filter(live),
                })
            }
            Task::Decrypt => Ok(Request::PgpDecrypt {
                message: self.input.read("encrypted message")?,
            }),
            Task::Sign => {
                let id = self
                    .signer
                    .filter(live)
                    .ok_or("Pick the key to sign with.")?;
                Ok(Request::PgpSign {
                    id,
                    data: self.input.read("text or file to sign")?,
                    armor,
                    // Pasted text gets a text signature, so it still checks
                    // after a mail program changes its line endings.
                    text: !self.input.file,
                })
            }
            Task::Verify => Ok(Request::PgpVerify {
                data: self.input.read("text or file that was signed")?,
                signature: self.signature.read("signature")?,
                certs: certificates(&self.others)?,
            }),
        }
    }

    /// A file name to suggest for the result.
    fn suggest_path(&self) -> String {
        let input = self.input.path.trim();
        if !self.input.file || input.is_empty() {
            return String::new();
        }
        let ext = if self.binary { "gpg" } else { "asc" };
        match self.task {
            Task::Encrypt => format!("{input}.{ext}"),
            Task::Sign => format!("{input}.{}", if self.binary { "sig" } else { "asc" }),
            Task::Decrypt => {
                let p = PathBuf::from(input);
                match p.extension().and_then(|e| e.to_str()) {
                    Some("gpg" | "pgp" | "asc") => p.with_extension("").display().to_string(),
                    _ => format!("{input}.out"),
                }
            }
            Task::Verify => String::new(),
        }
    }
}

/// Public keys from a box that holds armored keys, file paths (one per
/// line), or both.
fn certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut block: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(b) = &mut block {
            b.push_str(l);
            b.push('\n');
            if l.starts_with("-----END PGP") {
                out.push(block.take().expect("in a block").into_bytes());
            }
        } else if l.starts_with("-----BEGIN PGP") {
            block = Some(format!("{l}\n"));
        } else if !l.is_empty() {
            out.push(read_file(l)?);
        }
    }
    if block.is_some() {
        return Err("A pasted public key is cut off: its END line is missing.".into());
    }
    Ok(out)
}

/// The first lines of a result to show, and how many lines are left out.
fn preview(text: &str) -> (&str, usize) {
    const LINES: usize = 40;
    match text.match_indices('\n').nth(LINES - 1) {
        Some((end, _)) => (&text[..end], text[end + 1..].lines().count()),
        None => (text, 0),
    }
}

/// An example path for a file on this system.
fn file_example() -> &'static str {
    if cfg!(windows) {
        r"C:\Users\you\Documents\report.pdf"
    } else if cfg!(target_os = "macos") {
        "/Users/you/Documents/report.pdf"
    } else {
        "/home/you/Documents/report.pdf"
    }
}

/// Where an SSH key usually lives, to suggest on export.
fn key_example(pgp: bool) -> &'static str {
    match (pgp, cfg!(windows)) {
        (true, true) => r"C:\Users\you\Documents\secret-key.asc",
        (true, false) => "~/secret-key.asc",
        (false, true) => r"C:\Users\you\.ssh\id_ed25519",
        (false, false) => "~/.ssh/id_ed25519",
    }
}

/// `~/x` as a real path, since the field isn't run through a shell.
fn expand(path: &str) -> String {
    let path = path.trim();
    match path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        Some(rest) => std::env::home_dir()
            .map(|h| h.join(rest).display().to_string())
            .unwrap_or_else(|| path.to_owned()),
        None => path.to_owned(),
    }
}

impl App {
    /// Open the key import form in place of the item details.
    pub(super) fn start_import(&mut self, pgp: bool) {
        self.start_key(pgp);
        self.new_key = None;
        self.import_key = Some(KeyImport::new(pgp));
    }

    pub(super) fn on_key_result(&mut self, op: Op, r: Response) {
        match (op, r) {
            (Op::ImportKey, Response::ItemSaved { id }) => {
                self.import_key = None;
                self.notice = Some(
                    "Key imported. The vault keeps its own copy now, so you can delete the \
                     key file once you no longer need it."
                        .into(),
                );
                if !matches!(self.filter, Filter::All | Filter::Keys) {
                    self.filter = Filter::Keys;
                }
                self.send(Op::ListItems, Request::ListItems);
                self.select(id);
            }
            (Op::ExportKey(id), Response::ExportedKey(key)) => {
                if let Some(x) = self.export.as_mut().filter(|x| x.id == id) {
                    x.form = UnlockForm {
                        method: x.form.method,
                        ..UnlockForm::default()
                    };
                    x.key = Some(key);
                }
            }
            (Op::Pgp, Response::Bytes(b)) => {
                self.pgp.output = Some(Output::Public(b));
                self.pgp.scroll = true;
                self.pgp.save_path = self.pgp.suggest_path();
            }
            (Op::Pgp, Response::Decrypted { plaintext, key }) => {
                self.pgp.output = Some(Output::Plain(plaintext, key));
                self.pgp.scroll = true;
                self.pgp.reveal = false;
                self.pgp.save_path = self.pgp.suggest_path();
            }
            (Op::Pgp, Response::Verified(who)) => {
                self.pgp.output = Some(Output::Good(who));
                self.pgp.scroll = true;
            }
            _ => self.error = Some("Unexpected answer from vaultd.".into()),
        }
    }

    /// A failed import of an encrypted key asks for its passphrase.
    pub(super) fn on_key_error(&mut self, op: Op, m: &str) {
        if op == Op::ImportKey
            && let Some(f) = &mut self.import_key
            && (m.contains("passphrase") || m.contains("encrypted"))
        {
            f.needs_passphrase = true;
        }
    }

    pub(super) fn import_key_form(&mut self, ui: &mut Ui) {
        let Some(f) = &mut self.import_key else {
            return;
        };
        ui.label(theme::title(
            if f.pgp {
                "Import an OpenPGP key"
            } else {
                "Import an SSH key"
            },
            20.0,
        ));
        ui.label(
            RichText::new(if f.pgp {
                "Bring in a secret key you already use, such as one exported from GnuPG \
                 with gpg --export-secret-keys --armor. The vault stores it without a \
                 passphrase, protected by the vault itself."
            } else {
                "Bring in a private key you already use, such as ~/.ssh/id_ed25519. The \
                 vault stores it without a passphrase, protected by the vault itself. \
                 RSA and DSA keys can't be imported."
            })
            .color(theme::MUTED),
        );
        ui.add_space(10.0);
        egui::Grid::new("import-key")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                let l = ui.label("Key file");
                ui.add(
                    TextEdit::singleline(&mut f.path)
                        .hint_text(key_example(f.pgp))
                        .desired_width(340.0),
                )
                .labelled_by(l.id);
                ui.end_row();
                let l = ui.label("Or paste it");
                ui.add(
                    TextEdit::multiline(&mut *f.pasted)
                        .password(true)
                        .hint_text(if f.pgp {
                            "-----BEGIN PGP PRIVATE KEY BLOCK-----"
                        } else {
                            "-----BEGIN OPENSSH PRIVATE KEY-----"
                        })
                        .desired_rows(2)
                        .desired_width(340.0),
                )
                .labelled_by(l.id);
                ui.end_row();
                let l = ui.label("Title");
                ui.add(
                    TextEdit::singleline(&mut f.title)
                        .hint_text("The file's name, if left empty")
                        .desired_width(340.0),
                )
                .labelled_by(l.id);
                ui.end_row();
                if f.needs_passphrase {
                    let l = ui.label("Passphrase");
                    ui.add(
                        TextEdit::singleline(&mut *f.passphrase)
                            .password(true)
                            .desired_width(340.0),
                    )
                    .labelled_by(l.id);
                    ui.end_row();
                }
            });
        if f.needs_passphrase {
            ui.label(
                RichText::new("This key is protected by a passphrase. Type it to import the key.")
                    .small()
                    .color(theme::WARN),
            );
        }
        ui.add_space(8.0);
        ui.checkbox(&mut f.confirm, "Ask before each use");
        ui.label(
            RichText::new(
                "vaultd opens a window to approve every signature or decryption. You can \
                 change this later.",
            )
            .small()
            .color(theme::MUTED),
        );
        ui.add_space(12.0);
        let ok = self.busy.is_none();
        let (mut go, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            go = theme::primary_icon(ui, ok, Icon::Import, "Import key").clicked();
            cancel = ui.button("Cancel").clicked();
        });
        if cancel {
            self.import_key = None;
            self.error = None;
        } else if go && ok {
            let f = self.import_key.as_mut().expect("checked above");
            f.path = expand(&f.path);
            match f.to_request() {
                Ok(request) => self.act("Importing the key…", Op::ImportKey, request),
                Err(m) => self.error = Some(m),
            }
        }
    }

    /// The export part of a key's card: a button, then a form that proves an
    /// unlock factor again, then the key itself.
    pub(super) fn export_section(&mut self, ui: &mut Ui, id: ItemId, pgp: bool) {
        let ok = self.busy.is_none();
        let has = |kind: &str| self.slots.is_empty() || self.slots.iter().any(|s| s.kind == kind);
        let methods: Vec<(Method, &str)> = [
            (Method::Password, "password", "Master password"),
            (Method::SecurityKey, "fido2", "Security key"),
            (Method::Tpm, "tpm", "This device"),
            (Method::Recovery, "recovery", "Recovery code"),
        ]
        .into_iter()
        .filter(|(_, kind, _)| has(kind))
        .map(|(m, _, name)| (m, name))
        .collect();
        let Some(x) = self.export.as_mut().filter(|x| x.id == id) else {
            if theme::button(ui, Icon::Export, "Export private key").clicked() {
                self.error = None;
                self.notice = None;
                self.export = Some(Export::new(id));
                // To offer only the methods this vault has.
                self.send(Op::ListSlots, Request::ListSlots);
            }
            return;
        };
        ui.label(theme::bold("Export private key").size(15.0));
        let mut close = false;
        let mut copy = None;
        let mut save = None;
        if let Some(key) = &x.key {
            egui::Frame::new()
                .fill(theme::WARN_WEAK)
                .corner_radius(8)
                .inner_margin(Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Anyone with this key can sign and decrypt as you, and it has \
                                 no passphrase. Save it only somewhere you trust, and delete \
                                 copies you don't need.",
                            )
                            .color(theme::WARN),
                        )
                        .wrap(),
                    );
                });
            ui.add_space(6.0);
            if x.reveal {
                ui.add(egui::Label::new(RichText::new(key.as_str()).monospace().size(11.5)).wrap());
            }
            ui.horizontal(|ui| {
                if show_button(ui, x.reveal).clicked() {
                    x.reveal = !x.reveal;
                }
                if theme::primary_small(ui, Icon::Copy, "Copy private key").clicked() {
                    copy = Some(key.clone());
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let l = ui.label("Save to");
                ui.add(
                    TextEdit::singleline(&mut x.path)
                        .hint_text(key_example(pgp))
                        .desired_width(300.0),
                )
                .labelled_by(l.id);
                if theme::button(ui, Icon::Export, "Save key file").clicked() {
                    save = Some((expand(&x.path), key.clone()));
                }
            });
            ui.add_space(4.0);
            close = ui.button("Done").clicked();
        } else {
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "The vault is open, but exporting a private key needs one more \
                         proof that it's you. Use any of your unlock methods.",
                    )
                    .color(theme::TEXT),
                )
                .wrap(),
            );
            ui.add_space(4.0);
            let f = &mut x.form;
            if !methods.iter().any(|(m, _)| *m == f.method)
                && let Some((m, _)) = methods.first()
            {
                f.method = *m;
            }
            ui.horizontal_wrapped(|ui| {
                for (m, name) in &methods {
                    ui.selectable_value(&mut f.method, *m, *name);
                }
            });
            ui.add_space(4.0);
            let mut submit = false;
            egui::Grid::new("export-proof")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    let pin = f.method == Method::Tpm
                        || f.method == Method::SecurityKey && !WINDOWS_ASKS_KEY_PIN;
                    if f.method == Method::Recovery {
                        submit |= super::secret_field(ui, "Recovery code", &mut f.code);
                    } else {
                        submit |= super::secret_field(ui, "Master password", &mut f.password);
                    }
                    ui.end_row();
                    if pin {
                        submit |= super::secret_field(ui, "PIN (if set)", &mut f.pin);
                        ui.end_row();
                    }
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                submit |= theme::primary_icon(ui, ok, Icon::Export, "Export").clicked();
                close = ui.button("Cancel").clicked();
            });
            if submit && ok && !close {
                let empty = if f.method == Method::Recovery {
                    f.code.trim().is_empty()
                } else {
                    f.password.is_empty()
                };
                if empty {
                    self.error = Some("Prove it's you first: fill in the box above.".into());
                } else {
                    let busy = if f.method == Method::SecurityKey {
                        "Touch your security key when it blinks…"
                    } else {
                        "Checking…"
                    };
                    let method = f.to_method();
                    self.act(busy, Op::ExportKey(id), Request::ExportKey { id, method });
                }
            }
        }
        if let Some(k) = copy {
            self.copy(&k, "Private key");
        }
        if let Some((path, key)) = save {
            match write_new(&path, key.as_bytes(), true) {
                Ok(()) => {
                    self.error = None;
                    self.notice = Some(format!(
                        "Saved to {path}, readable only by you{}.",
                        if cfg!(windows) {
                            " and administrators"
                        } else {
                            ""
                        }
                    ));
                }
                Err(e) => self.error = Some(e),
            }
        }
        if close {
            self.export = None;
            self.error = None;
        }
    }

    /// The OpenPGP page.
    pub(super) fn pgp_page(&mut self, ui: &mut Ui) {
        page_header(
            ui,
            "Encrypt and sign",
            "Encrypt, decrypt, sign and check files and messages with your OpenPGP keys. \
             The secret keys stay inside vaultd; if a key asks before each use, vaultd \
             opens a window to approve it.",
        );
        let keys: Vec<ItemSummary> = self.items.iter().filter(|i| is_pgp(i)).cloned().collect();
        let keys: Vec<&ItemSummary> = keys.iter().collect();
        let mut task = self.pgp.task;
        ui.horizontal(|ui| {
            for (t, icon, name) in Task::ALL {
                let on = task == t;
                let fg = if on { theme::ACCENT } else { theme::TEXT };
                let b = egui::Button::new((
                    icon.atom_in(15.0, fg),
                    RichText::new(name).family(theme::semibold()).color(fg),
                ))
                .selected(on)
                .min_size(egui::Vec2::new(0.0, 34.0));
                if ui.add(b).clicked() {
                    task = t;
                }
            }
        });
        if task != self.pgp.task {
            // Each task starts empty: a message left from encrypting is
            // not what anyone means to sign or decrypt.
            self.pgp.task = task;
            self.pgp.clear();
            self.error = None;
            self.notice = None;
        }
        ui.add_space(12.0);
        let needs_key = matches!(task, Task::Decrypt | Task::Sign);
        if keys.is_empty() && needs_key {
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("You don't have an OpenPGP key yet.").color(theme::INK));
                ui.label(
                    RichText::new(
                        "Make one or import one under SSH and PGP keys, with the New button \
                         at the top.",
                    )
                    .color(theme::MUTED),
                );
            });
            return;
        }
        let mut run = false;
        theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let p = &mut self.pgp;
            let (label, hint) = match task {
                Task::Encrypt => ("Message", "What to encrypt"),
                Task::Decrypt => ("Encrypted message", "-----BEGIN PGP MESSAGE-----"),
                Task::Sign => ("What to sign", "The text to sign"),
                Task::Verify => ("What was signed", "The text the signature is for"),
            };
            p.input.show(ui, "pgp-input", label, hint, 6);
            ui.add_space(10.0);
            match task {
                Task::Encrypt => {
                    ui.label(theme::bold("Who can read it").size(13.0));
                    for k in &keys {
                        let mut on = p.to_items.contains(&k.id);
                        if ui.checkbox(&mut on, format!("{} (you)", k.title)).changed() {
                            if on {
                                p.to_items.push(k.id);
                            } else {
                                p.to_items.retain(|i| *i != k.id);
                            }
                        }
                    }
                    others_box(ui, &mut p.others, "Other people's public keys");
                    ui.add_space(8.0);
                    signer_box(ui, &mut p.signer, &keys, true);
                    ui.checkbox(
                        &mut p.binary,
                        "Binary output (smaller; for files, not mail)",
                    );
                }
                Task::Decrypt => {
                    ui.label(
                        RichText::new(
                            "vaultd tries each of your OpenPGP keys and uses the one the \
                             message was encrypted to.",
                        )
                        .small()
                        .color(theme::MUTED),
                    );
                }
                Task::Sign => {
                    signer_box(ui, &mut p.signer, &keys, false);
                    ui.checkbox(&mut p.binary, "Binary signature (.sig instead of .asc)");
                    ui.label(
                        RichText::new(
                            "Makes a detached signature: send it along with the text or \
                             file, which stays as it is.",
                        )
                        .small()
                        .color(theme::MUTED),
                    );
                }
                Task::Verify => {
                    p.signature.show(
                        ui,
                        "pgp-signature",
                        "Signature",
                        "-----BEGIN PGP SIGNATURE-----",
                        3,
                    );
                    ui.add_space(8.0);
                    others_box(ui, &mut p.others, "Signer's public key");
                    ui.label(
                        RichText::new(
                            "Leave it empty for signatures made with one of your own keys.",
                        )
                        .small()
                        .color(theme::MUTED),
                    );
                }
            }
            ui.add_space(10.0);
            let ok = self.busy.is_none();
            let (icon, name) = Task::ALL
                .iter()
                .find(|(t, ..)| *t == task)
                .map(|(_, i, n)| (*i, *n))
                .expect("every task is listed");
            ui.horizontal(|ui| {
                run = theme::primary_icon(ui, ok, icon, name).clicked() && ok;
                if ui.button("Clear").clicked() {
                    p.clear();
                }
            });
        });
        if run {
            match self.pgp.request(&keys) {
                Ok(request) => {
                    self.pgp.output = None;
                    let busy = match task {
                        Task::Encrypt => "Encrypting…",
                        Task::Decrypt => "Decrypting…",
                        Task::Sign => "Signing…",
                        Task::Verify => "Checking…",
                    };
                    self.act(busy, Op::Pgp, request);
                }
                Err(m) => self.error = Some(m),
            }
        }
        self.pgp_output(ui);
    }

    fn pgp_output(&mut self, ui: &mut Ui) {
        let scroll = std::mem::take(&mut self.pgp.scroll);
        let Some(out) = &self.pgp.output else {
            return;
        };
        ui.add_space(12.0);
        let mut copy = None;
        let mut save = false;
        let mut saving = None;
        let mut toggle = false;
        let reveal = self.pgp.reveal;
        let save_path = &mut self.pgp.save_path;
        let card = theme::card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            let (bytes, secret): (&[u8], bool) = match out {
                Output::Good(who) => {
                    ui.horizontal(|ui| {
                        Icon::Check.show(ui, 20.0, theme::OK);
                        ui.label(theme::bold("Good signature").size(15.0).color(theme::OK));
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("Signed by {who}")).color(theme::INK),
                        )
                        .wrap(),
                    );
                    return;
                }
                Output::Public(b) => {
                    theme::caption(
                        ui,
                        match self.pgp.task {
                            Task::Sign => "Signature",
                            _ => "Encrypted message",
                        },
                    );
                    (b, false)
                }
                Output::Plain(b, key) => {
                    theme::caption(ui, "Decrypted");
                    ui.label(
                        RichText::new(format!("Opened with your key \u{201c}{key}\u{201d}."))
                            .small()
                            .color(theme::MUTED),
                    );
                    (b, true)
                }
            };
            let text = std::str::from_utf8(bytes).ok();
            match text {
                Some(t) if !secret || reveal => {
                    // The page scrolls; a big result is cut short here, and
                    // Copy and Save still take all of it.
                    let (shown, more) = preview(t);
                    ui.add(
                        egui::Label::new(RichText::new(shown).monospace().size(12.0))
                            .wrap()
                            .selectable(!secret),
                    );
                    if more > 0 {
                        ui.label(
                            RichText::new(format!(
                                "… and {more} more lines. Copy or save it to get all of it."
                            ))
                            .small()
                            .color(theme::MUTED),
                        );
                    }
                }
                Some(_) => {
                    ui.label("••••••••••••");
                }
                None => {
                    ui.label(
                        RichText::new(format!(
                            "{} bytes of binary data. Save it to a file below.",
                            bytes.len()
                        ))
                        .color(theme::MUTED),
                    );
                }
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if let Some(t) = text {
                    if secret && show_button(ui, reveal).clicked() {
                        toggle = true;
                    }
                    let what = if secret { "Copy text" } else { "Copy" };
                    if theme::primary_small(ui, Icon::Copy, what).clicked() {
                        copy = Some((Zeroizing::new(t.to_owned()), secret));
                    }
                }
            });
            ui.add_space(4.0);
            detail_row(
                ui,
                |ui| {
                    let r = ui.add(
                        TextEdit::singleline(save_path)
                            .hint_text("Path of a new file to save it in")
                            .desired_width(f32::INFINITY),
                    );
                    ui.ctx()
                        .accesskit_node_builder(r.id, |n| n.set_label("Save as"));
                },
                |ui| save = theme::button(ui, Icon::Export, "Save to file").clicked(),
            );
            if save {
                saving = Some((expand(save_path), Zeroizing::new(bytes.to_vec()), secret));
            }
        });
        if scroll {
            card.response.scroll_to_me(Some(egui::Align::BOTTOM));
        }
        if toggle {
            self.pgp.reveal = !self.pgp.reveal;
        }
        if let Some((t, secret)) = copy {
            if secret {
                self.copy(&t, "Decrypted text");
            } else {
                // Ciphertext and signatures aren't secret: no clearing timer.
                match self.clip.set(&t) {
                    Ok(()) => self.notice = Some("Copied.".into()),
                    Err(e) => self.error = Some(format!("Couldn't copy: {e}")),
                }
            }
        }
        if let Some((path, bytes, secret)) = saving {
            match write_new(&path, &bytes, secret) {
                Ok(()) => {
                    self.error = None;
                    self.notice = Some(format!("Saved to {path}."));
                }
                Err(e) => self.error = Some(e),
            }
        }
    }

    /// Open the OpenPGP page on a task.
    pub(super) fn open_pgp(&mut self, task: Task) {
        self.go(View::Pgp);
        if self.pgp.task != task {
            self.pgp.task = task;
            self.pgp.clear();
        }
    }
}

/// The box for other people's public keys.
fn others_box(ui: &mut Ui, text: &mut String, label: &str) {
    ui.add_space(4.0);
    let l = ui.label(RichText::new(label).color(theme::TEXT));
    ui.add(
        TextEdit::multiline(text)
            .hint_text("Paste their public key (-----BEGIN PGP PUBLIC KEY BLOCK-----), or type the path of a key file on each line")
            .font(egui::TextStyle::Monospace)
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    )
    .labelled_by(l.id);
}

/// A choice of the vault's OpenPGP keys to sign with.
fn signer_box(ui: &mut Ui, signer: &mut Option<ItemId>, keys: &[&ItemSummary], optional: bool) {
    let name = |id: &Option<ItemId>| {
        id.and_then(|id| keys.iter().find(|k| k.id == id)).map_or(
            if optional { "Don't sign" } else { "Pick a key" }.to_owned(),
            |k| k.title.clone(),
        )
    };
    ui.horizontal(|ui| {
        let l = ui.label(if optional {
            "Also sign with"
        } else {
            "Sign with"
        });
        let r = egui::ComboBox::from_id_salt("pgp-signer")
            .selected_text(name(signer))
            .width(260.0)
            .show_ui(ui, |ui| {
                if optional {
                    ui.selectable_value(signer, None, "Don't sign");
                }
                for k in keys {
                    ui.selectable_value(signer, Some(k.id), &k.title);
                }
            });
        r.response.labelled_by(l.id);
    });
    if !optional && signer.is_none() && keys.len() == 1 {
        *signer = Some(keys[0].id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_take_pasted_blocks_and_paths() {
        assert!(certificates("").unwrap().is_empty());
        let two = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n\
                   \n  -----BEGIN PGP PUBLIC KEY BLOCK-----\nBBBB\n-----END PGP PUBLIC KEY BLOCK-----";
        let c = certificates(two).unwrap();
        assert_eq!(c.len(), 2);
        assert!(String::from_utf8_lossy(&c[1]).contains("BBBB"));
        assert!(certificates("-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA").is_err());

        let dir = std::env::temp_dir().join(format!("vault-gui-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bob.asc");
        std::fs::write(&file, b"key bytes").unwrap();
        let c = certificates(&format!("{}\n", file.display())).unwrap();
        assert_eq!(c, vec![b"key bytes".to_vec()]);
        let missing = dir.join("nobody.asc");
        assert!(certificates(&missing.display().to_string()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writes_only_new_files() {
        let dir = std::env::temp_dir().join(format!("vault-gui-write-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("out.asc").display().to_string();
        write_new(&p, b"one", true).unwrap();
        assert!(
            write_new(&p, b"two", true)
                .unwrap_err()
                .contains("already exists")
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(write_new("  ", b"x", false).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn import_takes_the_file_name_as_title() {
        let mut f = KeyImport::new(false);
        assert!(f.to_request().is_err(), "needs a key");
        f.pasted = Zeroizing::new("-----BEGIN OPENSSH PRIVATE KEY-----".into());
        assert!(f.to_request().err().unwrap().contains("title"));
        f.title = "Laptop".into();
        assert!(matches!(
            f.to_request(),
            Ok(Request::ImportSshKey { title, passphrase: None, confirm: true, .. })
                if title == "Laptop"
        ));
        f.title.clear();
        f.path = "/nowhere/id_ed25519".into();
        assert_eq!(f.title().unwrap(), "id_ed25519");
        assert!(f.to_request().is_err(), "the file doesn't exist");
    }

    #[test]
    fn previews_long_results() {
        assert_eq!(preview("a\nb"), ("a\nb", 0));
        let long: String = (0..50).map(|n| format!("{n}\n")).collect();
        let (shown, more) = preview(&long);
        assert_eq!(shown.lines().count(), 40);
        assert_eq!(more, 10);
    }

    #[test]
    fn suggests_where_to_save() {
        let mut p = PgpTools::default();
        assert_eq!(p.suggest_path(), "", "nothing for pasted text");
        p.input.file = true;
        p.input.path = "/tmp/report.pdf".into();
        assert_eq!(p.suggest_path(), "/tmp/report.pdf.asc");
        p.binary = true;
        assert_eq!(p.suggest_path(), "/tmp/report.pdf.gpg");
        p.task = Task::Sign;
        assert_eq!(p.suggest_path(), "/tmp/report.pdf.sig");
        p.task = Task::Decrypt;
        p.input.path = "/tmp/report.pdf.gpg".into();
        assert_eq!(p.suggest_path(), "/tmp/report.pdf");
        p.input.path = "/tmp/blob".into();
        assert_eq!(p.suggest_path(), "/tmp/blob.out");
    }
}
