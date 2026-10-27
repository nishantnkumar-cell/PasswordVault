//! `vault`: command-line client for `vaultd`. Run `vault help`.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use vault_core::SecureRandom;
use vault_core::item::{Card, CustomField, FieldKind, Identity, ItemData, ItemKind, UrlEntry};
use vault_core::origin::MatchMode;
use vault_core::totp::TotpConfig;
use vault_hw::phone::{self, PasskeyCred, PhoneEvent};
use vault_ipc::{
    ClientScope, ClientToken, Envelope, GenerateOptions, ImportFormat, ItemSummary, KeyKind,
    QuickUnlockInfo, Request, Response, Secret, SecretBytes, SlotInfo, SyncInfo, UnlockMethod, hex,
    local, parse_id, read_frame, write_frame,
};
use zeroize::Zeroizing;

const HELP: &str = r"vault: command-line client for vaultd

USAGE: vault <COMMAND> [ARGS]

SETUP
  init                         create a vault (password + recovery code)
  pair [--autofill] [METHOD]   pair this client: approve it in the window vaultd opens,
                               or prove METHOD instead
  status                       daemon and vault state
  version                      this program's version (also --version)

UNLOCKING                      METHOD is one of --password (default), --fido2, --phone, --tpm,
                               --recovery
  unlock [METHOD]              unlock the vault
  unlock --hello               quick unlock with Windows Hello or Touch ID (after a full
                               unlock, see below); --touch-id is the same
  lock [--full]                lock it and wipe keys from memory (--full: forget the
                               quick unlock key too, so the next unlock needs METHOD)
  quick-unlock [HOURS|off]     show, turn on (for HOURS after each full unlock, 1 to 24)
                               or turn off quick unlock with Windows Hello (Windows) or
                               Touch ID (macOS)

ITEMS                          ID may be any unique prefix of an item ID
  ls [KIND]                    list items, or only logins, notes, cards or identities
  show ID [--reveal]           show an item (secrets hidden unless --reveal)
  add [KIND] [--generate]      add an item interactively; KIND is login (default),
                               note, card or identity
  edit ID                      edit an item interactively (Enter keeps a field)
  rm ID                        delete an item
  totp ID                      current TOTP code
  find ORIGIN                  items that may be filled on ORIGIN, e.g. https://example.com
  gen [--length N] [--no-symbols] [--no-ambiguous]
  import bitwarden|csv FILE    import an unencrypted export (delete the file afterwards)

SSH KEYS                       keys stay in vaultd; ssh and git use them through its agent
  ssh new TITLE [--ecdsa] [--no-confirm]  generate a key (Ed25519 unless --ecdsa)
  ssh import TITLE FILE [--no-confirm]    store an OpenSSH private key (asks its passphrase)
  ssh ls                       list SSH keys
  ssh pub ID                   print the public key (ID may also be the title), for authorized_keys or GitHub
  ssh confirm ID on|off        ask before each use (on by default)
  ssh export ID [METHOD]       print the private key after proving a factor again
  ssh agent                    print the line that points SSH_AUTH_SOCK at vaultd

OPENPGP KEYS                   keys stay in vaultd; FILE defaults to stdin, -o to stdout
  pgp new TITLE USERID [--pq] [--no-confirm]
                               generate a key for USERID, like 'Name <mail>'
                               (--pq: post-quantum v6 key, RFC 9980)
  pgp import TITLE FILE [--no-confirm]    store a secret key (asks its passphrase)
  pgp ls | pub ID | confirm ID on|off | export ID [METHOD]
  pgp encrypt [-r ID].. [-R CERT].. [--sign ID] [--binary] [FILE] [-o OUT]
                               -r: a key in the vault, -R: a certificate file
  pgp decrypt [FILE] [-o OUT]  with whichever vault key the message is for
  pgp sign ID [--binary] [FILE] [-o OUT]  detached signature
  pgp verify SIG [-R CERT].. [FILE]       against vault keys and CERT files

KEYSLOTS
  slots                        list keyslots
  add-slot password [--label L]
  add-slot fido2 [--uv] [--label L]       touch the key when it blinks
  add-slot phone [--label L]              a passkey on your phone: scan the QR code with it
  add-slot tpm [--pin] [--pcr7] [--label L]
  add-slot recovery [--label L]
  rm-slot SLOT                 remove a slot (no key rotation)
  revoke --keep SLOT[,SLOT..]  rotate the vault key, keeping only these slots

SYNC                           through a folder that OneDrive, Google Drive or Dropbox syncs
  sync                         show sync state
  sync on FILE                 keep the vault merged with FILE, e.g. ~/OneDrive/vault.svault;
                               on a device with no vault yet, this joins the vault in FILE
  sync off                     stop syncing (the copy in the folder stays)
  sync now                     merge now instead of at the next check

ENVIRONMENT
  VAULT_SOCKET                 socket or pipe [default: $XDG_RUNTIME_DIR/vault/vaultd.sock,
                               on Windows \\.\pipe\vaultd-<your SID>]
  VAULT_TOKEN_FILE             pairing token [default: $XDG_CONFIG_HOME/vault/token,
                               on Windows %APPDATA%\vault\token]";

/// The quick unlock check on this system.
const PRESENCE: &str = if cfg!(target_os = "macos") {
    "Touch ID"
} else {
    "Windows Hello"
};
const CONFIRM: &str = if cfg!(target_os = "macos") {
    "Confirm it's you with Touch ID or your Mac password..."
} else {
    "Confirm it's you in the Windows Security window..."
};

fn print_quick(q: &QuickUnlockInfo) {
    if q.hours == 0 {
        println!("quick unlock: off (turn on with `vault quick-unlock 8`)");
        return;
    }
    println!(
        "quick unlock: {PRESENCE}, for {} h after each full unlock",
        q.hours
    );
    if let Some(t) = q.until {
        let left = t.saturating_sub(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        );
        println!(
            "              available now for {} h {} min (`vault unlock --hello`)",
            left / 3600,
            left % 3600 / 60
        );
    }
}

fn print_sync(s: &SyncInfo) {
    println!("sync:      {}", s.path);
    match s.last_sync {
        Some(t) => {
            let ago = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .saturating_sub(t);
            println!("synced:    {ago} s ago");
        }
        None => println!("synced:    not yet (unlock to sync)"),
    }
    if let Some(e) = &s.error {
        println!("sync problem: {e}");
    }
    if s.conflicts > 0 {
        println!(
            "conflicts: {} item(s) were edited on two devices at once; the other edit is kept as \"... (conflict)\"",
            s.conflicts
        );
    }
    if !s.other_copies.is_empty() {
        println!(
            "merged copies you can delete: {}",
            s.other_copies.join(", ")
        );
    }
}

/// An absolute path, with a leading `~` meaning the home folder.
fn sync_file(arg: &str) -> PathBuf {
    let home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| die("cannot tell where your home folder is"))
    };
    let p = match arg.strip_prefix("~/").or_else(|| arg.strip_prefix("~\\")) {
        Some(rest) => home().join(rest),
        None => PathBuf::from(arg),
    };
    std::path::absolute(&p).unwrap_or(p)
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("vault: {msg}");
    exit(1)
}

fn socket_path() -> PathBuf {
    local::endpoint().unwrap_or_else(|e| die(e))
}

fn token_path() -> PathBuf {
    if let Some(p) = std::env::var_os("VAULT_TOKEN_FILE") {
        return p.into();
    }
    local::config_dir().join("token")
}

fn load_token() -> Option<ClientToken> {
    let bytes = Zeroizing::new(std::fs::read(token_path()).ok()?);
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(arr))
}

fn save_token(t: &ClientToken) {
    let p = token_path();
    local::write_private(&p, &t[..]).unwrap_or_else(|e| die(format!("{}: {e}", p.display())));
}

struct Client {
    stream: local::Stream,
    token: Option<ClientToken>,
}

impl Client {
    fn connect() -> Client {
        let p = socket_path();
        let stream = local::connect(&p).unwrap_or_else(|e| {
            die(format!(
                "cannot reach vaultd at {}: {e}. Is it running?",
                p.display()
            ))
        });
        Client {
            stream,
            token: load_token(),
        }
    }

    fn call(&mut self, request: Request) -> Response {
        match self.try_call(request) {
            Response::Error(m) => die(m),
            r => r,
        }
    }

    /// Like [`Self::call`], but returns errors.
    fn try_call(&mut self, request: Request) -> Response {
        let env = Envelope {
            token: self.token.clone(),
            request,
        };
        write_frame(&mut self.stream, &env).unwrap_or_else(|e| die(e));
        read_frame(&mut self.stream).unwrap_or_else(|e| die(e))
    }
}

/// Read a secret: hidden from a terminal, else one line from stdin (for scripts).
fn secret(prompt: &str) -> Secret {
    if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password(prompt).unwrap_or_else(|e| die(e)))
    } else {
        Zeroizing::new(line_from_stdin())
    }
}

fn line_from_stdin() -> String {
    let mut s = String::new();
    io::stdin()
        .lock()
        .read_line(&mut s)
        .unwrap_or_else(|e| die(e));
    s.truncate(s.trim_end_matches(['\n', '\r']).len());
    // Windows PowerShell 5.1 starts piped text with a byte-order mark, which
    // would otherwise become part of the password and never match a typed one.
    if s.starts_with('\u{feff}') {
        s.drain(..'\u{feff}'.len_utf8());
    }
    s
}

fn ask(prompt: &str) -> String {
    if io::stdin().is_terminal() {
        print!("{prompt}");
        io::stdout().flush().ok();
    }
    line_from_stdin()
}

fn new_password(prompt: &str) -> Secret {
    let a = secret(prompt);
    if io::stdin().is_terminal() {
        let b = secret("Repeat: ");
        if a != b {
            die("the passwords do not match");
        }
    }
    a
}

fn optional(s: Secret) -> Option<Secret> {
    if s.is_empty() { None } else { Some(s) }
}

fn method(args: &[String]) -> UnlockMethod {
    if args.iter().any(|a| a == "--recovery") {
        UnlockMethod::Recovery {
            code: secret("Recovery code: "),
        }
    } else if args.iter().any(|a| a == "--fido2") {
        let password = secret("Password: ");
        // Windows asks for the PIN in its own window.
        let pin = if cfg!(windows) {
            None
        } else {
            optional(secret("Security key PIN (Enter if the slot has none): "))
        };
        eprintln!("Touch your security key...");
        UnlockMethod::Fido2 { password, pin }
    } else if args.iter().any(|a| a == "--phone") {
        phone_method()
    } else if args.iter().any(|a| a == "--tpm") {
        let password = secret("Password: ");
        let pin = optional(secret("TPM PIN (Enter if none): "));
        UnlockMethod::Tpm { password, pin }
    } else {
        UnlockMethod::Password {
            password: secret("Password: "),
        }
    }
}

/// Show what the phone ceremony needs: the QR code (Linux) and progress.
fn phone_event(e: PhoneEvent) {
    match e {
        PhoneEvent::Qr(uri) => {
            let code = qrcode::QrCode::new(uri.as_bytes()).unwrap_or_else(|e| die(e));
            // Light modules on dark, as terminals usually are; phones read both.
            let img = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            eprintln!("\n{img}\n");
            eprintln!(
                "Scan this with your phone's camera, keep Bluetooth on on both, and confirm on the phone."
            );
        }
        PhoneEvent::Status(s) => eprintln!("{s}..."),
    }
}

fn phone_method() -> UnlockMethod {
    let password = secret("Password: ");
    // Every slot's password has 8 or more characters: don't bother the phone.
    if password.chars().count() < 8 {
        die("wrong password or factor");
    }
    let Response::PasskeySlots(slots) = Client::connect().call(Request::PasskeySlots) else {
        die("unexpected response")
    };
    let creds: Vec<PasskeyCred> = slots
        .iter()
        .filter(|s| s.rp_id == vault_hw::RP_ID)
        .map(|s| PasskeyCred {
            credential_id: s.credential_id.clone(),
            prf_input: s.prf_input,
        })
        .collect();
    let (credential_id, out) =
        phone::prf(vault_hw::RP_ID, &creds, &phone_event).unwrap_or_else(|e| die(e));
    UnlockMethod::Passkey {
        password,
        credential_id,
        prf_output: Zeroizing::new(out.expose().to_vec()),
    }
}

fn add_phone_slot(c: &mut Client, label: String) -> Request {
    let password = secret("Master password: ");
    phone::check_available().unwrap_or_else(|e| die(e));
    let mut prf_input = [0u8; 32];
    vault_core::OsRandom
        .fill(&mut prf_input)
        .unwrap_or_else(|e| die(e));
    // Make sure the vault is open before the phone is asked.
    c.call(Request::ListSlots);
    eprintln!("Creating a passkey on your phone...");
    let made = phone::enroll(vault_hw::RP_ID, &prf_input, &phone_event).unwrap_or_else(|e| die(e));
    let out = match made.prf {
        Some(out) => out,
        None => {
            eprintln!("Passkey created. Now confirm it once more, so the vault can test it...");
            let cred = PasskeyCred {
                credential_id: made.credential_id.clone(),
                prf_input,
            };
            phone::prf(vault_hw::RP_ID, &[cred], &phone_event)
                .unwrap_or_else(|e| die(e))
                .1
        }
    };
    Request::AddPasskeySlot {
        password,
        credential_id: made.credential_id,
        prf_input,
        prf_output: Zeroizing::new(out.expose().to_vec()),
        label,
    }
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).map(|i| {
        args.get(i + 1)
            .cloned()
            .unwrap_or_else(|| die(format!("{name} needs a value")))
    })
}

fn positional(args: &[String], n: usize, what: &str) -> String {
    args.iter()
        .filter(|a| !a.starts_with("--"))
        .nth(n)
        .cloned()
        .unwrap_or_else(|| die(format!("missing {what}; see `vault help`")))
}

fn items(c: &mut Client) -> Vec<ItemSummary> {
    match c.call(Request::ListItems) {
        Response::Items(v) => v,
        _ => die("unexpected response"),
    }
}

fn slots(c: &mut Client) -> Vec<SlotInfo> {
    match c.call(Request::ListSlots) {
        Response::Slots(v) => v,
        _ => die("unexpected response"),
    }
}

/// Resolve a full ID or a unique hex prefix.
fn resolve<T>(ids: impl Iterator<Item = ([u8; 16], T)>, s: &str) -> ([u8; 16], T) {
    if let Some(id) = parse_id(s) {
        if let Some(hit) = ids.into_iter().find(|(i, _)| *i == id) {
            return hit;
        }
        die("no item or slot with that ID");
    }
    let s = s.to_ascii_lowercase();
    let mut hits: Vec<_> = ids.filter(|(i, _)| hex(i).starts_with(&s)).collect();
    match hits.len() {
        1 => hits.remove(0),
        0 => die("no item or slot with that ID"),
        _ => die("that ID prefix is ambiguous"),
    }
}

fn item_id(c: &mut Client, s: &str) -> [u8; 16] {
    resolve(items(c).into_iter().map(|i| (i.id, ())), s).0
}

fn get(c: &mut Client, id: [u8; 16]) -> ItemData {
    match c.call(Request::GetItem { id }) {
        Response::Item { item, .. } => item,
        _ => die("unexpected response"),
    }
}

fn short(id: &[u8; 16]) -> String {
    hex(&id[..4])
}

/// Ask for a field, showing the current value; Enter keeps it.
fn keep(prompt: &str, cur: &str) -> String {
    let shown = if cur.is_empty() {
        String::new()
    } else {
        format!(" [{cur}]")
    };
    let v = ask(&format!("{prompt}{shown}: "));
    if v.is_empty() { cur.to_owned() } else { v }
}

/// Ask for a secret field; Enter keeps it, '-' clears it.
fn keep_secret(prompt: &str, cur: &mut String) {
    let set = if cur.is_empty() { "" } else { ", '-' to clear" };
    let v = secret(&format!("{prompt} (Enter to keep{set}): "));
    match v.as_str() {
        "" => {}
        "-" => cur.clear(),
        s => *cur = s.to_owned(),
    }
}

fn edit_item(item: &mut ItemData, generate: bool, c: &mut Client) {
    item.title = keep("Title", &item.title);
    if item.title.is_empty() {
        die("a title is required");
    }
    match item.kind {
        ItemKind::Login => edit_login(item, generate, c),
        ItemKind::Note => {}
        ItemKind::Card => edit_card(item.card.get_or_insert_with(Card::default)),
        ItemKind::Identity => edit_identity(item.identity.get_or_insert_with(Identity::default)),
    }
    edit_fields(&mut item.fields);
    item.notes = keep("Notes", &item.notes);
}

fn edit_login(item: &mut ItemData, generate: bool, c: &mut Client) {
    item.username = keep("Username", &item.username);
    let url = keep("URL", item.urls.first().map_or("", |u| u.url.as_str()));
    if !url.is_empty() {
        let mode = if ask("Match the whole site including subdomains? [y/N]: ")
            .eq_ignore_ascii_case("y")
        {
            MatchMode::RegistrableDomain
        } else {
            MatchMode::Origin
        };
        let entry = UrlEntry {
            url: url.clone(),
            mode,
            allow_http: url.starts_with("http://"),
        };
        if item.urls.is_empty() {
            item.urls.push(entry)
        } else {
            item.urls[0] = entry
        }
    }
    if generate {
        if let Response::Generated(p) = c.call(Request::Generate {
            options: GenerateOptions {
                length: 24,
                symbols: true,
                avoid_ambiguous: false,
            },
        }) {
            item.password = p.to_string();
        }
        eprintln!("Generated a 24-character password.");
    } else {
        let p = secret("Password (Enter to keep): ");
        if !p.is_empty() {
            item.password = p.to_string();
        }
    }
    let t = secret("TOTP secret or otpauth:// URI (Enter to keep, '-' to remove): ");
    match t.as_str() {
        "" => {}
        "-" => item.totp = None,
        s => item.totp = Some(TotpConfig::parse(s).unwrap_or_else(|e| die(format!("TOTP: {e}")))),
    }
}

fn edit_card(card: &mut Card) {
    card.holder = keep("Name on card", &card.holder);
    keep_secret("Card number", &mut card.number);
    card.number = Card::clean_number(&card.number);
    if !card.number.is_empty() && !card.luhn_ok() {
        eprintln!("Note: that card number fails the checksum; check it for typos.");
    }
    loop {
        let e = keep("Expiry (MM/YY)", &card.expiry());
        if e.is_empty() {
            break;
        }
        match Card::parse_expiry(&e) {
            Some((m, y)) => {
                (card.exp_month, card.exp_year) = (m, y);
                break;
            }
            None => eprintln!("Type the expiry as MM/YY, for example 07/31."),
        }
    }
    keep_secret("Security code", &mut card.cvv);
    keep_secret("PIN", &mut card.pin);
}

fn edit_identity(id: &mut Identity) {
    for (label, field) in [
        ("Title (Mr, Ms, Dr...)", &mut id.honorific),
        ("First name", &mut id.given_name),
        ("Middle name", &mut id.middle_name),
        ("Last name", &mut id.family_name),
        ("Company", &mut id.company),
        ("Email", &mut id.email),
        ("Phone", &mut id.phone),
        ("Address line 1", &mut id.address1),
        ("Address line 2", &mut id.address2),
        ("Address line 3", &mut id.address3),
        ("City", &mut id.city),
        ("State / region", &mut id.region),
        ("Postcode", &mut id.postcode),
        ("Country", &mut id.country),
    ] {
        *field = keep(label, field);
    }
}

/// Edit existing custom fields, then offer to add more.
fn edit_fields(fields: &mut Vec<CustomField>) {
    for f in fields.iter_mut() {
        if f.kind == FieldKind::Hidden {
            keep_secret(&f.name, &mut f.value);
        } else {
            let v = keep(&format!("{} ('-' to clear)", f.name), &f.value);
            f.value = if v == "-" { String::new() } else { v };
        }
    }
    fields.retain(|f| !f.value.is_empty());
    loop {
        let name = ask("Add a custom field? Name (Enter to finish): ");
        if name.is_empty() {
            break;
        }
        let hidden = ask("Hide its value like a password? [y/N]: ").eq_ignore_ascii_case("y");
        let value = if hidden {
            secret("Value: ").to_string()
        } else {
            ask("Value: ")
        };
        fields.push(CustomField {
            name,
            value,
            kind: if hidden {
                FieldKind::Hidden
            } else {
                FieldKind::Text
            },
        });
    }
}

/// What `show` prints for a secret: the value with `--reveal`, else stars.
fn masked(value: &str, reveal: bool) -> &str {
    if reveal || value.is_empty() {
        value
    } else {
        "******** (use --reveal)"
    }
}

/// Item kind from the first word after the command, if there is one.
fn kind_arg(rest: &[String]) -> Option<ItemKind> {
    let k = rest.iter().find(|a| !a.starts_with("--"))?;
    let singular = match k.as_str() {
        "identities" => "identity",
        k => k.strip_suffix('s').unwrap_or(k),
    };
    Some(ItemKind::from_name(singular).unwrap_or_else(|| {
        die(format!(
            "unknown item kind {k}; use login, note, card or identity"
        ))
    }))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        println!("{HELP}");
        return;
    };
    let rest = &args[1..];

    match cmd {
        "help" | "-h" | "--help" => println!("{HELP}"),
        "version" | "-V" | "--version" => println!("vault {}", vault_ipc::VERSION),
        "init" => {
            let mut c = Client::connect();
            let password = new_password("New master password (at least 8 characters): ");
            eprintln!("Creating the vault (this takes a few seconds)...");
            let Response::Initialized {
                recovery_code,
                token,
            } = c.call(Request::Init {
                password,
                client_name: "vault-cli".into(),
            })
            else {
                die("unexpected response")
            };
            save_token(&token);
            println!(
                "Vault created and unlocked.\n\nRECOVERY CODE (shown once; write it down and store it offline):\n\n    {}\n",
                recovery_code.as_str()
            );
            println!("It unlocks the vault on its own. Anyone who has it can read your vault.");
        }
        "pair" => {
            let mut c = Client::connect();
            let scope = if rest.iter().any(|a| a == "--autofill") {
                ClientScope::Autofill
            } else {
                ClientScope::Full
            };
            let by_method = ["--password", "--fido2", "--phone", "--tpm", "--recovery"]
                .iter()
                .any(|m| rest.iter().any(|a| a == m));
            let Response::Status(s) = c.call(Request::Status) else {
                die("unexpected response")
            };
            if !s.initialized {
                die("no vault exists yet; run `vault init` first");
            }
            if !by_method {
                eprintln!("Approve the request in the window vaultd opens...");
            }
            let Response::Paired { token } = c.call(Request::Pair {
                client_name: "vault-cli".into(),
                scope,
                method: by_method.then(|| method(rest)),
            }) else {
                die("unexpected response")
            };
            save_token(&token);
            println!("Paired.");
        }
        "status" => {
            let Response::Status(s) = Client::connect().call(Request::Status) else {
                die("unexpected response")
            };
            println!(
                "vault:     {}",
                if !s.initialized {
                    "none (run `vault init`)"
                } else if s.unlocked {
                    "unlocked"
                } else {
                    "locked"
                }
            );
            if let Some(g) = s.generation {
                println!("generation: {g}");
            }
            if let Some(t) = s.idle_lock_in {
                println!("auto-lock in: {t} s");
            }
            if s.quick_unlock.supported {
                print_quick(&s.quick_unlock);
            }
            println!(
                "paired:    {}",
                if load_token().is_some() { "yes" } else { "no" }
            );
            if let Some(sync) = &s.sync {
                print_sync(sync);
            }
            if s.rollback_detected {
                println!(
                    "WARNING: the vault file is older than one vaultd saw before. Someone may have restored an old copy. Writes are refused."
                );
            }
        }
        "sync" => {
            let mut c = Client::connect();
            let req = match rest.first().map(String::as_str) {
                None => Request::Status,
                Some("on") => {
                    let file = rest
                        .get(1)
                        .unwrap_or_else(|| die("usage: vault sync on FILE"));
                    Request::SetSync {
                        path: Some(sync_file(file).display().to_string()),
                    }
                }
                Some("off") => Request::SetSync { path: None },
                Some("now") => Request::SyncNow,
                Some(other) => die(format!("unknown sync command {other}; see `vault help`")),
            };
            let was_new = rest.first().is_some_and(|a| a == "on") && load_token().is_none();
            let Response::Status(s) = c.call(req) else {
                die("unexpected response")
            };
            match &s.sync {
                Some(sync) => print_sync(sync),
                None => println!("sync:      off"),
            }
            if was_new && s.initialized {
                println!("Joined. Pair this client with `vault pair --password`.");
            }
        }
        "unlock" => {
            let method = if rest.iter().any(|a| a == "--hello" || a == "--touch-id") {
                // Ask only when vaultd will accept the check, so a refused
                // quick unlock does not first ask the user to confirm.
                let Response::Status(s) = Client::connect().call(Request::Status) else {
                    die("unexpected response")
                };
                if !s.unlocked && s.quick_unlock.until.is_none() {
                    die(
                        "quick unlock is not available now: unlock with your password (or another method) first",
                    );
                }
                eprintln!("{CONFIRM}");
                UnlockMethod::Hello
            } else {
                method(rest)
            };
            Client::connect().call(Request::Unlock { method });
            println!("Unlocked.");
        }
        "lock" => {
            if rest.iter().any(|a| a == "--full") {
                Client::connect().call(Request::LockFully);
                println!("Locked. The next unlock needs your password or another full method.");
            } else {
                Client::connect().call(Request::Lock);
                println!("Locked.");
            }
        }
        "quick-unlock" => {
            let mut c = Client::connect();
            let req = match rest.first().map(String::as_str) {
                None => Request::Status,
                Some("off" | "0") => Request::SetQuickUnlock { hours: 0 },
                Some(h) => {
                    let hours = h.parse().unwrap_or_else(|_| {
                        die("usage: vault quick-unlock [HOURS|off], HOURS from 1 to 24")
                    });
                    eprintln!("{CONFIRM}");
                    Request::SetQuickUnlock { hours }
                }
            };
            let Response::Status(s) = c.call(req) else {
                die("unexpected response")
            };
            if !s.quick_unlock.supported {
                die(
                    "quick unlock needs Windows Hello or Touch ID, which this system does not have",
                );
            }
            print_quick(&s.quick_unlock);
        }
        "ls" => {
            let only = kind_arg(rest);
            for i in items(&mut Client::connect()) {
                if only.is_some_and(|k| k != i.kind) {
                    continue;
                }
                let totp = if i.has_totp { "  [totp]" } else { "" };
                let key = if i.key.is_some() { "  [key]" } else { "" };
                println!(
                    "{}  {:<8} {:<28} {:<24} {}{totp}{key}",
                    short(&i.id),
                    i.kind.name(),
                    i.title,
                    i.subtitle,
                    i.urls.join(" ")
                );
            }
        }
        "show" => {
            let mut c = Client::connect();
            let id = item_id(&mut c, &positional(rest, 0, "ID"));
            let it = get(&mut c, id);
            let reveal = rest.iter().any(|a| a == "--reveal");
            let line = |label: &str, value: &str| {
                if !value.is_empty() {
                    println!("{:<16}{value}", format!("{label}:"));
                }
            };
            line("id", &hex(&id));
            line("kind", it.kind.label());
            line("title", &it.title);
            match it.kind {
                ItemKind::Login => {
                    line("username", &it.username);
                    line("password", masked(&it.password, reveal));
                    for u in &it.urls {
                        let mode = match u.mode {
                            MatchMode::Origin => "exact origin",
                            MatchMode::RegistrableDomain => "whole site",
                        };
                        let http = if u.allow_http { ", http allowed" } else { "" };
                        line("url", &format!("{} ({mode}{http})", u.url));
                    }
                    if it.totp.is_some() {
                        line("totp", &format!("yes (vault totp {})", short(&id)));
                    }
                }
                ItemKind::Note => {}
                ItemKind::Card => {
                    let card = it.card.clone().unwrap_or_default();
                    line("name on card", &card.holder);
                    line("card", &card.describe());
                    if reveal {
                        line("number", &card.number);
                    }
                    line("expires", &card.expiry());
                    line("security code", masked(&card.cvv, reveal));
                    line("PIN", masked(&card.pin, reveal));
                }
                ItemKind::Identity => {
                    let i = it.identity.clone().unwrap_or_default();
                    let name = [i.honorific.as_str(), &i.full_name()]
                        .iter()
                        .filter(|s| !s.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(" ");
                    line("name", &name);
                    line("company", &i.company);
                    line("email", &i.email);
                    line("phone", &i.phone);
                    let address: Vec<&str> = [
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
                    .collect();
                    line("address", &address.join(", "));
                }
            }
            for f in &it.fields {
                let v = if f.kind == FieldKind::Hidden {
                    masked(&f.value, reveal)
                } else {
                    &f.value
                };
                line(&f.name, v);
            }
            // A secure note's text is its secret.
            let secret_note = it.kind == ItemKind::Note;
            line("notes", masked(&it.notes, reveal || !secret_note));
        }
        "add" => {
            let mut c = Client::connect();
            let mut item = ItemData::new(kind_arg(rest).unwrap_or_default(), "");
            edit_item(&mut item, rest.iter().any(|a| a == "--generate"), &mut c);
            let Response::ItemSaved { id } = c.call(Request::PutItem { id: None, item }) else {
                die("unexpected response")
            };
            println!("Saved {}.", short(&id));
        }
        "edit" => {
            let mut c = Client::connect();
            let id = item_id(&mut c, &positional(rest, 0, "ID"));
            let mut item = get(&mut c, id);
            edit_item(&mut item, rest.iter().any(|a| a == "--generate"), &mut c);
            c.call(Request::PutItem { id: Some(id), item });
            println!("Saved {}.", short(&id));
        }
        "rm" => {
            let mut c = Client::connect();
            let id = item_id(&mut c, &positional(rest, 0, "ID"));
            c.call(Request::DeleteItem { id });
            println!("Deleted.");
        }
        "totp" => {
            let mut c = Client::connect();
            let id = item_id(&mut c, &positional(rest, 0, "ID"));
            let Response::Totp { code, remaining } = c.call(Request::Totp { id }) else {
                die("unexpected response")
            };
            println!("{} ({remaining} s left)", code.as_str());
        }
        "find" => {
            let origin = positional(rest, 0, "ORIGIN");
            let Response::Items(v) = Client::connect().call(Request::FindForOrigin { origin })
            else {
                die("unexpected response")
            };
            for i in v {
                println!("{}  {:<28} {}", short(&i.id), i.title, i.subtitle);
            }
        }
        "gen" => {
            let length = flag_value(rest, "--length").map_or(24, |v| {
                v.parse()
                    .unwrap_or_else(|_| die("--length must be a number"))
            });
            let options = GenerateOptions {
                length,
                symbols: !rest.iter().any(|a| a == "--no-symbols"),
                avoid_ambiguous: rest.iter().any(|a| a == "--no-ambiguous"),
            };
            let Response::Generated(p) = Client::connect().call(Request::Generate { options })
            else {
                die("unexpected response")
            };
            println!("{}", p.as_str());
        }
        "import" => {
            let format = match positional(rest, 0, "format").as_str() {
                "bitwarden" => ImportFormat::BitwardenJson,
                "csv" => ImportFormat::BrowserCsv,
                f => die(format!("unknown format {f}; use bitwarden or csv")),
            };
            let path = positional(rest, 1, "FILE");
            let data = Zeroizing::new(
                std::fs::read_to_string(&path).unwrap_or_else(|e| die(format!("{path}: {e}"))),
            );
            let Response::Imported(n) = Client::connect().call(Request::Import { format, data })
            else {
                die("unexpected response")
            };
            println!(
                "Imported {n} items. Delete {path} now: it holds your passwords in plain text."
            );
        }
        "slots" => {
            for s in slots(&mut Client::connect()) {
                println!("{}  {:<9} {}", short(&s.id), s.kind, s.label);
                if let Some(w) = &s.warning {
                    println!("{:8}  note: {w}", "");
                }
            }
        }
        "add-slot" => {
            let mut c = Client::connect();
            let label = flag_value(rest, "--label").unwrap_or_default();
            let req = match positional(rest, 0, "slot kind").as_str() {
                "password" => Request::AddPasswordSlot {
                    password: new_password("Password for the new slot: "),
                    label,
                },
                "fido2" => {
                    let password = secret("Master password: ");
                    let require_uv = rest.iter().any(|a| a == "--uv");
                    // Windows asks for the PIN in its own window. Elsewhere a
                    // key with a PIN set may want it even for a touch-only slot.
                    let pin = if cfg!(windows) {
                        None
                    } else if require_uv {
                        Some(secret("Security key PIN: "))
                    } else {
                        optional(secret("Security key PIN (Enter if the key has none): "))
                    };
                    eprintln!(
                        "Touch your security key (twice: once to create, once to confirm)..."
                    );
                    Request::AddFido2Slot {
                        password,
                        pin,
                        require_uv,
                        label,
                    }
                }
                "phone" => add_phone_slot(&mut c, label),
                "tpm" => {
                    let password = secret("Master password: ");
                    let pin = if rest.iter().any(|a| a == "--pin") {
                        Some(new_password("New TPM PIN: "))
                    } else {
                        None
                    };
                    Request::AddTpmSlot {
                        password,
                        pin,
                        bind_pcr7: rest.iter().any(|a| a == "--pcr7"),
                        label,
                    }
                }
                "recovery" => Request::AddRecoverySlot { label },
                k => die(format!("unknown slot kind {k}")),
            };
            let Response::SlotAdded { id, recovery_code } = c.call(req) else {
                die("unexpected response")
            };
            println!("Added slot {} and test-unlocked it.", short(&id));
            if let Some(code) = recovery_code {
                println!("\nRECOVERY CODE (shown once):\n\n    {}\n", code.as_str());
            }
        }
        "rm-slot" => {
            let mut c = Client::connect();
            let all = slots(&mut c);
            let (id, _) = resolve(
                all.into_iter().map(|s| (s.id, ())),
                &positional(rest, 0, "SLOT"),
            );
            c.call(Request::RemoveSlot { slot: id });
            println!(
                "Removed. The vault key is unchanged; use `vault revoke` if the factor may be compromised."
            );
        }
        "revoke" => {
            let mut c = Client::connect();
            let all = slots(&mut c);
            let list = flag_value(rest, "--keep")
                .unwrap_or_else(|| die("--keep SLOT[,SLOT..] is required"));
            let mut keep = Vec::new();
            for s in list.split(',') {
                let (id, info) = resolve(all.iter().map(|i| (i.id, i.clone())), s.trim());
                eprintln!("Prove slot {} ({}, {}):", short(&id), info.kind, info.label);
                let m = match info.kind.as_str() {
                    "recovery" => vec!["--recovery".to_string()],
                    // Phone passkeys are FIDO2 slots too.
                    "fido2" if ask("Security key or phone? [K/p]: ").trim() == "p" => {
                        vec!["--phone".to_string()]
                    }
                    "fido2" => vec!["--fido2".to_string()],
                    "tpm" => vec!["--tpm".to_string()],
                    _ => vec![],
                };
                keep.push((id, method(&m)));
            }
            let Response::Revoked { removed } = c.call(Request::Revoke { keep }) else {
                die("unexpected response")
            };
            println!("Vault key rotated. Removed {} slot(s):", removed.len());
            for id in removed {
                println!("  {}", short(&id));
            }
            println!("Copies of the old file can still be opened with the old factors.");
        }
        "ssh" => ssh(rest),
        "pgp" => pgp(rest),
        _ => die(format!("unknown command {cmd}; see `vault help`")),
    }
}

/// `vault ssh ...`.
fn ssh(args: &[String]) {
    let sub = args.first().map(String::as_str).unwrap_or("ls");
    let rest = args.get(1..).unwrap_or_default();
    let confirm = !rest.iter().any(|a| a == "--no-confirm");
    let key_id = |c: &mut Client, s: &str| key_item(c, s, |k| !k.starts_with("OpenPGP"));
    match sub {
        "new" => {
            let title = positional(rest, 0, "TITLE");
            let kind = if rest.iter().any(|a| a == "--ecdsa") {
                KeyKind::SshEcdsaP256
            } else {
                KeyKind::SshEd25519
            };
            let mut c = Client::connect();
            let Response::ItemSaved { id } = c.call(Request::GenerateKey {
                title,
                kind,
                confirm,
            }) else {
                die("unexpected response")
            };
            print_public(&mut c, id);
        }
        "import" => {
            let title = positional(rest, 0, "TITLE");
            let file = positional(rest, 1, "FILE");
            let private = Zeroizing::new(
                std::fs::read_to_string(&file).unwrap_or_else(|e| die(format!("{file}: {e}"))),
            );
            let passphrase = if private.contains("BEGIN OPENSSH PRIVATE KEY") && encrypted(&private)
            {
                Some(secret("Key passphrase: "))
            } else {
                None
            };
            let mut c = Client::connect();
            let Response::ItemSaved { id } = c.call(Request::ImportSshKey {
                title,
                private,
                passphrase,
                confirm,
            }) else {
                die("unexpected response")
            };
            print_public(&mut c, id);
            eprintln!("Stored. You can delete {file} once ssh works through the vault.");
        }
        "ls" => {
            for i in items(&mut Client::connect()) {
                if let Some(k) = &i.key {
                    println!("{}  {:<28} {k}", short(&i.id), i.title);
                }
            }
        }
        "pub" => {
            let mut c = Client::connect();
            let id = key_id(&mut c, &positional(rest, 0, "ID"));
            print_public(&mut c, id);
        }
        "confirm" => {
            let mut c = Client::connect();
            let id = key_id(&mut c, &positional(rest, 0, "ID"));
            let on = match positional(rest, 1, "on|off").as_str() {
                "on" => true,
                "off" => false,
                _ => die("say on or off"),
            };
            c.call(Request::SetKeyConfirm { id, confirm: on });
            println!(
                "{}",
                if on {
                    "Each use will ask first."
                } else {
                    "Any program running as you can now use this key while the vault is unlocked."
                }
            );
        }
        "export" => {
            let mut c = Client::connect();
            let id = key_id(&mut c, &positional(rest, 0, "ID"));
            eprintln!("Prove an unlock factor again to export a private key.");
            let Response::ExportedKey(k) = c.call(Request::ExportKey {
                id,
                method: method(rest),
            }) else {
                die("unexpected response")
            };
            print!("{}", k.as_str());
        }
        "agent" => {
            let p = local::ssh_agent_endpoint().unwrap_or_else(|e| die(e));
            #[cfg(unix)]
            println!("export SSH_AUTH_SOCK={}", p.display());
            #[cfg(windows)]
            println!("$env:SSH_AUTH_SOCK = '{}'", p.display());
        }
        _ => die(format!("unknown ssh command {sub}; see `vault help`")),
    }
}

/// A key item by exact title or ID prefix, among keys whose description
/// passes `kind`.
fn key_item(c: &mut Client, s: &str, kind: impl Fn(&str) -> bool) -> [u8; 16] {
    let keys: Vec<ItemSummary> = items(c)
        .into_iter()
        .filter(|i| i.key.as_deref().is_some_and(&kind))
        .collect();
    let named: Vec<_> = keys.iter().filter(|i| i.title == s).collect();
    match named.len() {
        1 => named[0].id,
        0 => resolve(keys.iter().map(|i| (i.id, ())), s).0,
        _ => die(format!("several keys are titled {s}; use the ID")),
    }
}

/// Arguments of `vault pgp ...`: flags with values, switches, positionals.
struct PgpArgs {
    recipients: Vec<String>,
    certs: Vec<String>,
    sign: Option<String>,
    out: Option<String>,
    binary: bool,
    pq: bool,
    confirm: bool,
    pos: Vec<String>,
}

fn pgp_args(args: &[String]) -> PgpArgs {
    let mut a = PgpArgs {
        recipients: vec![],
        certs: vec![],
        sign: None,
        out: None,
        binary: false,
        pq: false,
        confirm: true,
        pos: vec![],
    };
    let mut it = args.iter();
    while let Some(x) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .unwrap_or_else(|| die(format!("{x} needs a value")))
        };
        match x.as_str() {
            "-r" => a.recipients.push(val()),
            "-R" => a.certs.push(val()),
            "--sign" => a.sign = Some(val()),
            "-o" => a.out = Some(val()),
            "--binary" => a.binary = true,
            "--pq" => a.pq = true,
            "--no-confirm" => a.confirm = false,
            // Unlock methods for `export`.
            "--password" | "--fido2" | "--phone" | "--tpm" | "--recovery" => {}
            f if f.starts_with('-') && f.len() > 1 => die(format!("unknown option {f}")),
            _ => a.pos.push(x.clone()),
        }
    }
    a
}

/// A file's bytes, or stdin's for `None` or `-`.
fn read_input(path: Option<&String>) -> Vec<u8> {
    use std::io::Read;
    match path.map(String::as_str) {
        None | Some("-") => {
            let mut v = Vec::new();
            io::stdin().read_to_end(&mut v).unwrap_or_else(|e| die(e));
            v
        }
        Some(p) => std::fs::read(p).unwrap_or_else(|e| die(format!("{p}: {e}"))),
    }
}

fn write_output(path: Option<&String>, bytes: &[u8]) {
    match path {
        None => io::stdout().write_all(bytes).unwrap_or_else(|e| die(e)),
        Some(p) => local::write_private(std::path::Path::new(p), bytes)
            .unwrap_or_else(|e| die(format!("{p}: {e}"))),
    }
}

/// `vault pgp ...`.
fn pgp(args: &[String]) {
    let sub = args.first().map(String::as_str).unwrap_or("ls");
    let a = pgp_args(args.get(1..).unwrap_or_default());
    let pos = |n: usize, what: &str| {
        a.pos
            .get(n)
            .cloned()
            .unwrap_or_else(|| die(format!("missing {what}; see `vault help`")))
    };
    let key_id = |c: &mut Client, s: &str| key_item(c, s, |k| k.starts_with("OpenPGP"));
    let mut c = Client::connect();
    match sub {
        "new" => {
            let Response::ItemSaved { id } = c.call(Request::GeneratePgpKey {
                title: pos(0, "TITLE"),
                user_id: pos(1, "user ID"),
                post_quantum: a.pq,
                confirm: a.confirm,
            }) else {
                die("unexpected response")
            };
            print_public(&mut c, id);
        }
        "import" => {
            let title = pos(0, "TITLE");
            let key: SecretBytes = Zeroizing::new(read_input(Some(&pos(1, "FILE"))));
            let req = |passphrase| Request::ImportPgpKey {
                title: title.clone(),
                key: key.clone(),
                passphrase,
                confirm: a.confirm,
            };
            let r = match c.try_call(req(None)) {
                Response::Error(m) if m.contains("give its passphrase") => {
                    c.call(req(Some(secret("Key passphrase: "))))
                }
                Response::Error(m) => die(m),
                r => r,
            };
            let Response::ItemSaved { id } = r else {
                die("unexpected response")
            };
            print_public(&mut c, id);
        }
        "ls" => {
            for i in items(&mut c) {
                if let Some(k) = i.key.as_deref().filter(|k| k.starts_with("OpenPGP")) {
                    println!("{}  {:<20} {k}", short(&i.id), i.title);
                }
            }
        }
        "pub" => {
            let id = key_id(&mut c, &pos(0, "ID"));
            print_public(&mut c, id);
        }
        "confirm" => {
            let id = key_id(&mut c, &pos(0, "ID"));
            let on = match pos(1, "on|off").as_str() {
                "on" => true,
                "off" => false,
                _ => die("say on or off"),
            };
            c.call(Request::SetKeyConfirm { id, confirm: on });
        }
        "export" => {
            let id = key_id(&mut c, &pos(0, "ID"));
            eprintln!("Prove an unlock factor again to export a secret key.");
            let Response::ExportedKey(k) = c.call(Request::ExportKey {
                id,
                method: method(args),
            }) else {
                die("unexpected response")
            };
            eprintln!("This key has no passphrase: keep the output safe.");
            print!("{}", k.as_str());
        }
        "encrypt" => {
            let to_items = a.recipients.iter().map(|r| key_id(&mut c, r)).collect();
            let to_certs = a.certs.iter().map(|p| read_input(Some(p))).collect();
            let sign_with = a.sign.as_ref().map(|s| key_id(&mut c, s));
            let data = Zeroizing::new(read_input(a.pos.first()));
            let Response::Bytes(out) = c.call(Request::PgpEncrypt {
                to_items,
                to_certs,
                data,
                armor: !a.binary,
                sign_with,
            }) else {
                die("unexpected response")
            };
            write_output(a.out.as_ref(), &out);
        }
        "decrypt" => {
            let message = read_input(a.pos.first());
            let Response::Decrypted { plaintext, key } = c.call(Request::PgpDecrypt { message })
            else {
                die("unexpected response")
            };
            eprintln!("Decrypted with \u{201c}{key}\u{201d}.");
            write_output(a.out.as_ref(), &plaintext);
        }
        "sign" => {
            let id = key_id(&mut c, &pos(0, "ID"));
            let data = read_input(a.pos.get(1));
            let Response::Bytes(sig) = c.call(Request::PgpSign {
                id,
                data,
                armor: !a.binary,
                text: false,
            }) else {
                die("unexpected response")
            };
            write_output(a.out.as_ref(), &sig);
        }
        "verify" => {
            let signature = read_input(Some(&pos(0, "SIG")));
            let data = read_input(a.pos.get(1));
            let certs = a.certs.iter().map(|p| read_input(Some(p))).collect();
            let Response::Verified(who) = c.call(Request::PgpVerify {
                data,
                signature,
                certs,
            }) else {
                die("unexpected response")
            };
            println!("Good signature from {who}");
        }
        _ => die(format!("unknown pgp command {sub}; see `vault help`")),
    }
}

fn print_public(c: &mut Client, id: [u8; 16]) {
    let Response::PublicKey(line) = c.call(Request::PublicKey { id }) else {
        die("unexpected response")
    };
    println!("{line}");
}

/// Whether an OpenSSH private key file is passphrase-protected: its cipher
/// name, the first field after the magic, is not "none".
fn encrypted(pem: &str) -> bool {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    let Ok(raw) = data_encoding::BASE64.decode(body.trim().as_bytes()) else {
        return false;
    };
    let rest = raw.strip_prefix(b"openssh-key-v1\0").unwrap_or_default();
    let n = rest.get(..4).map_or(0, |b| {
        u32::from_be_bytes(b.try_into().unwrap_or_default()) as usize
    });
    rest.get(4..4 + n).is_some_and(|c| c != b"none")
}
