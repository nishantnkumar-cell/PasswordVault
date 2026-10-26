//! `vault-gpg`: a gpg-compatible front end for OpenPGP keys held in vaultd.
//!
//! Programs that call `gpg` (git, pass, mutt and other mail clients that run
//! gpg commands) can call this instead. Signing and decryption happen in the
//! daemon, which asks before each use of a key that requires it; the secret
//! keys never reach this process. Verification, key listings, import and
//! export happen here, on certificates only.
//!
//! Only the subset of gpg those programs use is provided: detached
//! signatures, verification of detached signatures, encryption (optionally
//! signed), decryption, key listings (also `--with-colons`), import and
//! export of certificates, and gpg's `--status-fd` lines.

#![forbid(unsafe_code)]

mod args;
mod keys;

use std::io::{self, IsTerminal, Read, Write};
use std::process::exit;

use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, Esk, Message};
use pgp::packet::Signature;
use pgp::ser::Serialize;
use pgp::types::KeyDetails;
use vault_ipc::{ClientToken, Envelope, Request, Response, local, read_frame, write_frame};
use zeroize::Zeroizing;

use args::Args;
use keys::{Key, fpr, keyid};

const HELP: &str = "vault-gpg: a gpg-compatible front end for OpenPGP keys held in vaultd

Use it wherever a program runs gpg, for example:
  git config --global gpg.program vault-gpg

COMMANDS (gpg's spelling)
  -b, --detach-sign [FILE]        detached signature (-a: armored, -u KEY: which key)
  -e, --encrypt -r KEY.. [FILE]   encrypt (add -s to sign as well)
  -d, --decrypt [FILE]            decrypt with whichever vault key can
  --verify SIG DATA               verify a detached signature (DATA may be -)
  -k, --list-keys [KEY..]         certificates: vault keys and imported ones
  -K, --list-secret-keys [KEY..]  vault keys
  --import [FILE..]               store certificates in the keyring directory
  --export [KEY..]                print certificates (-a: armored)
  OPTIONS: -o FILE, --status-fd N, --with-colons, -t/--textmode, -q

KEY may be a fingerprint, a key ID, an address, or part of a user ID.

ENVIRONMENT
  VAULT_GPG_KEYRING   imported certificates [default: pgp-certs beside the vault file]
  VAULT_SOCKET, VAULT_TOKEN_FILE  as for `vault`";

/// Exit with gpg's status 2 (error) and a message.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("vault-gpg: {msg}");
    exit(2)
}

/// `--status-fd`: machine-readable `[GNUPG:]` lines.
struct Status(Option<Box<dyn Write>>);

impl Status {
    fn open(fd: Option<i32>) -> Status {
        let w: Option<Box<dyn Write>> = match fd {
            None => None,
            Some(1) => Some(Box::new(io::stdout())),
            Some(2) => Some(Box::new(io::stderr())),
            #[cfg(unix)]
            Some(n) => match std::fs::OpenOptions::new()
                .append(true)
                .open(format!("/dev/fd/{n}"))
            {
                Ok(f) => Some(Box::new(f)),
                Err(e) => die(format!("--status-fd {n}: {e}")),
            },
            #[cfg(not(unix))]
            Some(n) => die(format!("--status-fd {n}: only 1 and 2 are supported here")),
        };
        Status(w)
    }

    fn line(&mut self, s: impl std::fmt::Display) {
        if let Some(w) = &mut self.0 {
            let _ = writeln!(w, "[GNUPG:] {s}");
            let _ = w.flush();
        }
    }
}

struct Client {
    stream: local::Stream,
    token: Option<ClientToken>,
}

impl Client {
    fn connect() -> Result<Client, String> {
        let p = local::endpoint().map_err(|e| e.to_string())?;
        let stream = local::connect(&p).map_err(|e| {
            format!(
                "cannot reach vaultd at {}: {e}. Is it running?",
                p.display()
            )
        })?;
        let token_file = std::env::var_os("VAULT_TOKEN_FILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| local::config_dir().join("token"));
        let token = std::fs::read(token_file).ok().and_then(|b| {
            let b = Zeroizing::new(b);
            let arr: [u8; 32] = b.as_slice().try_into().ok()?;
            Some(Zeroizing::new(arr))
        });
        Ok(Client { stream, token })
    }

    fn call(&mut self, request: Request) -> Result<Response, String> {
        let env = Envelope {
            token: self.token.clone(),
            request,
        };
        write_frame(&mut self.stream, &env).map_err(|e| e.to_string())?;
        match read_frame(&mut self.stream).map_err(|e| e.to_string())? {
            Response::Error(m) => Err(m),
            r => Ok(r),
        }
    }
}

struct Gpg {
    a: Args,
    status: Status,
    client: Option<Client>,
}

impl Gpg {
    fn client(&mut self) -> Result<&mut Client, String> {
        if self.client.is_none() {
            self.client = Some(Client::connect()?);
        }
        Ok(self.client.as_mut().expect("just connected"))
    }

    fn call(&mut self, request: Request) -> Response {
        self.client()
            .and_then(|c| c.call(request))
            .unwrap_or_else(|e| die(e))
    }

    /// The certificates of the OpenPGP keys in the vault.
    fn vault_keys(&mut self) -> Result<Vec<Key>, String> {
        let c = self.client()?;
        let Response::Items(items) = c.call(Request::ListItems)? else {
            return Err("unexpected response".into());
        };
        let mut out = Vec::new();
        for i in items {
            if !i.key.as_deref().is_some_and(|k| k.starts_with("OpenPGP")) {
                continue;
            }
            let Response::PublicKey(armored) = c.call(Request::PublicKey { id: i.id })? else {
                return Err("unexpected response".into());
            };
            for k in keys::parse_many(armored.as_bytes())? {
                out.push(Key {
                    cert: keys::public(k),
                    item: Some(i.id),
                });
            }
        }
        Ok(out)
    }

    /// Vault keys, then imported certificates. Without the vault
    /// (`required` false), imported certificates only, with a warning.
    fn keys(&mut self, required: bool) -> Vec<Key> {
        let mut all = match self.vault_keys() {
            Ok(v) => v,
            Err(e) if required => die(e),
            Err(e) => {
                if !self.a.quiet {
                    eprintln!("vault-gpg: vault keys unavailable: {e}");
                }
                vec![]
            }
        };
        for k in keys::keyring(&keys::keyring_dir()) {
            let f = fpr(&k.cert.primary_key);
            if !all.iter().any(|v| fpr(&v.cert.primary_key) == f) {
                all.push(k);
            }
        }
        all
    }

    fn input(&self, path: Option<&String>) -> Vec<u8> {
        match path.map(String::as_str) {
            None | Some("-") => {
                let mut v = Vec::new();
                io::stdin()
                    .read_to_end(&mut v)
                    .unwrap_or_else(|e| die(format!("reading stdin: {e}")));
                v
            }
            Some(p) => std::fs::read(p).unwrap_or_else(|e| die(format!("{p}: {e}"))),
        }
    }

    fn output(&self, bytes: &[u8]) {
        match self.a.output.as_deref() {
            None | Some("-") => {
                let mut out = io::stdout();
                out.write_all(bytes)
                    .and_then(|()| out.flush())
                    .unwrap_or_else(|e| die(e));
            }
            Some(p) => local::write_private(std::path::Path::new(p), bytes)
                .unwrap_or_else(|e| die(format!("{p}: {e}"))),
        }
    }

    /// The vault key to sign with: `-u`, else `--default-key`, else the
    /// first vault key that can sign.
    fn signer<'k>(&self, keys: &'k [Key]) -> &'k Key {
        let wanted: Vec<&String> = if self.a.local_users.is_empty() {
            self.a.default_key.iter().collect()
        } else {
            self.a.local_users.iter().collect()
        };
        let mine = || keys.iter().filter(|k| k.item.is_some());
        for w in &wanted {
            if let Some(k) = mine().find(|k| keys::matches(&k.cert, w)) {
                return k;
            }
        }
        if let Some(w) = wanted.first() {
            die(format!(
                "skipped \"{w}\": No secret key in the vault (see `vault pgp ls`)"
            ));
        }
        mine()
            .next()
            .unwrap_or_else(|| die("no OpenPGP key in the vault; create one with `vault pgp new`"))
    }

    fn detach_sign(&mut self) {
        let keys = self.keys(true);
        let k = self.signer(&keys);
        let id = k.item.expect("vault key");
        let data = self.input(self.a.files.first());
        let Response::Bytes(sig) = self.call(Request::PgpSign {
            id,
            data,
            armor: self.a.armor,
            text: self.a.textmode,
        }) else {
            die("unexpected response")
        };
        let (ds, _) = DetachedSignature::from_reader_single(&sig[..])
            .unwrap_or_else(|e| die(format!("the daemon returned a bad signature: {e}")));
        let s = &ds.signature;
        let (signing_fpr, algo) = signing_key(k, s).unwrap_or_else(|| {
            (
                fpr(&k.cert.primary_key),
                u8::from(k.cert.primary_key.algorithm()),
            )
        });
        let hash = s.hash_alg().map(u8::from).unwrap_or(0);
        self.status
            .line(format!("KEY_CONSIDERED {} 0", fpr(&k.cert.primary_key)));
        self.status.line(format!("BEGIN_SIGNING H{hash}"));
        self.status.line(format!(
            "SIG_CREATED D {algo} {hash} {:02X} {} {signing_fpr}",
            s.typ().map(u8::from).unwrap_or(0),
            s.created().map(|t| t.as_secs()).unwrap_or(0),
        ));
        self.output(&sig);
    }

    fn verify(&mut self) {
        let [sig_file, data_file] = self.a.files.as_slice() else {
            die(
                "give the signature file and the signed data (- for stdin); \
                 only detached signatures can be verified",
            )
        };
        let sig_bytes = self.input(Some(sig_file));
        let data = self.input(Some(data_file));
        let Ok((ds, _)) = DetachedSignature::from_reader_single(&sig_bytes[..]) else {
            self.status.line("NODATA 1");
            die("no signature found");
        };
        let s = &ds.signature;
        let keys = self.keys(false);
        let hash = s.hash_alg().map(u8::from).unwrap_or(0);
        let class = s.typ().map(u8::from).unwrap_or(0);
        let created = s.created().map(|t| t.as_secs()).unwrap_or(0);
        let issuer_fpr = s
            .issuer_fingerprint()
            .first()
            .map(|f| keys::upper_hex(f.as_bytes()));
        let issuer_id = s
            .issuer_key_id()
            .first()
            .map(|i| keys::upper_hex(i.as_ref()))
            .or_else(|| issuer_fpr.as_deref().map(fpr_to_keyid));

        self.status.line("NEWSIG");
        eprintln!("vault-gpg: Signature made {}", keys::date_time(created));
        if let Some(i) = issuer_fpr.as_ref().or(issuer_id.as_ref()) {
            eprintln!("vault-gpg:                using key {i}");
        }

        // The certificate the issuer names, else any whose key verifies.
        let named = keys.iter().find(|k| signing_key(k, s).is_some());
        let candidates: Vec<&Key> = match named {
            Some(k) => vec![k],
            None if issuer_fpr.is_none() && issuer_id.is_none() => keys.iter().collect(),
            None => vec![],
        };
        if candidates.is_empty() {
            let id = issuer_id.unwrap_or_else(|| "0000000000000000".into());
            self.status.line(format!(
                "ERRSIG {id} {} {hash} {class:02X} {created} 9 {}",
                0,
                issuer_fpr.as_deref().unwrap_or("-")
            ));
            self.status.line(format!("NO_PUBKEY {id}"));
            die(
                "Can't check signature: No public key. Import the signer's certificate with \
                 `vault-gpg --import FILE`",
            );
        }
        for k in &candidates {
            let c = &k.cert;
            let good = if ds.verify(c, &data).is_ok() {
                Some((fpr(&c.primary_key), keyid(&c.primary_key)))
            } else {
                c.public_subkeys
                    .iter()
                    .find(|sub| ds.verify(*sub, &data).is_ok())
                    .map(|sub| (fpr(&sub.key), keyid(&sub.key)))
            };
            let Some((signing_fpr, signing_id)) = good else {
                continue;
            };
            let uid = keys::first_uid(c);
            let algo = signing_key(k, s)
                .map(|(_, a)| a)
                .unwrap_or_else(|| u8::from(c.primary_key.algorithm()));
            self.status.line(format!("GOODSIG {signing_id} {uid}"));
            self.status.line(format!(
                "VALIDSIG {signing_fpr} {} {created} 0 {} 0 {algo} {hash} {class:02X} {}",
                keys::date(created),
                u8::from(s.version()),
                fpr(&c.primary_key)
            ));
            let trust = if k.item.is_some() {
                self.status.line("TRUST_ULTIMATE 0 pgp");
                "ultimate"
            } else {
                self.status.line("TRUST_UNDEFINED 0 pgp");
                "unknown"
            };
            eprintln!("vault-gpg: Good signature from \"{uid}\" [{trust}]");
            if k.item.is_none() {
                eprintln!(
                    "vault-gpg: WARNING: this certificate was imported, not made in the vault; \
                     check its fingerprint with its owner: {}",
                    fpr(&c.primary_key)
                );
            }
            exit(0);
        }
        let k = candidates[0];
        let uid = keys::first_uid(&k.cert);
        let id = issuer_id.unwrap_or_else(|| keyid(&k.cert.primary_key));
        self.status.line(format!("BADSIG {id} {uid}"));
        eprintln!("vault-gpg: BAD signature from \"{uid}\"");
        exit(1);
    }

    fn encrypt(&mut self) {
        if self.a.recipients.is_empty() {
            die("no recipients; give -r KEY");
        }
        let keys = self.keys(true);
        let mut to_items = Vec::new();
        let mut to_certs = Vec::new();
        for r in self.a.recipients.clone() {
            let Some(k) = keys
                .iter()
                .find(|k| keys::matches(&k.cert, &r) && keys::can_encrypt(&k.cert))
            else {
                self.status.line(format!("INV_RECP 0 {r}"));
                die(format!("{r}: skipped: No public key"));
            };
            match k.item {
                Some(id) if !to_items.contains(&id) => to_items.push(id),
                Some(_) => {}
                None => to_certs.push(k.cert.to_bytes().unwrap_or_else(|e| die(e))),
            }
        }
        let sign_with = self
            .a
            .sign
            .then(|| self.signer(&keys).item.expect("vault key"));
        let data = Zeroizing::new(self.input(self.a.files.first()));
        self.status.line("BEGIN_ENCRYPTION 2 9");
        let Response::Bytes(out) = self.call(Request::PgpEncrypt {
            to_items,
            to_certs,
            data,
            armor: self.a.armor,
            sign_with,
        }) else {
            die("unexpected response")
        };
        self.status.line("END_ENCRYPTION");
        self.output(&out);
    }

    fn decrypt(&mut self) {
        let message = self.input(self.a.files.first());
        for (id, algo) in recipients(&message) {
            self.status.line(format!("ENC_TO {id} {algo} 0"));
            if self.a.list_only || self.a.verbose {
                eprintln!("gpg: public key is {id}");
            }
        }
        if self.a.list_only {
            return;
        }
        self.status.line("BEGIN_DECRYPTION");
        let r = self
            .client()
            .and_then(|c| c.call(Request::PgpDecrypt { message }));
        match r {
            Ok(Response::Decrypted { plaintext, key }) => {
                self.status.line("DECRYPTION_OKAY");
                self.status.line("GOODMDC");
                self.status.line("END_DECRYPTION");
                if !self.a.quiet {
                    eprintln!("vault-gpg: decrypted with \u{201c}{key}\u{201d}");
                }
                self.output(&plaintext);
            }
            Ok(_) => die("unexpected response"),
            Err(e) => {
                self.status.line("DECRYPTION_FAILED");
                self.status.line("END_DECRYPTION");
                die(format!("decryption failed: {e}"));
            }
        }
    }

    fn selected(&mut self, secret_only: bool) -> Vec<Key> {
        let all = if secret_only {
            self.vault_keys().unwrap_or_else(|e| die(e))
        } else {
            self.keys(false)
        };
        if self.a.files.is_empty() {
            return all;
        }
        let picked: Vec<Key> = all
            .into_iter()
            .filter(|k| self.a.files.iter().any(|q| keys::matches(&k.cert, q)))
            .collect();
        if picked.is_empty() {
            die(format!(
                "error reading key: No {} key",
                if secret_only { "secret" } else { "public" }
            ));
        }
        picked
    }

    fn list(&mut self, secret: bool) {
        let mut out = String::new();
        for k in self.selected(secret) {
            if self.a.colons {
                out.push_str(&keys::colons(&k, secret));
            } else {
                out.push_str(&keys::human(&k, secret));
                out.push('\n');
            }
        }
        print!("{out}");
    }

    fn export(&mut self) {
        let mut out = Vec::new();
        for k in self.selected(false) {
            if self.a.armor {
                let s = k
                    .cert
                    .to_armored_string(ArmorOptions::default())
                    .unwrap_or_else(|e| die(e));
                out.extend_from_slice(s.as_bytes());
            } else {
                out.extend(k.cert.to_bytes().unwrap_or_else(|e| die(e)));
            }
        }
        self.output(&out);
    }

    fn import(&mut self) {
        let dir = keys::keyring_dir();
        let inputs: Vec<Vec<u8>> = if self.a.files.is_empty() {
            vec![self.input(None)]
        } else {
            self.a.files.iter().map(|f| self.input(Some(f))).collect()
        };
        let (mut count, mut imported, mut secret_read) = (0, 0, 0);
        for bytes in inputs {
            for k in keys::parse_many(&bytes).unwrap_or_else(|e| die(e)) {
                count += 1;
                let was_secret = matches!(k, pgp::composed::PublicOrSecret::Secret(_));
                let cert = keys::public(k);
                let id = keyid(&cert.primary_key);
                if let Err(e) = cert.verify_bindings() {
                    eprintln!(
                        "vault-gpg: key {id}: skipped, its self-signatures are not valid: {e}"
                    );
                    continue;
                }
                let f = fpr(&cert.primary_key);
                let armored = cert
                    .to_armored_string(ArmorOptions::default())
                    .unwrap_or_else(|e| die(e));
                std::fs::create_dir_all(&dir)
                    .and_then(|()| std::fs::write(dir.join(format!("{f}.asc")), armored))
                    .unwrap_or_else(|e| die(format!("{}: {e}", dir.display())));
                imported += 1;
                self.status.line(format!("IMPORT_OK 1 {f}"));
                eprintln!(
                    "vault-gpg: key {id}: public key \"{}\" imported",
                    keys::first_uid(&cert)
                );
                if was_secret {
                    secret_read += 1;
                    eprintln!(
                        "vault-gpg: key {id}: secret key not imported; store it in the vault \
                         with `vault pgp import TITLE FILE`"
                    );
                }
            }
        }
        self.status.line(format!(
            "IMPORT_RES {count} 0 {imported} 0 0 0 0 0 0 {secret_read} 0 0 0 0 0"
        ));
    }
}

/// The key of `k` that `sig` names as its issuer: its fingerprint and
/// algorithm ID.
fn signing_key(k: &Key, sig: &Signature) -> Option<(String, u8)> {
    let fprs: Vec<String> = sig
        .issuer_fingerprint()
        .iter()
        .map(|f| keys::upper_hex(f.as_bytes()))
        .collect();
    let ids: Vec<String> = sig
        .issuer_key_id()
        .iter()
        .map(|i| keys::upper_hex(i.as_ref()))
        .collect();
    let named = |key: &dyn KeyDetails| {
        let f = keys::upper_hex(key.fingerprint().as_bytes());
        let i = keys::upper_hex(key.legacy_key_id().as_ref());
        (fprs.contains(&f) || ids.contains(&i)).then(|| (f, u8::from(key.algorithm())))
    };
    named(&k.cert.primary_key).or_else(|| k.cert.public_subkeys.iter().find_map(|s| named(&s.key)))
}

/// The long key ID within a fingerprint: its last 8 bytes for v4, its
/// first 8 for v6.
fn fpr_to_keyid(f: &str) -> String {
    if f.len() == 64 {
        f[..16].to_owned()
    } else {
        f[f.len().saturating_sub(16)..].to_owned()
    }
}

/// The key IDs (and algorithm IDs) a message is encrypted to.
fn recipients(message: &[u8]) -> Vec<(String, u8)> {
    let msg = Message::from_reader(message)
        .map(|(m, _)| m)
        .or_else(|_| Message::from_bytes(message));
    let Ok(Message::Encrypted { esk, .. }) = msg else {
        return vec![];
    };
    esk.iter()
        .filter_map(|e| match e {
            Esk::PublicKeyEncryptedSessionKey(p) => {
                let id = match p.fingerprint() {
                    Ok(Some(f)) => fpr_to_keyid(&keys::upper_hex(f.as_bytes())),
                    _ => keys::upper_hex(p.id().ok()?.as_ref()),
                };
                let algo = p.algorithm().map(u8::from).unwrap_or(0);
                Some((id, algo))
            }
            _ => None,
        })
        .collect()
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = args::parse(&argv).unwrap_or_else(|e| die(e));
    let status = Status::open(a.status_fd);
    let mut g = Gpg {
        a,
        status,
        client: None,
    };
    let a = &g.a;
    if a.version {
        println!("gpg (GnuPG) 2.4.4");
        println!(
            "This is vault-gpg {}, a gpg-compatible front end for vaultd; it is not GnuPG.",
            vault_ipc::VERSION
        );
    } else if a.help {
        println!("{HELP}");
    } else if a.list_config {
        // No groups or other settings to report.
    } else if let Some(secret) = a.list {
        g.list(secret);
    } else if a.import {
        g.import();
    } else if a.export {
        g.export();
    } else if a.verify {
        g.verify();
    } else if a.decrypt {
        g.decrypt();
    } else if a.encrypt {
        g.encrypt();
    } else if a.detach {
        g.detach_sign();
    } else if a.sign {
        die("only detached signatures are supported; use --detach-sign (-b)");
    } else if !g.a.files.is_empty() || !io::stdin().is_terminal() {
        // gpg guesses what to do with a message; mail clients rely on it
        // to open encrypted mail. Encrypted is the only kind we read.
        g.decrypt();
    } else {
        die("no command given; see vault-gpg --help");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ids_from_fingerprints() {
        let v4 = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert_eq!(fpr_to_keyid(v4), "89ABCDEF01234567");
        let v6 = "AA".repeat(8) + &"BB".repeat(24);
        assert_eq!(fpr_to_keyid(&v6), "AA".repeat(8));
    }
}
