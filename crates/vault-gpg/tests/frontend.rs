//! vault-gpg against a real daemon, called the way git and pass call gpg.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vault_core::KdfCost;
use vault_core::item::KeyData;
use vault_ipc::{Envelope, Request, Response, read_frame, write_frame};
use vaultd::approve::{Approver, Prompt, UsePrompt};
use vaultd::daemon::Daemon;
use vaultd::hw::Hardware;
use vaultd::server;
use vaultd::store::Store;
use zeroize::Zeroizing;

/// Allows every key use, and records it.
struct Allow(Mutex<Vec<UsePrompt>>);

impl Approver for Allow {
    fn approve(&self, _: &Prompt) -> Result<bool, String> {
        Ok(false)
    }
    fn confirm_use(&self, p: &UsePrompt) -> Result<bool, String> {
        self.0.lock().unwrap().push(p.clone());
        Ok(true)
    }
}

fn endpoint(dir: &Path) -> PathBuf {
    #[cfg(unix)]
    return dir.join("vaultd.sock");
    #[cfg(windows)]
    {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let _ = dir;
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!(r"\\.\pipe\vaultd-gpg-test-{}-{n}", std::process::id()).into()
    }
}

struct Env {
    dir: tempfile::TempDir,
    sock: PathBuf,
    allow: Arc<Allow>,
}

fn call(sock: &Path, token: &Option<vault_ipc::ClientToken>, request: Request) -> Response {
    let mut s = vault_ipc::local::connect(sock).unwrap();
    write_frame(
        &mut s,
        &Envelope {
            token: token.clone(),
            request,
        },
    )
    .unwrap();
    match read_frame(&mut s).unwrap() {
        Response::Error(m) => panic!("{m}"),
        r => r,
    }
}

/// A daemon with an initialized vault, a paired token on disk, and the
/// key "Alex Example <alex@example.com>", asking before use.
fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("vault.svault"), dir.path().join("state")).unwrap();
    let hw = Hardware {
        fido2: None,
        tpm: None,
        presence: None,
    };
    let d = Arc::new(Mutex::new(Daemon::new(
        store,
        hw,
        KdfCost::MINIMUM,
        Duration::from_secs(600),
    )));
    let allow = Arc::new(Allow(Mutex::new(vec![])));
    d.lock().unwrap().set_approver(allow.clone());
    let sock = endpoint(dir.path());
    let l = server::bind(&sock, false).unwrap();
    std::thread::spawn(move || {
        server::serve(l, server::current_user(), move |c, pid| {
            let _ = server::connection(c, &d, pid);
        })
    });
    let Response::Initialized { token, .. } = call(
        &sock,
        &None,
        Request::Init {
            password: Zeroizing::new("correct horse battery".into()),
            client_name: "test".into(),
        },
    ) else {
        panic!()
    };
    std::fs::write(dir.path().join("token"), &token[..]).unwrap();
    call(
        &sock,
        &Some(token),
        Request::GeneratePgpKey {
            title: "alex".into(),
            user_id: "Alex Example <alex@example.com>".into(),
            post_quantum: false,
            confirm: true,
        },
    );
    Env { dir, sock, allow }
}

impl Env {
    fn gpg(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vault-gpg"))
            .args(args)
            .current_dir(self.dir.path())
            .env("VAULT_SOCKET", &self.sock)
            .env("VAULT_TOKEN_FILE", self.dir.path().join("token"))
            .env("VAULT_GPG_KEYRING", self.dir.path().join("certs"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_string_lossy().into_owned()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn git_signs_and_verifies_commits() {
    let e = setup();
    let commit = b"tree 0123\nauthor Alex Example <alex@example.com> 1 +0000\n\nmsg\n";

    // git: gpg --status-fd=2 -bsau <signing key>
    let out = e.gpg(
        &["--status-fd=2", "-bsau", "Alex Example <alex@example.com>"],
        commit,
    );
    let err = text(&out.stderr);
    assert!(out.status.success(), "{err}");
    // git looks for this line after a newline.
    assert!(err.contains("\n[GNUPG:] SIG_CREATED D 22 10 00 "), "{err}");
    assert!(text(&out.stdout).starts_with("-----BEGIN PGP SIGNATURE-----"));
    let prompts = e.allow.0.lock().unwrap().clone();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].key, "alex");
    std::fs::write(e.path("sig"), &out.stdout).unwrap();

    // git: gpg --keyid-format=long --status-fd=1 --verify <sig file> -
    let out = e.gpg(
        &[
            "--keyid-format=long",
            "--status-fd=1",
            "--verify",
            "sig",
            "-",
        ],
        commit,
    );
    let status = text(&out.stdout);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(status.contains("[GNUPG:] GOODSIG "), "{status}");
    assert!(status.contains("Alex Example <alex@example.com>"));
    assert!(status.contains("[GNUPG:] TRUST_ULTIMATE 0 pgp"));
    let validsig = status
        .lines()
        .find(|l| l.starts_with("[GNUPG:] VALIDSIG "))
        .unwrap();
    // pass reads the signing and primary fingerprints from fields 1 and 10.
    let f: Vec<&str> = validsig.split(' ').collect();
    assert_eq!(f.len(), 12);
    assert_eq!(f[2].len(), 40);
    assert_eq!(f[2], f[11]);

    // A changed commit does not verify.
    let out = e.gpg(&["--status-fd=1", "--verify", "sig", "-"], b"tampered");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).contains("[GNUPG:] BADSIG "));
}

#[test]
fn pass_encrypts_and_decrypts() {
    let e = setup();
    // pass resolves recipients to encryption subkeys from colon listings.
    let out = e.gpg(&["--list-keys", "--with-colons", "alex@example.com"], b"");
    let list = text(&out.stdout);
    assert!(out.status.success());
    let sub = list.lines().find(|l| l.starts_with("sub:")).unwrap();
    let fields: Vec<&str> = sub.split(':').collect();
    assert_eq!(fields[11], "e");
    let subkey = fields[4];
    assert_eq!(subkey.len(), 16);

    let opts = [
        "--quiet",
        "--yes",
        "--compress-algo=none",
        "--no-encrypt-to",
        "--batch",
        "--use-agent",
    ];
    let file = e.path("site.gpg");
    let mut args = vec!["-e", "-r", "alex@example.com", "-o", &file];
    args.extend(opts);
    let out = e.gpg(&args, b"hunter2-but-longer\n");
    assert!(out.status.success(), "{}", text(&out.stderr));
    // Encrypting asks nothing: it uses only the certificate.
    assert!(e.allow.0.lock().unwrap().is_empty());

    // pass init re-encrypts after comparing these key IDs with the listing.
    let out = e.gpg(
        &[
            "-v",
            "--decrypt",
            "--list-only",
            "--keyid-format",
            "long",
            &file,
        ],
        b"",
    );
    assert_eq!(
        text(&out.stderr).trim(),
        format!("gpg: public key is {subkey}")
    );

    let mut args = vec!["-d"];
    args.extend(opts);
    args.push(&file);
    let out = e.gpg(&args, b"");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, b"hunter2-but-longer\n");
    assert_eq!(e.allow.0.lock().unwrap().len(), 1);
}

#[test]
fn imported_certificates() {
    let e = setup();
    let KeyData::OpenPgp { tsk, .. } =
        vaultd::pgp::generate("Bo Example <bo@example.org>", false, false).unwrap()
    else {
        panic!()
    };
    let cert = vaultd::pgp::public_armored(&tsk).unwrap();
    let out = e.gpg(&["--status-fd=1", "--import"], cert.as_bytes());
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("[GNUPG:] IMPORT_OK 1 "));

    // Listed with unknown validity; not a secret key.
    let out = e.gpg(&["-k", "--with-colons"], b"");
    let list = text(&out.stdout);
    assert!(list.contains("pub:u:"));
    assert!(list.contains("pub:-:"));
    let out = e.gpg(&["-K", "--with-colons"], b"");
    assert!(!text(&out.stdout).contains("bo@example.org"));
    let out = e.gpg(&["-k", "nobody@example.net"], b"");
    assert_eq!(out.status.code(), Some(2));

    // Encrypt to it, signed by the vault key; it decrypts outside the vault.
    let out = e.gpg(
        &["-a", "-s", "-e", "-r", "bo@example.org", "-u", "alex"],
        b"for bo",
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        &**vaultd::pgp::decrypt(&tsk, &out.stdout).unwrap(),
        b"for bo"
    );
    // The vault cannot read it: alex is not a recipient.
    let out = e.gpg(&["-d"], &out.stdout);
    assert_eq!(out.status.code(), Some(2));

    // Its signatures verify, with unknown trust.
    let sig = vaultd::pgp::sign(&tsk, b"from bo", true, false).unwrap();
    std::fs::write(e.path("bo.sig"), sig).unwrap();
    let out = e.gpg(&["--status-fd=1", "--verify", "bo.sig", "-"], b"from bo");
    assert!(out.status.success());
    assert!(text(&out.stdout).contains("[GNUPG:] TRUST_UNDEFINED 0 pgp"));

    // Unknown recipients and signers are errors, as in gpg.
    let out = e.gpg(&["--status-fd=1", "-e", "-r", "cy@example.net"], b"x");
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stdout).contains("[GNUPG:] INV_RECP 0 cy@example.net"));
    let out = e.gpg(&["-bu", "bo@example.org"], b"x");
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("No secret key"));
}
