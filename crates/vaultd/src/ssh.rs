//! SSH keys held in the vault, and the ssh-agent protocol
//! (draft-miller-ssh-agent) that lets `ssh`, `git` and `ssh-keygen -Y sign`
//! use them without the private key leaving the daemon.
//!
//! The agent only lists keys and signs. It never accepts keys from
//! `ssh-add`, never exports them, and lists nothing while the vault is
//! locked. Keys marked `confirm` are used only after the user allows it in
//! the approval window, which names the key, the purpose and the program.

use std::io::{self, Read, Write};

use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use vault_core::item::KeyData;
use vault_ipc::{ItemId, KeyKind};
use zeroize::Zeroizing;

use crate::approve::{self, UsePrompt};
use crate::server::Shared;

type R<T> = Result<T, String>;

/// Largest agent message accepted. Sign requests carry at most a git object
/// hash or an SSH session's userauth request.
const MAX_MESSAGE: usize = 256 * 1024;

// Message numbers.
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// The extension that tells the agent which server a connection is for.
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// Most bindings kept per connection (one per hop of a forwarded chain).
const MAX_BINDINGS: usize = 8;

/// A `session-bind@openssh.com` the client sent, after its signature was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// SHA-256 fingerprint of the server's host key.
    pub host: String,
    /// The SSH session identifier the server signed.
    pub session: Vec<u8>,
    /// Whether the connection to this agent is a forwarded one (`ssh -A`).
    pub forwarded: bool,
}

/// Check a `session-bind@openssh.com` body (after the extension name): the
/// host key, the session identifier, the host's signature over it, and
/// whether this is a forwarding hop.
fn parse_binding(r: &mut Reader<'_>) -> R<Binding> {
    use signature::Verifier;
    let hostkey = r.string().ok_or("bad session-bind")?;
    let session = r.string().ok_or("bad session-bind")?;
    let sig = r.string().ok_or("bad session-bind")?;
    let forwarded = r.byte().ok_or("bad session-bind")? != 0;
    let key = ssh_key::PublicKey::from_bytes(hostkey).map_err(|e| e.to_string())?;
    let sig = ssh_key::Signature::try_from(sig).map_err(|e| e.to_string())?;
    Verifier::verify(&key, session, &sig).map_err(|_| "session-bind signature is wrong")?;
    Ok(Binding {
        host: key.fingerprint(HashAlg::Sha256).to_string(),
        session: session.to_vec(),
        forwarded,
    })
}

/// What a sign request means given the bindings of its connection: extra
/// words for the approval window, and whether to ask even for a key that is
/// not marked "ask before each use". A connection that came through agent
/// forwarding always asks, because a program on another computer is using the
/// key.
fn binding_context(bindings: &[Binding], data: &[u8]) -> (Option<String>, bool) {
    let forwarded = bindings.iter().any(|b| b.forwarded);
    let session = Reader(data).string();
    let bound = session.and_then(|sid| bindings.iter().find(|b| b.session == sid));
    let text = match (bound, forwarded) {
        (Some(b), true) => Some(format!(
            "forwarded from another computer, for the server {}",
            b.host
        )),
        (Some(b), false) => Some(format!("for the server {}", b.host)),
        (None, true) => Some("forwarded from another computer, for an unknown server".into()),
        (None, false) => None,
    };
    (text, forwarded)
}

/// Parse a stored key.
fn parse(openssh: &str) -> R<PrivateKey> {
    PrivateKey::from_openssh(openssh).map_err(|e| format!("stored SSH key is unreadable: {e}"))
}

fn check_algorithm(k: &PrivateKey) -> R<()> {
    match k.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(()),
        a => Err(format!(
            "{} keys are not supported; use Ed25519 or ECDSA",
            a.as_str()
        )),
    }
}

/// A new key of `kind`, commented with `title`.
pub fn generate(kind: KeyKind, title: &str, confirm: bool) -> R<KeyData> {
    let alg = match kind {
        KeyKind::SshEd25519 => Algorithm::Ed25519,
        KeyKind::SshEcdsaP256 => Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    };
    let mut k = PrivateKey::random(&mut UnwrapErr(SysRng), alg).map_err(|e| e.to_string())?;
    k.set_comment(title);
    encode(&k, confirm)
}

/// Read an OpenSSH private key, decrypting it with `passphrase` if needed.
pub fn import(openssh: &str, passphrase: Option<&str>, confirm: bool) -> R<KeyData> {
    let mut k = PrivateKey::from_openssh(openssh.trim())
        .map_err(|e| format!("not an OpenSSH private key: {e}"))?;
    if k.is_encrypted() {
        let p = passphrase.ok_or("this key is encrypted; give its passphrase")?;
        k = k.decrypt(p).map_err(|_| "wrong passphrase for this key")?;
    }
    check_algorithm(&k)?;
    encode(&k, confirm)
}

fn encode(k: &PrivateKey, confirm: bool) -> R<KeyData> {
    let text = k.to_openssh(LineEnding::LF).map_err(|e| e.to_string())?;
    Ok(KeyData::Ssh {
        openssh: String::from(text.as_str()),
        confirm,
    })
}

/// `ssh-ed25519 AAAA... comment`.
pub fn public_line(openssh: &str) -> R<String> {
    parse(openssh)?
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())
}

/// `ssh-ed25519 SHA256:...` for listings.
pub fn describe(openssh: &str) -> R<String> {
    let k = parse(openssh)?;
    Ok(format!(
        "{} {}",
        k.algorithm().as_str(),
        k.fingerprint(HashAlg::Sha256)
    ))
}

/// The private key in OpenSSH format, for export.
pub fn private_text(openssh: &str) -> R<Zeroizing<String>> {
    parse(openssh)?
        .to_openssh(LineEnding::LF)
        .map_err(|e| e.to_string())
}

/// A key the agent may offer: its wire-format public blob and comment.
pub struct Identity {
    pub id: ItemId,
    pub title: String,
    pub blob: Vec<u8>,
    pub confirm: bool,
}

/// Wire-format public blob of a stored key.
pub fn public_blob(openssh: &str) -> R<Vec<u8>> {
    parse(openssh)?
        .public_key()
        .to_bytes()
        .map_err(|e| e.to_string())
}

/// Sign `data` with a stored key; returns the wire-format signature.
pub fn sign(openssh: &str, data: &[u8]) -> R<Vec<u8>> {
    use signature::Signer;
    let k = parse(openssh)?;
    check_algorithm(&k)?;
    let sig: ssh_key::Signature = k.try_sign(data).map_err(|e| e.to_string())?;
    Vec::try_from(sig).map_err(|e| e.to_string())
}

/// What a signature is for, from the signed data, for the approval window.
/// Informational: the data comes from the program asking.
pub fn purpose(data: &[u8]) -> String {
    let mut r = Reader(data);
    // `ssh-keygen -Y sign` (git, files): "SSHSIG" then the namespace.
    if data.starts_with(b"SSHSIG") {
        r.0 = &data[6..];
        return match r.string() {
            Some(b"git") => "sign a git commit or tag".into(),
            Some(b"file") => "sign a file".into(),
            Some(ns) => format!("sign data (namespace \u{201c}{}\u{201d})", printable(ns)),
            None => "sign data".into(),
        };
    }
    // A userauth request: session ID, 50, user name, service, "publickey".
    if r.string().is_some()
        && r.byte() == Some(50)
        && let Some(user) = r.string()
    {
        return format!("log in over SSH as \u{201c}{}\u{201d}", printable(user));
    }
    "sign data".into()
}

fn printable(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let (n, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_be_bytes(*n))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        if self.0.len() < n {
            return None;
        }
        let (s, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(s)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn read_message(s: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad agent message length",
        ));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_message(s: &mut impl Write, body: &[u8]) -> io::Result<()> {
    s.write_all(&(body.len() as u32).to_be_bytes())?;
    s.write_all(body)?;
    s.flush()
}

/// Serve one agent connection. `pid` is the peer, for the approval window.
pub fn connection(mut s: impl Read + Write, daemon: &Shared, pid: Option<u32>) -> io::Result<()> {
    let mut bindings: Vec<Binding> = Vec::new();
    loop {
        let msg = match read_message(&mut s) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let reply =
            handle(&msg, daemon, pid, &mut bindings).unwrap_or_else(|_| vec![SSH_AGENT_FAILURE]);
        write_message(&mut s, &reply)?;
    }
}

/// Answer another user's agent connection: their first request gets
/// SSH_AGENT_FAILURE ("agent refused operation"), then the connection closes.
pub fn refuse(s: &mut (impl Read + Write)) {
    if read_message(s).is_ok() {
        let _ = write_message(s, &[SSH_AGENT_FAILURE]);
    }
}

/// One request to one reply. `Err` becomes `SSH_AGENT_FAILURE`.
fn handle(
    msg: &[u8],
    daemon: &Shared,
    pid: Option<u32>,
    bindings: &mut Vec<Binding>,
) -> R<Vec<u8>> {
    let lock = || daemon.lock().unwrap_or_else(|p| p.into_inner());
    let mut r = Reader(msg);
    match r.byte() {
        Some(SSH_AGENTC_REQUEST_IDENTITIES) => {
            let ids = lock().ssh_identities();
            let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
            out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
            for i in &ids {
                put_string(&mut out, &i.blob);
                put_string(&mut out, i.title.as_bytes());
            }
            Ok(out)
        }
        Some(SSH_AGENTC_SIGN_REQUEST) => {
            let blob = r.string().ok_or("bad sign request")?;
            let data = r.string().ok_or("bad sign request")?;
            let flags = r.u32().ok_or("bad sign request")?;
            // RSA hash selection flags only; no RSA keys are held.
            if flags != 0 {
                return Err("unsupported signature flags".into());
            }
            let ident = lock()
                .ssh_identities()
                .into_iter()
                .find(|i| i.blob == blob)
                .ok_or("no such key")?;
            let (context, forwarded) = binding_context(bindings, data);
            if ident.confirm || forwarded {
                // Ask without holding the daemon lock while the window is open.
                let approver = lock().approver().ok_or("no approval window available")?;
                let mut purpose = purpose(data);
                if let Some(c) = context {
                    purpose = format!("{purpose} ({c})");
                }
                let prompt = UsePrompt {
                    key: approve::clean_name(&ident.title),
                    purpose,
                    program: pid.and_then(approve::program_of),
                };
                if approver.confirm_use(&prompt) != Ok(true) {
                    return Err("declined".into());
                }
            }
            let sig = lock().ssh_sign(&ident.id, &ident.blob, data)?;
            let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
            put_string(&mut out, &sig);
            Ok(out)
        }
        Some(SSH_AGENTC_EXTENSION) => {
            // Only session-bind is understood; a client falls back without it.
            if r.string() != Some(SESSION_BIND) {
                return Err("unsupported extension".into());
            }
            let b = parse_binding(&mut r)?;
            if bindings.len() >= MAX_BINDINGS {
                bindings.remove(0);
            }
            bindings.push(b);
            Ok(vec![SSH_AGENT_SUCCESS])
        }
        _ => Err("unsupported".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn another_users_request_gets_agent_failure() {
        let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        write_message(&mut theirs, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        refuse(&mut ours);
        drop(ours);
        assert_eq!(read_message(&mut theirs).unwrap(), [SSH_AGENT_FAILURE]);
    }

    #[test]
    fn keys_generate_import_and_sign() {
        use signature::Verifier;
        let KeyData::Ssh { openssh, confirm } =
            generate(KeyKind::SshEd25519, "laptop", true).unwrap()
        else {
            panic!()
        };
        assert!(confirm);
        assert!(public_line(&openssh).unwrap().starts_with("ssh-ed25519 "));
        assert!(public_line(&openssh).unwrap().ends_with(" laptop"));
        assert!(describe(&openssh).unwrap().contains("SHA256:"));
        let sig = sign(&openssh, b"hello").unwrap();
        let k = PrivateKey::from_openssh(&openssh).unwrap();
        let sig = ssh_key::Signature::try_from(sig.as_slice()).unwrap();
        Verifier::verify(k.public_key(), b"hello", &sig).unwrap();

        // Re-import, encrypted with a passphrase.
        let pass = "x".repeat(12);
        let enc = k
            .encrypt(&mut SysRng, &pass)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();
        assert!(import(&enc, None, false).is_err());
        assert!(import(&enc, Some("wrong"), false).is_err());
        let KeyData::Ssh { openssh: again, .. } = import(&enc, Some(&pass), false).unwrap() else {
            panic!()
        };
        assert_eq!(public_blob(&again).unwrap(), public_blob(&openssh).unwrap());

        let ecdsa = generate(KeyKind::SshEcdsaP256, "work", false).unwrap();
        let KeyData::Ssh { openssh, .. } = ecdsa else {
            panic!()
        };
        assert!(
            public_line(&openssh)
                .unwrap()
                .starts_with("ecdsa-sha2-nistp256 ")
        );
    }

    fn binding_body(forwarded: bool, tamper: bool) -> (Vec<u8>, String) {
        use signature::Signer;
        let host = PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519).unwrap();
        let session = [9u8; 32];
        let sig: ssh_key::Signature = Signer::sign(&host, &session);
        let mut sig = Vec::try_from(sig).unwrap();
        if tamper {
            let n = sig.len();
            sig[n - 1] ^= 1;
        }
        let mut body = Vec::new();
        put_string(&mut body, &host.public_key().to_bytes().unwrap());
        put_string(&mut body, &session);
        put_string(&mut body, &sig);
        body.push(u8::from(forwarded));
        (
            body,
            host.public_key().fingerprint(HashAlg::Sha256).to_string(),
        )
    }

    #[test]
    fn session_bind_is_checked_and_names_the_server() {
        let (body, fp) = binding_body(false, false);
        let b = parse_binding(&mut Reader(&body)).unwrap();
        assert_eq!(b.host, fp);
        assert!(!b.forwarded);
        assert_eq!(b.session, vec![9u8; 32]);

        // A signature that does not verify is refused.
        let (bad, _) = binding_body(false, true);
        assert!(parse_binding(&mut Reader(&bad)).is_err());
        assert!(parse_binding(&mut Reader(b"short")).is_err());
    }

    #[test]
    fn forwarded_connections_always_ask() {
        let (body, fp) = binding_body(true, false);
        let b = parse_binding(&mut Reader(&body)).unwrap();
        assert!(b.forwarded);
        // A userauth request for the bound session.
        let mut auth = Vec::new();
        put_string(&mut auth, &[9u8; 32]);
        auth.push(50);
        let (text, ask) = binding_context(std::slice::from_ref(&b), &auth);
        assert!(ask);
        let text = text.unwrap();
        assert!(text.contains("forwarded") && text.contains(&fp));
        // Data for some other session on a forwarded connection still asks.
        let mut other = Vec::new();
        put_string(&mut other, &[1u8; 32]);
        let (text, ask) = binding_context(&[b], &other);
        assert!(ask && text.unwrap().contains("unknown server"));
        // No bindings (an older ssh, or git signing): nothing changes.
        assert_eq!(binding_context(&[], &auth), (None, false));
        // A direct connection names the server but does not force a question.
        let (direct, _) = binding_body(false, false);
        let d = parse_binding(&mut Reader(&direct)).unwrap();
        let (text, ask) = binding_context(&[d], &auth);
        assert!(!ask && text.is_some());
    }

    #[test]
    fn purposes_are_named() {
        let mut sshsig = b"SSHSIG".to_vec();
        put_string(&mut sshsig, b"git");
        assert_eq!(purpose(&sshsig), "sign a git commit or tag");
        let mut auth = Vec::new();
        put_string(&mut auth, &[7; 32]);
        auth.push(50);
        put_string(&mut auth, b"alice\n");
        assert_eq!(purpose(&auth), "log in over SSH as \u{201c}alice\u{201d}");
        assert_eq!(purpose(b"junk"), "sign data");
    }
}
