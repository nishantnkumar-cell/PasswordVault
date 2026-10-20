//! Certificates: the public halves of vault keys, and correspondents'
//! certificates in a keyring directory. How gpg names them (fingerprints,
//! key IDs, user IDs) and lists them.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use pgp::composed::{PublicOrSecret, SignedPublicKey};
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{KeyFlags, Signature};
use pgp::types::KeyDetails;

/// A certificate, and the vault item holding its secret key, if any.
pub struct Key {
    pub cert: SignedPublicKey,
    pub item: Option<[u8; 16]>,
}

/// Where imported certificates live: `VAULT_GPG_KEYRING`, else
/// `pgp-certs` beside the vault file.
pub fn keyring_dir() -> PathBuf {
    std::env::var_os("VAULT_GPG_KEYRING")
        .map(PathBuf::from)
        .unwrap_or_else(|| vault_ipc::local::data_dir().join("pgp-certs"))
}

/// Every certificate (and public half of a secret key) in `bytes`.
pub fn parse_many(bytes: &[u8]) -> Result<Vec<PublicOrSecret>, String> {
    let (it, _) = PublicOrSecret::from_reader_many(bytes).map_err(|e| e.to_string())?;
    it.collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("not an OpenPGP key: {e}"))
}

pub fn public(k: PublicOrSecret) -> SignedPublicKey {
    match k {
        PublicOrSecret::Public(p) => p,
        PublicOrSecret::Secret(s) => s.to_public_key(),
    }
}

/// Certificates in the keyring directory. Unreadable files are skipped
/// with a warning.
pub fn keyring(dir: &Path) -> Vec<Key> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "asc"))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for p in paths {
        match std::fs::read(&p)
            .map_err(|e| e.to_string())
            .and_then(|b| parse_many(&b))
        {
            Ok(certs) => out.extend(certs.into_iter().map(|c| Key {
                cert: public(c),
                item: None,
            })),
            Err(e) => eprintln!("vault-gpg: skipping {}: {e}", p.display()),
        }
    }
    out
}

pub fn upper_hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

pub fn fpr(k: &impl KeyDetails) -> String {
    upper_hex(k.fingerprint().as_bytes())
}

pub fn keyid(k: &impl KeyDetails) -> String {
    upper_hex(k.legacy_key_id().as_ref())
}

pub fn uids(c: &SignedPublicKey) -> Vec<String> {
    c.details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

pub fn first_uid(c: &SignedPublicKey) -> String {
    uids(c).into_iter().next().unwrap_or_default()
}

/// Whether `query` names this certificate, the way gpg matches: a
/// fingerprint or key ID (of the primary or a subkey, `0x` and a trailing
/// `!` allowed), `<mail>` for an exact address, `=uid` for an exact user ID,
/// `@part` for part of an address, else any part of a user ID, ignoring case.
pub fn matches(c: &SignedPublicKey, query: &str) -> bool {
    let q = query.trim();
    let hexq = q.trim_end_matches('!');
    let hexq = hexq
        .strip_prefix("0x")
        .or_else(|| hexq.strip_prefix("0X"))
        .unwrap_or(hexq);
    if matches!(hexq.len(), 8 | 16 | 40 | 64) && hexq.bytes().all(|b| b.is_ascii_hexdigit()) {
        let hexq = hexq.to_ascii_uppercase();
        let ids = std::iter::once((fpr(&c.primary_key), keyid(&c.primary_key))).chain(
            c.public_subkeys
                .iter()
                .map(|s| (fpr(&s.key), keyid(&s.key))),
        );
        for (f, id) in ids {
            if f == hexq || id == hexq || id.ends_with(&hexq) && hexq.len() == 8 {
                return true;
            }
        }
        return false;
    }
    let uids = uids(c);
    if let Some(exact) = q.strip_prefix('=') {
        return uids.iter().any(|u| u == exact);
    }
    let lower = q.to_lowercase();
    if lower.starts_with('<') && lower.ends_with('>') {
        return uids.iter().any(|u| u.to_lowercase().contains(&lower));
    }
    if let Some(part) = lower.strip_prefix('@') {
        return uids.iter().any(|u| {
            let u = u.to_lowercase();
            match (u.rfind('<'), u.rfind('>')) {
                (Some(a), Some(b)) if a < b => u[a + 1..b].contains(part),
                _ => u.contains('@') && u.contains(part),
            }
        });
    }
    // An address alone (alex@example.com) matches `<alex@example.com>`.
    if lower.contains('@') && !lower.contains(' ') {
        let bracketed = format!("<{lower}>");
        if uids.iter().any(|u| u.to_lowercase().contains(&bracketed)) {
            return true;
        }
    }
    uids.iter().any(|u| u.to_lowercase().contains(&lower))
}

/// The newest key flags among `sigs` (binding or self-signatures).
fn flags(sigs: &[Signature]) -> KeyFlags {
    sigs.iter()
        .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0))
        .map(Signature::key_flags)
        .unwrap_or_default()
}

/// The primary key's flags: from its user ID self-signatures, else from a
/// direct-key signature (v6 keys).
fn primary_flags(c: &SignedPublicKey) -> KeyFlags {
    let sigs: Vec<Signature> = c
        .details
        .users
        .iter()
        .flat_map(|u| u.signatures.iter().cloned())
        .chain(c.details.direct_signatures.iter().cloned())
        .collect();
    flags(&sigs)
}

fn caps(f: &KeyFlags) -> String {
    let mut s = String::new();
    if f.encrypt_comms() || f.encrypt_storage() {
        s.push('e');
    }
    if f.sign() {
        s.push('s');
    }
    if f.certify() {
        s.push('c');
    }
    if f.authentication() {
        s.push('a');
    }
    s
}

/// Whether some key of `c` may encrypt.
pub fn can_encrypt(c: &SignedPublicKey) -> bool {
    c.public_subkeys
        .iter()
        .any(|s| caps(&flags(&s.signatures)).contains('e'))
}

/// gpg's algorithm names, as in `ed25519` or `cv25519`.
pub fn algo_name(a: PublicKeyAlgorithm) -> String {
    match a {
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => "ed25519".into(),
        PublicKeyAlgorithm::ECDH | PublicKeyAlgorithm::X25519 => "cv25519".into(),
        PublicKeyAlgorithm::Ed448 => "ed448".into(),
        PublicKeyAlgorithm::X448 => "cv448".into(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            "rsa".into()
        }
        other => format!("{other:?}").to_lowercase(),
    }
}

/// The key size gpg reports: the curve's for 25519 and 448 keys.
fn bits(a: PublicKeyAlgorithm) -> u32 {
    match a {
        PublicKeyAlgorithm::EdDSALegacy
        | PublicKeyAlgorithm::Ed25519
        | PublicKeyAlgorithm::ECDH
        | PublicKeyAlgorithm::X25519 => 255,
        PublicKeyAlgorithm::Ed448 | PublicKeyAlgorithm::X448 => 448,
        _ => 0,
    }
}

/// `YYYY-MM-DD` for a Unix time (UTC).
pub fn date(secs: u32) -> String {
    let (y, m, d) = civil(secs as i64 / 86_400);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD hh:mm:ss UTC` for a Unix time.
pub fn date_time(secs: u32) -> String {
    let s = secs % 86_400;
    format!(
        "{} {:02}:{:02}:{:02} UTC",
        date(secs),
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), after Howard Hinnant's
/// `civil_from_days`.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// A listing in gpg's `--with-colons` format. `secret`: list as `sec`/`ssb`
/// (`--list-secret-keys`).
pub fn colons(k: &Key, secret: bool) -> String {
    let c = &k.cert;
    // Vault keys are ours: ultimately trusted. Others: unknown validity.
    let validity = if k.item.is_some() { "u" } else { "-" };
    let ownertrust = if k.item.is_some() { "u" } else { "" };
    let token = if secret { "+" } else { "" };
    let (pub_tag, sub_tag) = if secret {
        ("sec", "ssb")
    } else {
        ("pub", "sub")
    };
    let pk = &c.primary_key;
    let mut whole: String = caps(&primary_flags(c));
    for s in &c.public_subkeys {
        whole.push_str(&caps(&flags(&s.signatures)));
    }
    let mut all_caps: String = String::new();
    for ch in ['e', 's', 'c', 'a'] {
        if whole.contains(ch) {
            all_caps.push(ch.to_ascii_uppercase());
        }
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{pub_tag}:{validity}:{}:{}:{}:{}:::{ownertrust}:::{}{all_caps}:::{token}::{}:::0:",
        bits(pk.algorithm()),
        u8::from(pk.algorithm()),
        keyid(pk),
        pk.created_at().as_secs(),
        caps(&primary_flags(c)),
        algo_name(pk.algorithm()),
    );
    let _ = writeln!(out, "fpr:::::::::{}:", fpr(pk));
    for u in uids(c) {
        let _ = writeln!(
            out,
            "uid:{validity}::::{}::::{}::::::::::0:",
            pk.created_at().as_secs(),
            u.replace(':', "\\x3a")
        );
    }
    for s in &c.public_subkeys {
        let _ = writeln!(
            out,
            "{sub_tag}:{validity}:{}:{}:{}:{}::::::{}:::{token}::{}::",
            bits(s.key.algorithm()),
            u8::from(s.key.algorithm()),
            keyid(&s.key),
            s.key.created_at().as_secs(),
            caps(&flags(&s.signatures)),
            algo_name(s.key.algorithm()),
        );
        let _ = writeln!(out, "fpr:::::::::{}:", fpr(&s.key));
    }
    out
}

/// A listing as gpg prints it for people.
pub fn human(k: &Key, secret: bool) -> String {
    let c = &k.cert;
    let pk = &c.primary_key;
    let (pub_tag, sub_tag) = if secret {
        ("sec", "ssb")
    } else {
        ("pub", "sub")
    };
    let trust = if k.item.is_some() {
        "ultimate"
    } else {
        "unknown"
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{pub_tag}   {} {} [{}]",
        algo_name(pk.algorithm()),
        date(pk.created_at().as_secs()),
        caps(&primary_flags(c)).to_uppercase()
    );
    let _ = writeln!(out, "      {}", fpr(pk));
    for u in uids(c) {
        let _ = writeln!(out, "uid           [{trust:>8}] {u}");
    }
    for s in &c.public_subkeys {
        let _ = writeln!(
            out,
            "{sub_tag}   {} {} [{}]",
            algo_name(s.key.algorithm()),
            date(s.key.created_at().as_secs()),
            caps(&flags(&s.signatures)).to_uppercase()
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date_time(1_792_502_096), "2026-10-20 13:14:56 UTC");
    }
}
