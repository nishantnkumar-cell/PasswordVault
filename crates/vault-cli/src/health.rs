//! `vault health`: reused, weak and old passwords, logins without a
//! one-time code, and (with `--online`) passwords seen in known breaches.
//!
//! The analysis runs here in the CLI, on items fetched through the daemon, so
//! `vaultd` never needs network access. The breach check uses the Have I Been
//! Pwned range API by k-anonymity: only the first 5 hex characters of the
//! password's SHA-1 leave the machine, never the password or the full hash.

use std::collections::BTreeMap;

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// One login to check.
pub struct Entry {
    pub title: String,
    pub password: Zeroizing<String>,
    /// Seconds since the Unix epoch.
    pub modified: u64,
    pub has_totp: bool,
    pub has_url: bool,
}

/// What `analyze` found, as indexes into the entries.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Groups of logins that share a password.
    pub reused: Vec<Vec<usize>>,
    pub weak: Vec<usize>,
    pub old: Vec<usize>,
    /// Logins with a website but no one-time code.
    pub no_code: Vec<usize>,
}

/// A password counts as old after this long.
pub const OLD_AFTER: u64 = 365 * 86_400;

pub fn analyze(entries: &[Entry], now: u64) -> Report {
    let mut r = Report::default();
    let mut by_password: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        if e.password.is_empty() {
            continue;
        }
        by_password.entry(e.password.as_str()).or_default().push(i);
        if zxcvbn::zxcvbn(e.password.as_str(), &[e.title.as_str()]).score() < zxcvbn::Score::Three {
            r.weak.push(i);
        }
        if e.modified != 0 && now.saturating_sub(e.modified) > OLD_AFTER {
            r.old.push(i);
        }
        if e.has_url && !e.has_totp {
            r.no_code.push(i);
        }
    }
    r.reused = by_password.into_values().filter(|v| v.len() > 1).collect();
    r
}

/// The 5-character prefix that is sent and the 35-character suffix that stays.
pub fn hibp_parts(password: &str) -> (String, String) {
    let hex: String = Sha1::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    (hex[..5].to_owned(), hex[5..].to_owned())
}

/// How many times `suffix` appears in a range reply (`SUFFIX:COUNT` lines;
/// padding lines have a count of 0).
pub fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Ask the range API for `prefix`, through `curl` (present on Linux, macOS and
/// Windows 10 and later), so no HTTP library is built into the program.
pub fn fetch_range(prefix: &str) -> Result<String, String> {
    let out = std::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "20",
            "--header",
            "Add-Padding: true",
            &format!("https://api.pwnedpasswords.com/range/{prefix}"),
        ])
        .output()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    String::from_utf8(out.stdout).map_err(|_| "the reply was not text".into())
}

/// Entries whose password appears in a breach, with the count, using `fetch`
/// for each distinct prefix once.
pub fn breached(
    entries: &[Entry],
    fetch: &mut dyn FnMut(&str) -> Result<String, String>,
) -> Result<Vec<(usize, u64)>, String> {
    let mut replies: BTreeMap<String, String> = BTreeMap::new();
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.password.is_empty() {
            continue;
        }
        let (prefix, suffix) = hibp_parts(e.password.as_str());
        if !replies.contains_key(&prefix) {
            let body = fetch(&prefix)?;
            replies.insert(prefix.clone(), body);
        }
        let n = count_in_range(&replies[&prefix], &suffix);
        if n > 0 {
            out.push((i, n));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, password: &str, modified: u64, totp: bool) -> Entry {
        Entry {
            title: title.into(),
            password: Zeroizing::new(password.into()),
            modified,
            has_totp: totp,
            has_url: true,
        }
    }

    #[test]
    fn finds_reused_weak_old_and_codeless_logins() {
        let now = 3 * OLD_AFTER;
        let e = vec![
            entry("Mail", "correct horse battery staple", now, true),
            entry("Bank", "Tr0ub4dor&3-quartz-lantern", now, false),
            entry("Forum", "password123", now, true),
            entry(
                "Shop",
                "Tr0ub4dor&3-quartz-lantern",
                now - OLD_AFTER - 1,
                true,
            ),
            entry("Empty", "", 0, false),
        ];
        let r = analyze(&e, now);
        assert_eq!(r.reused, vec![vec![1, 3]]);
        assert_eq!(r.weak, vec![2]);
        assert_eq!(r.old, vec![3]);
        assert_eq!(r.no_code, vec![1]);
    }

    #[test]
    fn hibp_uses_a_five_character_prefix() {
        // The well-known example from the API's documentation.
        let (p, s) = hibp_parts("password");
        assert_eq!(p, "5BAA6");
        assert_eq!(s, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn counts_a_suffix_in_a_range_reply() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFF0000000000000000000000000000000:0\r\n";
        assert_eq!(
            count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            9_545_824
        );
        assert_eq!(
            count_in_range(body, "AAAAA00000000000000000000000000000"),
            0
        );
        // A padding line counts as zero.
        assert_eq!(
            count_in_range(body, "FFFF0000000000000000000000000000000"),
            0
        );
    }

    #[test]
    fn asks_once_per_prefix_and_only_sends_the_prefix() {
        let e = vec![
            entry("A", "password", 0, true),
            entry("B", "password", 0, true),
            entry("C", "an unusual long passphrase 7131", 0, true),
        ];
        let mut asked = Vec::new();
        let hits = breached(&e, &mut |prefix| {
            asked.push(prefix.to_owned());
            Ok("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n".into())
        })
        .unwrap();
        assert_eq!(hits, vec![(0, 3), (1, 3)]);
        assert!(asked.iter().all(|p| p.len() == 5));
        assert_eq!(asked.iter().filter(|p| *p == "5BAA6").count(), 1);
    }
}
