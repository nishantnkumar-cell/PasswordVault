//! Import from Bitwarden's unencrypted JSON export and browser CSV exports.
//!
//! Export files hold every secret in plain text; callers should delete them
//! after import.

#![forbid(unsafe_code)]

use serde::Deserialize;
use vault_core::item::{ItemData, UrlEntry};
use vault_core::origin::MatchMode;
use vault_core::totp::TotpConfig;

/// Why an import failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    /// The file is not valid JSON or CSV of the expected shape.
    Parse(String),
    /// The Bitwarden export is encrypted; export it unencrypted instead.
    Encrypted,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Parse(m) => write!(f, "could not parse export: {m}"),
            ImportError::Encrypted => f.write_str(
                "encrypted Bitwarden exports are not supported; export as unencrypted JSON",
            ),
        }
    }
}

impl std::error::Error for ImportError {}

fn url_entry(url: &str) -> Option<UrlEntry> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    Some(UrlEntry {
        url: url.to_owned(),
        mode: MatchMode::Origin,
        allow_http: url.starts_with("http://"),
    })
}

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
}

#[derive(Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

/// Parse a Bitwarden unencrypted JSON export. Logins (type 1) and secure
/// notes (type 2) are imported; cards and identities are skipped. Returns the
/// items and the number skipped.
pub fn bitwarden_json(data: &str, now: u64) -> Result<(Vec<ItemData>, usize), ImportError> {
    let export: BwExport =
        serde_json::from_str(data).map_err(|e| ImportError::Parse(e.to_string()))?;
    if export.encrypted {
        return Err(ImportError::Encrypted);
    }
    let mut items = Vec::new();
    let mut skipped = 0;
    for it in export.items {
        if it.kind != 1 && it.kind != 2 {
            skipped += 1;
            continue;
        }
        let login = it.login.unwrap_or(BwLogin {
            username: None,
            password: None,
            totp: None,
            uris: None,
        });
        let totp = login
            .totp
            .as_deref()
            .filter(|t| !t.trim().is_empty())
            .and_then(|t| TotpConfig::parse(t).ok());
        items.push(ItemData {
            title: it.name.unwrap_or_default(),
            username: login.username.unwrap_or_default(),
            password: login.password.unwrap_or_default(),
            urls: login
                .uris
                .unwrap_or_default()
                .iter()
                .filter_map(|u| u.uri.as_deref().and_then(url_entry))
                .collect(),
            totp,
            notes: it.notes.unwrap_or_default(),
            created: now,
            modified: now,
        });
    }
    Ok((items, skipped))
}

/// Parse a browser password CSV (Chrome, Edge, Firefox, Safari). Columns are
/// found by header name, so column order does not matter.
pub fn browser_csv(data: &str, now: u64) -> Result<Vec<ItemData>, ImportError> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(data.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| ImportError::Parse(e.to_string()))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let url = col(&["url", "website", "login_uri"]);
    let user = col(&["username", "login", "login_username"]);
    let pass = col(&["password", "login_password"]);
    let (Some(url), Some(pass)) = (url, pass) else {
        return Err(ImportError::Parse("missing url or password column".into()));
    };
    let name = col(&["name", "title"]);
    let note = col(&["note", "notes", "comments"]);
    let otp = col(&["otpauth", "totp", "otp"]);

    let mut items = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| ImportError::Parse(e.to_string()))?;
        let get = |i: Option<usize>| i.and_then(|i| rec.get(i)).unwrap_or("").to_owned();
        let u = get(Some(url));
        let title = Some(get(name))
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| {
                vault_core::origin::Origin::parse(&u)
                    .map(|o| o.host)
                    .unwrap_or_else(|| u.clone())
            });
        items.push(ItemData {
            title,
            username: get(user),
            password: get(Some(pass)),
            urls: url_entry(&u).into_iter().collect(),
            totp: Some(get(otp))
                .filter(|t| !t.is_empty())
                .and_then(|t| TotpConfig::parse(&t).ok()),
            notes: get(note),
            created: now,
            modified: now,
        });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_logins_and_notes() {
        let json = r#"{"encrypted":false,"items":[
            {"type":1,"name":"Example","notes":null,"login":{"username":"me","password":"pw",
             "totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8","uris":[{"uri":"https://example.com/login"}]}},
            {"type":2,"name":"Wifi","notes":"pass: abc"},
            {"type":3,"name":"Card"}]}"#;
        let (items, skipped) = bitwarden_json(json, 7).unwrap();
        assert_eq!((items.len(), skipped), (2, 1));
        assert_eq!(items[0].username, "me");
        assert_eq!(items[0].urls[0].url, "https://example.com/login");
        assert_eq!(items[0].totp.as_ref().unwrap().digits, 8);
        assert_eq!(items[1].notes, "pass: abc");
        assert_eq!(
            bitwarden_json(r#"{"encrypted":true,"items":[]}"#, 0).err(),
            Some(ImportError::Encrypted)
        );
        assert!(bitwarden_json("nope", 0).is_err());
    }

    #[test]
    fn chrome_and_firefox_csv() {
        let chrome = "name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,hi\n";
        let items = browser_csv(chrome, 0).unwrap();
        assert_eq!(items[0].title, "GitHub");
        assert_eq!(items[0].password, "pw1");
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"http://router.local\",\"admin\",\"pw2\",,\"\",\"{x}\"\n";
        let items = browser_csv(firefox, 0).unwrap();
        assert_eq!(items[0].title, "router.local");
        assert!(items[0].urls[0].allow_http);
        assert!(browser_csv("a,b\n1,2\n", 0).is_err());
    }
}
