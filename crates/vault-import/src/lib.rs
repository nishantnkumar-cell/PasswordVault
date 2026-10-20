//! Import from Bitwarden's unencrypted JSON export and browser CSV exports.
//!
//! Export files hold every secret in plain text; callers should delete them
//! after import.

#![forbid(unsafe_code)]

use serde::Deserialize;
use vault_core::item::{Card, CustomField, FieldKind, Identity, ItemData, ItemKind, UrlEntry};
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
    #[serde(default)]
    card: Option<BwCard>,
    #[serde(default)]
    identity: Option<BwIdentity>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwCard {
    cardholder_name: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct BwIdentity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    username: Option<String>,
    ssn: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    /// 0 text, 1 hidden, 2 boolean, 3 linked (no value of its own).
    #[serde(rename = "type", default)]
    kind: u8,
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

/// Parse a Bitwarden unencrypted JSON export: logins (type 1), secure notes
/// (2), cards (3) and identities (4), with their custom fields. Returns the
/// items and the number skipped (other types).
pub fn bitwarden_json(data: &str, now: u64) -> Result<(Vec<ItemData>, usize), ImportError> {
    let export: BwExport =
        serde_json::from_str(data).map_err(|e| ImportError::Parse(e.to_string()))?;
    if export.encrypted {
        return Err(ImportError::Encrypted);
    }
    let mut items = Vec::new();
    let mut skipped = 0;
    for it in export.items {
        let kind = match it.kind {
            1 => ItemKind::Login,
            2 => ItemKind::Note,
            3 => ItemKind::Card,
            4 => ItemKind::Identity,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let mut item = ItemData::new(kind, it.name.unwrap_or_default());
        item.notes = it.notes.unwrap_or_default();
        item.created = now;
        item.modified = now;
        item.fields = it
            .fields
            .unwrap_or_default()
            .into_iter()
            .filter(|f| f.kind != 3)
            .map(|f| CustomField {
                name: f.name.unwrap_or_default(),
                value: f.value.unwrap_or_default(),
                kind: if f.kind == 1 {
                    FieldKind::Hidden
                } else {
                    FieldKind::Text
                },
            })
            .collect();
        match kind {
            ItemKind::Login => {
                if let Some(login) = it.login {
                    item.username = login.username.unwrap_or_default();
                    item.password = login.password.unwrap_or_default();
                    item.urls = login
                        .uris
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|u| u.uri.as_deref().and_then(url_entry))
                        .collect();
                    item.totp = login
                        .totp
                        .as_deref()
                        .filter(|t| !t.trim().is_empty())
                        .and_then(|t| TotpConfig::parse(t).ok());
                }
            }
            ItemKind::Note => {}
            ItemKind::Card => {
                let c = it.card.unwrap_or_default();
                let month = c.exp_month.as_deref().and_then(|m| m.trim().parse().ok());
                let year = c.exp_year.as_deref().and_then(|y| {
                    let y: u16 = y.trim().parse().ok()?;
                    Some(if y < 100 { 2000 + y } else { y })
                });
                item.card = Some(Card {
                    holder: c.cardholder_name.unwrap_or_default(),
                    number: Card::clean_number(&c.number.unwrap_or_default()),
                    exp_month: month.filter(|m| (1..=12).contains(m)).unwrap_or(0),
                    exp_year: year.unwrap_or(0),
                    cvv: c.code.unwrap_or_default(),
                    pin: String::new(),
                });
            }
            ItemKind::Identity => {
                let i = it.identity.unwrap_or_default();
                let s = |v: Option<String>| v.unwrap_or_default();
                // Fields this vault has no slot for become hidden custom fields.
                for (name, value) in [
                    ("Username", i.username.clone()),
                    ("National ID / SSN", i.ssn.clone()),
                    ("Passport number", i.passport_number.clone()),
                    ("Licence number", i.license_number.clone()),
                ] {
                    if let Some(value) = value.filter(|v| !v.is_empty()) {
                        item.fields.push(CustomField {
                            name: name.into(),
                            value,
                            kind: FieldKind::Hidden,
                        });
                    }
                }
                item.identity = Some(Identity {
                    honorific: s(i.title),
                    given_name: s(i.first_name),
                    middle_name: s(i.middle_name),
                    family_name: s(i.last_name),
                    company: s(i.company),
                    email: s(i.email),
                    phone: s(i.phone),
                    address1: s(i.address1),
                    address2: s(i.address2),
                    address3: s(i.address3),
                    city: s(i.city),
                    region: s(i.state),
                    postcode: s(i.postal_code),
                    country: s(i.country),
                });
            }
        }
        item.normalize();
        items.push(item);
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
        let mut item = ItemData::new(ItemKind::Login, title);
        item.username = get(user);
        item.password = get(Some(pass));
        item.urls = url_entry(&u).into_iter().collect();
        item.totp = Some(get(otp))
            .filter(|t| !t.is_empty())
            .and_then(|t| TotpConfig::parse(&t).ok());
        item.notes = get(note);
        item.created = now;
        item.modified = now;
        items.push(item);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitwarden_every_kind() {
        let json = r#"{"encrypted":false,"items":[
            {"type":1,"name":"Example","notes":null,"login":{"username":"me","password":"pw",
             "totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8","uris":[{"uri":"https://example.com/login"}]},
             "fields":[{"name":"PIN","value":"1234","type":1},{"name":"Linked","value":null,"type":3}]},
            {"type":2,"name":"Wifi","notes":"pass: abc"},
            {"type":3,"name":"Travel","card":{"cardholderName":"A Person","brand":"Visa",
             "number":"4111 1111 1111 1111","expMonth":"7","expYear":"31","code":"123"}},
            {"type":4,"name":"Home","identity":{"firstName":"Ada","lastName":"Lovelace",
             "address1":"1 Main St","city":"London","postalCode":"N1","country":"GB","passportNumber":"P1"}},
            {"type":5,"name":"SSH key"}]}"#;
        let (items, skipped) = bitwarden_json(json, 7).unwrap();
        assert_eq!((items.len(), skipped), (4, 1));
        assert_eq!(items[0].username, "me");
        assert_eq!(items[0].urls[0].url, "https://example.com/login");
        assert_eq!(items[0].totp.as_ref().unwrap().digits, 8);
        assert_eq!(items[0].fields.len(), 1);
        assert_eq!(items[0].fields[0].kind, FieldKind::Hidden);
        assert_eq!(items[1].kind, ItemKind::Note);
        assert_eq!(items[1].notes, "pass: abc");
        let card = items[2].card.as_ref().unwrap();
        assert_eq!(items[2].kind, ItemKind::Card);
        assert_eq!(card.number, "4111111111111111");
        assert_eq!((card.exp_month, card.exp_year), (7, 2031));
        let id = items[3].identity.as_ref().unwrap();
        assert_eq!(id.full_name(), "Ada Lovelace");
        assert_eq!(id.postcode, "N1");
        assert_eq!(items[3].fields[0].name, "Passport number");
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
