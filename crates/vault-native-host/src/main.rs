//! Native messaging host for the autofill extension. The browser starts it and
//! talks JSON over stdin/stdout (u32 native-endian length, then UTF-8 JSON);
//! it relays each message to `vaultd` with a token of `Autofill` scope, so the
//! daemon itself refuses anything beyond origin-bound lookups and fills.
//!
//! It pairs itself when the extension asks (`{"type":"pair"}`): vaultd shows
//! its own approval window. `vault-native-host --pair [--password]` does the
//! same from a terminal, or pairs by typing the vault password instead.
//! `vault-native-host --install CHROME_EXTENSION_ID [FIREFOX_EXTENSION_ID]`
//! writes the browsers' host manifests.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};
use vault_ipc::{
    ClientScope, ClientToken, Envelope, GenerateOptions, PasswordStyle, Request, Response,
    UnlockMethod, hex, local, parse_id, read_frame, write_frame,
};
use zeroize::Zeroizing;

const HOST_NAME: &str = "dev.passwordvault.host";
/// Chrome's limit on a message from the host.
const MAX_OUT: usize = 1 << 20;
/// Messages from the extension are small; refuse anything large.
const MAX_IN: usize = 64 << 10;

#[cfg(unix)]
fn home(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

fn token_path() -> PathBuf {
    local::config_dir().join("native-host-token")
}

/// Messages the extension sends. The origin always comes from the
/// extension's background script, which takes it from the browser.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum HostRequest {
    Status,
    Pair,
    Unlock {
        password: Zeroizing<String>,
    },
    Lock,
    Find {
        origin: String,
    },
    Fill {
        id: String,
        origin: String,
    },
    Totp {
        id: String,
        origin: String,
    },
    Forms {
        origin: String,
    },
    #[serde(rename = "fillIdentity")]
    FillIdentity {
        id: String,
        origin: String,
    },
    #[serde(rename = "fillCard")]
    FillCard {
        id: String,
        origin: String,
    },
    Generate {
        length: Option<u16>,
        /// "random" (the default), "words" or "apple".
        style: Option<String>,
    },
}

fn id(s: &str) -> Result<[u8; 16], String> {
    parse_id(s).ok_or_else(|| "bad item id".to_string())
}

/// Map one extension message to a daemon request and the reply back to JSON.
fn handle(req: HostRequest, call: &mut dyn FnMut(Request) -> Response) -> Value {
    let request = match req {
        HostRequest::Status => Request::Status,
        HostRequest::Pair => return json!({ "ok": false, "error": "already paired" }),
        HostRequest::Unlock { password } => Request::Unlock {
            method: UnlockMethod::Password { password },
        },
        HostRequest::Lock => Request::Lock,
        HostRequest::Find { origin } => Request::FindForOrigin { origin },
        HostRequest::Fill { id: i, origin } => match id(&i) {
            Ok(id) => Request::GetForFill { id, origin },
            Err(e) => return json!({ "ok": false, "error": e }),
        },
        HostRequest::Totp { id: i, origin } => match id(&i) {
            Ok(id) => Request::TotpForFill { id, origin },
            Err(e) => return json!({ "ok": false, "error": e }),
        },
        HostRequest::Forms { origin } => Request::FormItems { origin },
        HostRequest::FillIdentity { id: i, origin } => match id(&i) {
            Ok(id) => Request::IdentityForFill { id, origin },
            Err(e) => return json!({ "ok": false, "error": e }),
        },
        HostRequest::FillCard { id: i, origin } => match id(&i) {
            Ok(id) => Request::CardForFill { id, origin },
            Err(e) => return json!({ "ok": false, "error": e }),
        },
        HostRequest::Generate { length, style } => Request::GenerateStyled {
            style: match style.as_deref() {
                None | Some("random") => PasswordStyle::Random(GenerateOptions {
                    length: length.unwrap_or(24),
                    ..GenerateOptions::default()
                }),
                Some("words") => PasswordStyle::three_random_words(),
                Some("apple") => PasswordStyle::Apple,
                Some(_) => return json!({ "ok": false, "error": "unknown password style" }),
            },
        },
    };
    match call(request) {
        Response::Ok => json!({ "ok": true }),
        Response::Error(e) => json!({ "ok": false, "error": e }),
        Response::Status(s) => {
            json!({ "ok": true, "paired": true, "initialized": s.initialized, "unlocked": s.unlocked })
        }
        Response::Items(items) => json!({
            "ok": true,
            "items": items.iter().map(|i| json!({
                "id": hex(&i.id), "kind": i.kind.name(), "title": i.title,
                "subtitle": i.subtitle, "hasTotp": i.has_totp,
            })).collect::<Vec<_>>(),
        }),
        Response::Item { item, .. } => match (&item.card, &item.identity) {
            (Some(c), _) => json!({ "ok": true, "card": {
                "holder": c.holder, "number": c.number, "expMonth": c.exp_month,
                "expYear": c.exp_year, "cvv": c.cvv,
                "brand": c.brand().map(|b| b.name()),
            }}),
            (_, Some(i)) => json!({ "ok": true, "identity": {
                "honorific": i.honorific, "givenName": i.given_name, "middleName": i.middle_name,
                "familyName": i.family_name, "fullName": i.full_name(), "company": i.company,
                "email": i.email, "phone": i.phone, "address1": i.address1,
                "address2": i.address2, "address3": i.address3, "city": i.city,
                "region": i.region, "postcode": i.postcode, "country": i.country,
            }}),
            _ => json!({ "ok": true, "username": item.username, "password": item.password }),
        },
        Response::Totp { code, remaining } => {
            json!({ "ok": true, "code": code.as_str(), "remaining": remaining })
        }
        Response::Generated(p) => json!({ "ok": true, "password": p.as_str() }),
        _ => json!({ "ok": false, "error": "unexpected response from vaultd" }),
    }
}

fn read_message(r: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_IN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_message(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(v)?);
    if bytes.len() > MAX_OUT {
        return write_message(w, &json!({ "ok": false, "error": "response too large" }));
    }
    w.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    w.write_all(&bytes)?;
    w.flush()
}

struct Daemon {
    stream: Option<local::Stream>,
    token: Option<ClientToken>,
}

impl Daemon {
    fn call(&mut self, request: Request) -> Response {
        if self.stream.is_none() {
            match local::endpoint().and_then(|p| local::connect(&p)) {
                Ok(s) => self.stream = Some(s),
                Err(_) => return Response::Error("vaultd is not running".into()),
            }
        }
        let s = self.stream.as_mut().expect("connected above");
        let env = Envelope {
            token: self.token.clone(),
            request,
        };
        match write_frame(s, &env).and_then(|()| read_frame(s)) {
            Ok(r) => r,
            Err(e) => {
                self.stream = None;
                Response::Error(format!("lost connection to vaultd: {e}"))
            }
        }
    }
}

fn load_token() -> Option<ClientToken> {
    let b = Zeroizing::new(std::fs::read(token_path()).ok()?);
    Some(Zeroizing::new(b.as_slice().try_into().ok()?))
}

/// Ask vaultd for an autofill token, by its approval window or (with a
/// password) by proving the password, and save it.
fn pair_with(d: &mut Daemon, password: Option<Zeroizing<String>>) -> Result<(), String> {
    let req = Request::Pair {
        client_name: "browser".into(),
        scope: ClientScope::Autofill,
        method: password.map(|password| UnlockMethod::Password { password }),
    };
    match d.call(req) {
        Response::Paired { token } => {
            let p = token_path();
            local::write_private(&p, &token[..]).map_err(|e| format!("{}: {e}", p.display()))?;
            d.token = Some(token);
            Ok(())
        }
        Response::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

fn pair(with_password: bool) -> Result<(), String> {
    let mut d = Daemon {
        stream: None,
        token: None,
    };
    match d.call(Request::Status) {
        Response::Status(s) if !s.initialized => {
            return Err("no vault exists yet; run `vault init` first".into());
        }
        Response::Error(e) => return Err(e),
        _ => {}
    }
    let password = if with_password {
        Some(Zeroizing::new(
            rpassword::prompt_password("Vault password: ").map_err(|e| e.to_string())?,
        ))
    } else {
        eprintln!("Approve the request in the window vaultd opens...");
        None
    };
    pair_with(&mut d, password)?;
    println!("Paired the browser host (autofill only).");
    Ok(())
}

fn install(chrome_id: &str, firefox_id: Option<&str>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe.to_str().ok_or("executable path is not UTF-8")?;
    let desc = "Secret Vault autofill host";
    let chrome = json!({
        "name": HOST_NAME, "description": desc, "path": path, "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{chrome_id}/")],
    });
    let firefox = firefox_id.map(|fx| {
        json!({
            "name": HOST_NAME, "description": desc, "path": path, "type": "stdio", "allowed_extensions": [fx],
        })
    });
    let write = |file: &std::path::Path, manifest: &Value| -> Result<(), String> {
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
        std::fs::write(file, bytes).map_err(|e| format!("{}: {e}", file.display()))?;
        println!("wrote {}", file.display());
        Ok(())
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let (chrome_dirs, firefox_dir) = (
        [
            ".config/google-chrome/NativeMessagingHosts",
            ".config/chromium/NativeMessagingHosts",
            ".config/microsoft-edge/NativeMessagingHosts",
        ],
        ".mozilla/native-messaging-hosts",
    );
    #[cfg(target_os = "macos")]
    let (chrome_dirs, firefox_dir) = (
        [
            "Library/Application Support/Google/Chrome/NativeMessagingHosts",
            "Library/Application Support/Chromium/NativeMessagingHosts",
            "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
        ],
        "Library/Application Support/Mozilla/NativeMessagingHosts",
    );
    #[cfg(unix)]
    {
        let mut targets: Vec<_> = chrome_dirs
            .iter()
            .map(|d| (home(d), chrome.clone()))
            .collect();
        if let Some(fx) = firefox {
            targets.push((home(firefox_dir), fx));
        }
        for (dir, manifest) in targets {
            write(&dir.join(format!("{HOST_NAME}.json")), &manifest)?;
        }
    }
    // Windows finds manifests through the registry, per browser.
    #[cfg(windows)]
    {
        let dir = local::config_dir();
        let chrome_file = dir.join(format!("{HOST_NAME}.json"));
        write(&chrome_file, &chrome)?;
        let mut keys = vec![
            (
                r"Software\Google\Chrome\NativeMessagingHosts",
                chrome_file.clone(),
            ),
            (r"Software\Microsoft\Edge\NativeMessagingHosts", chrome_file),
        ];
        if let Some(fx) = firefox {
            let fx_file = dir.join(format!("{HOST_NAME}.firefox.json"));
            write(&fx_file, &fx)?;
            keys.push((r"Software\Mozilla\NativeMessagingHosts", fx_file));
        }
        for (key, file) in keys {
            let key = format!(r"HKCU\{key}\{HOST_NAME}");
            let ok = std::process::Command::new("reg")
                .args(["add", &key, "/ve", "/t", "REG_SZ", "/f", "/d"])
                .arg(&file)
                .stdout(std::process::Stdio::null())
                .status()
                .map_err(|e| format!("reg: {e}"))?
                .success();
            if !ok {
                return Err(format!("could not set {key}"));
            }
            println!("registered {key}");
        }
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--version") => {
            println!("vault-native-host {}", vault_ipc::VERSION);
            Ok(())
        }
        Some("--pair") => pair(args.iter().any(|a| a == "--password")),
        Some("--install") => match args.get(1) {
            Some(id) => install(id, args.get(2).map(String::as_str)),
            None => Err(
                "usage: vault-native-host --install CHROME_EXTENSION_ID [FIREFOX_EXTENSION_ID]"
                    .into(),
            ),
        },
        // Started by the browser: argv holds the caller's origin or manifest path.
        _ => serve(),
    };
    if let Err(e) = result {
        eprintln!("vault-native-host: {e}");
        std::process::exit(1);
    }
}

fn serve() -> Result<(), String> {
    let mut d = Daemon {
        stream: None,
        token: load_token(),
    };
    let (mut input, mut output) = (io::stdin().lock(), io::stdout().lock());
    while let Some(msg) = read_message(&mut input).map_err(|e| e.to_string())? {
        let reply = match serde_json::from_slice::<HostRequest>(&msg) {
            Ok(HostRequest::Pair) if d.token.is_none() => match pair_with(&mut d, None) {
                Ok(()) => json!({ "ok": true }),
                Err(e) => json!({ "ok": false, "error": e }),
            },
            // Status works unpaired, so the popup can offer to pair.
            Ok(HostRequest::Status) if d.token.is_none() => {
                let mut v = handle(HostRequest::Status, &mut |r| d.call(r));
                v["paired"] = json!(false);
                v
            }
            Ok(_) if d.token.is_none() => {
                json!({ "ok": false, "error": "not paired yet: press Connect in the extension" })
            }
            Ok(req) => handle(req, &mut |r| d.call(r)),
            Err(e) => json!({ "ok": false, "error": format!("bad message: {e}") }),
        };
        write_message(&mut output, &reply).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::item::ItemData;

    #[test]
    fn messages_round_trip_and_large_input_is_refused() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({ "type": "status" })).unwrap();
        let msg = read_message(&mut buf.as_slice()).unwrap().unwrap();
        assert!(matches!(
            serde_json::from_slice::<HostRequest>(&msg).unwrap(),
            HostRequest::Status
        ));
        assert!(read_message(&mut [].as_slice()).unwrap().is_none());
        let big = ((MAX_IN + 1) as u32).to_ne_bytes();
        assert!(read_message(&mut big.as_slice()).is_err());
    }

    #[test]
    fn fill_passes_the_origin_to_the_daemon() {
        let req: HostRequest = serde_json::from_value(json!({
            "type": "fill", "id": "00112233445566778899aabbccddeeff", "origin": "https://example.com",
        }))
        .unwrap();
        let mut seen = None;
        let out = handle(req, &mut |r| {
            if let Request::GetForFill { id, origin } = r {
                seen = Some((id, origin));
            }
            let mut item = ItemData::default();
            item.username = "u".into();
            item.password = "p".into();
            Response::Item { id: [0; 16], item }
        });
        let (id, origin) = seen.expect("GetForFill was sent");
        assert_eq!(hex(&id), "00112233445566778899aabbccddeeff");
        assert_eq!(origin, "https://example.com");
        assert_eq!(out["username"], "u");
    }

    #[test]
    fn cards_and_identities_go_out_as_their_own_fields() {
        use vault_core::item::{Card, Identity, ItemKind};
        let req: HostRequest = serde_json::from_value(json!({
            "type": "fillCard", "id": "00112233445566778899aabbccddeeff", "origin": "https://shop.example",
        }))
        .unwrap();
        let out = handle(req, &mut |r| {
            assert!(matches!(r, Request::CardForFill { .. }));
            let mut item = ItemData::new(ItemKind::Card, "Travel");
            item.card = Some(Card {
                number: "4111111111111111".into(),
                exp_month: 7,
                exp_year: 2031,
                ..Card::default()
            });
            Response::Item { id: [0; 16], item }
        });
        assert_eq!(out["card"]["number"], "4111111111111111");
        assert_eq!(out["card"]["expMonth"], 7);
        assert_eq!(out["card"]["brand"], "Visa");
        assert!(out.get("password").is_none());

        let req: HostRequest = serde_json::from_value(json!({
            "type": "fillIdentity", "id": "00112233445566778899aabbccddeeff", "origin": "https://shop.example",
        }))
        .unwrap();
        let out = handle(req, &mut |r| {
            assert!(matches!(r, Request::IdentityForFill { .. }));
            let mut item = ItemData::new(ItemKind::Identity, "Home");
            item.identity = Some(Identity {
                given_name: "Alex".into(),
                family_name: "Example".into(),
                ..Identity::default()
            });
            Response::Item { id: [0; 16], item }
        });
        assert_eq!(out["identity"]["fullName"], "Alex Example");

        let req: HostRequest =
            serde_json::from_value(json!({ "type": "forms", "origin": "https://shop.example" }))
                .unwrap();
        handle(req, &mut |r| {
            assert!(matches!(r, Request::FormItems { .. }));
            Response::Items(vec![])
        });
    }

    #[test]
    fn bad_ids_never_reach_the_daemon() {
        let req: HostRequest =
            serde_json::from_value(json!({ "type": "fill", "id": "nope", "origin": "https://a" }))
                .unwrap();
        let out = handle(req, &mut |_| panic!("must not call vaultd"));
        assert_eq!(out["ok"], false);
    }
}
