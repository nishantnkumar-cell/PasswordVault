//! Native messaging host for the autofill extension. The browser starts it and
//! talks JSON over stdin/stdout (u32 native-endian length, then UTF-8 JSON);
//! it relays each message to `vaultd` with a token of `Autofill` scope, so the
//! daemon itself refuses anything beyond origin-bound lookups and fills.
//!
//! `vault-native-host --pair` pairs it (run once, in a terminal).
//! `vault-native-host --install CHROME_EXTENSION_ID [FIREFOX_EXTENSION_ID]`
//! writes the browsers' host manifests.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};
use vault_ipc::{
    ClientScope, ClientToken, Envelope, GenerateOptions, Request, Response, UnlockMethod, hex,
    parse_id, read_frame, write_frame,
};
use zeroize::Zeroizing;

const HOST_NAME: &str = "dev.passwordvault.host";
/// Chrome's limit on a message from the host.
const MAX_OUT: usize = 1 << 20;
/// Messages from the extension are small; refuse anything large.
const MAX_IN: usize = 64 << 10;

fn home(rel: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
}

fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("VAULT_SOCKET") {
        return p.into();
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("vault/vaultd.sock"),
        None => std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home(".local/state"))
            .join("vault/vaultd.sock"),
    }
}

fn token_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home(".config"))
        .join("vault/native-host-token")
}

/// Messages the extension sends. The origin always comes from the
/// extension's background script, which takes it from the browser.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum HostRequest {
    Status,
    Unlock { password: Zeroizing<String> },
    Lock,
    Find { origin: String },
    Fill { id: String, origin: String },
    Totp { id: String, origin: String },
    Generate { length: Option<u16> },
}

fn id(s: &str) -> Result<[u8; 16], String> {
    parse_id(s).ok_or_else(|| "bad item id".to_string())
}

/// Map one extension message to a daemon request and the reply back to JSON.
fn handle(req: HostRequest, call: &mut dyn FnMut(Request) -> Response) -> Value {
    let request = match req {
        HostRequest::Status => Request::Status,
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
        HostRequest::Generate { length } => Request::Generate {
            options: GenerateOptions {
                length: length.unwrap_or(24),
                symbols: true,
                avoid_ambiguous: false,
            },
        },
    };
    match call(request) {
        Response::Ok => json!({ "ok": true }),
        Response::Error(e) => json!({ "ok": false, "error": e }),
        Response::Status(s) => {
            json!({ "ok": true, "initialized": s.initialized, "unlocked": s.unlocked })
        }
        Response::Items(items) => json!({
            "ok": true,
            "items": items.iter().map(|i| json!({
                "id": hex(&i.id), "title": i.title, "username": i.username, "hasTotp": i.has_totp,
            })).collect::<Vec<_>>(),
        }),
        Response::Item { item, .. } => {
            json!({ "ok": true, "username": item.username, "password": item.password })
        }
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
    stream: Option<UnixStream>,
    token: Option<ClientToken>,
}

impl Daemon {
    fn call(&mut self, request: Request) -> Response {
        if self.stream.is_none() {
            match UnixStream::connect(socket_path()) {
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

fn pair() -> Result<(), String> {
    let password =
        Zeroizing::new(rpassword::prompt_password("Vault password: ").map_err(|e| e.to_string())?);
    let mut d = Daemon {
        stream: None,
        token: None,
    };
    let req = Request::Pair {
        client_name: "browser".into(),
        scope: ClientScope::Autofill,
        method: UnlockMethod::Password { password },
    };
    match d.call(req) {
        Response::Paired { token } => {
            let p = token_path();
            if let Some(dir) = p.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&p)
                .map_err(|e| e.to_string())?;
            f.write_all(&token[..]).map_err(|e| e.to_string())?;
            println!("Paired the browser host (autofill only).");
            Ok(())
        }
        Response::Error(e) => Err(e),
        _ => Err("unexpected response".into()),
    }
}

fn install(chrome_id: &str, firefox_id: Option<&str>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe.to_str().ok_or("executable path is not UTF-8")?;
    let desc = "Secret Vault autofill host";
    let chrome = json!({
        "name": HOST_NAME, "description": desc, "path": path, "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{chrome_id}/")],
    });
    let mut targets = vec![
        (
            home(".config/google-chrome/NativeMessagingHosts"),
            chrome.clone(),
        ),
        (
            home(".config/chromium/NativeMessagingHosts"),
            chrome.clone(),
        ),
        (home(".config/microsoft-edge/NativeMessagingHosts"), chrome),
    ];
    if let Some(fx) = firefox_id {
        let firefox = json!({
            "name": HOST_NAME, "description": desc, "path": path, "type": "stdio", "allowed_extensions": [fx],
        });
        targets.push((home(".mozilla/native-messaging-hosts"), firefox));
    }
    for (dir, manifest) in targets {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let file = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(
            &file,
            serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("{}: {e}", file.display()))?;
        println!("wrote {}", file.display());
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--pair") => pair(),
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
            Ok(_) if d.token.is_none() => {
                json!({ "ok": false, "error": "not paired; run `vault-native-host --pair` in a terminal" })
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
    fn bad_ids_never_reach_the_daemon() {
        let req: HostRequest =
            serde_json::from_value(json!({ "type": "fill", "id": "nope", "origin": "https://a" }))
                .unwrap();
        let out = handle(req, &mut |_| panic!("must not call vaultd"));
        assert_eq!(out["ok"], false);
    }
}
