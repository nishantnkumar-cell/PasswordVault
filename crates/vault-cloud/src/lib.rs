//! Cloud sync through the user's own Cloudflare Worker (docs/cloud-sync.md).
//!
//! - [`Cloudflare`] uploads the sync server ([`WORKER_JS`], the file in
//!   `server/sync/src/index.js`) to the user's account with their API token.
//! - [`Server`] and [`Mailbox`] talk to that server: create a mailbox, join a
//!   device with a one-time link, read and save the encrypted vault file.
//! - The `vault-sync` binary mirrors the mailbox to the folder `vaultd`
//!   already keeps in sync, so `vaultd` itself never touches the network.
//!
//! The server only ever holds the encrypted vault file; everything here
//! moves ciphertext and access tokens, never a vault key.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use ureq::Agent;
use vault_core::{OsRandom, SecureRandom};
use vault_ipc::Secret;

/// The sync server, uploaded as it is by [`Cloudflare::deploy`].
pub const WORKER_JS: &str = include_str!("../../../server/sync/src/index.js");
/// The Workers compatibility date the server is written for.
pub const COMPATIBILITY_DATE: &str = "2026-11-01";
/// The Worker's name unless the user picks another.
pub const DEFAULT_WORKER: &str = "vault-sync";
/// Largest vault file the server accepts (`MAX_FILE` in the server).
pub const MAX_FILE: usize = 4 * 1024 * 1024;

/// `REVISION` in [`WORKER_JS`]: what this program would deploy.
pub fn worker_revision() -> u32 {
    WORKER_JS
        .lines()
        .find_map(|l| l.strip_prefix("const REVISION = ")?.strip_suffix(';'))
        .and_then(|n| n.trim().parse().ok())
        .expect("server/sync/src/index.js declares REVISION")
}

/// A failure, with a message safe to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn err(s: impl Into<String>) -> Error {
    Error(s.into())
}

fn agent() -> Agent {
    Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .http_status_as_error(false)
        .user_agent(concat!("secret-vault/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn net(e: ureq::Error) -> Error {
    err(format!("could not reach the server: {e}"))
}

/// A random 256-bit token, base64url without padding (43 characters).
pub fn random_token() -> Result<Secret> {
    let mut b = zeroize::Zeroizing::new([0u8; 32]);
    OsRandom.fill(&mut b[..]).map_err(|e| err(e.to_string()))?;
    Ok(Secret::new(data_encoding::BASE64URL_NOPAD.encode(&b[..])))
}

/// A random mailbox id: 32 lowercase hex characters.
pub fn random_mailbox() -> Result<String> {
    let mut b = [0u8; 16];
    OsRandom.fill(&mut b).map_err(|e| err(e.to_string()))?;
    Ok(data_encoding::HEXLOWER.encode(&b))
}

/// A server address this program talks to: `https://`, or plain `http://` to
/// this computer only (`wrangler dev`, tests).
pub fn is_server_address(s: &str) -> bool {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://127.0.0.1:"))
        .or_else(|| s.strip_prefix("http://localhost:"));
    rest.is_some_and(|r| !r.is_empty() && !r.contains(char::is_whitespace) && !r.contains('#'))
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_token(s: &str) -> bool {
    (43..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// SHA-256 of a file, to notice when it changed.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ---- Join links ----

/// What a join link carries: where the server is, which mailbox, and a
/// one-time ticket. No key or password.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinLink {
    pub server: String,
    pub mailbox: String,
    pub ticket: Secret,
}

impl JoinLink {
    /// `https://<server>/join#v1.<mailbox>.<ticket>`. Browsers never send
    /// the part after `#`, so the ticket stays out of server logs even if
    /// someone opens the link in a browser (which shows how to use it).
    pub fn to_link(&self) -> Secret {
        Secret::new(format!(
            "{}/join#v1.{}.{}",
            self.server.trim_end_matches('/'),
            self.mailbox,
            *self.ticket
        ))
    }

    /// Reads [`Self::to_link`]'s format.
    pub fn parse(link: &str) -> Result<JoinLink> {
        let bad = || {
            err(
                "that is not a Secret Vault join link (it starts with https:// and has /join# in it)",
            )
        };
        let (base, frag) = link.trim().split_once("/join#").ok_or_else(bad)?;
        let mut parts = frag.split('.');
        let (Some("v1"), Some(mailbox), Some(ticket), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        if !is_server_address(base) {
            return Err(bad());
        }
        if !is_hex(mailbox, 32) || !is_token(ticket) {
            return Err(bad());
        }
        Ok(JoinLink {
            server: base.to_owned(),
            mailbox: mailbox.to_owned(),
            ticket: Secret::new(ticket.to_owned()),
        })
    }
}

// ---- The sync server ----

/// The sync server at `base` (such as `https://vault-sync.example-name.workers.dev`).
pub struct Server {
    agent: Agent,
    base: String,
}

/// What `GET /` says.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub service: String,
    pub api: u32,
    pub revision: u32,
}

#[derive(Deserialize)]
struct DeviceId {
    device: String,
}

fn read_text(resp: &mut ureq::http::Response<ureq::Body>) -> String {
    resp.body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn read_json<T: for<'a> Deserialize<'a>>(resp: &mut ureq::http::Response<ureq::Body>) -> Result<T> {
    let text = read_text(resp);
    serde_json::from_str(&text)
        .map_err(|_| err("the server sent an answer this program does not understand"))
}

/// Turns an unexpected answer into an error with the server's message.
fn refused(what: &str, resp: &mut ureq::http::Response<ureq::Body>) -> Error {
    let status = resp.status().as_u16();
    let msg = read_text(resp);
    let hint = match status {
        401 => " (this device may have been removed; join again with a new link)",
        _ => "",
    };
    err(format!("{what}: the server said {status} {msg}{hint}"))
}

impl Server {
    pub fn new(base: &str) -> Result<Server> {
        let base = base.trim().trim_end_matches('/');
        if !is_server_address(base) {
            return Err(err("the server address must start with https://"));
        }
        Ok(Server {
            agent: agent(),
            base: base.to_owned(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// The server's name and revision; checks it is a Secret Vault sync server.
    pub fn info(&self) -> Result<ServerInfo> {
        let mut r = self
            .agent
            .get(&format!("{}/", self.base))
            .call()
            .map_err(net)?;
        if r.status() != 200 {
            return Err(refused("checking the server", &mut r));
        }
        let info: ServerInfo = read_json(&mut r)?;
        if info.service != "secret-vault-sync" {
            return Err(err("that address is not a Secret Vault sync server"));
        }
        Ok(info)
    }

    /// Creates an empty mailbox; `token` becomes this device's. Returns the
    /// device id the server gave it.
    pub fn create(
        &self,
        mailbox: &str,
        admin_key: &str,
        token: &str,
        name: &str,
    ) -> Result<String> {
        let mut r = self
            .agent
            .post(&format!("{}/v1/m/{mailbox}", self.base))
            .header("authorization", &format!("Bearer {token}"))
            .header("x-admin-key", admin_key)
            .header("x-device-name", &header_name(name))
            .send_empty()
            .map_err(net)?;
        if r.status() != 201 {
            return Err(refused("creating the mailbox", &mut r));
        }
        Ok(read_json::<DeviceId>(&mut r)?.device)
    }

    /// Joins a device with a link's one-time ticket; `token` becomes the
    /// new device's. Returns its device id.
    pub fn join(&self, link: &JoinLink, token: &str, name: &str) -> Result<String> {
        let mut r = self
            .agent
            .post(&format!("{}/v1/m/{}/join", self.base, link.mailbox))
            .header("authorization", &format!("Bearer {token}"))
            .header("x-ticket", &*link.ticket)
            .header("x-device-name", &header_name(name))
            .send_empty()
            .map_err(net)?;
        if r.status() != 201 {
            return Err(refused("joining", &mut r));
        }
        Ok(read_json::<DeviceId>(&mut r)?.device)
    }
}

/// Device names go in a header: printable ASCII only, at most 64 characters.
fn header_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    if s.trim().is_empty() {
        "device".into()
    } else {
        s
    }
}

/// What a read of the mailbox found.
pub enum Fetched {
    /// Still the version asked about.
    Unchanged,
    /// Nothing saved yet; the version to save on top of (0).
    Empty(u64),
    /// The file and its version.
    File(u64, Vec<u8>),
}

/// What a save did.
#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    /// Saved; the new version.
    Saved(u64),
    /// Another device saved first; the version it made. Read, merge, retry.
    Conflict(u64),
}

/// One device in a mailbox.
#[derive(Deserialize, Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub created: u64,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    /// The device asking.
    pub current: bool,
}

/// A ticket for [`JoinLink`], with when it expires (Unix seconds).
pub struct Ticket {
    pub ticket: Secret,
    pub expires: u64,
}

#[derive(Deserialize)]
struct TicketJson {
    ticket: String,
    expires: u64,
}

/// One mailbox, as one device.
pub struct Mailbox {
    agent: Agent,
    url: String,
    token: Secret,
}

fn version_of(resp: &ureq::http::Response<ureq::Body>) -> Result<u64> {
    resp.headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.trim_start_matches("W/").trim_matches('"').parse().ok())
        .ok_or_else(|| err("the server's answer has no version"))
}

impl Mailbox {
    pub fn new(server: &str, mailbox: &str, token: &str) -> Result<Mailbox> {
        let s = Server::new(server)?;
        if !is_hex(mailbox, 32) || !is_token(token) {
            return Err(err("malformed mailbox id or device token"));
        }
        Ok(Mailbox {
            agent: s.agent,
            url: format!("{}/v1/m/{mailbox}", s.base),
            token: Secret::new(token.to_owned()),
        })
    }

    pub fn from_device(d: &vault_ipc::CloudDevice) -> Result<Mailbox> {
        Mailbox::new(&d.server, &d.mailbox, &d.token)
    }

    fn auth(&self) -> String {
        format!("Bearer {}", *self.token)
    }

    /// Reads the file, or only checks whether it is still at `known`.
    pub fn get(&self, known: Option<u64>) -> Result<Fetched> {
        let mut req = self
            .agent
            .get(&self.url)
            .header("authorization", &self.auth());
        if let Some(v) = known {
            req = req.header("if-none-match", &format!("\"{v}\""));
        }
        let mut r = req.call().map_err(net)?;
        match r.status().as_u16() {
            304 => Ok(Fetched::Unchanged),
            204 => Ok(Fetched::Empty(version_of(&r)?)),
            200 => {
                let v = version_of(&r)?;
                let mut body = Vec::new();
                r.body_mut()
                    .with_config()
                    .limit(MAX_FILE as u64 + 1)
                    .reader()
                    .read_to_end(&mut body)
                    .map_err(|e| err(format!("reading the vault from the server: {e}")))?;
                Ok(Fetched::File(v, body))
            }
            _ => Err(refused("reading the vault", &mut r)),
        }
    }

    /// Saves `file` on top of version `base`.
    pub fn put(&self, base: u64, file: &[u8]) -> Result<Saved> {
        let mut r = self
            .agent
            .put(&self.url)
            .header("authorization", &self.auth())
            .header("if-match", &format!("\"{base}\""))
            .content_type("application/octet-stream")
            .send(file)
            .map_err(net)?;
        match r.status().as_u16() {
            200 => Ok(Saved::Saved(version_of(&r)?)),
            412 => Ok(Saved::Conflict(version_of(&r)?)),
            _ => Err(refused("saving the vault", &mut r)),
        }
    }

    /// A one-time ticket for a join link, valid ten minutes.
    pub fn ticket(&self) -> Result<Ticket> {
        let mut r = self
            .agent
            .post(&format!("{}/tickets", self.url))
            .header("authorization", &self.auth())
            .send_empty()
            .map_err(net)?;
        if r.status() != 201 {
            return Err(refused("making a join link", &mut r));
        }
        let t: TicketJson = read_json(&mut r)?;
        Ok(Ticket {
            ticket: Secret::new(t.ticket),
            expires: t.expires,
        })
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut r = self
            .agent
            .get(&format!("{}/devices", self.url))
            .header("authorization", &self.auth())
            .call()
            .map_err(net)?;
        if r.status() != 200 {
            return Err(refused("listing devices", &mut r));
        }
        read_json(&mut r)
    }

    pub fn remove_device(&self, id: &str) -> Result<()> {
        if !is_hex(id, 16) {
            return Err(err(
                "a device id is 16 hex characters; see `vault cloud devices`",
            ));
        }
        let mut r = self
            .agent
            .delete(&format!("{}/devices/{id}", self.url))
            .header("authorization", &self.auth())
            .call()
            .map_err(net)?;
        if r.status() != 204 {
            return Err(refused("removing the device", &mut r));
        }
        Ok(())
    }

    /// Deletes the mailbox, its file and every device's access.
    pub fn delete(&self) -> Result<()> {
        let mut r = self
            .agent
            .delete(&self.url)
            .header("authorization", &self.auth())
            .call()
            .map_err(net)?;
        if r.status() != 204 {
            return Err(refused("deleting the mailbox", &mut r));
        }
        Ok(())
    }

    /// The WebSocket request that watches for changes.
    pub fn watch_request(&self) -> Result<tungstenite::handshake::client::Request> {
        use tungstenite::client::IntoClientRequest;
        let url = format!("{}/watch", self.url);
        let url = match url.strip_prefix("https://") {
            Some(rest) => format!("wss://{rest}"),
            None => url.replacen("http://", "ws://", 1),
        };
        let mut req = url.into_client_request().map_err(|e| err(e.to_string()))?;
        req.headers_mut().insert(
            "authorization",
            self.auth().parse().map_err(|_| err("bad token"))?,
        );
        Ok(req)
    }
}

// ---- Cloudflare ----

const API: &str = "https://api.cloudflare.com/client/v4";

/// The user's Cloudflare account, through an API token that needs only
/// "Account > Workers Scripts > Edit".
pub struct Cloudflare {
    agent: Agent,
    account: String,
    token: Secret,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Subdomain {
    subdomain: Option<String>,
}

#[derive(Deserialize)]
struct Script {
    id: String,
    #[serde(default)]
    migration_tag: Option<String>,
}

impl Cloudflare {
    pub fn new(account: &str, token: &str) -> Result<Cloudflare> {
        let account = account.trim();
        if !is_hex(account, 32) {
            return Err(err(
                "the account ID is 32 hex characters, shown on the Workers & Pages page of the Cloudflare dashboard",
            ));
        }
        let token = token.trim();
        if token.is_empty() || token.contains(char::is_whitespace) {
            return Err(err("paste the API token as Cloudflare shows it"));
        }
        Ok(Cloudflare {
            agent: agent(),
            account: account.to_owned(),
            token: Secret::new(token.to_owned()),
        })
    }

    fn auth(&self) -> String {
        format!("Bearer {}", *self.token)
    }

    fn result<T: for<'a> Deserialize<'a>>(
        what: &str,
        mut r: ureq::http::Response<ureq::Body>,
    ) -> Result<Option<T>> {
        let status = r.status().as_u16();
        let text = r
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024)
            .read_to_string()
            .unwrap_or_default();
        let env: Envelope<T> = serde_json::from_str(&text).map_err(|_| {
            err(format!(
                "{what}: Cloudflare answered {status} with something unexpected"
            ))
        })?;
        if env.success {
            return Ok(env.result);
        }
        let msgs: Vec<String> = env
            .errors
            .iter()
            .map(|e| format!("{} (code {})", e.message, e.code))
            .collect();
        let hint = if matches!(status, 401 | 403) {
            ". Check the account ID and that the token has \"Workers Scripts: Edit\" for this account"
        } else {
            ""
        };
        Err(err(format!(
            "{what}: Cloudflare said {}{hint}",
            msgs.join("; ")
        )))
    }

    /// The account's `workers.dev` subdomain (`example-name` in
    /// `example-name.workers.dev`).
    pub fn subdomain(&self) -> Result<String> {
        let r = self
            .agent
            .get(&format!(
                "{API}/accounts/{}/workers/subdomain",
                self.account
            ))
            .header("authorization", &self.auth())
            .call()
            .map_err(net)?;
        Self::result::<Subdomain>("reading your workers.dev subdomain", r)?
            .and_then(|s| s.subdomain)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                err("your account has no workers.dev subdomain yet: open Workers & Pages in the Cloudflare dashboard once and pick one")
            })
    }

    /// The Durable Object migration tag of an existing Worker named
    /// `worker`: `None` when there is no such Worker.
    fn existing(&self, worker: &str) -> Result<Option<Option<String>>> {
        let r = self
            .agent
            .get(&format!("{API}/accounts/{}/workers/scripts", self.account))
            .header("authorization", &self.auth())
            .call()
            .map_err(net)?;
        let list = Self::result::<Vec<Script>>("listing your Workers", r)?.unwrap_or_default();
        Ok(list
            .into_iter()
            .find(|s| s.id == worker)
            .map(|s| s.migration_tag))
    }

    /// Uploads [`WORKER_JS`] as `worker` with `admin_key` as its secret, and
    /// serves it on `workers.dev`. Running it again updates the code in
    /// place; the mailboxes stay.
    pub fn deploy(&self, worker: &str, admin_key: &str) -> Result<()> {
        if worker.is_empty()
            || worker.len() > 63
            || !worker
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(err("a Worker name uses only a-z, 0-9 and -"));
        }
        let mut meta = serde_json::json!({
            "main_module": "index.js",
            "compatibility_date": COMPATIBILITY_DATE,
            "bindings": [
                { "type": "durable_object_namespace", "name": "MAILBOX", "class_name": "Mailbox" },
                { "type": "secret_text", "name": "ADMIN_KEY", "text": admin_key },
            ],
        });
        match self.existing(worker)? {
            Some(Some(tag)) if tag == "v1" => {}
            Some(Some(tag)) => {
                return Err(err(format!(
                    "a Worker named {worker} already exists and is something else (migration {tag}); choose another name"
                )));
            }
            Some(None) => {
                return Err(err(format!(
                    "a Worker named {worker} already exists and is not a Secret Vault server; choose another name"
                )));
            }
            None => {
                meta["migrations"] =
                    serde_json::json!({ "new_tag": "v1", "new_sqlite_classes": ["Mailbox"] });
            }
        }
        let boundary = format!("secret-vault-{}", random_mailbox()?);
        let mut body = Vec::new();
        let part = |body: &mut Vec<u8>, name: &str, file: Option<&str>, ty: &str, data: &[u8]| {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let fname = file
                .map(|f| format!("; filename=\"{f}\""))
                .unwrap_or_default();
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"{fname}\r\nContent-Type: {ty}\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        };
        let meta = zeroize::Zeroizing::new(meta.to_string());
        part(
            &mut body,
            "metadata",
            None,
            "application/json",
            meta.as_bytes(),
        );
        part(
            &mut body,
            "index.js",
            Some("index.js"),
            "application/javascript+module",
            WORKER_JS.as_bytes(),
        );
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let body = zeroize::Zeroizing::new(body);
        let r = self
            .agent
            .put(&format!(
                "{API}/accounts/{}/workers/scripts/{worker}",
                self.account
            ))
            .header("authorization", &self.auth())
            .content_type(&format!("multipart/form-data; boundary={boundary}"))
            .send(&body[..])
            .map_err(net)?;
        Self::result::<serde_json::Value>("uploading the sync server", r)?;

        let r = self
            .agent
            .post(&format!(
                "{API}/accounts/{}/workers/scripts/{worker}/subdomain",
                self.account
            ))
            .header("authorization", &self.auth())
            .content_type("application/json")
            .send(r#"{"enabled":true,"previews_enabled":false}"#)
            .map_err(net)?;
        Self::result::<serde_json::Value>("turning on its workers.dev address", r)?;
        Ok(())
    }
}

/// The address a Worker gets on `workers.dev`.
pub fn worker_url(worker: &str, subdomain: &str) -> String {
    format!("https://{worker}.{subdomain}.workers.dev")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_round_trip_and_refuse_junk() {
        let l = JoinLink {
            server: "https://vault-sync.example-name.workers.dev".into(),
            mailbox: "0123456789abcdef0123456789abcdef".into(),
            ticket: Secret::new("T".repeat(43)),
        };
        let text = l.to_link();
        assert!(text.starts_with("https://vault-sync.example-name.workers.dev/join#v1."));
        assert!(JoinLink::parse(&text).unwrap() == l);
        assert!(JoinLink::parse(&format!("  {}\n", *text)).unwrap() == l);
        for bad in [
            "http://x.example.com/join#v1.0123456789abcdef0123456789abcdef.TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
            "https://x.example.com/join#v2.0123456789abcdef0123456789abcdef.TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
            "https://x.example.com/join#v1.XYZ.TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT",
            "https://x.example.com/join#v1.0123456789abcdef0123456789abcdef.short",
            "https://x.example.com/join#v1.0123456789abcdef0123456789abcdef.TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT.extra",
            "not a link",
        ] {
            assert!(JoinLink::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens_and_ids_have_the_server_shapes() {
        let t = random_token().unwrap();
        assert!(is_token(&t) && t.len() == 43);
        assert!(is_hex(&random_mailbox().unwrap(), 32));
        assert_ne!(*random_token().unwrap(), *t);
    }

    #[test]
    fn the_embedded_server_declares_its_revision() {
        assert!(worker_revision() >= 1);
        assert!(WORKER_JS.contains("export class Mailbox"));
    }

    #[test]
    fn device_names_are_safe_headers() {
        assert_eq!(header_name("Alex's laptop"), "Alex's laptop");
        assert_eq!(header_name("\u{1F600}\n"), "device");
        assert_eq!(header_name(&"a".repeat(100)).len(), 64);
    }
}
