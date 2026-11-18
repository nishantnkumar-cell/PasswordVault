//! What `vault cloud` and the desktop app's Cloud sync page do, in one place.
//!
//! Each step talks to the sync server (or Cloudflare) here and to `vaultd`
//! through `call`, which sends one request and returns its answer: the CLI
//! passes its connection, the desktop app its worker thread's.

use std::time::{Duration, Instant};

use vault_ipc::{CloudDevice, CloudInfo, CloudSettings, Request, Response, Secret, StatusInfo};

use crate::{
    Cloudflare, DEFAULT_WORKER, DeviceInfo, Fetched, JoinLink, Mailbox, OwnCa, Result, Server, err,
};

/// Sends one request to `vaultd`.
pub type Call<'a> = dyn FnMut(Request) -> Result<Response> + 'a;

fn ask(call: &mut Call<'_>, r: Request) -> Result<Response> {
    match call(r)? {
        Response::Error(m) => Err(err(m)),
        other => Ok(other),
    }
}

/// The vault's cloud settings and this device's access.
pub fn info(call: &mut Call<'_>) -> Result<CloudInfo> {
    match ask(call, Request::CloudGet)? {
        Response::Cloud(i) => Ok(i),
        _ => Err(err("unexpected answer from vaultd")),
    }
}

fn status(call: &mut Call<'_>) -> Result<StatusInfo> {
    match ask(call, Request::Status)? {
        Response::Status(s) => Ok(s),
        _ => Err(err("unexpected answer from vaultd")),
    }
}

fn need_unlocked(call: &mut Call<'_>) -> Result<()> {
    if status(call)?.unlocked {
        Ok(())
    } else {
        Err(err("the vault is locked; unlock it first"))
    }
}

/// This device's access, or why there is none.
pub fn device(i: &CloudInfo) -> Result<&CloudDevice> {
    i.device.as_ref().ok_or_else(|| {
        err("cloud sync is not set up on this device: set it up, or join with a link from another device")
    })
}

/// The vault's settings, or why there are none.
pub fn settings(i: &CloudInfo) -> Result<&CloudSettings> {
    i.settings.as_ref().ok_or_else(|| {
        err("the vault has no cloud sync settings (is it unlocked? was cloud sync set up?)")
    })
}

/// This computer's name, for the device list.
pub fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "computer".into())
}

/// Where the sync server runs.
pub enum Host {
    /// Upload the server to the user's Cloudflare account.
    Cloudflare {
        account: String,
        token: Secret,
        /// The Worker's name; [`DEFAULT_WORKER`] if empty.
        worker: String,
        /// Keep the API token in the vault for later updates.
        keep_token: bool,
    },
    /// A server the user runs: in Docker on their own computer, or deployed
    /// by hand with `wrangler`.
    Own {
        server: String,
        /// The server's own certificate authority's fingerprint, as the
        /// Docker server's `show` prints it; `None` for a public certificate.
        fingerprint: Option<String>,
        admin_key: Secret,
    },
}

/// Sets cloud sync up for this vault: the server (uploaded to Cloudflare, or
/// the user's own), a new mailbox, this device, and the settings in the
/// vault. `progress` hears each step. Returns the server's address.
pub fn setup(
    call: &mut Call<'_>,
    host: Host,
    name: &str,
    progress: &dyn Fn(&str),
) -> Result<String> {
    need_unlocked(call)?;
    if info(call)?.settings.is_some() {
        return Err(err(
            "cloud sync is already set up for this vault; join other devices with a link instead",
        ));
    }
    let (url, account, worker, admin_key, token, ca) = match host {
        Host::Own {
            server,
            fingerprint,
            admin_key,
        } => {
            let url = server.trim().trim_end_matches('/').to_owned();
            let ca = match fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|f| !f.is_empty())
            {
                Some(f) => {
                    progress("Checking the server's certificate...");
                    Some(OwnCa::fetch(&url, f)?)
                }
                None => None,
            };
            let key = admin_key.trim().to_owned();
            if key.is_empty() {
                return Err(err("enter the server's admin key"));
            }
            (
                url,
                String::new(),
                String::new(),
                Secret::new(key),
                None,
                ca,
            )
        }
        Host::Cloudflare {
            account,
            token,
            worker,
            keep_token,
        } => {
            let worker = if worker.trim().is_empty() {
                DEFAULT_WORKER.to_owned()
            } else {
                worker.trim().to_owned()
            };
            let cf = Cloudflare::new(&account, &token)?;
            progress("Checking your Cloudflare account...");
            let sub = cf.subdomain()?;
            let admin_key = crate::random_token()?;
            progress(&format!(
                "Uploading the sync server as the Worker \"{worker}\"..."
            ));
            cf.deploy(&worker, &admin_key)?;
            let url = crate::worker_url(&worker, &sub);
            let kept = keep_token.then(|| Secret::new(token.trim().to_owned()));
            (
                url,
                account.trim().to_owned(),
                worker,
                admin_key,
                kept,
                None,
            )
        }
    };
    let ca_pem = ca.as_ref().map(|c| c.pem().to_owned());
    let server = Server::with_ca(&url, ca_pem.as_deref())?;
    // A Worker just uploaded can take a minute to answer on its new address;
    // a server the user runs should answer at once.
    let patience = if account.is_empty() {
        Duration::ZERO
    } else {
        progress(&format!(
            "Waiting for {url} to answer (a new address can take a minute)..."
        ));
        Duration::from_secs(120)
    };
    let start = Instant::now();
    loop {
        match server.info() {
            Ok(_) => break,
            Err(e) if start.elapsed() >= patience => {
                return Err(err(format!(
                    "the server did not come up: {e}. Try again in a few minutes"
                )));
            }
            Err(_) => std::thread::sleep(Duration::from_secs(3)),
        }
    }
    let mailbox = crate::random_mailbox()?;
    let device_token = crate::random_token()?;
    let device_id = server.create(&mailbox, &admin_key, &device_token, name)?;
    ask(
        call,
        Request::CloudSet {
            settings: Some(CloudSettings {
                server: url.clone(),
                mailbox: mailbox.clone(),
                account_id: account,
                worker,
                admin_key,
                api_token: token,
                ca_cert: ca_pem.clone(),
            }),
        },
    )?;
    ask(
        call,
        Request::CloudAttach {
            device: Some(CloudDevice {
                server: url.clone(),
                mailbox,
                device: device_id,
                token: device_token,
                ca_cert: ca_pem,
            }),
            file: None,
        },
    )?;
    Ok(url)
}

/// A one-time join link for another device, and the minutes it is valid.
pub fn link(i: &CloudInfo) -> Result<(Secret, u64)> {
    let d = device(i)?;
    let t = Mailbox::from_device(d)?.ticket()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let link = JoinLink {
        server: d.server.clone(),
        mailbox: d.mailbox.clone(),
        ticket: t.ticket,
        fingerprint: d
            .ca_cert
            .as_deref()
            .and_then(|p| OwnCa::from_pem(p).ok())
            .map(|c| c.fingerprint()),
    };
    Ok((link.to_link(), t.expires.saturating_sub(now).div_ceil(60)))
}

/// Joins this device with a link from another one, and hands the
/// downloaded vault file to `vaultd`. Returns `vaultd`'s status after.
pub fn join(call: &mut Call<'_>, link: &str, name: &str) -> Result<(String, StatusInfo)> {
    let link = JoinLink::parse(link)?;
    let ca_pem = match &link.fingerprint {
        Some(f) => Some(OwnCa::fetch(&link.server, f)?.pem().to_owned()),
        None => None,
    };
    let server = Server::with_ca(&link.server, ca_pem.as_deref())?;
    server.info()?;
    let token = crate::random_token()?;
    let device_id = server.join(&link, &token, name)?;
    let m = Mailbox::new(&link.server, &link.mailbox, &token, ca_pem.as_deref())?;
    let file = match m.get(None)? {
        Fetched::File(_, bytes) => Some(bytes),
        Fetched::Empty(_) | Fetched::Unchanged => None,
    };
    match ask(
        call,
        Request::CloudAttach {
            device: Some(CloudDevice {
                server: link.server.clone(),
                mailbox: link.mailbox.clone(),
                device: device_id,
                token,
                ca_cert: ca_pem,
            }),
            file,
        },
    )? {
        Response::Status(s) => Ok((link.server, s)),
        _ => Err(err("unexpected answer from vaultd")),
    }
}

/// Every device that joined.
pub fn devices(i: &CloudInfo) -> Result<Vec<DeviceInfo>> {
    Mailbox::from_device(device(i)?)?.devices()
}

/// Cuts another device off.
pub fn remove(i: &CloudInfo, id: &str) -> Result<()> {
    let d = device(i)?;
    if d.device == id {
        return Err(err("that is this device; turn cloud sync off here instead"));
    }
    Mailbox::from_device(d)?.remove_device(id)
}

/// Uploads this program's copy of the server to Cloudflare, with the
/// kept API token or `token`.
pub fn update(call: &mut Call<'_>, token: Option<Secret>) -> Result<String> {
    need_unlocked(call)?;
    let i = info(call)?;
    let s = settings(&i)?;
    if s.account_id.is_empty() {
        return Err(err(
            "this server was set up by hand: for Docker, `git pull` and `docker compose up -d --build` in server/sync; otherwise `npx wrangler deploy` there",
        ));
    }
    let token = token
        .or_else(|| s.api_token.clone())
        .ok_or_else(|| err("a Cloudflare API token is needed (Workers Scripts: Edit)"))?;
    Cloudflare::new(&s.account_id, &token)?.deploy(&s.worker, &s.admin_key)?;
    Ok(s.server.clone())
}

/// Stops keeping the Cloudflare API token in the vault.
pub fn forget_token(call: &mut Call<'_>) -> Result<()> {
    need_unlocked(call)?;
    let mut s = settings(&info(call)?)?.clone();
    s.api_token = None;
    ask(call, Request::CloudSet { settings: Some(s) })?;
    Ok(())
}

/// Turns cloud sync off on this device; with `everywhere`, also deletes the
/// mailbox from the server and the settings from the vault.
pub fn off(call: &mut Call<'_>, everywhere: bool) -> Result<()> {
    let i = info(call)?;
    if everywhere {
        need_unlocked(call)?;
        let i = info(call)?;
        settings(&i)?;
        if let Some(d) = &i.device {
            Mailbox::from_device(d)?.delete()?;
        }
        ask(call, Request::CloudSet { settings: None })?;
    } else {
        let d = device(&i)?;
        // Best effort: a device that was already removed cannot remove itself.
        if let Ok(m) = Mailbox::from_device(d) {
            let _ = m.remove_device(&d.device);
        }
    }
    ask(
        call,
        Request::CloudAttach {
            device: None,
            file: None,
        },
    )?;
    Ok(())
}

/// One line on how the `vault-sync` helper on this computer is doing, and
/// whether that is a problem.
pub fn helper_line(i: &CloudInfo) -> (String, bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let ago = |t: u64| {
        let s = now.saturating_sub(t);
        match s {
            0..60 => "just now".to_owned(),
            60..7200 => format!("{} minutes ago", s / 60),
            _ => format!("{} hours ago", s / 3600),
        }
    };
    match &i.helper {
        Some(h) if now.saturating_sub(h.written) <= 180 => match &h.error {
            Some(e) => (format!("running, but: {e}"), true),
            None if h.watching => (
                "running; connected to the server and listening for changes".into(),
                false,
            ),
            None if h.reached == 0 => ("running, has not reached the server yet".into(), false),
            None => (
                format!(
                    "running; server reached {} (checks every 30 seconds)",
                    ago(h.reached)
                ),
                false,
            ),
        },
        Some(h) => (
            format!(
                "not running (last seen {}); start vault-sync",
                ago(h.written)
            ),
            true,
        ),
        None => (
            "not started on this computer yet; start vault-sync".into(),
            true,
        ),
    }
}
