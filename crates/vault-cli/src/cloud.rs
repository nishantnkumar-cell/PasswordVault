//! `vault cloud`: cloud sync through the user's own Cloudflare Worker
//! (docs/cloud-sync.md). This client does the network work; `vaultd` only
//! keeps the settings in the vault and syncs the folder `vault-sync` mirrors.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use vault_cloud::{Cloudflare, Fetched, JoinLink, Mailbox, Server};
use vault_ipc::{CloudDevice, CloudInfo, CloudSettings, Request, Response, Secret};
use zeroize::Zeroizing;

use crate::{Client, die, line_from_stdin, load_token, print_qr, secret, unix_now};

fn ok<T>(r: vault_cloud::Result<T>) -> T {
    r.unwrap_or_else(|e| die(e))
}

fn info(c: &mut Client) -> CloudInfo {
    match c.call(Request::CloudGet) {
        Response::Cloud(i) => i,
        _ => die("unexpected response"),
    }
}

fn need_unlocked(c: &mut Client) {
    let Response::Status(s) = c.call(Request::Status) else {
        die("unexpected response")
    };
    if !s.unlocked {
        die("the vault is locked; run `vault unlock` first");
    }
}

fn device(i: &CloudInfo) -> &CloudDevice {
    i.device
        .as_ref()
        .unwrap_or_else(|| die("cloud sync is not set up on this device; see `vault cloud setup` or `vault cloud join`"))
}

fn settings(i: &CloudInfo) -> &CloudSettings {
    i.settings.as_ref().unwrap_or_else(|| {
        die("the vault has no cloud sync settings (is it unlocked? was `vault cloud setup` run?)")
    })
}

/// This computer's name, for the device list.
fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "computer".into())
}

fn flag(rest: &[String], name: &str) -> Option<String> {
    rest.iter().position(|a| a == name).map(|i| {
        rest.get(i + 1)
            .cloned()
            .unwrap_or_else(|| die(format!("{name} needs a value")))
    })
}

fn prompt_line(p: &str) -> String {
    eprint!("{p}");
    let _ = io::stderr().flush();
    line_from_stdin()
}

fn when(t: u64) -> String {
    let ago = unix_now().saturating_sub(t);
    match ago {
        0..120 => "just now".into(),
        120..7200 => format!("{} minutes ago", ago / 60),
        7200..172_800 => format!("{} hours ago", ago / 3600),
        _ => format!("{} days ago", ago / 86_400),
    }
}

pub fn cloud(rest: &[String]) {
    let sub = rest.first().map(String::as_str).unwrap_or("status");
    let rest = rest.get(1..).unwrap_or_default();
    match sub {
        "status" => status(),
        "setup" => setup(rest),
        "link" => link(),
        "join" => join(rest),
        "devices" => devices(),
        "remove" => {
            let id = rest
                .first()
                .unwrap_or_else(|| die("usage: vault cloud remove DEVICE-ID"));
            let mut c = Client::connect();
            let i = info(&mut c);
            let m = ok(Mailbox::from_device(device(&i)));
            if device(&i).device == *id {
                die("that is this device; use `vault cloud off` here instead");
            }
            ok(m.remove_device(id));
            println!("Removed. That device can no longer read or save the vault on the server.");
            println!(
                "It keeps its own copy of the vault; to also lock its unlock methods out, see `vault revoke`."
            );
        }
        "update" => update(),
        "forget-token" => {
            let mut c = Client::connect();
            need_unlocked(&mut c);
            let mut s = settings(&info(&mut c)).clone();
            s.api_token = None;
            c.call(Request::CloudSet { settings: Some(s) });
            println!("The Cloudflare API token is no longer kept in the vault.");
            println!(
                "`vault cloud update` will ask for one. You can also delete the token in the Cloudflare dashboard."
            );
        }
        "off" => off(rest.iter().any(|a| a == "--everywhere")),
        other => die(format!("unknown cloud command {other}; see `vault help`")),
    }
}

fn status() {
    let mut c = Client::connect();
    let i = info(&mut c);
    let Response::Status(st) = c.call(Request::Status) else {
        die("unexpected response")
    };
    match (&i.settings, &i.device) {
        (None, None) if !st.unlocked => {
            println!(
                "cloud sync: unknown while the vault is locked (and not joined on this device)"
            );
            return;
        }
        (None, None) => {
            println!("cloud sync: off (set it up with `vault cloud setup`)");
            return;
        }
        _ => {}
    }
    if let Some(s) = &i.settings {
        println!("server:     {}", s.server);
        if s.account_id.is_empty() {
            println!("worker:     deployed by hand");
        } else {
            println!(
                "worker:     {} in Cloudflare account {}",
                s.worker, s.account_id
            );
        }
        println!(
            "API token:  {}",
            if s.api_token.is_some() {
                "kept in the vault (remove with `vault cloud forget-token`)"
            } else {
                "not kept"
            }
        );
    }
    match &i.device {
        Some(d) => {
            if i.settings.is_none() {
                println!("server:     {}", d.server);
            }
            println!("this device: {} (joined)", d.device);
            if let Ok(srv) = Server::new(&d.server) {
                match srv.info() {
                    Ok(si) if si.revision < vault_cloud::worker_revision() => println!(
                        "server code: revision {}, older than this program's {}; run `vault cloud update`",
                        si.revision,
                        vault_cloud::worker_revision()
                    ),
                    Ok(si) => println!("server code: revision {} (up to date)", si.revision),
                    Err(e) => println!("server code: unknown ({e})"),
                }
            }
        }
        None => println!(
            "this device: not joined (run `vault cloud join` with a link from another device)"
        ),
    }
    match &st.sync {
        Some(s) => crate::print_sync(s),
        None => println!("sync:       off"),
    }
}

fn setup(rest: &[String]) {
    let mut c = Client::connect();
    need_unlocked(&mut c);
    let i = info(&mut c);
    if i.settings.is_some() {
        die(
            "cloud sync is already set up for this vault; see `vault cloud status`, or `vault cloud join` on another device",
        );
    }
    let name = flag(rest, "--name").unwrap_or_else(host_name);
    let keep = rest.iter().any(|a| a == "--keep-token");
    let (url, account, worker, admin_key, token) = match flag(rest, "--server") {
        // A server deployed by hand (`npx wrangler deploy` in server/sync,
        // with its ADMIN_KEY secret set): nothing to upload.
        Some(url) => {
            let admin_key = secret("The server's admin key (its ADMIN_KEY secret): ");
            (
                url.trim().trim_end_matches('/').to_owned(),
                String::new(),
                String::new(),
                admin_key,
                None,
            )
        }
        None => {
            let worker =
                flag(rest, "--worker").unwrap_or_else(|| vault_cloud::DEFAULT_WORKER.into());
            let account =
                flag(rest, "--account").unwrap_or_else(|| prompt_line("Cloudflare account ID: "));
            let token = secret("Cloudflare API token (Workers Scripts: Edit): ");
            let cf = ok(Cloudflare::new(&account, &token));
            eprintln!("Checking your Cloudflare account...");
            let sub = ok(cf.subdomain());
            let admin_key = ok(vault_cloud::random_token());
            eprintln!("Uploading the sync server as the Worker \"{worker}\"...");
            ok(cf.deploy(&worker, &admin_key));
            let url = vault_cloud::worker_url(&worker, &sub);
            (
                url,
                account.trim().to_owned(),
                worker,
                admin_key,
                Some(token),
            )
        }
    };
    let s_hand = account.is_empty();
    let server = ok(Server::new(&url));
    eprintln!("Waiting for {url} to answer (a new address can take a minute)...");
    let start = Instant::now();
    loop {
        match server.info() {
            Ok(_) => break,
            Err(e) if start.elapsed() > Duration::from_secs(120) => die(format!(
                "the server did not come up: {e}. Run `vault cloud setup` again in a few minutes"
            )),
            Err(_) => std::thread::sleep(Duration::from_secs(3)),
        }
    }

    let mailbox = ok(vault_cloud::random_mailbox());
    let device_token = ok(vault_cloud::random_token());
    let device_id = ok(server.create(&mailbox, &admin_key, &device_token, &name));
    c.call(Request::CloudSet {
        settings: Some(CloudSettings {
            server: url.clone(),
            mailbox: mailbox.clone(),
            account_id: account,
            worker,
            admin_key,
            api_token: token
                .filter(|_| keep)
                .map(|t| Secret::new(t.trim().to_owned())),
        }),
    });
    c.call(Request::CloudAttach {
        device: Some(CloudDevice {
            server: url.clone(),
            mailbox,
            device: device_id,
            token: device_token,
        }),
        file: None,
    });
    println!("Cloud sync is set up on {url}.");
    println!();
    println!("Next:");
    println!(
        "  1. Start the background helper on this device: `systemctl --user enable --now vault-sync`"
    );
    println!("     (see the user guide, chapter 15, for the system service, macOS and Windows).");
    println!(
        "  2. On each other device: run `vault cloud link` here and `vault cloud join LINK` there."
    );
    if !keep && !s_hand {
        println!(
            "  3. The API token was not kept. You can delete it in the Cloudflare dashboard now;"
        );
        println!(
            "     `vault cloud update` will ask for a new one when the server needs an update."
        );
    }
}

fn link() {
    let mut c = Client::connect();
    let i = info(&mut c);
    let d = device(&i);
    let t = ok(ok(Mailbox::from_device(d)).ticket());
    let link = JoinLink {
        server: d.server.clone(),
        mailbox: d.mailbox.clone(),
        ticket: t.ticket,
    }
    .to_link();
    print_qr(&link);
    println!("{}", *link);
    eprintln!();
    eprintln!(
        "On the new device run `vault cloud join '<link>'` or scan the code in the app. It works once, for {} minutes.",
        t.expires.saturating_sub(unix_now()).div_ceil(60)
    );
    eprintln!(
        "Anyone with this link can download the encrypted vault, so share it only with your own devices."
    );
}

fn join(rest: &[String]) {
    let text = match rest.first() {
        Some(l) if !l.starts_with("--") => Zeroizing::new(l.clone()),
        _ => secret("Join link: "),
    };
    let link = ok(JoinLink::parse(&text));
    let name = flag(rest, "--name").unwrap_or_else(host_name);
    let server = ok(Server::new(&link.server));
    ok(server.info());
    let token = ok(vault_cloud::random_token());
    let device_id = ok(server.join(&link, &token, &name));
    let m = ok(Mailbox::new(&link.server, &link.mailbox, &token));
    let file = match ok(m.get(None)) {
        Fetched::File(_, bytes) => Some(bytes),
        Fetched::Empty(_) | Fetched::Unchanged => None,
    };
    let mut c = Client::connect();
    let paired = load_token().is_some();
    let Response::Status(s) = c.call(Request::CloudAttach {
        device: Some(CloudDevice {
            server: link.server.clone(),
            mailbox: link.mailbox.clone(),
            device: device_id,
            token,
        }),
        file,
    }) else {
        die("unexpected response")
    };
    println!("Joined cloud sync on {}.", link.server);
    if let Some(sync) = &s.sync {
        crate::print_sync(sync);
    }
    println!(
        "Start the background helper: `systemctl --user enable --now vault-sync` (user guide, chapter 15)."
    );
    if !paired && s.initialized {
        println!(
            "Then pair this client with `vault pair --password` and unlock with your master password."
        );
    }
}

fn devices() {
    let mut c = Client::connect();
    let i = info(&mut c);
    let list = ok(ok(Mailbox::from_device(device(&i))).devices());
    println!("{:<18} {:<24} {:<16} LAST SEEN", "ID", "NAME", "ADDED");
    for d in list {
        println!(
            "{:<18} {:<24} {:<16} {}{}",
            d.id,
            d.name,
            when(d.created),
            when(d.last_seen),
            if d.current { "  (this device)" } else { "" }
        );
    }
    println!();
    println!("Remove a lost device with `vault cloud remove ID`.");
}

fn update() {
    let mut c = Client::connect();
    need_unlocked(&mut c);
    let s = settings(&info(&mut c)).clone();
    if s.account_id.is_empty() {
        die(
            "this server was deployed by hand; update it with `npx wrangler deploy` in server/sync",
        );
    }
    let token = match &s.api_token {
        Some(t) => t.clone(),
        None => secret("Cloudflare API token (Workers Scripts: Edit): "),
    };
    let cf = ok(Cloudflare::new(&s.account_id, &token));
    eprintln!(
        "Uploading revision {} of the sync server...",
        vault_cloud::worker_revision()
    );
    ok(cf.deploy(&s.worker, &s.admin_key));
    println!("Updated {}. Mailboxes and devices are unchanged.", s.server);
}

fn off(everywhere: bool) {
    let mut c = Client::connect();
    let i = info(&mut c);
    if everywhere {
        need_unlocked(&mut c);
        let i = info(&mut c);
        settings(&i);
        if let Some(d) = &i.device {
            ok(ok(Mailbox::from_device(d)).delete());
        }
        c.call(Request::CloudSet { settings: None });
        println!(
            "Deleted the vault and every device's access from the server, and the settings from the vault."
        );
        println!(
            "The Worker stays in your Cloudflare account; delete it there if you no longer want it."
        );
    } else {
        let d = device(&i);
        // Best effort: a device that was already removed cannot remove itself.
        if let Ok(m) = Mailbox::from_device(d) {
            let _ = m.remove_device(&d.device);
        }
    }
    c.call(Request::CloudAttach {
        device: None,
        file: None,
    });
    println!("Cloud sync is off on this device. Its own vault file is unchanged.");
    if !everywhere {
        println!("Other devices keep syncing. Join again later with a new link from one of them.");
    }
}
