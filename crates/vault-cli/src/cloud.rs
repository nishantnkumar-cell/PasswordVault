//! `vault cloud`: cloud sync through the user's own Cloudflare Worker
//! (docs/cloud-sync.md). This client does the network work; `vaultd` only
//! keeps the settings in the vault and syncs the folder `vault-sync` mirrors.

use std::io::{self, Write};

use vault_cloud::flows::{self, Host};
use vault_cloud::{OwnCa, Server};
use vault_ipc::{CloudInfo, CloudSettings, Request, Response, Secret};
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

fn settings(i: &CloudInfo) -> &CloudSettings {
    i.settings.as_ref().unwrap_or_else(|| {
        die("the vault has no cloud sync settings (is it unlocked? was `vault cloud setup` run?)")
    })
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
            ok(flows::remove(&i, id));
            println!("Removed. That device can no longer read or save the vault on the server.");
            println!(
                "It keeps its own copy of the vault; to also lock its unlock methods out, see `vault revoke`."
            );
        }
        "update" => update(),
        "forget-token" => {
            let mut c = Client::connect();
            ok(flows::forget_token(&mut call(&mut c)));
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
            println!("cloud sync: off");
            println!();
            crate::print_sync_options();
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
        if let Some(ca) = s.ca_cert.as_deref().and_then(|p| OwnCa::from_pem(p).ok()) {
            println!(
                "certificate: the server's own (fingerprint {})",
                ca.fingerprint()
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
            // The id of this vault's mailbox on the server. Moving to another
            // server (vault-server import) needs it: it is not in the server's
            // files in a form anyone can read. It is not a secret on its own
            // (access takes this device's token), but it is not shown widely.
            println!("mailbox:    {}", d.mailbox);
            println!("helper:     {}", flows::helper_line(&i).0);
            if let Ok(srv) = Server::with_ca(&d.server, d.ca_cert.as_deref()) {
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

fn call(c: &mut Client) -> impl FnMut(Request) -> vault_cloud::Result<Response> + '_ {
    |r| Ok(c.try_call(r))
}

fn setup(rest: &[String]) {
    let mut c = Client::connect();
    need_unlocked(&mut c);
    if info(&mut c).settings.is_some() {
        die(
            "cloud sync is already set up for this vault; see `vault cloud status`, or `vault cloud join` on another device",
        );
    }
    let name = flag(rest, "--name").unwrap_or_else(flows::host_name);
    let keep = rest.iter().any(|a| a == "--keep-token");
    let fingerprint = flag(rest, "--fingerprint");
    if fingerprint.is_some() && flag(rest, "--server").is_none() {
        die("--fingerprint goes with --server (a server on your own computer)");
    }
    let host = match flag(rest, "--server") {
        // A server run by hand: in Docker on your own computer, or deployed
        // with `npx wrangler deploy` in server/sync. Nothing to upload.
        Some(server) => Host::Own {
            server,
            fingerprint,
            admin_key: Secret::new(
                secret(
                    "The server's admin key (`docker compose exec vault-sync show`, or its ADMIN_KEY secret): ",
                )
                .to_string(),
            ),
        },
        None => Host::Cloudflare {
            worker: flag(rest, "--worker").unwrap_or_default(),
            account: flag(rest, "--account")
                .unwrap_or_else(|| prompt_line("Cloudflare account ID: ")),
            token: Secret::new(
                secret("Cloudflare API token (Workers Scripts: Edit): ").to_string(),
            ),
            keep_token: keep,
        },
    };
    let own = matches!(host, Host::Own { .. });
    let url = ok(flows::setup(&mut call(&mut c), host, &name, &|p| {
        eprintln!("{p}")
    }));
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
    if !keep && !own {
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
    let (link, minutes) = ok(flows::link(&i));
    print_qr(&link);
    println!("{}", *link);
    eprintln!();
    eprintln!(
        "On the new device run `vault cloud join '<link>'` or paste it in the app's Cloud sync page. It works once, for {minutes} minutes."
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
    let name = flag(rest, "--name").unwrap_or_else(flows::host_name);
    let mut c = Client::connect();
    let paired = load_token().is_some();
    let (server, s) = ok(flows::join(&mut call(&mut c), &text, &name));
    println!("Joined cloud sync on {server}.");
    if let Some(sync) = &s.sync {
        crate::print_sync(sync);
    }
    println!();
    println!("Next, on this device:");
    println!("  1. Start the background helper: `systemctl --user enable --now vault-sync`");
    println!("     (other systems: user guide, chapter 15)");
    if !paired {
        println!("  2. Pair this client:  vault pair --password");
        println!("  3. Unlock:            vault unlock");
        println!("(Use the master password you chose on your first device.)");
    }
}

fn devices() {
    let mut c = Client::connect();
    let i = info(&mut c);
    let list = ok(flows::devices(&i));
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
    let token = match (&s.api_token, s.account_id.is_empty()) {
        (None, false) => Some(Secret::new(
            secret("Cloudflare API token (Workers Scripts: Edit): ").to_string(),
        )),
        _ => None,
    };
    eprintln!(
        "Uploading revision {} of the sync server...",
        vault_cloud::worker_revision()
    );
    let server = ok(flows::update(&mut call(&mut c), token));
    println!("Updated {server}. Mailboxes and devices are unchanged.");
}

fn off(everywhere: bool) {
    let mut c = Client::connect();
    ok(flows::off(&mut call(&mut c), everywhere));
    if everywhere {
        println!(
            "Deleted the vault and every device's access from the server, and the settings from the vault."
        );
        println!(
            "The Worker stays in your Cloudflare account; delete it there if you no longer want it."
        );
    }
    println!("Cloud sync is off on this device. Its own vault file is unchanged.");
    if !everywhere {
        println!("Other devices keep syncing. Join again later with a new link from one of them.");
    }
}
