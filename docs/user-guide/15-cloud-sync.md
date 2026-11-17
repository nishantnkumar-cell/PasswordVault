# 15. Cloud sync with your own Cloudflare account

Cloud sync keeps one vault on all your computers through a small sync
server that Secret Vault puts in **your own free Cloudflare account**. It
works like folder sync ([chapter 10](10-sync.md)) without a cloud drive app:
a change on one computer reaches the others within seconds, and there are
no "conflicted copy" files.

The server only ever stores the encrypted vault file. It never gets your
master password, your keys or your items, and nobody else runs it: it is in
your account, and only your vault can use it. It costs nothing on
Cloudflare's free plan.

Use it when:

- you want your logins on a Linux laptop, a Windows desktop and a Mac
  without installing OneDrive, Dropbox or Google Drive on each;
- you use Linux, where OneDrive and Google Drive have no official app;
- you want changes to show up on your other computers quickly.

You can still use folder sync instead. Use one or the other on a device,
not both.

> Phones and tablets cannot join cloud sync yet, and the desktop app has no
> cloud sync screen yet: both are coming next. Until then, phones keep using
> folder sync, and you set cloud sync up with the `vault` command.

## What you need

- A free Cloudflare account. No card is needed.
- Secret Vault on each computer, with `vaultd` running and the vault
  unlocked on the first one.
- About ten minutes for the first computer, two for each other one.

## Step 1: make the Cloudflare account and an API token

Do this once, in a web browser.

1. Sign up at [dash.cloudflare.com/sign-up](https://dash.cloudflare.com/sign-up)
   and confirm your email address.
2. In the dashboard, open **Workers & Pages** (in the menu on the left,
   sometimes under **Compute**). The first time, Cloudflare asks you to pick a
   **workers.dev subdomain**, such as `example-name`. Pick anything; your
   server will be at `https://vault-sync.example-name.workers.dev`.
3. On the same page, copy your **Account ID** (a 32-character code on the
   right). You will paste it in step 2.
4. Make an API token: click your profile icon, **My Profile**, **API
   Tokens**, **Create Token**, then **Use template** next to **Edit
   Cloudflare Workers**.
   - Under **Account Resources**, pick **Include** and your account.
   - Under **Zone Resources**, pick **All zones** (nothing uses a zone; the
     template needs a choice).
   - Click **Continue to summary**, then **Create Token**, and copy the
     token. Cloudflare shows it only once.

The only permission Secret Vault uses is *Workers Scripts: Edit* on that one
account. Treat the token like a password: whoever has it can change or
delete the sync server (though not read your vault).

## Step 2: set up the first computer

With the vault unlocked, run:

```sh
vault cloud setup
```

It asks for the account ID and the token (the token is not shown as you
paste it), then:

```
Checking your Cloudflare account...
Uploading the sync server as the Worker "vault-sync"...
Waiting for https://vault-sync.example-name.workers.dev to answer (a new address can take a minute)...
Cloud sync is set up on https://vault-sync.example-name.workers.dev.
```

What happened: Secret Vault uploaded its sync server to your account, made
a mailbox for your vault, and saved the server's address and keys **inside
your vault**, so your other computers learn them when they join.

Options:

| Option | What it does |
|---|---|
| `--keep-token` | Keep the API token in the vault so `vault cloud update` does not ask for it. Without it, the token is forgotten after setup |
| `--worker NAME` | Use another Worker name than `vault-sync` |
| `--name NAME` | How this computer appears in the device list (default: its name) |
| `--account ID` | Give the account ID on the command line |

If you did not use `--keep-token`, you can delete the token now in the
Cloudflare dashboard (**My Profile**, **API Tokens**, **Delete**). You only
need a new one to update the server later.

## Step 3: start the sync helper

A small program, `vault-sync`, does the uploading and downloading in the
background. `vaultd` itself never goes on the internet.

| Your setup | Run once |
|---|---|
| Linux, `vaultd` as your own user service (the default with `install.sh`) | `systemctl --user enable --now vault-sync` |
| Linux, `vaultd@you` system service (the default with `get.sh`) | `sudo systemctl enable --now vault-sync@$USER` |
| Windows | Not in the installer yet: build it with `cargo build --release -p vault-cloud`, then press Win+R, type `shell:startup`, add a shortcut to `target\release\vault-sync.exe` there and double-click it once |
| macOS | Not in the installer yet: build it with `cargo build --release -p vault-cloud` and run `target/release/vault-sync &` in Terminal |

The Linux `.deb` and `.tar.gz` (with `install.sh` or `get.sh`) include the
helper and its service files. If you built from source on Linux, copy
`contrib/systemd/vault-sync.service` to `~/.config/systemd/user/` and fix
its `ExecStart=` path first.

Check it: `vault cloud` shows the server, this device and when the vault
last synced. On Linux, `journalctl --user -u vault-sync` (or
`sudo journalctl -u vault-sync@$USER`) shows what the helper did.

## Step 4: add your other computers

On the first computer, make a one-time link:

```sh
vault cloud link
```

It prints a QR code and a link like
`https://vault-sync.example-name.workers.dev/join#v1.…`. The link works
**once** and for **10 minutes**. It contains no password or key, but it lets
a device download the encrypted vault, so send it only to yourself (for
example by copying it into a terminal on the other computer, or a note to
yourself, not a public chat).

On the new computer, with `vaultd` running:

```sh
vault cloud join 'https://vault-sync.example-name.workers.dev/join#v1.…'
vault pair --password        # only on a computer with no vault yet
vault unlock
```

Then start the sync helper there too (step 3). The vault, your items and
all unlock methods are now on both. A security key works on every computer;
a TPM unlock method only works on the computer that made it.

If the new computer already had a different vault, its copy is refused
(a vault only merges with itself): stop `vaultd`, move that vault file
aside ([chapter 8, "Where your files are"](08-troubleshooting.md#where-your-files-are)),
start `vaultd` again and join.

## Everyday use

There is nothing to do. Edit on any computer while it is unlocked; the
others pick the change up within seconds while they are unlocked, or at
their next unlock. Two computers editing the same item at the same time
keep both edits: the later one wins and the other is kept as a copy titled
"(conflict)", as with folder sync.

| Command | What it does |
|---|---|
| `vault cloud` | Server, this device, last sync, and whether the server needs an update |
| `vault cloud devices` | Every device that joined, when it was added and last seen |
| `vault cloud remove ID` | Cut off a lost or sold device (it keeps what it already had) |
| `vault cloud update` | Upload the newer server that came with a Secret Vault update |
| `vault cloud forget-token` | Stop keeping the Cloudflare API token in the vault |
| `vault cloud off` | Stop cloud sync on this computer only |
| `vault cloud off --everywhere` | Delete the vault from the server and the settings from the vault |

### A device was lost or stolen

1. On another computer: `vault cloud devices`, then `vault cloud remove ID`.
   The lost device can no longer download or upload.
2. It still has its own copy of the vault, protected by your master
   password and unlock methods. If you think someone may get past them,
   change the master password and revoke its unlock methods
   ([chapter 2](02-unlocking.md)).

### Running your own server by hand

If you would rather deploy the server yourself (for example with your own
Cloudflare settings), run `npm ci`, `npx wrangler deploy` and
`npx wrangler secret put ADMIN_KEY` (any random value) in `server/sync` of
the source code, then `vault cloud setup --server https://your-address`.
`vault cloud update` does not work for such a server; deploy again with
`wrangler` instead.

## What differs between systems

| | Linux | Windows | macOS |
|---|---|---|---|
| `vault cloud` commands | Yes | Yes | Yes |
| Background helper | In the packages; systemd service, starts with the computer or at sign-in | Build from source; Startup folder shortcut | Build from source; start it yourself |
| Desktop app screen | Coming next | Coming next | Coming next |
| Phones and tablets | Coming next (use folder sync until then) | | |

## Troubleshooting

| Message | What to do |
|---|---|
| `your account has no workers.dev subdomain yet` | Open **Workers & Pages** in the dashboard once and pick one (step 1.2) |
| `Cloudflare said Authentication error` | Check the account ID and that the token has *Workers Scripts: Edit* for that account |
| `a Worker named vault-sync already exists and is not a Secret Vault server` | Use `--worker` with another name |
| `this join link was used already or has expired` | Run `vault cloud link` again; each link works once, for 10 minutes |
| `the server said 401 ... this device may have been removed` | The device was removed: get a new link and `vault cloud join` again |
| `vault cloud` says "synced: not yet (unlock to sync)" | Unlock the vault; syncing happens only while it is unlocked |
| Changes do not arrive | Check the helper is running (step 3) and `vault cloud` shows no error |

How it works inside, and what the server can and cannot see:
[docs/cloud-sync.md](../cloud-sync.md).
