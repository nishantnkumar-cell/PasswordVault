# Cloud sync

Keep one vault on several devices through a small sync server that runs in
**your own free Cloudflare account**. The vault program puts the server
there itself (`vault cloud setup`); nothing is hosted by the project, and
nothing about your server is in this repository or in the downloads.

The server only ever holds the encrypted vault file, the same file folder
sync puts in OneDrive or Dropbox ([sync.md](sync.md)). It never sees a
password, key or item. Folder sync keeps working and stays the default.

The step-by-step guide is [user guide, chapter 15](user-guide/15-cloud-sync.md).
This page is how it works.

## Parts

| Part | Where | What it does |
| --- | --- | --- |
| Sync server | `server/sync/src/index.js`, a Cloudflare Worker with one Durable Object per mailbox | Keeps the file, a version number and each device's access token (only its SHA-256) |
| `vault-cloud` crate | `crates/vault-cloud` | Uploads the server to your account; talks to it; join links |
| `vault-sync` | `crates/vault-cloud/src/bin/vault-sync.rs` | Background helper: mirrors the mailbox to the `cloud` folder next to the vault file |
| `vaultd` | unchanged sync code | Keeps the vault in sync with `cloud/vault.svault`, exactly as with a cloud folder; keeps the settings in the vault |
| `vault cloud` | `crates/vault-cli/src/cloud.rs` | Setup, join links, devices, updates |

`vaultd` still has no network access (its units allow only Unix sockets).
`vault-sync` is the only program that talks to the server, and it holds no
key: only the encrypted file and this device's token.

```
 your devices                                    your Cloudflare account
 ┌───────────────────────────────┐                ┌──────────────────────┐
 │ vaultd ── vault.svault        │                │ Worker "vault-sync"  │
 │   │ (folder sync, 5 s)        │   HTTPS + WSS  │   Durable Object     │
 │   └─ cloud/vault.svault ◄────►│ vault-sync ◄──►│   per mailbox:       │
 │      cloud/device.conf        │                │   file, version,     │
 └───────────────────────────────┘                │   device tokens      │
                                                  └──────────────────────┘
```

## Setup: what `vault cloud setup` does

1. Asks for your Cloudflare **account ID** and an **API token** with one
   permission, *Account → Workers Scripts → Edit*, for that account only.
2. Reads the account's `workers.dev` subdomain.
3. Makes a random 256-bit **admin key** and uploads the server code built
   into this program as the Worker `vault-sync`, with the admin key as its
   secret `ADMIN_KEY` and a SQLite Durable Object class `Mailbox`. Then it
   turns on `https://vault-sync.<subdomain>.workers.dev`.
4. Creates this vault's mailbox (a random 128-bit id) with the admin key,
   and registers this device with a fresh random token.
5. Stores the **settings** in the vault (below) and gives `vaultd` this
   device's access (`cloud/device.conf`). `vaultd` writes the vault to
   `cloud/vault.svault`; `vault-sync` uploads it.

The API token is used only in steps 2 and 3, and kept only with
`--keep-token` (for `vault cloud update` without pasting it again). It is
never sent to the sync server and never put in a join link.

`vault cloud setup --server URL` uses a server you deployed yourself
(`npx wrangler deploy` in `server/sync`, then `npx wrangler secret put
ADMIN_KEY`) and asks for its admin key instead of a token.

## Settings in the vault

The settings live in the vault's encrypted body as the setting
`cloud-sync` (format.md 5.2), so every device gets them through the merge
and they are in every backup:

| Field | Meaning |
| --- | --- |
| `server` | `https://vault-sync.<subdomain>.workers.dev` |
| `mailbox` | 32 hex characters |
| `account_id`, `worker` | Where the server runs (empty for a hand-deployed server) |
| `admin_key` | Creates mailboxes on your server |
| `api_token` | Only with `--keep-token` |

Each device's own token is **not** synced. `vaultd` keeps it in
`cloud/device.conf` (mode 0600) next to the vault file, so a lost device can
be removed on its own. That file gives access to the encrypted file only,
as the vault file on the same disk already does.

## Adding a device

`vault cloud link` asks the server for a **one-time ticket**, valid 10
minutes, and shows it as a link and QR code:

```
https://vault-sync.example-name.workers.dev/join#v1.<mailbox>.<ticket>
```

The part after `#` never leaves a browser, so opening the link in one by
mistake shows a help page and leaks nothing. `vault cloud join LINK` on the
new device picks its own random token, trades the ticket for a device id,
downloads the file and hands both to `vaultd`, which joins the vault from it
as folder sync does. You then unlock with the master password.

`vault cloud devices` lists devices; `vault cloud remove ID` deletes one's
token on the server and closes its connection.

## Server API

Tokens are base64url, 256 bits; `Authorization: Bearer <token>` is a device
token unless said otherwise. Every answer has `Cache-Control: no-store`.

| Call | Does |
| --- | --- |
| `GET /` | `{"service":"secret-vault-sync","api":1,"revision":N}` |
| `POST /v1/m/<id>` | Create an empty mailbox. Needs `X-Admin-Key`; the bearer token becomes the first device's; `X-Device-Name` |
| `GET /v1/m/<id>` | The file, `ETag: "<version>"`; 204 while empty; 304 for `If-None-Match` |
| `PUT /v1/m/<id>` | Save. `If-Match: "<version>"` required (428), 412 with the current ETag when another device saved first |
| `DELETE /v1/m/<id>` | Delete the mailbox, its file and every device |
| `POST /v1/m/<id>/tickets` | One-time join ticket, 10 minutes |
| `POST /v1/m/<id>/join` | `X-Ticket`; the bearer token is the new device's |
| `GET /v1/m/<id>/devices`, `DELETE /v1/m/<id>/devices/<dev>` | List, remove |
| `GET /v1/m/<id>/watch` | WebSocket; `{"version":n}` on connect and after every save; `ping` → `pong` |

A wrong token and an unknown mailbox get the same 401. Limits: 4 MiB per
file, 60 saves a minute, 32 devices, 32 open watchers, 5 unused tickets per
mailbox. Requests to one mailbox run one at a time inside its Durable
Object, so the version check and the write cannot interleave.

## How `vault-sync` keeps the two sides equal

- It watches the mailbox over the WebSocket (pinging every 50 s, which the
  server answers without waking up) and also asks every 15 minutes, or every
  30 seconds when the WebSocket cannot connect.
- Every second it checks whether `vaultd` wrote `cloud/vault.svault`. If so
  it saves the file on top of the version it last saw.
- **Another device saved first** (412): it downloads that version into
  `cloud/vault.svault`. `vaultd` merges it with this device's edits within
  5 seconds (the normal merge, format.md 5.1) and writes the copy again,
  which `vault-sync` then saves. Nothing is lost; two devices editing the
  same item get the usual "(conflict)" copy.
- A change from the server is written to the copy atomically, under a
  temporary name `vaultd` ignores.

A change on one device reaches another unlocked device in about 5 to 10
seconds, mostly `vaultd`'s own folder check.

## Cost

Everything fits the Workers Free plan: about 100,000 requests a day and 5 GB
of Durable Object storage. One device uses a few hundred requests a day
(each save, each change notice, a check every 15 minutes). No card is
needed.

## Updating the server

`vault cloud status` compares the server's `revision` with the copy built
into this program. `vault cloud update` uploads the newer code with the
same admin key; mailboxes and devices stay.

## Platform differences

| | Linux | Windows | macOS | iPhone, iPad, Android |
| --- | --- | --- | --- | --- |
| `vault cloud` commands | Yes | Yes | Yes | Not yet (next pull request) |
| `vault-sync` helper | In the `.deb` and `.tar.gz`; systemd user unit `vault-sync.service`, or `vault-sync@you` next to the system service | Not in the installer yet; build it and start it at sign-in (Startup folder) | Not in the `.pkg` yet; build it and run it | n/a |
| Desktop app screen | Not yet (next pull request) | Not yet | Not yet | n/a |

## Limits

- Merging happens on unlocked devices only, as with folder sync.
- The server sees when devices sync, from which addresses, and the padded
  file size.
- The server cannot read or change the vault, but it (or someone with your
  Cloudflare account) can withhold or delay copies, and delete them. Each
  device keeps its own file, so nothing is lost locally.
- Family sharing is not part of this; it is planned as shared collections
  with their own keys.
