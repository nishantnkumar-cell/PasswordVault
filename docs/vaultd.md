# vaultd and vault-cli

`vaultd` owns the vault file, holds keys only while unlocked, talks to FIDO2 keys and the TPM, and serves clients over a Unix socket. `vault` is the command-line client.

## Build and run (Linux)

```sh
sudo apt-get install libtss2-dev libudev-dev libhidapi-dev pkg-config   # Debian/Ubuntu
cargo install --path crates/vaultd && cargo install --path crates/vault-cli
cargo install --path crates/vault-gui    # the desktop app and vault-prompt, the pairing window
vaultd &                      # or: contrib/systemd/vaultd.service as a user service
vault init                    # master password; prints the recovery code once
vault add --generate
vault ls
vault add-slot fido2 --uv     # security key with PIN
vault add-slot tpm --pin --pcr7
```

Build without hardware support with `cargo build -p vaultd --no-default-features`.

## Paths

| What | Default |
| --- | --- |
| Vault file | `$XDG_DATA_HOME/vault/vault.svault` |
| Daemon state (generation counters, client token hashes, lock) | `$XDG_STATE_HOME/vault/` (0700) |
| Socket | `$XDG_RUNTIME_DIR/vault/vaultd.sock` (0600, directory 0700) |
| ssh-agent socket | `$XDG_RUNTIME_DIR/vault/ssh-agent.sock` (0600), see [`ssh.md`](ssh.md) |
| Client token | `$XDG_CONFIG_HOME/vault/token` (0600) |

## Protocol

`crates/vault-ipc`: each frame is a u32 little-endian length (max 16 MiB) and a postcard body. A client sends `Envelope { token, request }` and gets one `Response`.

- The server checks the peer's UID with `SO_PEERCRED` and refuses every other UID.
- `Status`, `Init` and `Pair` need no token, nor does `SetSync` while no vault exists (a new device joining a synced vault, docs/sync.md). `Pair` returns a 32-byte token; the daemon stores only its SHA-256. It is granted either by proving an unlock method (`method: Some`, which also unlocks) or, with `method: None`, by the user in an approval window the daemon opens itself (below).

## Pairing by approval

A client asks with no factor. vaultd runs `vault-prompt` (found next to `vaultd`, or at `VAULT_PROMPT`), which shows the name the client gave, what it would be allowed to do, and the program that connected (`/proc/<pid>/exe` from the socket's peer credentials, or the pipe client's image path on Windows). Deny has the focus, Escape denies and the window denies by itself after a minute. The client cannot answer: it only learns the outcome.

- One prompt at a time; a second request is refused while one is open.
- After a decline or a timeout, new requests are refused for 10 seconds, so a client cannot keep the window popping up.
- The program path is informational: on Linux the PID could be reused between connecting and the lookup (pidfd-based identification is still open), and a same-user program can always pose as another one.
- `--no-prompt` turns it off, and a daemon running as its own system user (`vaultd@.service`) never shows it, since it has no desktop: pairing there needs an unlock method.

The same window confirms each card the browser asks to fill (docs/browser.md, Cards and addresses), with the same one-at-a-time rule and cooldown.

`vault pair` and `vault-native-host --pair` use the prompt unless given a method (`--password`, `--fido2`, `--tpm`, `--recovery`; the host takes `--password`). The browser extension's Connect button and the desktop app's "Ask for approval" use it too.
- Tokens have a scope. `Full` is for the CLI. `Autofill` is for the browser's native host: it may unlock, lock, look up logins by origin, fetch one login or TOTP code only if that login may be filled on the given origin, list cards and identities and fetch one for an `https` page (a card only after the user confirms in vaultd's window), and generate passwords. It cannot list, export, edit or manage slots.

## Behaviour

- **Unlock** tries every enrolled slot of the requested kind. After 3 failures, each further failure doubles a wait (2 s up to 5 min) before the next attempt is accepted.
- **Auto-lock** after `--idle-secs` (default 900) without an authenticated request, and on SIGTERM, SIGINT or SIGHUP.
- **Rollback.** After every unlock and write the daemon records `(vault_id, generation)`. If an unlocked file's generation is lower, `status` warns and every write is refused.
- **Sync.** `SetSync { path }` turns folder sync on or off; the path is kept in the state directory with a random device ID. While unlocked the daemon merges the synced copy when it changes and writes it after every save. `SyncNow` merges at once. `Status` reports the path, the last merge, any problem and the conflict copies it merged. See docs/sync.md.
- **New slots** are test-unlocked from the file on disk before the command reports success. TPM slots are also unsealed once before enrollment.
- **Quick unlock** (Windows). `SetQuickUnlock { hours }` (1 to 24, 0 is off; asks for Windows Hello to turn on) is kept in the state directory. On any lock within `hours` of the last full unlock the daemon keeps the vault key parked in memory (format.md 4.6); `Unlock { method: Hello }` reopens it after Windows Hello verifies the user. Three failed checks, the window ending, `LockFully` or a daemon restart forget it. `Hello` is refused for `Pair` and anything else that proves a factor. `Status` reports the setting and, while locked, until when quick unlock is available.
- **TPM.** On Windows, see docs/windows.md: the secret is wrapped to a TPM-bound RSA key through the Platform Crypto Provider. On Linux: sealed under a transient ECC P-256 storage key; every seal and unseal runs in a session salted to that key with parameter encryption. With a PIN the object is subject to the TPM's dictionary-attack lockout. With `--pcr7`, a change to Secure Boot state makes the slot unusable until it is re-enrolled; use another slot to unlock and re-add it.
- **Hardening.** `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at start. Secrets in the protocol and the item model are zeroized on drop.

## Secret Service (Linux)

With `--secret-service` (not on by default), vaultd takes `org.freedesktop.secrets` on the
session bus and serves the freedesktop Secret Service API:

- One collection, `/org/freedesktop/secrets/collection/vault` ("Vault"),
  also `/org/freedesktop/secrets/aliases/default`. `CreateCollection` with
  alias `default` returns it; other collections are refused.
- Sessions: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`. A session is
  usable only by the bus connection that opened it and closes when that
  connection goes away.
- Only items created through the API are visible: logins with a custom
  field named `Secret Service` (content type) and `ss:<attribute>` fields.
  Non-UTF-8 secrets are stored base64 with a `Secret Service encoding`
  field. No item schema change, so older vaultd versions read these items.
- Each caller's executable (from `GetConnectionUnixProcessID`) must be
  allowed in vault-prompt (`--secret-service [--command LINE] [--program
  PATH]`) before it can list items or read, write or delete them. Allowed
  programs are kept in memory until vaultd exits; a decline holds for 60 s.
  Callers whose bus UID differs from the owner are refused. As the brief
  says, the sender's identity is advisory against same-user programs.
- Locked vault: `SearchItems` returns nothing, item access fails with
  `IsLocked`, `Unlock` returns a prompt whose `Prompt()` starts the desktop
  app (`VAULT_GUI`, else `vault-gui` next to vaultd) and completes when the
  vault is unlocked by any means, within 5 minutes. `Lock` locks the vault.
- Secret Service calls don't reset the idle timer.
- Not served when another process owns the name, or when vaultd runs as a
  separate system user (no session bus).

## Running as a separate system user

`contrib/systemd/vaultd@.service` runs the daemon as the `vault` user, one instance per person (`vaultd@yourname`), with the vault in `/var/lib/vault/yourname/` and the socket at `/run/vault/yourname/vaultd.sock`. The socket is world-connectable, and the daemon accepts only the UID named by `--owner-user`. Install steps are at the top of the unit file. Set `VAULT_SOCKET` for `vault` and the browser host. The unit expects a `tss` group for the TPM; remove `SupplementaryGroups=tss` on distributions without one.

`contrib/udev/70-vault-fido.rules` gives the `vault` group access to FIDO2 keys (it relies on systemd's `ID_FIDO_TOKEN` tagging), while your own session keeps access too.

## Memory and session locking

- With `RLIMIT_MEMLOCK` unlimited (both units set `LimitMEMLOCK=infinity`), all daemon memory is locked with `mlockall`, so keys never reach swap. With a lower limit it warns and continues unlocked, because locking would make large Argon2id allocations fail.
- With the default `logind` feature, the daemon listens on the system bus and locks when logind announces suspend (`PrepareForSleep`) or any session `Lock`. Signals from anything other than logind's bus name are ignored.

## Checking a FIDO2 key

On Linux, macOS or Windows, with the key plugged in:

```sh
cargo run -p vault-hw --example fido2-check
```

It creates throwaway credentials, asks for hmac-secret twice in touch-only mode and, if you give a PIN, twice with the PIN, and prints PASS if the key returns the same secret each time. Touch the key whenever it blinks. On Linux it needs `libudev-dev` and `libhidapi-dev`, and access to `/dev/hidraw*`.

## Not done yet

- Identifying the pairing client by pidfd (`SO_PEERPIDFD`) instead of its PID.
- vaultd on macOS (the FIDO2 check already runs there). Windows: see windows.md.
- Secret Service: approvals can't be listed or revoked, and nothing is imported from GNOME Keyring or KWallet.
- The desktop app (docs/desktop.md) has no file picker for imports and no revoke; use the CLI for revoke.
