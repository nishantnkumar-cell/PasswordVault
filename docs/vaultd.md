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
| Client token | `$XDG_CONFIG_HOME/vault/token` (0600) |

## Protocol

`crates/vault-ipc`: each frame is a u32 little-endian length (max 16 MiB) and a postcard body. A client sends `Envelope { token, request }` and gets one `Response`.

- The server checks the peer's UID with `SO_PEERCRED` and refuses every other UID.
- `Status`, `Init` and `Pair` need no token. `Pair` returns a 32-byte token; the daemon stores only its SHA-256. It is granted either by proving an unlock method (`method: Some`, which also unlocks) or, with `method: None`, by the user in an approval window the daemon opens itself (below).

## Pairing by approval

A client asks with no factor. vaultd runs `vault-prompt` (found next to `vaultd`, or at `VAULT_PROMPT`), which shows the name the client gave, what it would be allowed to do, and the program that connected (`/proc/<pid>/exe` from the socket's peer credentials, or the pipe client's image path on Windows). Deny has the focus, Escape denies and the window denies by itself after a minute. The client cannot answer: it only learns the outcome.

- One prompt at a time; a second request is refused while one is open.
- After a decline or a timeout, new requests are refused for 10 seconds, so a client cannot keep the window popping up.
- The program path is informational: on Linux the PID could be reused between connecting and the lookup (pidfd-based identification is still open), and a same-user program can always pose as another one.
- `--no-prompt` turns it off, and a daemon running as its own system user (`vaultd@.service`) never shows it, since it has no desktop: pairing there needs an unlock method.

`vault pair` and `vault-native-host --pair` use the prompt unless given a method (`--password`, `--fido2`, `--tpm`, `--recovery`; the host takes `--password`). The browser extension's Connect button and the desktop app's "Ask for approval" use it too.
- Tokens have a scope. `Full` is for the CLI. `Autofill` is for the browser's native host: it may unlock, lock, look up items by origin, fetch one item or TOTP code only if that item may be filled on the given origin, and generate passwords. It cannot list, export, edit or manage slots.

## Behaviour

- **Unlock** tries every enrolled slot of the requested kind. After 3 failures, each further failure doubles a wait (2 s up to 5 min) before the next attempt is accepted.
- **Auto-lock** after `--idle-secs` (default 900) without an authenticated request, and on SIGTERM, SIGINT or SIGHUP.
- **Rollback.** After every unlock and write the daemon records `(vault_id, generation)`. If an unlocked file's generation is lower, `status` warns and every write is refused.
- **New slots** are test-unlocked from the file on disk before the command reports success. TPM slots are also unsealed once before enrollment.
- **TPM.** Sealed under a transient ECC P-256 storage key; every seal and unseal runs in a session salted to that key with parameter encryption. With a PIN the object is subject to the TPM's dictionary-attack lockout. With `--pcr7`, a change to Secure Boot state makes the slot unusable until it is re-enrolled; use another slot to unlock and re-add it.
- **Hardening.** `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at start. Secrets in the protocol and the item model are zeroized on drop.

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
- The desktop app (docs/desktop.md) has no file picker for imports and no revoke; use the CLI for revoke.
