# Desktop app

`vault-gui` is a window onto `vaultd`. It holds no keys and reads no vault
file: everything goes through the daemon's socket as a paired client with
full scope, like the CLI.

## Build and run

    cargo run -p vault-gui

It needs a running `vaultd` (see vaultd.md) and, on Linux, a desktop with
X11 or Wayland and OpenGL (libGL, libxkbcommon-x11). To show it in the app
menu, install `contrib/desktop/dev.passwordvault.app.desktop` to
`~/.local/share/applications/` and put `vault-gui` on your PATH.

Like vaultd, it runs on Linux and Windows; macOS follows the daemon port.

## What it does

- First run with no vault: choose a master password, then the recovery code
  is shown once.
- First run with a vault: pair by proving any unlock method once, or press "Ask for approval" and allow it in the window vaultd opens. The token
  goes to `$XDG_CONFIG_HOME/vault/desktop-token` (0600), separate from the
  CLI's so either can be revoked alone. `VAULT_SOCKET` and
  `VAULT_DESKTOP_TOKEN_FILE` override the paths.
- Unlock with a password, password + security key, password + TPM, or the
  recovery code. Ctrl+L locks.
- Items: search, view, copy username, password or one-time code, show the
  password, add, edit (websites with match mode and http opt-in, TOTP secret
  or `otpauth://` link, notes), delete after a confirmation.
- Password generator, import (Bitwarden JSON, browser CSV) and unlock
  methods (list, add any kind, remove with a confirmation). Revoking with key
  rotation stays in the CLI: `vault revoke`.

## Safety

- Slow calls (Argon2, a key waiting for a touch) run on a worker thread so
  the window never freezes; one call at a time, in order.
- The app polls status every 2 seconds without its token, which does not
  count as activity, so the daemon's idle lock still fires and the window
  follows it.
- When the vault locks (button, idle, suspend, another client) the window
  drops every item, open detail, edit form, TOTP code and generated
  password it held.
- A copied secret is cleared from the clipboard after 30 seconds, on lock
  and on exit, unless something else was copied since. On Windows and macOS
  it is also marked to stay out of clipboard history and cloud sync.
- Secrets typed or shown pass through egui's text layout, which keeps its own
  short-lived copies that are not zeroized. This is the same limit as any
  toolkit; keep the window locked when you leave it.

## Tests

    cargo test -p vault-gui

They drive the real window headless through its accessibility tree
(egui_kittest) against an in-process daemon on a real socket: create, pair a
second window, unlock with a wrong then right password, add with a generated
password, copy, show, search, lock (clipboard cleared, items dropped),
import, add a TOTP seed, reject a bad seed, delete, add a recovery slot, a
stale token, idle lock and a missing daemon.
