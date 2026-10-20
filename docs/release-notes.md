# Release notes

Each change to the design or features adds an entry here, newest first, in
the same pull request as the change. The [user guide](user-guide/README.md)
is updated in that pull request too.

An entry says what you can now do, how to start using it (with a link to the
guide), what differs between Linux, Windows and macOS, and what is known not
to work yet.

> Status: not audited. Do not trust the vault with real secrets yet.

---

## Unreleased

### Windows: installer, background start and security keys without admin

- **Installer.** `SecretVault-Setup-<version>.exe` installs the daemon, the
  desktop app, the `vault` command and the browser host. By default it
  installs for you only, into `%LOCALAPPDATA%\Programs\Secret Vault`, and
  needs no administrator rights. Choose *Install for all users* on its first
  page to install into Program Files instead: Windows asks for an
  administrator once, during setup, and never again.
- **Starts at sign-in, with no window.** The installer adds a sign-in entry
  that runs the new `vaultw.exe`, which starts vaultd in the background
  without a console window. vaultd always runs as you, never as
  administrator, even after an all-users install. Its messages go to
  `%LOCALAPPDATA%\vault\state\vaultd.log`.
- **Security keys without administrator rights.** vaultd now talks to
  security keys through Windows' own WebAuthn service, so it no longer has
  to run as administrator. Windows shows its own window for the touch and,
  if the slot needs it, the key's PIN. A security key slot made on Linux
  unlocks on Windows and the other way round.
- **No console windows.** The desktop app and the approval window no longer
  open a console window behind them.
- **Uninstall** from *Settings > Apps*. It stops vaultd and removes the
  programs, the sign-in entry and the PATH entry, but keeps your vault file.

Platform notes: Windows only; Linux keeps using the systemd unit and macOS is
not supported yet. Security keys without administrator rights need Windows 11
or an up-to-date Windows 10 (WebAuthn API version 4); on older builds vaultd
falls back to direct USB access, which still needs administrator rights. The
installer is not code-signed yet, so SmartScreen warns before running it.

How to use it: [installing and running on Windows](user-guide/windows-install.md).

### Desktop app: new layout and command palette

- **Three-column window.** A sidebar on the left holds the vault status,
  filters and tools; the item list sits in the middle; the item you picked
  is on the right. Before, the app had a tab bar and a two-column view.
- **Filters.** The sidebar shows *All items*, *Logins*, *One-time codes* or
  *SSH and PGP keys*. Rows carry a **2FA** or **Key** tag.
- **Command palette.** Press Ctrl K, type part of a name and press Enter to
  copy that item's password. The palette also copies user names and
  one-time codes, opens items, and runs vault actions such as *Lock now*,
  *New item* and *Generate a password*.
- **Clearer item details.** Fields sit in cards. One-time codes show a
  countdown ring that turns orange in the last five seconds. The websites
  autofill may use are listed under *Autofill is bound to*. Key items show
  their fingerprint and never their private key.
- **Unlock card.** The locked window lists each unlock method with a short
  description of what it needs.
- **New look.** Light theme with one blue accent, larger default window
  (1180 × 740).

Platform notes: Linux and Windows. Ctrl K and Ctrl L become Cmd K and Cmd L
on macOS once the app supports it. TPM unlock is Linux only.

How to use it: [the desktop window and command palette](user-guide/desktop-window-and-palette.md).

---

## 0.1.0: first feature-complete version (2026-10-20)

This entry covers everything built so far: pull requests #1 to #11 on `main`.

### Platform support at a glance

| Feature | Linux | Windows 10/11 | macOS |
|---|---|---|---|
| Vault daemon (`vaultd`) and `vault` command | Yes | Yes | Not yet |
| Desktop app (`vault-gui`) | Yes | Yes | Not yet |
| Browser autofill | Chrome, Chromium, Edge, Firefox 128+ | Chrome, Edge, Firefox 128+ | Not yet |
| Unlock with password, recovery code | Yes | Yes | Not yet |
| Unlock with password + FIDO2 security key | Yes | Only when `vaultd` runs as administrator | Not yet (the key check tool runs) |
| Unlock with password + TPM | Yes | Not yet | Not applicable (Secure Enclave planned) |
| Windows Hello, Touch ID / Secure Enclave, phone passkey | Not yet | Not yet | Not yet |
| SSH agent and git commit signing | Yes, tested with OpenSSH 9 | Yes, untested on real hardware | Not yet |
| OpenPGP keys (`vault pgp`) | Yes, tested with GnuPG 2.4 | Builds and passes tests | Not yet |
| Lock on screen lock and suspend | Yes (logind) | Yes (session and power notifications) | Not yet |
| Keys kept out of swap and core dumps | Yes | Not yet | Not yet |
| Run as a separate system user | Yes (systemd unit) | No | Not yet |

### New features

**Vault file and unlock methods.** One encrypted file holds everything
(XChaCha20-Poly1305, Argon2id, a keyed header MAC and key commitment). You
can unlock it several ways, each one a separate *slot*: master password,
password plus a FIDO2 security key, password plus the computer's TPM (with
an optional PIN and an optional Secure Boot binding), and a recovery code
shown once when the vault is created. Slots can be added and removed, and
`vault revoke` rotates the vault key to cut off a lost factor completely.
See [Unlocking](user-guide/02-unlocking.md).

**Items.** Logins with a title, username, password, one or more websites,
an optional one-time code (TOTP) and notes. Each website is matched either
by exact origin or by the whole site including subdomains.
See [Items](user-guide/03-items.md).

**One-time codes (TOTP).** Store the secret or the `otpauth://` link from a
site's QR code; the vault produces the 6 to 8 digit code. SHA-1, SHA-256
and SHA-512 are supported.

**Password generator.** 8 to 256 characters, with or without symbols, and
optionally without look-alike characters. Available in the CLI, the desktop
app and the browser popup.

**Import.** From a Bitwarden unencrypted JSON export, or a password CSV
exported from Chrome, Edge, Firefox or Safari.

**`vaultd` and the `vault` command.** The daemon holds keys only while the
vault is unlocked, locks itself after 15 minutes idle, slows down guessing
after 3 wrong attempts, and refuses to write if someone swaps in an older
copy of the vault file. Every program that talks to it must be *paired*
first. See [Getting started](user-guide/01-getting-started.md).

**Pairing by approval.** A new program (the CLI, the desktop app, the
browser) can ask to be paired, and `vaultd` opens its own window naming the
program so you can allow or deny it. Proving an unlock method instead also
works.

**Browser autofill.** An extension for Chrome, Edge, Firefox and (on
Linux) Chromium that fills a login only when you ask, only on the website
the login belongs to, and only into visible fields. Logins in frames from other sites are
filled only after you pick the site. One-time codes and generated passwords
can be copied from the popup. See [Browser autofill](user-guide/04-browser-autofill.md).

**Desktop app.** A window for everything the CLI does except SSH and OpenPGP
keys and key rotation: create the vault, unlock, browse and edit items, copy
secrets (cleared from the clipboard after 30 seconds), generate passwords,
import and manage unlock methods. See [Desktop app](user-guide/05-desktop-app.md).

**Windows port.** `vaultd`, `vault`, the desktop app and the browser host
run on Windows 10 and 11 over a named pipe that only your account can open.
The vault file is the same on every system.
See [Getting started](user-guide/01-getting-started.md#windows).

**SSH keys and git signing.** Generate or import Ed25519 and ECDSA P-256
keys; `vaultd` serves them over the standard ssh-agent protocol, so `ssh`
and `git` use them without a key file in `~/.ssh`. Each use asks for your
approval by default. See [SSH and git signing](user-guide/06-ssh-and-git.md).

**OpenPGP keys (`vault pgp`).** Generate or import keys and sign, verify,
encrypt and decrypt with them while the secret key stays in the vault.
Classic keys work with GnuPG and Thunderbird; `--pq` makes a post-quantum
hybrid key (ML-DSA-65 + Ed25519, ML-KEM-768 + X25519).
See [OpenPGP](user-guide/07-openpgp.md).

**Licence.** The project is licensed under the PolyForm Noncommercial
License 1.0.0: free for personal, research, educational and other
noncommercial use; commercial use is not permitted. See [LICENSE.md](../LICENSE.md).

### Known limitations

- macOS: only the core library, import and the FIDO2 key check build there.
  The daemon, CLI, app and browser host are not ported yet.
- Windows: no TPM or Windows Hello unlock; security keys only with an
  elevated daemon; keys can reach the page file and crash dumps.
- No passkeys, Secret Service, phone unlock or sync yet.
- No command to unpair one program; see
  [Troubleshooting](user-guide/08-troubleshooting.md#unpair-a-program).
- The desktop app has no file picker for imports and cannot create,
  import or use SSH or OpenPGP keys.
- OpenPGP: messages up to 16 MiB; decrypting does not check signatures
  inside the message; no gpg-compatible front end for Evolution, KMail or
  Thunderbird yet; no key expiry, revocation or subkey management.
- SSH agent: no RSA keys; keys cannot be added with `ssh-add`.
- A FIDO2 security key with a PIN (`--uv`) has not been tested on real
  hardware yet; touch-only mode has.
