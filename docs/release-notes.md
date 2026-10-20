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

### vault-gpg: git, pass and mail with OpenPGP keys in the vault

- **New program, `vault-gpg`.** Programs that run `gpg` can run
  `vault-gpg` instead and use the OpenPGP keys in your vault. Signing and
  decrypting still happen inside `vaultd`, with the usual approval window;
  the secret key never leaves it.
- **Sign git commits and tags with an OpenPGP key**
  (`git config --global gpg.program vault-gpg`). GitHub and GitLab show
  them as *Verified* once you add your public key there, and
  `git log --show-signature` checks them locally.
- **A `pass` password store** encrypted to a vault key: `pass init`,
  `insert`, `show`, `generate`, `grep` and re-encrypting all work.
- **NeoMutt and Mutt** can sign, encrypt, decrypt and check signatures, with
  a ready-made command file in `contrib/neomutt/vault-gpg.rc`.
- **Other people's public keys** can be imported with
  `vault-gpg --import`, then used to encrypt to them and check their
  signatures.
- **Text signatures.** `vaultd` can now make text-mode signatures (gpg's
  `--textmode`), which mail needs so a signature still checks after line
  endings change in transit.

Platform notes: Linux: git, pass and NeoMutt, tested with git 2.43, pass
1.7.4 and GnuPG 2.4. Windows: git signing should work the same way
(`vault-gpg.exe`), but it has only run in CI so far, not on a real
machine; `pass` and NeoMutt are Unix programs. macOS: not yet, because
`vaultd` does not run there yet.

Known gaps: Evolution, KMail and Thunderbird with GnuPG keys still cannot
use vault keys (they need GnuPG's agent services, not the `gpg` command).
Clear-signed messages and password-only encryption are not supported. A
message that is both signed and encrypted decrypts, but its inner
signature is not checked. Checking signatures by your own vault keys needs
the vault unlocked.

How to use it: [Programs that call gpg](user-guide/09-gpg-programs.md).

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
on macOS once the app supports it. TPM unlock is Linux only, and security
keys on Windows need vaultd running as administrator.

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
