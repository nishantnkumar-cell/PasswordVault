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

### Security keys in the desktop app on Windows

- **No PIN box on Windows.** On Windows, Secret Vault reaches security keys
  through Windows' own security key service, which shows its own window for
  the touch and the key's PIN. The desktop app now leaves out the **PIN**
  box for security keys there, on the lock screen and under **Add a
  method**, and says that Windows will ask. Before, the box was shown but
  what you typed in it was ignored.
- **A hint for keys with a PIN.** Under **Add a method**, **Security key**
  now explains on Windows that a key with a PIN needs **Also ask for the
  key's PIN every time** ticked, because Windows always checks that PIN and
  a touch-only method then can't work.
- **How to use it:**
  [Add a security key](user-guide/02-unlocking.md#add-a-security-key-fido2)
  and [Unlock methods](user-guide/05-desktop-app.md#unlock-methods).
- **Platforms.** Windows only. Linux keeps the PIN box, because there
  Secret Vault talks to the key directly and passes the PIN itself. The app
  does not run on macOS yet.
- **Not yet.** On Windows 10 builds too old for Windows' security key
  service (WebAuthn API version 4), vaultd falls back to direct USB access,
  which needs administrator rights and the PIN from the app; use the
  `vault` command there for slots with a PIN.

### Make SSH and OpenPGP keys in the desktop app

- **New keys without the command line.** **New item** now also offers
  **SSH key** and **OpenPGP key** (the Ctrl K palette has **New SSH key**
  and **New OpenPGP key** too). A short form asks for a title (and, for
  OpenPGP, your name and email), the kind of key and whether to ask before
  each use; **Make key** makes it and opens it with **Copy public key**
  ready. The key is made inside `vaultd`, so its private half never reaches
  the app, the screen or a file.
- **The same choices as the command line.** SSH: Ed25519 (recommended) or
  ECDSA P-256, like `vault ssh new [--ecdsa]`. OpenPGP: classic (v4
  Ed25519/Curve25519, works with GnuPG and Thunderbird) or post-quantum (v6
  ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519, which GnuPG 2.4 cannot
  read), like `vault pgp new [--pq]`. Each choice explains itself on the
  form. **Ask before each use** is ticked by default, as on the command
  line.
- **How to use it:**
  [Make a new key](user-guide/05-desktop-app.md#make-a-new-key).
- **Platforms.** Works the same on Linux and Windows. The app does not run
  on macOS yet.
- **Not yet.** Importing existing keys, exporting a private key, and
  encrypting, decrypting or signing with OpenPGP still use `vault ssh` and
  `vault pgp`.

### Desktop app: key details, Unlock methods and Sync pages

- **SSH and PGP keys show what you need.** Selecting a key now shows its
  type and fingerprint, its public key with a **Copy public key** button
  (the line for `authorized_keys` or GitHub, or the armored block for an
  OpenPGP key), and an **Ask before each use** tick box that does the same
  as `vault ssh confirm` and `vault pgp confirm`. The empty box and the
  autofill box that keys used to show are gone. The private key is still
  never shown. How to use it:
  [SSH and PGP keys](user-guide/05-desktop-app.md#ssh-and-pgp-keys).
- **Unlock methods page, redone.** Each method has its own row that says
  what it needs (password, security key, this computer's TPM, recovery
  code) instead of a raw slot ID. A line under the list says how many ways
  you have to unlock, and turns orange when there is only one. Each choice
  under **Add a method** explains itself before you fill it in. See
  [Unlock methods](user-guide/05-desktop-app.md#unlock-methods).
- **Sync page, redone.** A green or red dot shows at a glance whether sync
  is on and working, "Last synced" reads like "3 seconds ago", and
  conflicts and leftover copies are grouped in a **Needs a look** box. See
  [chapter 10](user-guide/10-sync.md#turn-it-on-on-the-first-device).
- **Steadier item details.** Only secrets (passwords, card numbers,
  security codes, one-time codes) and keys use the code font; names,
  usernames and dates use the normal font.
- **Platforms.** Everything here works the same on Linux and Windows. The
  Windows Hello box on the Unlock methods page shows only on Windows. The
  app does not run on macOS yet.
- **For developers.** `ItemSummary` gains `key_confirm`, so clients can show
  whether a key asks before each use. Clients and `vaultd` must be updated
  together.

### TPM unlock and Windows Hello quick unlock on Windows

- **TPM slots on Windows.** `vault add-slot tpm` (or **Unlock methods**,
  then **TPM**, in the desktop app) now works on Windows too, with the same
  options as on Linux: an optional TPM PIN, which the TPM protects against
  guessing, and `--pcr7` to tie the slot to the Secure Boot state. It needs
  no administrator rights. Like every TPM slot, it opens only on the
  computer that made it, so a stolen copy of the vault file is useless even
  with your password.
- **Quick unlock with Windows Hello.** After you unlock with your password
  (or a security key, TPM or recovery code), Windows Hello can open the
  vault again each time it locks, for 1 to 24 hours that you choose. Turn
  it on with `vault quick-unlock 8`, or under **Unlock methods** in the
  desktop app. Then `vault unlock --hello`, or **Unlock with Windows
  Hello** on the app's lock screen, asks for your face, fingerprint or
  Windows PIN. It is off by default.
- **Limits that keep the password in charge.** Quick unlock ends when its
  time is up, when the computer restarts or `vaultd` stops, after three
  failed or cancelled Windows Hello checks, and with `vault lock --full`.
  Windows Hello never pairs an app, exports a key or revokes a slot.
- **Check your hardware first** from the source folder with
  `cargo run -p vault-hw --example tpm-check` and
  `cargo run -p vault-hw --example hello-check`. Neither stores anything.

Platform notes: Windows: both new features, no administrator rights. The
Windows TPM is used through Windows' own TPM service, so a TPM slot made
under Windows doesn't open under Linux on the same dual-boot computer, or
the other way round; add one from each. Linux: TPM slots work as before;
there is no Windows Hello equivalent yet. macOS: not yet, because `vaultd`
does not run there yet; Touch ID and the Secure Enclave are planned to
work the same way. Security keys on Windows were already supported without
administrator rights (through Windows' own security key service) and are
unchanged.

Known gaps: while quick unlock is available, the vault key stays in
`vaultd`'s memory (encrypted, with the key to it protected by Windows), so
malware running as you could still reach it, as it could while the vault
is unlocked. The quick unlock time counts in wall-clock time, so time
asleep counts too. CI runners have no TPM or Windows Hello. Both the TPM
slot and Windows Hello quick unlock were checked on a real Windows 11 PC,
including a quick unlock confirmed with a real Windows Hello check.

How to use it: [Add the TPM](user-guide/02-unlocking.md#add-the-tpm) and
[Quick unlock with Windows Hello](user-guide/02-unlocking.md#quick-unlock-with-windows-hello-windows).

### Sync one vault across your devices

- **Sync through a folder you already have.** Point Secret Vault at a file
  in a folder that OneDrive, Google Drive, Dropbox, Syncthing or a network
  share keeps in sync (`vault sync on PATH`, or **Sync** in the desktop
  app's sidebar). Each device merges its changes with that file while it is
  unlocked and before every save.
- **Join from a new device** without copying files: on a device with no
  vault, `vault sync on PATH` (or **Join** on the app's first screen), then
  unlock with your master password.
- **Edits on two devices are merged, not overwritten.** If both devices
  change the same item, the newer edit wins and the other is kept as a
  *(conflict)* copy. Deleted items stay deleted. Unlock methods added on any
  device work on all of them, except a TPM, which belongs to one computer.
- **Cloud conflict files** such as `vault (1).svault` are merged too and
  listed as safe to delete.
- **Revoking an unlock method** re-keys the vault on every device at its
  next unlock.
- The cloud service sees only the encrypted file; it gets no account
  details or keys from Secret Vault.

Platform notes: Linux and Windows work the same, and a vault synced between
them is the same file. On Windows, mark the file *Always keep on this
device* in OneDrive or Google Drive. macOS: not yet, because `vaultd` does
not run there yet.

Known gaps: merging happens only on an unlocked device. Every save uploads
the whole file. Conflicts are decided by each device's clock. A device that
is never unlocked again keeps the old key after a revoke. A vault saved by
this version can't be opened by older builds of Secret Vault.

How to use it: [Sync between devices](user-guide/10-sync.md).

### Secure notes, cards and identities

- **Four kinds of item.** Besides logins, the vault now keeps **secure
  notes**, **payment cards** and **identities** (name, email, phone and
  postal address). Any item can also carry **custom fields**, plain or
  hidden like a password.
- **Cards** keep the name on the card, number, expiry, security code and
  PIN. A typo in the number is caught by its checksum, and the card's
  network (Visa, Mastercard, Amex and others) is recognised from its first
  digits. Lists show only the network and the last four digits.
- **Secure notes are hidden** until you press **Show**, in the desktop app
  and with `vault show --reveal`, because notes often hold secrets.
- **Fill cards and addresses in the browser.** On a checkout or address
  form the popup lists **Cards** and **Addresses**. A card is filled only
  after you press **Allow** in the Secret Vault window, which names the card
  and the site.
- **Desktop app:** the sidebar filters by **Logins**, **Secure notes**,
  **Cards** and **Identities**, and **New item** asks which kind to make.
- **Command line:** `vault add card` (or `note`, `identity`) and
  `vault ls cards` (or `logins`, `notes`, `identities`).
- **Bitwarden import** now brings cards, identities and custom fields too.

Platform notes: the same on Linux and Windows. The card approval window
needs a desktop session, so a `vaultd` started with `--no-prompt`, or
running as a separate user, cannot fill cards. macOS: not yet, because
`vaultd` does not run there yet.

Known gaps: card fields inside a payment provider's own frame (common with
Stripe-style checkouts) are not filled yet. Addresses are filled only into
the page's top frame. The extension does not save new cards or addresses
from forms. Items saved by this version use item schema 3, which older
builds of Secret Vault cannot read; older items are upgraded when next
saved.

How to use it: [Item types](user-guide/03-items.md#item-types) and
[Fill a card or an address](user-guide/04-browser-autofill.md#fill-a-card-or-an-address).

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
1.7.4 and GnuPG 2.4. Windows: the installer includes `vault-gpg.exe`, and
git signing should work the same way, but it has only run in CI so far, not on a real
machine; `pass` and NeoMutt are Unix programs. macOS: not yet, because
`vaultd` does not run there yet.

Known gaps: Evolution, KMail and Thunderbird with GnuPG keys still cannot
use vault keys (they need GnuPG's agent services, not the `gpg` command).
Clear-signed messages and password-only encryption are not supported. A
message that is both signed and encrypted decrypts, but its inner
signature is not checked. Checking signatures by your own vault keys needs
the vault unlocked.

How to use it: [Programs that call gpg](user-guide/09-gpg-programs.md).

### App icon: a keyhole on a red tile

- **Secret Vault has its own icon.** A white keyhole on a signal-red tile
  replaces the generic padlock (Linux) and the default program icon
  (Windows). It shows in the title bar, the taskbar or dock, the window
  switcher, the Start menu and applications menu, and the approval window
  `vaultd` opens.
- **Made for small sizes.** At 48 px and below the icon drops its halo and
  ring and draws a bigger keyhole on a full tile, so it stays clear in the
  system tray and title bar.
- **One source, every format.** `contrib/icons/generate.py` draws the icon
  and exports it for each system; the files are in `contrib/icons/`.

Platform notes:

- **Windows:** the icon is built into `vault-gui.exe` and `vault-prompt.exe`,
  so the Start menu shortcut, taskbar and Explorer show it, and the installer
  (`SecretVault-Setup-<version>.exe`) uses it too. Nothing to do: install or
  upgrade as usual.
- **Linux:** the icon ships as a hicolor theme folder (PNG from 16 to 512 px,
  a scalable SVG and a one-colour *symbolic* version for GNOME), and the
  `.desktop` file now asks for it by the app id `dev.passwordvault.app`.
  Copy the folder once to see it in your applications menu and dock. On
  Wayland the dock and window switcher take the icon from the `.desktop`
  file, not from the window, so the copy step matters there.
- **macOS:** a `.icns` file with the padding macOS expects is included for
  when the desktop app comes to macOS; the app does not run there yet.

How to use it: [desktop app, adding it to your menu](user-guide/05-desktop-app.md#start-it).

### Build tools and dependencies brought up to date

This changes nothing in how the vault works or in the vault file. It matters
if you build Secret Vault yourself or run its tests.

- **Rust.** The project now builds and is tested with Rust 1.99, the latest
  stable release. Run `rustup update` before building if your Rust is older
  ([getting started](user-guide/01-getting-started.md)). Same on Linux,
  Windows and macOS.
- **Rust libraries.** All dependencies were moved to their newest compatible
  releases, and the daemon's signal handling library moved to `signal-hook`
  0.4 (Linux and macOS only; Windows does not use it). Three stay where they
  are on purpose: `zbus` stays on 5.x (Linux only) because 6.0, out on
  2026-10-16, dropped the blocking API the screen-lock watcher uses; `rand`
  0.8 and `signature` 2 stay because the OpenPGP and SSH libraries
  (`pgp` 0.21, `ssh-key` 0.6, both their latest stable releases) are built
  on them.
- **Node.js for the extension tests** is now Node.js 24, the current LTS
  (it was 22). `extension/package.json` declares it. The extension
  itself runs in the browser and does not use Node.js.
- **Windows installer.** The script compiles with Inno Setup 7 (the newest
  release) and with Inno Setup 6. CI builds it with the newest Inno Setup
  that Chocolatey offers, which is 6.7.1 today, and moves to 7 when
  Chocolatey does. The installer behaves the same either way.
- **CI** uses the current `actions/checkout`, `actions/setup-node` and
  `actions/upload-artifact` (v7), which run on Node.js 24. This removes the
  GitHub warning that Node.js 20 actions are deprecated.

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
  unlocks on Windows and the other way round. If your key has a PIN, use a
  slot that asks for it (`--uv`): Windows always checks the PIN of such a
  key, so touch-only slots can't work with it on Windows.
- **Touch-only slots on keys with a PIN** (all systems). Many security keys
  with a PIN set refuse to register a credential without it, so adding a
  touch-only slot failed with `PIN_REQUIRED`. The `vault` command now asks
  for the PIN (Enter if the key has none) and uses it only to register; you
  still unlock that slot with a touch.
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
