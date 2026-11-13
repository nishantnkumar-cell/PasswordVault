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

### Android app on the Releases page

- **Install the Android app without Google Play.** From `0.2.0-beta.2` on,
  each release (betas too) has `secret-vault-<version>-android.apk` for
  Android 9 and newer phones, tablets and foldables. Download it on the
  phone, allow your browser to install apps once, and tap **Install**. It is
  free, with no Google account and no store.
- **Updates install over the top.** Every APK is signed with the same
  project key, so a newer one installs over the old app and keeps your
  vault and quick unlock. The release description shows the key's SHA-256
  fingerprint, and the APK is in `SHA256SUMS.txt`, so you can check a
  download.
- How to start: [Install the Android app](user-guide/14-phone-apps.md#android).

| | Android | iPhone and iPad | Windows, Linux, macOS |
| --- | --- | --- | --- |
| On the Releases page | Yes, `.apk` (from 0.2.0-beta.2) | No, build from source | Yes, as before |
| One-time warning | Allow installing from your browser; Play Protect may ask you to confirm | n/a | As before |

Known limits: not on Google Play, and the app doesn't tell you about
updates (watch the Releases page instead). A copy installed earlier from a
GitHub Actions run or built by hand has a different signature, so Android
won't update it: sync, uninstall it and install the release APK. Google
has announced that certified Android phones will only install apps from
verified developers, rolling out country by country from late 2026; this
may later need an extra step or block sideloading in some countries. No
vault file change.

### iPhone and iPad: unlock methods, import, SSH keys and keyboard shortcuts

- **Change your unlock methods on the phone.** **Settings > Unlock
  Methods** now lets you change the master password, make a new recovery
  code (the old one stops working), and remove any unlock method, such as
  a security key you no longer use. Swipe left on a method to remove it.
- **Lost a device or key?** **Remove All Other Unlock Methods** gives the
  vault a new key, keeps only your master password, and shows a new
  recovery code. Every security key, TPM, phone passkey, other password and
  old recovery code stops working. Your other devices ask for the master
  password once, at their next sync.
- **Import from another password manager.** **Settings > Import from
  Another App** reads an export saved in Files: the CSV from Apple
  Passwords (with one-time codes), Chrome, Edge, Firefox or Safari, or
  Bitwarden's unencrypted JSON. Afterwards it offers to delete the export,
  which holds every password in plain text.
- **SSH and OpenPGP keys show their public half.** A key item now shows the
  key type, the fingerprint and the public key (or certificate), with
  **Copy** and **Share**. You can add an SSH key to GitHub or a server from
  the phone.
- **Make an SSH key on the phone.** **+ > SSH Key** makes an Ed25519 (or
  ECDSA P-256) key in the vault. After the vault syncs, your computer's
  vault daemon offers it to `ssh` and `git`.
- **Keyboard shortcuts on iPad.** With a keyboard attached, the iPadOS
  menu bar lists them, and holding ⌘ shows them: ⌘N new login, ⌘F search,
  ⌘E edit, ⇧⌘C copy password, ⌥⌘C copy username, ⌃⌘C copy one-time code,
  ⌘R sync now, ⌘L lock, ⌥⌘N new window.
- How to start: [Change unlock methods](user-guide/14-phone-apps.md#change-unlock-methods-on-the-phone),
  [Import](user-guide/14-phone-apps.md#import-from-another-app),
  [SSH and PGP keys](user-guide/14-phone-apps.md#ssh-and-pgp-keys-on-the-phone),
  [Keyboard shortcuts](user-guide/14-phone-apps.md#keyboard-shortcuts-on-ipad).

| | iPhone and iPad | Android | Windows, Linux, macOS |
| --- | --- | --- | --- |
| Change master password, new recovery code, remove a method | Yes (new) | Not yet | Yes |
| Remove all other methods (new vault key) | Yes (new) | Not yet | Yes (`vault revoke`) |
| Add a security key, TPM or phone passkey | No | No | Yes |
| Import from another password manager | Yes (new), from Files | Not yet | Yes |
| Show and share a key's public half | Yes (new) | Not yet | Yes |
| Make a key | SSH (new) | No | SSH and OpenPGP |
| Use a key for SSH, Git or OpenPGP | No | No | Yes |

Known limits: OpenPGP keys can't be made on the phone (make them in the
desktop app). The phone never shows or exports a private key. The phone
can't remove its own last master password, because that is how it
unlocks. Android gets these screens later; its app is unchanged. No vault
file change: a vault changed on the phone opens everywhere as before.

### macOS: locks with the screen, and copied passwords stay on the Mac

- **The vault locks when your Mac does.** Locking the screen, putting the
  Mac to sleep, or switching to another account now locks the vault right
  away and wipes its keys from memory, as on Linux and Windows. Before, a
  Mac only locked after 15 idle minutes. With quick unlock on, Touch ID
  opens it again.
- **Copied secrets no longer reach your other Apple devices.** A password,
  code or card number copied in the desktop app is marked "this Mac only",
  so Universal Clipboard does not pass it to your iPhone, iPad or other
  Macs. Clipboard history apps still skip it, and it is still cleared after
  30 seconds.
- How to start: nothing to set up, install this version. Details in
  [When the vault locks by itself](user-guide/13-macos.md#when-the-vault-locks-by-itself)
  and [Copying passwords](user-guide/13-macos.md#copying-passwords).
- Linux and Windows: no change.
- Known limits: a `vaultd` started over SSH, outside your desktop session,
  only locks on sleep. Universal Clipboard is a macOS feature; Windows
  already kept copies off its cloud clipboard.

### Add a one-time code on the desktop and from the command line

- **Add Code on the desktop.** Open **One-time codes** in the sidebar and
  click **Add code** at the top right (in **All items**, it's under
  **New item ▾ > One-time code**; the Ctrl K palette has **Add a one-time
  code**). Paste the setup key or `otpauth://` link the site shows, or
  read the site's QR code from a screenshot: type the image's path and
  click **Read QR code**, or drag the image onto the window. The form
  shows the current code so you can finish the site's setup, then keeps
  the code on a new login or on a login you already have. When the QR
  code names the site, the title and username are filled in, and if
  exactly one of your logins fits, it is picked.
- **Add a code from the command line.** `vault code add` asks for the
  setup key or link without showing it (so it never lands in your shell
  history), prints the current code, and saves it on a new login.
  `--qr IMAGE` reads the QR code from a screenshot instead, `--to ID` puts
  the code on an existing login, and `--title` / `--account` name a new
  one. `vault code ls` lists every code with its current value.
- **Fix: a code added to a secure note on a phone was lost.** The phone
  apps offered secure notes as a place for a new code, but a note can't
  keep one, so the code was silently dropped when saved. Now only logins
  are offered, as on the desktop and command line.
- How to start: [Add a one-time code (desktop)](user-guide/05-desktop-app.md#add-a-one-time-code)
  and [One-time codes](user-guide/03-items.md#one-time-codes-totp).

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Paste a setup key or link | Yes | Yes | Yes |
| Read a QR code from an image file (PNG, JPEG, GIF, BMP) | Yes | Yes | Yes |
| Drag the image onto the window | X11 desktops; on Wayland, type the path instead | Yes | Yes |
| Quick way to take the screenshot | Print Screen (GNOME saves it in Pictures/Screenshots) | Win + Shift + S, then save it from the notification | Cmd + Shift + 4 (saves it on the Desktop) |
| `vault code add` / `vault code ls` | Yes | Yes | Yes |

Known limits: the desktop can't use a camera, and reads a QR code only from
a saved image, not straight from the screen or clipboard. Google
Authenticator's "Transfer accounts" QR code (`otpauth-migration://`) isn't
supported yet: add each code from its site. To swap the code a login
already has, edit the login (desktop) or use `vault code add --to ID
--replace`. Delete the screenshot afterwards: anyone with it can make your
codes. No vault file change.

### Sync with the Linux systemd service

- **Fixed in the docs, with an example file.** The shipped `vaultd.service`
  can write only its own folders, so the synced file in `~/Dropbox` or
  `~/OneDrive` was read-only to it and sync reported an error without saying
  why. The sync chapter now shows the two-line drop-in that allows the folder
  (`contrib/systemd/vaultd-sync.conf.example`).
- **Linux only.** Windows, macOS and a `vaultd` started from a terminal are
  not affected. Found by the November 2026 security review, together with the
  note that Linux clipboard managers can keep copied passwords (the clipboard
  library cannot mark them); a threat-model line now says so.

How to use it: [Sync, Linux notes](user-guide/10-sync.md#differences-between-systems).

### Linux fixes from testing in WSL

- **vaultd locks its memory on more systems.** It used to lock memory only
  when the lock limit was unlimited or at least 5 GiB. Now it first raises
  its own limit as far as the system allows, and 1.5 GiB is enough: the
  largest Argon2id buffer a vault can use (1 GiB) plus room for the rest.
  On WSL, the limit is set lower than that, so keys could reach swap there.
  vaultd says so at start, and
  [Memory locking](vaultd.md#memory-and-session-locking) shows how to raise
  the limit.
- **`vault ssh agent` prints the right socket.** With `VAULT_SOCKET` set
  (the system-user service, or a second test vault), it printed the default
  agent socket instead of the one vaultd was serving. A vaultd on its own
  socket now serves its agent next to it, and `vault ssh agent` prints that
  path. The system-user service's agent moves to
  `/run/vault/<you>/ssh-agent.sock`: run `vault ssh agent` again and update
  `SSH_AUTH_SOCK` in your shell profile if you set it by hand.
- **`vault ls` shows SSH and OpenPGP keys as keys**, not as logins with a
  `[key]` mark, and `vault ls keys` lists only them.

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Memory lock needs | 1.5 GiB lock limit (was 5 GiB) | Nothing (locks per block) | Not used (swap is encrypted) |
| `vault ssh agent` with `VAULT_SOCKET` | Fixed | Fixed | Fixed |

No vault file change.

### Signed Mac downloads, the iPhone app in TestFlight, and Secure Enclave unlock

- **Mac downloads open with a double-click.** The `.pkg` installer and the
  app in the `.tar.gz` are signed with the project's Apple Developer ID and
  notarized by Apple, so macOS no longer stops them and there is no **Open
  Anyway** step. This starts with the first release after `0.2.0-beta.1`.
- **iPhone and iPad app in TestFlight.** Every release is uploaded to
  App Store Connect, and invited testers install it from Apple's
  TestFlight app instead of building it in Xcode.
- **AutoFill on a real iPhone.** The TestFlight app can fill your
  passwords and one-time codes in Safari and other apps. (Apple doesn't
  allow AutoFill in apps built with a free account, which is what you had
  to use before.)
- **Unlock with the Mac's Secure Enclave.** A new "this device" unlock
  method on Macs with Apple silicon or a T2 chip: the master password plus
  a key that never leaves the Mac's security chip, so a copied vault file
  is useless on any other computer. It is the Mac version of the TPM unlock
  method on Linux and Windows. The enclave only does classical P-256
  cryptography, so the slot is built to keep the vault file safe from
  future quantum computers anyway: the file never holds the enclave key's
  public key.
- How to start: Mac downloads need nothing new. iPhone:
  [Install the iPhone and iPad app](user-guide/14-phone-apps.md#install-the-iphone-and-ipad-app).
  Secure Enclave: **Unlock methods > Add a method > Secure Enclave** in the
  desktop app, or `vault add-slot tpm`; see
  [Unlock with the Secure Enclave](user-guide/13-macos.md#unlock-with-the-secure-enclave).
  Maintainers: [Setting up the Apple Developer account](apple-account.md).

| | macOS | Windows | Linux | iPhone and iPad | Android |
| --- | --- | --- | --- | --- | --- |
| Signed downloads | Yes, Developer ID and notarized | Not yet (SmartScreen warns once) | Not needed | Through TestFlight | Signed with the project key, as before |
| Store | n/a | n/a | n/a | TestFlight now; App Store later | Not on Google Play |
| "This device" unlock method | Secure Enclave, no PIN | TPM, optional PIN and PCR 7 | TPM, optional PIN and PCR 7 | No | No |

Known limits: Windows code signing and Google Play need separate paid
accounts and are not done. The App Store listing needs Apple's review and
is a later step. A Secure Enclave slot works only on the Mac that made it:
erasing the Mac, a repair that replaces the logic board, or moving to a new
Mac with Migration Assistant means adding it again (keep your password and
recovery code). The enclave has no PIN with a guess limit, so `--pin` and
`--pcr7` are refused on a Mac. Intel Macs without a T2 chip have no Secure
Enclave. The vault file format only gains a new kind of device blob
(`VMSEP1`, [format.md](format.md) section 4.2); older versions see such a
slot as a TPM slot they can't open.

### Thunderbird signs and decrypts with your vault key

- **Use a vault OpenPGP key in Thunderbird without giving Thunderbird the
  key.** Thunderbird can treat a key as an "external GnuPG key"; point its
  GnuPG path at `vault-gpg` and it signs mail and opens encrypted mail with
  the key in your vault. The secret key stays in `vaultd`, and each
  signature or decryption opens the approval window. Encrypting to others
  and checking their signatures stays in Thunderbird, as before.
- **Signed-and-encrypted mail now has its signature checked** by
  `vault-gpg -d`, so NeoMutt and other programs that run gpg see whether it
  is good (import the sender's public key first).
- **Clear-signed and inline-signed messages.** `vault-gpg --clearsign` and
  `vault-gpg --sign` make them, and `vault-gpg --verify FILE` checks them.
- **New keys interoperate better.** Keys made from now on list preferred
  algorithms (SHA-512, AES-256 and others). Without them, GnuPG users
  sending you signed and encrypted mail signed it with SHA-1, which
  Thunderbird rejects as invalid.
- How to start: [Thunderbird](user-guide/09-gpg-programs.md#6-thunderbird)
  in the user guide. `contrib/thunderbird/gpgme-check.py` checks the set-up
  without Thunderbird.

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| What to install (free) | GPGME from the distribution (`libgpgme11`), usually there already | Gpg4win, plus its `bin_64` folder on the system `Path` | `brew install gpgme` |
| Tested | Thunderbird's GPGME calls with GPGME 1.18, results checked with RNP 0.17 and GnuPG 2.4 | Not yet | Not yet |

Known limits: not yet clicked through in Thunderbird itself on any system.
Thunderbird from a Snap or Flatpak cannot run `vault-gpg`. Post-quantum (v6)
keys do not work in Thunderbird yet; use a classic key. Keys made before
this release still list no preferred algorithms (make a new key if GnuPG
users' signatures show as invalid in Thunderbird). Evolution and KMail are
not connected yet. No vault file change; `vaultd`, `vault-gpg` and the other
programs must be updated together (two new requests).

<<<<<<< HEAD
### Windows keeps your keys out of the page file, crash reports and screen shares

- **The last "Not yet" for Windows memory safety is closed.** vaultd now
  locks the memory it holds keys and items in, so Windows never writes it to
  the page file, the same as on Linux.
- **No crash reports with secrets.** vaultd, the desktop app and the
  approval window are excluded from Windows Error Reporting, so a crash does
  not leave a dump of their memory on disk.
- **Other programs cannot read their memory.** Their process permissions
  now let other programs (even ones running as you) only see and end them,
  not read or change their memory. vaultd also refuses legacy DLL injection
  and loads system DLLs only from System32.
- **The app is left out of screenshots and screen sharing.** The desktop
  app and the approval window no longer show up in screenshots, screen
  recordings or a shared screen in Teams or Zoom; you still see them as
  usual. To take a screenshot on purpose, start the app with
  `VAULT_ALLOW_CAPTURE=1`; see
  [Screenshots and screen sharing](user-guide/05-desktop-app.md#screenshots-and-screen-sharing-windows).
- Nothing to set up: it is on after updating. Turn on BitLocker or Device
  Encryption as well, because hibernation and blue-screen dumps write all of
  memory to disk. How it works and how to check it:
  [How vaultd protects its memory](user-guide/windows-install.md#how-vaultd-protects-its-memory).

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Keys kept out of swap / page file | Yes (`mlockall`) | Yes (new) | Swap is always encrypted |
| No crash dumps | Yes | Yes (new) | Yes |
| Other programs of yours can't read the memory | With the system-user unit | Yes, unless they change the permissions back first (new) | Debugger attach refused |
| App hidden from screenshots and screen sharing | Not yet | Yes (new) | Not yet |

Known limits: the desktop app does not lock its own memory (it holds only
what is on screen). An administrator, or malware that first changes the
process permissions, can still read memory. `VAULT_HARDEN=off` turns the
permission change off for debugging. Because of it, PowerShell's
`Stop-Process -Name vaultd` now says "Access is denied": stop vaultd with
`taskkill /im vaultd.exe` instead: vaultd now locks and exits when asked
to close. The installer and uninstaller stop it that way.
No vault file change.

- **An open Windows Hello prompt no longer holds up everything else.**
  While a quick-unlock prompt (Windows Hello or Touch ID) waited for you,
  every other request to vaultd waited too, even `vault status`, until the
  prompt was answered. Now the rest keeps working, and you can unlock with
  your password instead while it is open. Found in testing on a real PC.

### Windows on Arm

- **A native installer for Arm PCs**, such as Snapdragon laptops:
  `SecretVault-Setup-<version>-arm64.exe` on the Releases page, next to the
  usual one. Everything runs natively instead of through Windows' x64
  emulation, so unlocking (Argon2id) is faster and uses less battery.
- Which one to download: [Before you start](user-guide/windows-install.md#before-you-start).
  Installing the Arm version over the x64 one (or back) upgrades in place,
  as the same app.

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Arm downloads | Not yet (build from source) | Yes (new) | Yes (universal, already) |

Known limits: built and tested in CI on GitHub's Windows 11 Arm runners;
not yet tried on a real Arm PC (no TPM, security key or Windows Hello there).
Windows 10 on Arm is untested.
=======
### Sync: three devices now always end with the same item

- If three devices edited one item at once and synced in a particular order,
  two of them could end up with different text under the same version and
  never agree. They now settle it the same way everywhere. No data is lost:
  the edit that loses is still kept as a "(conflict)" copy, as before.
- Found by the automatic test that mixes edits and syncs at random; it failed
  once on Windows CI. Same on Linux, Windows and macOS and on the phone apps.
>>>>>>> origin/main

### Safer unlock limits, sync limits and Android AutoFill frames

These fix three findings from a security review (issues #49, #50 and #51).
Nothing changes in day-to-day use.

- **Unlock settings have a lower ceiling.** Each unlock method stores how
  much memory and time the password check (Argon2) takes. A vault file now
  asks for at most 1 GiB of memory, 10 passes and 8 lanes, and at most
  2 GiB of total work, which is just under three times the default
  (256 MiB, 3 passes). Before this, an edited vault file could ask for 4 GiB
  and 20 passes, enough to freeze a phone or stall a computer for minutes
  before the file was found to be fake. Vaults made by Secret Vault always
  use the default, so they all still open. Details: [file format, section
  3.1](format.md#31-parse-time-bounds).
- **Sync reads only vault-sized files.** It looks at the synced copy and at
  most 16 conflict copies, skips any file over 64 MiB, and reads at most
  256 MiB per check, so junk in the sync folder can't run the daemon out of
  memory. See [sync, things to know](user-guide/10-sync.md#things-to-know).
- **Android AutoFill checks each field's own site.** When a page shows a
  sign-in box from another site in an embedded frame, Secret Vault now uses
  the password field's own site to pick logins. It never fills a username
  field that belongs to a different site. Before, it used the first site
  named anywhere on the screen. See [fill a
  login](user-guide/14-phone-apps.md#fill-a-login).

| | Linux | Windows | macOS | Android | iPhone and iPad |
| --- | --- | --- | --- | --- | --- |
| Unlock limits | Yes | Yes | Yes | Yes | Yes |
| Sync limits | Yes | Yes | Yes | n/a (opens only the synced file, no conflict copies) | n/a (same) |
| AutoFill frame check | n/a | n/a | n/a | Yes | n/a (separate code, not part of this finding) |

Known limits: the Android frame check has unit tests but hasn't been tried
on a real phone with a mixed-site page. No vault file change.

### The approval window ignores clicks that come too soon

- **Safer approvals.** In the window that asks to pair, fill a card, use an SSH
  or PGP key or share app passwords, **Allow** now stays grey until the
  window has had the focus for about a second, and starts over if the focus
  is lost. A click meant for another window, or a program that clicks for you
  the moment the window appears, can no longer approve a request.
  Reported by the November 2026 security review.
- **What to do.** Nothing, except wait a moment before pressing **Allow**.
  Deny, Escape and the one-minute timeout work as before. Linux, Windows and
  macOS behave the same.
- **Known limit.** Same-user malware can still wait a second and click; the
  window narrows the attack but is not a barrier against it (threat model A3).
  A Windows Hello check for pairing and key export is a possible next step.

How to use it: [Getting started, pairing](user-guide/01-getting-started.md).

### Security fixes in the libraries the vault uses

Nothing changes in how you use the vault, and the vault file is the same.
Install the new version as usual ([versions and
upgrades](user-guide/11-versions-and-upgrades.md)). This entry matters
most if you build Secret Vault yourself.

- **Fixed library advisories.** `cargo audit` reported five security
  advisories. Two are fixed by newer releases: `tokio` 1.54.1 (a timing
  race in its timers; 1.54.0 was also withdrawn) and `ctutils` 0.4.8
  (comparisons that were meant to take the same time for every input
  didn't always). All Rust libraries are on their newest compatible
  releases again.
- **App-password sessions (Secret Service, Linux only).** The encrypted
  session that apps such as browsers and mail clients open with the vault
  now uses `crypto-bigint` 0.7, which fixes timing leaks in the 0.5 release
  it used before. Apps notice no difference.
- **Screen lock and Secret Service on `zbus` 6 (Linux only).** The parts of
  the daemon that lock the vault when the computer sleeps or the screen
  locks, and that serve app passwords, moved from `zbus` 5 (whose helper
  libraries are no longer maintained) to `zbus` 6. They behave as before.
  Windows and macOS don't use `zbus`.

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| `tokio`, `ctutils` and other library updates | Yes | Yes | Yes |
| App-password session fix (`crypto-bigint` 0.7) | Yes | n/a (no Secret Service) | n/a |
| `zbus` 6 | Yes | n/a | n/a |

Known limits: three advisories remain until the OpenPGP and SSH libraries
(`pgp` 0.21.0 and `ssh-key` 0.6.7, their newest stable releases) move to
fixed versions. A timing leak in `ml-dsa` 0.0.4 can matter when the vault
signs with a post-quantum OpenPGP key (the Ed25519 half of that hybrid
signature is not affected). The older `crypto-bigint` 0.5 they use is in
the code for NIST P-256 keys, so ECDSA P-256 SSH keys are the ones it
touches; Ed25519 SSH keys (the default) are not affected. The `rsa`
"Marvin" advisory affects decrypting and signing with RSA secret keys,
which the vault refuses to store, so it does not apply. The desktop app still
pulls in `zbus` 5 through its screen-reader support (`eframe` 0.37, its
newest release); it moves when `eframe` does.

### Library advisories: what is left

Nothing changes in how you use the vault, and the vault file is the same,
with one exception: importing some kinds of OpenPGP secret key is now
refused (below). This follows the [library security
fixes](#security-fixes-in-the-libraries-the-vault-uses) above, which left
three advisories waiting on the OpenPGP and SSH libraries. Their newest
releases (`pgp` 0.21.0, `ssh-key` 0.6.7) still haven't moved, so the vault
now deals with them itself.

- **Post-quantum OpenPGP signatures are constant-time (fixed).** Signing
  with a post-quantum key (`vault pgp new --pq`) used a division whose time
  depended on the secret key (`ml-dsa`, RUSTSEC-2025-0144). The vault now
  builds a copy of `ml-dsa` 0.0.4 with the upstream fix applied, until `pgp`
  moves to the fixed `ml-dsa` 0.1. Signatures are exactly the same as
  before.
- **ECDSA P-256 SSH keys use the fixed code (fixed).** SSH signing moved to
  `ssh-key` 0.7 (release candidate 12), which uses the newer P-256 code on
  `crypto-bigint` 0.7. Existing keys keep working, and servers see the same
  public key. Ed25519 SSH keys (the default) were never affected.
- **Some OpenPGP secret keys can no longer be imported.** `vault pgp import`
  (and **Import OpenPGP key** in the desktop app) now accepts only
  Ed25519/Curve25519 keys and the post-quantum keys built on them. NIST
  P-256/P-384/P-521, brainpool, secp256k1, Ed448 and X448 secret keys are
  refused, joining RSA, DSA and ElGamal, because the code `pgp` 0.21 uses for
  them can leak timing information. Keys made with `vault pgp new` are not
  affected, and you can still encrypt to and check signatures from people
  with any kind of key. A key of a refused kind that you imported earlier
  keeps working; replace it with `vault pgp new` when you can. See [Make or
  import a key](user-guide/07-openpgp.md#1-make-or-import-a-key).
- **The build checks for advisories.** Every pull request now runs `cargo
  audit`. The two advisories that can't be fixed yet are listed, each with
  its reason, in `.cargo/audit.toml`.

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Post-quantum OpenPGP signing fix | Yes | Yes | Yes |
| P-256 SSH signing fix | Yes | Yes | Yes |
| OpenPGP import limited to Curve25519 keys | Yes | Yes | Yes |

Known limits: two advisories stay open until other projects release fixes.
`rsa` "Marvin" (RUSTSEC-2023-0071) doesn't apply, because the vault never
holds an RSA secret key; it lifts when `pgp` moves to `rsa` 0.10, which came
out on 2026-11-08. The older `crypto-bigint` 0.5 (RUSTSEC-2026-0387) is
still in the code used for one-time keys only: the PIN exchange with a
FIDO2 security key and the phone-unlock tunnel (`libwebauthn`, `snow`), and
the throwaway key when you encrypt to someone else's NIST-curve OpenPGP key.
It lifts when those libraries move to the newer P-256 code. `ssh-key` 0.7
is a release candidate, pinned to one exact version until 0.7.0 is final.

### Public beta downloads

- **Try Secret Vault before 0.2.0 is final.** Public betas are published on
  the [Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases)
  for anyone to download, no GitHub account needed. A beta has a version
  such as `0.2.0-beta.1`, is labelled **Pre-release** on GitHub, and starts
  its description with a warning. It has the same six downloads and
  `SHA256SUMS.txt` as a full release: the Windows installer, the Linux
  `.deb` and `.tar.gz`, the macOS `.pkg` and `.tar.gz`, and the browser
  extension.
- **Upgrading from a beta is the usual upgrade.** Installing 0.2.0 (or a
  later beta) over `0.2.0-beta.1` keeps your vault, unlock methods and
  settings, on every system. On Debian and Ubuntu, apt sorts the beta
  before 0.2.0, so `apt install` of 0.2.0 upgrades it in place.
- How to start: [Where to download](user-guide/11-versions-and-upgrades.md#where-to-download)
  and [Betas](user-guide/11-versions-and-upgrades.md#betas-pre-releases).

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Beta downloads | Installer (`.exe`) | `.deb`, `.tar.gz` | `.pkg`, `.tar.gz` |
| One-time warning (unsigned) | SmartScreen: **More info** > **Run anyway** | None | **Open Anyway** in Privacy & Security |

Known limits: betas are not security audited, so do not trust one with real
secrets yet and keep a backup of your vault file. `0.2.0-beta.1` has no
phone apps; the Android app joins from `0.2.0-beta.2` (below), and the
iPhone and iPad app is not on the Releases page (it needs a paid Apple
developer account);
see [Phone and tablet apps](user-guide/14-phone-apps.md). GitHub's
"latest release" link skips betas, so link to the Releases page itself
while only betas exist. No vault file change.

### Easier passwords, codes added from the Codes screen, and the real app icon

- **Three random words.** The generator can now make passwords the way the
  UK National Cyber Security Centre recommends: three random words run
  together, such as `CupFishBiscuit`. They are easy to remember and to type
  on a phone. You can pick 3 to 10 words, what goes between them, whether
  each starts with a capital, and an optional digit and symbol at the end
  for sites that insist on them. Words come from the EFF's list of 7,772
  common words.
- **Apple-style passwords.** A second new style makes passwords like the
  ones iPhones and Macs suggest: three groups of six letters joined by
  hyphens, with one capital and one digit, such as `fokjyb-Xewpud-hamu4s`.
  About 74 bits, roughly as hard to guess as an 11-character random password,
  but much easier to type.
- **Every app has the styles.** Desktop app (Generator page), command line
  (`vault gen --words`, `vault gen --apple`), browser extension (a style
  menu next to **Generate password**), iPhone, iPad and Android (Generator
  tab). Each shows roughly how strong its passwords are. The style you pick
  is also what **Generate** (or the dice) uses in the item editor.
- **Add a one-time code from the Codes screen (iPhone, iPad and Android).**
  The Codes tab has an **Add Code** button: scan the site's QR code or
  paste its setup key, then keep the code on a new login or on a login you
  already have. Before, you had to edit a login to add a code.
- **The real app icon inside the app, green when unlocked.** The plain dark
  padlock at the top left of the desktop app is replaced by the app's own
  keyhole icon. It is red while the vault is locked and green while it is
  unlocked. The iPhone Items screen, the iPad status pill and the Android
  items screen show the same green icon; tap it to lock.
- **Long text wraps instead of overlapping (desktop).** Long item names,
  usernames, web addresses and descriptions now wrap. Edit and Delete no
  longer cover a long item name, and move under it in a narrow window; copy
  buttons move under their value too. The item list shows names on two
  lines, the sidebar scrolls instead of running into the version line, and
  the top bar hides the lock timer before anything overlaps. In a narrow
  window the sidebar, item list and margins slim down so an item's details
  stay inside the window instead of running off its left edge. On phones,
  item names take up to two lines and long email addresses are shortened in
  the middle so both ends stay visible.
- How to start: [the generator](user-guide/03-items.md#password-generator),
  [the desktop Generator page](user-guide/05-desktop-app.md#generator) and
  [one-time codes on phones](user-guide/14-phone-apps.md#one-time-codes).

| | Linux, Windows, macOS desktop app | Command line | Browser extension | iPhone and iPad | Android |
| --- | --- | --- | --- | --- | --- |
| Three random words | Yes, with all options | `vault gen --words` with all options | Yes, 3 words with capitals | Yes, with all options | Yes, with all options |
| Apple style | Yes | `vault gen --apple` | Yes | Yes | Yes |
| Add a code from the Codes screen | Yes, see *Add a one-time code on the desktop* above | `vault code add`, see above | No | Yes, with the camera | Yes, with the camera (Google Play services scanner) |
| Green icon when unlocked | Top left of the window | No | No | Items screen (phone), status pill (iPad) | Items screen |

Known limits: the browser extension always makes three capitalised words
(change the details in the desktop app or with `vault gen`). The extension needs the matching new
`vault-native-host` and `vaultd`; an older `vaultd` answers "unknown
request" for the new styles. No vault file change.

### Apps for iPhone, iPad and Android

- **Your vault on your phone and tablet.** New apps for iPhone and iPad
  (iOS 26) and for Android phones, tablets and foldables (Android 9 or
  later). Look up and copy passwords, cards and identities, add and edit
  items, see every one-time code in one place, and make passwords with the
  same generator as the desktop.
- **The same vault as your computer.** Pick the vault file your computer
  syncs (iCloud Drive, OneDrive, Google Drive or Dropbox) and the phone
  merges with it, exactly like another computer. Or start a vault on the
  phone and join it from a computer later.
- **Face ID, Touch ID or fingerprint unlock.** After you unlock once with
  the master password, your face or fingerprint opens the vault for up to
  14 days. The key behind it stays in the phone's secure hardware and is
  dropped when a new face or fingerprint is added.
- **AutoFill in your browser.** Turn on Secret Vault as the phone's
  AutoFill provider. Logins are offered only on the websites they are saved
  for, the same rule as the browser extension. On iPhone, one-time codes
  can be filled too.
- **Set up codes from the camera (iPhone and iPad).** Choose Secret Vault
  under Settings > General > AutoFill & Passwords > **Set Up Codes In**, and
  a website's setup QR code or link opens a new login in Secret Vault with
  the code filled in. Android has no system setting for this; scan the QR
  code inside the app.
- **Made for every screen.** On phones the app uses a tab bar (Liquid Glass
  on iOS 26) and Material 3 on Android. On iPad, tablets, unfolded
  foldables and wide split-screen windows it shows the list and the item
  side by side, with three columns on iPad like the desktop app. On a
  half-folded Android foldable the Codes tab shows the code on the top half.
- How to start: [Phone and tablet apps](user-guide/14-phone-apps.md).
  Technical details: [mobile.md](mobile.md).

| | iPhone and iPad | Android |
| --- | --- | --- |
| Face or fingerprint unlock | Face ID, Touch ID | Strong biometrics (fingerprint, some face unlock) |
| AutoFill unlock | Face ID or Touch ID only | Biometrics or master password |
| One-time codes in AutoFill | Yes | Not yet |
| How you get it | Build with Xcode on a Mac | APK from the Mobile CI run |

Known limits: not yet in the App Store or on Google Play. Tried on a real
iPhone; Android so far only on emulators. Security keys, TPM and phone-passkey
unlock methods work only on the computer they were made on. Saving a new
login from another app's sign-up form is not built yet. No vault file
change: computers and phones read the same files.

### See and take back app approvals, and import from GNOME Keyring or KWallet

- **See and take back approvals.** The programs you allowed to use app
  passwords are listed on the desktop app's new **App passwords** page and
  by `vault apps`. **Take back** (or `vault apps revoke PROGRAM`, or
  `--all`) makes that program ask again next time.
- **Bring your keyring's passwords along.** Before switching vaultd on as
  the Secret Service, **App passwords → Import** (or `vault apps import`)
  copies every password GNOME Keyring or KWallet holds into the vault, so
  apps find them after the switch. A locked keyring asks for its own
  password first; one that stays locked is skipped and named. Running it
  again copies only what is new, and nothing is removed from the keyring.
- **How to use it:**
  [Bring your passwords over first](user-guide/12-secret-service.md#turn-it-on)
  and [See and take back approvals](user-guide/12-secret-service.md#see-and-take-back-approvals).
- **Platforms.** Linux only, like the Secret Service itself. The **App
  passwords** page is not shown on Windows or macOS.
- **Not yet.** Approvals still end when vaultd restarts (they are not saved).
  Import reads the keyring while it is the running Secret Service, so it
  must happen before vaultd takes over; it does not read keyring files
  directly.

### Public downloads with checksums

Every release is published on the
[Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases)
for anyone to download, no GitHub account needed: the Windows installer, the
Linux `.deb` and `.tar.gz`, the macOS `.pkg` and `.tar.gz`, and the browser
extension. New with this release:

- **`SHA256SUMS.txt`** is attached to every release. It holds a fingerprint
  of each file, so you can check that a download is complete and unchanged
  before you run it. How to check it on Linux, macOS and Windows is in
  [Versions, downloads and upgrading](user-guide/11-versions-and-upgrades.md#checking-a-download-optional).
- The release is only published if **all six downloads** were built, so a
  release can never be missing one system's installer.
- The user guide now explains the **one-time warnings** Windows (SmartScreen:
  **More info** > **Run anyway**) and macOS (**Open Anyway** in Privacy &
  Security) show for an unsigned installer, and what code signing would cost
  to remove them. Linux shows no warning.

Not included yet: the iPhone, iPad and Android apps, which are still in
development and need app store accounts to be published.

### A macOS installer

Secret Vault now comes as a normal Mac installer, `SecretVault-<version>-macos.pkg`:
double-click it, click through, enter your administrator password, and it is
installed. One download works on Apple silicon and on Intel Macs.

How to start:

1. Download `SecretVault-<version>-macos.pkg` from the
   [Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases).
2. Double-click it. The first time, macOS stops it because it is not signed
   with an Apple developer ID yet: on macOS 15 and newer, click **Done**, then
   **Open Anyway** under System Settings > Privacy & Security; on macOS 11 to
   14, right-click it and choose **Open**.
3. Follow the installer, then open **Secret Vault** from Launchpad.

What it installs: **Secret Vault.app** in `/Applications`, the `vault`,
`vaultd` and `vault-gpg` commands in `/usr/local/bin` (already on every
Terminal's `PATH`), and a launch agent in `/Library/LaunchAgents` that starts
`vaultd` for each account when it signs in. Every account keeps its own vault.

- **Upgrading:** open a newer `.pkg`. It keeps your vault and settings and
  restarts `vaultd`. It refuses to install an older version over a newer one.
- **Moving from `install.sh`:** the `.pkg` replaces a copy in `~/Applications`
  (its launch agent and its links in `~/.local/bin` too) and points your
  browsers at the new app, so autofill keeps working.
- **Removing:** `sudo "/Applications/Secret Vault.app/Contents/Resources/uninstall.sh"`.
  Your vault file stays.
- **No administrator password?** The `.tar.gz` with `install.sh` is still
  there, now also universal: `secret-vault-<version>-macos-universal.tar.gz`
  (it replaces the separate `-arm64` archive). `install.sh` stops if the
  `.pkg` version is installed.

The whole walk-through: [Installing and running on macOS](user-guide/13-macos.md).

Platform differences: macOS only. Linux (`.deb`, `.tar.gz`) and Windows
(`SecretVault-Setup-<version>.exe`) are unchanged. Unlike the Windows
installer, the macOS one needs an administrator password, because it
installs for every account.

Known gaps: the installer and the app are not signed with an Apple developer
ID or notarised yet ([what that needs](macos-signing.md)). The launch agent
starts an idle `vaultd` in accounts that never create a vault.

### Secret Vault runs on macOS

Until now only the core library ran on a Mac. Now everything does: `vaultd`,
the `vault` command, the desktop app, security keys, browser autofill, the
SSH agent, OpenPGP and sync. It needs macOS 11 or newer, on Apple silicon or
Intel.

How to start:

1. Install it with `SecretVault-<version>-macos.pkg` (see
   [A macOS installer](#a-macos-installer) above), or, without an
   administrator password, unpack
   `secret-vault-<version>-macos-universal.tar.gz` and run `./install.sh`
   in it from Terminal.
2. Open **Secret Vault** from Launchpad or Spotlight. The setup wizard
   walks you through the master password, the recovery code, Touch ID and
   the browser.

The `.pkg` puts **Secret Vault.app** in `/Applications` and the `vault`
command in `/usr/local/bin` (`install.sh`: `~/Applications` and
`~/.local/bin`), and a launch agent that starts `vaultd` at every sign-in. Your vault lives in `~/Library/Application Support/vault/`. The
whole walk-through is in
[Installing and running on macOS](user-guide/13-macos.md).

New on the Mac:

- **Quick unlock with Touch ID.** After you unlock with your password,
  Touch ID (or a paired Apple Watch, or your login password) opens the vault
  again when it locks, for up to 24 hours. Turn it on under **Unlock
  methods** > **Quick unlock with Touch ID**, or with `vault quick-unlock 8`.
  Use it with **Unlock with Touch ID** or `vault unlock --touch-id`. Like
  Windows Hello, it never opens a vault on its own: after a restart, you
  need your password.
- **Browsers:** Chrome, Chromium, Edge and Firefox. The setup wizard
  registers them. Safari is not supported.
- **Security keys** work as on Linux: the app asks for the key's PIN, and no
  extra permission is needed. A key slot made on a Mac also unlocks on
  Linux and Windows.
- **Security keys with a PIN:** if a key has a PIN set and needs it to
  register (many older or Feitian keys do), `vault add-slot fido2` now says
  so at once, instead of waiting for a touch that times out. Run it again
  and type the PIN. This applies on Linux and macOS; on Windows, Windows'
  own security key window asks for the PIN as before.
- **Quick unlock that is not available** (after `vault lock --full`, a
  restart, or once its hours run out) is refused straight away by
  `vault unlock --touch-id` / `--hello`, without first asking you to
  confirm with Touch ID or Windows Hello.
- The desktop app shows **Cmd K** for the command palette, and copied
  secrets are marked so clipboard managers skip them.

Platform differences:

- **macOS:** no TPM, so no TPM slots. TPM slots made on other computers are
  skipped. A Secure Enclave slot is not supported yet. vaultd turns off
  core dumps and blocks debuggers. There is no memory locking on macOS, but
  macOS always encrypts swap. vaultd does not yet lock when the screen
  locks or the Mac sleeps; it locks after 15 idle minutes. The app is not
  signed with an Apple developer ID, so macOS asks you to allow the
  installer once (or, with `install.sh`, the script clears the download
  flag).
- **Linux and Windows:** nothing changes. The `vault` command now also
  accepts `vault unlock --touch-id` as another name for `--hello`.

Known gaps: the app is not notarised. `pass` and NeoMutt through
`vault-gpg` should work on a Mac but are untested. Locking on screen lock
and sleep, and a Secure Enclave slot, are still to come.

### Unlock with a passkey on your phone (Linux and Windows)

- **Your phone as a second factor.** You can now add a passkey on your
  iPhone or Android phone as a way to unlock the vault, together with your
  master password. The passkey is saved in the phone's password manager
  (iCloud Keychain, Google Password Manager, or another one that supports
  passkeys with PRF).
- **How it connects.** The computer shows a QR code. You scan it with the
  phone's camera, the two check over Bluetooth that they are near each
  other, and you confirm on the phone with your face, fingerprint or screen
  lock.
- **The password is still needed.** The phone adds to the password and never
  replaces it. A synced passkey can be restored through your Apple or Google
  account, so the vault does not trust the phone on its own.
- **Desktop app:** a new **Phone** choice on the lock screen and under
  **Unlock methods > Add a method**.
- **Command line:** `vault add-slot phone`, and `--phone` for `unlock`,
  `pair`, `export` and `revoke`.
- **No change to the vault file.** A phone method is stored as a security
  key method that checks the user, so older versions still open the vault
  with your other methods.
- How to start: [Unlock with your phone](user-guide/02-unlocking.md#unlock-with-your-phone).

| | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Phone passkey unlock | Yes (needs Bluetooth and BlueZ) | Yes (Windows 11 23H2 or later) | Not yet |
| Who shows the QR code | Secret Vault | Windows' own window | |

Known limits: not yet tried with a real phone at the time of writing.
Whether every phone accepts the vault's passkey name `vault.local` is still
to be confirmed on hardware.

### Import, export, encrypt, decrypt, sign and verify from the desktop app

Until now the desktop app could only make SSH and OpenPGP keys. Everything
else needed the `vault` command line. You can now do all of it in the app:

- **Import a key you already have.** In SSH and PGP keys, the small ▾ next
  to **New SSH key** now also offers **Import SSH key** and **Import OpenPGP
  key**. The New item menu in All items has them too. Pick the key file, or
  paste the key. If the key has a passphrase, the app asks for it. The
  vault then stores the key without a passphrase, protected by the vault
  itself.
- **Export a private key**, to move it to a computer that doesn't have this
  vault. Open the key and press **Export private key**. Even though the
  vault is open, you have to prove it's you once more, with any of your
  unlock methods (only the ones this vault has are offered). Then you can
  copy the key (the clipboard clears after 30 seconds) or save it to a
  file. The app never overwrites an existing file.
- **A new Encrypt and sign page** under Tools, with four tasks:
  - **Encrypt** a message or file for yourself and/or other people. Paste
    their public keys or give the key files. You can also sign it.
  - **Decrypt** a message or file. The vault finds the right key. The text
    stays hidden until you press **Show**.
  - **Sign** a text or file with a detached signature (`.asc`, or `.sig`
    for binary).
  - **Verify** a signature against your own keys or the signer's public
    key.

  Each task works on pasted text or on a file, up to about 15 MiB. The
  result can be copied or saved, with a file name already suggested.
- Ctrl K can start all of these: type "import", "encrypt", "decrypt",
  "sign" or "verify".

Platform differences:

- **Linux and macOS:** saved private keys and decrypted files are readable
  only by you (permissions 600).
- **Windows:** a saved file gets the permissions of its folder. Keep keys
  and decrypted files inside your user folder (`C:\Users\<you>\…`), which
  only you and administrators can open. When you export with a security
  key, Windows asks for the touch and PIN in its own window.
- **macOS:** the desktop app and vaultd don't run on macOS yet. These notes
  apply when they do.
- Paths starting with `~/` work on every system, meaning your home folder.

### Post-quantum Windows TPM slots

- **Windows TPM slots are now sealed inside the TPM.** A TPM slot added on
  Windows is now locked by the TPM's own internal key, the way Linux has
  always done it. Before, the slot's secret was wrapped with an RSA key,
  and a future quantum computer could unwrap it from a copy of the vault
  file, leaving only your password to protect that copy.
- **Old slots still work, and are marked.** A Windows TPM slot added
  before this version keeps unlocking. `vault slots` shows a note under it
  and the desktop app's **Unlock methods** page marks it **Not
  post-quantum**. Add the TPM again and remove or revoke the old slot.
- **How to use it:**
  [Post-quantum protection](user-guide/02-unlocking.md#post-quantum-protection)
  explains which unlock methods are post-quantum and how to replace an old
  slot step by step.
- **Platform differences:** Windows only. Linux TPM slots, security keys,
  passwords and recovery codes were already safe against a future quantum
  computer. macOS has no TPM.
- **Known limits:** a group policy that blocks TPM commands for programs
  stops new Windows TPM slots from being added; the error says so. A slot
  added on Windows still cannot be opened under Linux on the same PC, or
  the other way round.

### Keep apps' passwords in the vault (Secret Service, Linux)

- **What's new.** On Linux, vaultd can now stand in for GNOME Keyring or
  KWallet as the desktop's *Secret Service*. Apps that save passwords
  through it (mail and chat clients, `secret-tool`, many GNOME and KDE
  apps, Python's `keyring`) then keep them in your vault, encrypted like
  everything else, and folder sync carries them to your other computers.
- **Safe by default.** It is off until you turn it on. Each program must be
  allowed once in Secret Vault's approval window, which names the program
  and its command line. Apps only ever see the passwords apps saved, never
  your own logins, cards, identities or keys. Nothing can be read while the
  vault is locked; an app that asks to unlock opens the desktop app. Secrets
  travel over the encrypted session apps use by default.
- **How to use it:** [Keep apps' passwords in the vault](user-guide/12-secret-service.md).
- **Platforms.** Linux only. Windows (Credential Manager) and macOS
  (Keychain) have their own stores that are not replaced.
- **Not yet.** Approvals last until vaultd restarts. While the vault is locked, apps find no saved passwords (they
  can't see that there are any), so some apps ask you to type the password
  again; unlock the vault first. There is one collection: apps that create
  their own collections are refused.

### One search bar and a New button that follows you

- **Search at the top.** One search field runs across the top of the
  desktop app's window and stays there on every page. While a category is
  open it searches only that category, shown by a small blue "in Logins ×"
  tag; click the × (or **Search all items** under an empty result) to
  search everything. Typing in it from Generator, Import, Unlock methods
  or Sync jumps back to the item list. Ctrl K still opens the palette for
  items and actions together.
- **New button named for the category.** The blue button at the top right
  says what it makes: **New login** in Logins and One-time codes, **New
  secure note**, **New card**, **New identity**, and **New SSH key** in SSH
  and PGP keys, with a small ▾ beside it for **New OpenPGP key**. In All
  items it is **New item ▾**, a menu of every kind. The separate "New item"
  button above the list is gone.
- **Lock** and the auto-lock timer moved to the top right.
- **Icons before words.** Every sidebar entry has an icon (the open one
  sits on a white button with a blue icon tile), and so do the main
  buttons: New, Lock, Edit, Delete (now red), Copy, Show/Hide, Save,
  Generate, Import and Sync now.
- **How to use it:**
  [Search](user-guide/05-desktop-app.md#search) and
  [Add an item](user-guide/05-desktop-app.md#add-an-item-the-new-button).
- **Platforms.** The same on Linux and Windows. The app does not run on
  macOS yet.

### A clearer first-time setup

- The setup card now lists its steps down the left side (Password,
  Recovery code, Unlock methods, Browser, Finish). Finished steps get a
  green tick and the current one is blue, with "Step 2 of 4" above each
  page's title.
- **Back** sits at the bottom left and the next step's button at the
  bottom right, under a thin line, on every page.
- The master password fields are full width, with the strength bar under
  the first and "They match" under the second.
- The recovery code is shown in boxes, one group each, so it's easier to
  copy onto paper.
- Unlock methods show an icon for each (chip, security key, Windows Hello)
  that turns green once added.
- The last page sums up what was set up in one card, with **Import
  passwords** and **Open my vault** side by side.
- On a small screen (window under about 750 points wide) the step list
  folds back into dots across the top.
- **How to use it:**
  [No vault yet: the setup wizard](user-guide/05-desktop-app.md#no-vault-yet-the-setup-wizard).
- **Platforms.** No differences in the layout. The Unlock methods step
  offers Windows Hello, the TPM chip and security keys on Windows, and the
  TPM chip and security keys on Linux. The app does not run on macOS yet.

### Version numbers, release downloads and in-place upgrades

- **One version for everything.** The daemon, the `vault` command, the
  desktop app, the browser host, `vault-gpg`, the extension and the
  installers now share one version number, starting at **0.2.0**. Releases
  with new features raise the middle number, fix-only releases the last.
- **See your version.** `vault --version`, `vaultd --version`,
  `vault-native-host --version` and `vault-gpg --version` print it, and the
  desktop app shows it at the bottom of the sidebar. Builds that are not
  releases say so: `0.2.0-dev.1a2b3c4` (the commit they were built from).
- **Release downloads.** Each release is published on the project's GitHub
  Releases page, no account needed, with the Windows installer, a Debian /
  Ubuntu package (`.deb`), a Linux archive (`.tar.gz`) and the browser
  extension (`.zip`), all named with the version. Every CI run also keeps
  development builds of the same files.
- **Upgrades in place.** Running a newer Windows installer upgrades the
  existing install: same folder, mode and choices, closes the app and
  vaultd, and starts vaultd again. Its last page says *Upgrade Secret Vault
  from X to Y*. The `.deb` upgrades with `apt install`, and the archive's
  `install.sh` upgrades a `~/.local` install and restarts vaultd. The vault,
  unlock methods and paired apps are always kept.
- **Going back asks first.** An older Windows installer or `install.sh`
  over a newer version asks before going ahead, with No as the default,
  since an older version may not read a vault a newer one saved; apt
  refuses unless told `--allow-downgrades`.
- **Windows Installed apps** shows the version, and the installer file's
  properties carry it too.

Platform notes: Windows has the installer; Linux has the `.deb` (Debian 13,
Ubuntu 24.04 and newer) and the `.tar.gz` (any 64-bit distribution). After
a `.deb` upgrade, each user runs `systemctl --user restart vaultd`; the
installer and `install.sh` restart vaultd themselves. macOS has no package
yet because the daemon does not run there.

How to use it: [Versions, downloads and upgrading](user-guide/11-versions-and-upgrades.md).

### A cleaner, more polished desktop app

- **New look throughout.** The app now ships its own fonts (Inter for text,
  JetBrains Mono for passwords, codes and keys), so it looks the same on
  Linux and Windows. Names and headings are semibold, lines between panes
  and rows are soft grey instead of dark, and spacing follows the design
  mockups.
- **Item list.** Each item has a coloured letter tile, its title in bold over
  the username, and small tags for 2FA and keys. The sidebar shows how many
  items each category holds.
- **Item details.** Each field is a row with its name over its value and a
  Copy button on the right; the password's Copy is the blue one.
- **Unlock screen.** The ways to unlock (master password, security key, this
  device, recovery code) are listed on the left; the form for the chosen one
  is on the right.
- **Ctrl K palette.** Items show their letter tile and username; the
  highlighted row shows that Enter runs it.
- **Windows fit the screen.** The main window opens centred and no larger
  than the free part of the screen, leaving the taskbar and the title bar
  visible. On a 1920x1080 display at 150% scaling it opens at 1180x624
  instead of running off the bottom. The approval window (pairing, card
  fill, key use) grows to fit its text instead of cutting it off.
- **Always light.** The app and its title bar stay light even when Windows or
  Linux is set to dark mode, so there is no black title bar or black approval
  window any more.
- **How to use it:**
  [The desktop app: window layout and the command palette](user-guide/desktop-window-and-palette.md).
- **Platforms.** No feature differences between Linux and Windows. On Linux
  with Wayland the compositor decides where windows open, so "opens
  centred" may not apply there. The app does not run on macOS yet.

### Setup wizard in the desktop app

- **A guided first run.** When there is no vault yet, the desktop app now
  opens a setup wizard instead of a bare password form. It walks you
  through five steps, listed down the left of the card: choose a master password (with a
  strength meter), save the recovery code (you must tick that you saved it
  before going on), add more unlock methods, connect the browser, and a
  summary.
- **Add unlock methods without retyping.** In the wizard you can add a TPM
  method, a security key or (on Windows) Windows Hello quick unlock with one
  press each. The wizard reuses the password you just chose and forgets it
  when setup ends or the vault locks.
- **Register the browser from the app.** Paste the extension's ID and press
  **Register**; the app runs `vault-native-host --install` for you.
- **Join from the welcome screen.** **I already use Secret Vault on another
  device** opens the join-a-synced-vault form.
- **Platforms:** Windows shows Windows Hello, TPM and security key; Linux
  shows TPM and security key. The wizard is written to show only the
  security key and to say autofill isn't available on macOS, but the app
  can't be used on macOS yet because vaultd doesn't run there.
- **Known limits:** the wizard ends if the vault locks part-way; finish the
  optional steps under **Unlock methods**. **Register** needs the Chrome or
  Edge extension ID, so a Firefox-only setup still runs
  `vault-native-host --install` by hand.
- **How to use it:**
  [No vault yet: the setup wizard](user-guide/05-desktop-app.md#no-vault-yet-the-setup-wizard)

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
- **Earlier, clearer error for touch-only keys with a PIN.** On Windows,
  adding a touch-only security key that has a PIN or fingerprint now stops
  after the first touch, with a message saying to use a method that asks
  for the PIN. Before, it failed only after the second touch, with a
  harder-to-read message.
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

### Sidebar categories now visibly change the screen

- **What was wrong.** Choosing **Secure notes**, **SSH and PGP keys** or
  another category in the desktop app's sidebar did filter the list, but
  the window hardly changed: an empty category still said "No items yet.",
  and an item you had open stayed on the right. On Windows and Linux alike
  it looked as if the click did nothing.
- **What you see now.** The item list starts with the category's name
  (for example **Secure notes**). An empty category says so in its own
  words, such as "No secure notes yet.", and points you to the **New**
  button at the top, which is named for the category (see the next
  entry). Switching category closes an open item that isn't
  in the new category; a form you are filling in stays open, so nothing
  you typed is lost. Opening an item from the Ctrl K palette switches the
  list to **All items** if the item is in another category.
- **How to use it:**
  [Browse by category](user-guide/05-desktop-app.md#browse-by-category).
- **Platforms.** The same on Linux and Windows. The app does not run on
  macOS yet.

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

### Automatic snapshots and `vault backup`

- **A safety net for merges, imports and revokes.** Before `vaultd` writes
  a merged, imported, re-keyed or slot-removed vault, it keeps the file as
  it was (and one copy every ten minutes for ordinary edits), 20 in all.
  `vault snapshots` lists them and `vault backup --snapshot NAME FILE`
  saves one. Putting one back is a manual copy, written up in the
  troubleshooting chapter.
- **`vault backup FILE`** saves the encrypted vault file through the
  daemon, which works when `vaultd` runs as its own Linux system user. It
  will not replace an existing file without `--force`.
- Same on Linux, Windows and macOS (the commands and the snapshot folder
  next to the daemon's state). The desktop app and the phone apps do not
  show snapshots yet. A snapshot keeps the slots it had when taken, so
  delete old ones after a revoke.

How to use it: [Back up your vault](user-guide/08-troubleshooting.md#back-up-your-vault).

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
  2026-10-16, dropped the blocking API the screen-lock watcher uses (it
  moved to 6.x later, see "Security fixes in the libraries the vault
  uses"); `rand`
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

### Trash with 30-day restore, and earlier passwords

- **Delete is no longer final.** Deleting an item (`vault rm`, or
  **Delete** in the desktop app) moves it to the trash for 30 days. Trashed
  items are hidden everywhere: lists, search, autofill, the SSH agent and
  app passwords. Bring one back with `vault restore ID` or **Restore** on the
  new **Trash** page in the desktop app; `vault purge`, `vault empty-trash`
  and **Delete for good** remove items at once.
- **Earlier passwords are kept.** Changing a login's password keeps the old
  one (the last 10). `vault history ID` shows them. The desktop app does not
  show history yet.
- A delete on one computer now reaches the others as a move to the trash,
  so it can be undone. Computers still on an older version show a trashed
  item as normal until they are updated, so update them all. No file format
  change. Linux, Windows, macOS and the desktop app work the same. The phone
  apps hide trashed items and delete into the trash too, and keep the
  history, but have no Trash page yet: restore on a computer.

How to use it: [Delete](user-guide/03-items.md#delete) and [Earlier passwords](user-guide/03-items.md#earlier-passwords).

### A revoke can no longer be undone through a synced copy

- **Fixed (security).** Before, someone who kept an old copy of your vault and
  a factor you later revoked (a recovery code, a lost key) could write a copy
  under the old vault key into your sync folder, claiming a newer key
  generation. Your next unlock took that key, which brought their own unlock
  method back into your vault. Now each vault records the keys it has retired
  and refuses a copy under one of them. A device that was offline during the
  revoke still takes the new key from the device that made it.
- **What you see.** The sync status says the copy in the folder uses a
  revoked key and was not merged. Delete that file from the folder and this
  device writes its current vault again.
- **Compatibility.** Vault files gain a list of retired keys at their next
  write. Older versions of the programs cannot open such a file, so update
  every device. Linux, Windows, macOS and the phone apps behave the same.
- **Reported by the November 2026 security review.** If you ever revoked a
  factor with sync turned on, revoke it again after updating, as an old copy
  could have been merged before.

How to use it: [Removing an unlock method](user-guide/10-sync.md#removing-an-unlock-method).

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
