# User guide

This guide is for people using Secret Vault for the first time. It explains
what each feature is for and walks through using it step by step. What is
new in each version is in the [release notes](../release-notes.md).

> Secret Vault has not been audited yet. Try it with test data, not with
> passwords you cannot afford to lose.

## How Secret Vault fits together

Secret Vault keeps your passwords, one-time codes and keys in **one
encrypted file** on your own computer. Nothing is sent to a server.

A background program, **`vaultd`** (the *daemon*), is the only thing that
ever opens that file. Everything else is a *client* that asks `vaultd` for
what it needs:

| Client | What you use it for |
|---|---|
| `vault` (the command line) | Every feature, including SSH and OpenPGP keys |
| The desktop app (`vault-gui`) | Day-to-day use in a window |
| The browser extension | Filling logins on websites |
| `ssh`, `git`, `ssh-keygen` | Using SSH keys stored in the vault |
| `vault-gpg` | Lets programs that run `gpg` (git, pass, NeoMutt) use OpenPGP keys stored in the vault |

The vault is either **locked** (the keys are not in memory; nobody can read
anything) or **unlocked** (clients can read and change items). `vaultd`
locks it again after 15 minutes without use, when you lock your screen or
suspend the computer, and when it stops.

Each client must be **paired** once before `vaultd` will talk to it, so a
random program on your computer cannot just ask for your passwords.

## Chapters

1. [Getting started](01-getting-started.md): install, create a vault, save the recovery code, pair the CLI.
   On Windows, use the installer: [Installing and running on Windows](windows-install.md).
   On a Mac: [Installing and running on macOS](13-macos.md).
2. [Unlocking and unlock methods](02-unlocking.md): password, security key, TPM, recovery code, quick unlock with Windows Hello or Touch ID; adding, removing and revoking them.
3. [Items, one-time codes, the generator and import](03-items.md): logins,
   secure notes, cards and identities.
4. [Browser autofill](04-browser-autofill.md)
5. [Desktop app](05-desktop-app.md), with a tour of the window and the
   Ctrl K command palette in
   [The desktop window and command palette](desktop-window-and-palette.md).
6. [SSH keys and git signing](06-ssh-and-git.md)
7. [OpenPGP keys](07-openpgp.md): signing, encrypting and decrypting files and mail.
8. [Troubleshooting, backups and safety tips](08-troubleshooting.md)
9. [Programs that call gpg](09-gpg-programs.md): git signing with OpenPGP,
   `pass`, and NeoMutt, through `vault-gpg`.
10. [Sync between devices](10-sync.md): one vault on several computers
    through OneDrive, Google Drive, Dropbox or any synced folder.
11. [Versions, downloads and upgrading](11-versions-and-upgrades.md): which
    version you have, where to download one, and upgrading in place.
12. [Keep apps' passwords in the vault](12-secret-service.md): Linux apps
    that save passwords through the Secret Service (GNOME Keyring's or
    KWallet's job) keep them in the vault instead.
13. [Installing and running on macOS](13-macos.md): the app, the launch
    agent, Touch ID quick unlock, browsers, SSH, and what differs on a Mac.

## What works where

| Feature | Linux | Windows 10/11 | macOS |
|---|---|---|---|
| `vaultd`, `vault` command, desktop app | Yes | Yes | Yes (macOS 11 or newer) |
| Browser autofill | Chrome, Chromium, Edge, Firefox 128+ | Chrome, Edge, Firefox 128+ | Chrome, Chromium, Edge, Firefox 128+ (not Safari) |
| Secure notes, cards, identities | Yes | Yes | Yes |
| Card and address autofill | Yes (card fill needs a desktop session) | Yes | Yes |
| Unlock: password, recovery code | Yes | Yes | Yes |
| Packages and in-place upgrades | `.deb`, and `.tar.gz` with `install.sh` | Installer, no administrator rights needed | `.tar.gz` with `install.sh`, no administrator rights needed |
| Unlock: password + FIDO2 security key | Yes | Yes (Windows 11, or Windows 10 with current updates) | Yes |
| Unlock: password + TPM | Yes | Yes | Not applicable |
| Quick unlock with Windows Hello or Touch ID (after a full unlock) | Not yet | Yes (Windows Hello) | Yes (Touch ID) |
| Face or fingerprint quick unlock on Linux, phone passkey | Not yet | Not applicable | Not yet |
| SSH agent and git signing | Yes | Yes (untested on real hardware) | Yes |
| OpenPGP keys | Yes | Yes | Yes |
| `vault-gpg` for git and NeoMutt | Yes | git only (untested on real hardware) | Yes (untested on real hardware) |
| `vault-gpg` for `pass` | Yes | Not applicable | Should work; untested |
| Sync through OneDrive, Google Drive, Dropbox | Yes | Yes | Yes, and iCloud Drive |
| Apps keep passwords in the vault (Secret Service) | Yes, opt-in | Not applicable | Not applicable |
| Locks on screen lock and suspend | Yes | Yes | Not yet (locks after 15 idle minutes) |
| Keys kept out of swap and crash dumps | Yes | Not yet | Yes (core dumps off; macOS always encrypts swap) |

A vault file can be copied between Linux, Windows and macOS: the file
format is the same everywhere. Only TPM slots are tied to one computer and
one system.

## Reference

The guide covers how to use each feature. For the technical details behind
it, see [`vaultd.md`](../vaultd.md), [`windows.md`](../windows.md),
[`browser.md`](../browser.md), [`desktop.md`](../desktop.md),
[`items.md`](../items.md), [`ssh.md`](../ssh.md), [`pgp.md`](../pgp.md),
[`format.md`](../format.md) and the [threat model](../threat-model.md).
