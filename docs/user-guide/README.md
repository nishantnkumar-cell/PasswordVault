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

The vault is either **locked** (the keys are not in memory; nobody can read
anything) or **unlocked** (clients can read and change items). `vaultd`
locks it again after 15 minutes without use, when you lock your screen or
suspend the computer, and when it stops.

Each client must be **paired** once before `vaultd` will talk to it, so a
random program on your computer cannot just ask for your passwords.

## Chapters

1. [Getting started](01-getting-started.md): install, create a vault, save the recovery code, pair the CLI.
   On Windows, use the installer: [Installing and running on Windows](windows-install.md).
2. [Unlocking and unlock methods](02-unlocking.md): password, security key, TPM, recovery code; adding, removing and revoking them.
3. [Items, one-time codes, the generator and import](03-items.md)
4. [Browser autofill](04-browser-autofill.md)
5. [Desktop app](05-desktop-app.md), with a tour of the window and the
   Ctrl K command palette in
   [The desktop window and command palette](desktop-window-and-palette.md).
6. [SSH keys and git signing](06-ssh-and-git.md)
7. [OpenPGP keys](07-openpgp.md): signing, encrypting and decrypting files and mail.
8. [Troubleshooting, backups and safety tips](08-troubleshooting.md)

## What works where

| Feature | Linux | Windows 10/11 | macOS |
|---|---|---|---|
| `vaultd`, `vault` command, desktop app | Yes | Yes | Not yet |
| Browser autofill | Chrome, Chromium, Edge, Firefox 128+ | Chrome, Edge, Firefox 128+ | Not yet |
| Unlock: password, recovery code | Yes | Yes | Not yet |
| Installer | Not yet (build, then the systemd unit) | Yes, no administrator rights needed | Not yet |
| Unlock: password + FIDO2 security key | Yes | Yes (Windows 11, or Windows 10 with current updates) | Not yet |
| Unlock: password + TPM | Yes | Not yet | Not applicable |
| Windows Hello, Touch ID, phone passkey | Not yet | Not yet | Not yet |
| SSH agent and git signing | Yes | Yes (untested on real hardware) | Not yet |
| OpenPGP keys | Yes | Yes | Not yet |
| Locks on screen lock and suspend | Yes | Yes | Not yet |
| Keys kept out of swap and crash dumps | Yes | Not yet | Not yet |

On macOS only the core library and the security-key check
(`cargo run -p vault-hw --example fido2-check`) build today. A vault file
made on Linux or Windows can be copied between those systems: the file
format is the same everywhere.

## Reference

The guide covers how to use each feature. For the technical details behind
it, see [`vaultd.md`](../vaultd.md), [`windows.md`](../windows.md),
[`browser.md`](../browser.md), [`desktop.md`](../desktop.md),
[`items.md`](../items.md), [`ssh.md`](../ssh.md), [`pgp.md`](../pgp.md),
[`format.md`](../format.md) and the [threat model](../threat-model.md).
