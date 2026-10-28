# PasswordVault

A local-first password vault in Rust. Linux first, then Windows and macOS.

Status: v1 feature-complete on Linux and Windows, not yet audited. Do not trust it with real secrets yet.

| Crate | What |
| --- | --- |
| `vault-core` | File format, key hierarchy, keyslots, items (logins, secure notes, cards, identities, custom fields), TOTP, generator, origin policy. Pure, no I/O. |
| `vault-import` | Bitwarden JSON (all four item types) and browser CSV import. |
| `vault-ipc` | Wire protocol between the daemon and clients. |
| `vaultd` | The daemon: storage, unlock, FIDO2 and TPM factors, folder sync, socket server. |
| `vault-hw` | Hardware unlock factors: FIDO2 security keys and phone passkeys, the TPM, Windows Hello. |
| `vault-cli` | The `vault` command. |
| `vault-gui` | The desktop app: setup wizard, items, key tools, unlock methods, sync, and the pairing approval window. |
| `vault-gpg` | A gpg-compatible front end, so git, pass and mail programs can use OpenPGP keys held in the vault. |
| `vault-native-host` | Native messaging host for the browser extension. |
| `extension/` | Browser autofill extension (Manifest V3): logins, cards and addresses. |
| `vault-mobile`, `mobile/` | iPhone, iPad and Android apps (SwiftUI, Jetpack Compose) over `vault-core` through UniFFI. |

## Download

Installers for Windows, Linux and macOS and the browser extension are on the
[Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases/latest),
free to download without a GitHub account. Windows and macOS warn once the
first time you open them because they are not code-signed yet; the
[download guide](docs/user-guide/11-versions-and-upgrades.md#where-to-download)
says what to click and how to check a download.

## Documentation

New here? Read the [user guide](docs/user-guide/README.md): it walks through installing, creating a vault and using each feature on Linux, Windows and macOS. What changed in each version is in the [release notes](docs/release-notes.md).

For the technical reference, start with [`docs/vaultd.md`](docs/vaultd.md), then [`docs/browser.md`](docs/browser.md) for autofill.

- [`docs/brief.md`](docs/brief.md): project brief, the source of truth for scope and design.
- [`docs/threat-model.md`](docs/threat-model.md): v1 threat model.
- [`docs/format.md`](docs/format.md): vault file format, version 1.
- [`docs/items.md`](docs/items.md): item types, TOTP and autofill origin policy.
- [`docs/desktop.md`](docs/desktop.md): the desktop app and its approval window.
- [`docs/windows.md`](docs/windows.md): what differs on Windows (installer, background start, TPM, Windows Hello).
- [`docs/sync.md`](docs/sync.md): syncing devices through OneDrive, Google Drive or Dropbox.
- [`docs/mobile.md`](docs/mobile.md): the iPhone, iPad and Android apps, phone quick unlock and AutoFill.
- [`docs/ssh.md`](docs/ssh.md): SSH keys in the vault, the ssh-agent and git commit signing.
- [`docs/pgp.md`](docs/pgp.md): OpenPGP keys in the vault, classic and post-quantum, and the gpg-compatible front end.
- [`docs/architecture-review.md`](docs/architecture-review.md): the review that produced brief Revision 2.

## Documentation for changes

Every change to the design or features updates, in the same pull request:

- [`docs/release-notes.md`](docs/release-notes.md): a new entry saying what you can now do, platform differences and known limits.
- [`docs/user-guide/`](docs/user-guide/README.md): step-by-step instructions written for first-time users, with differences between Linux, Windows and macOS called out.

Examples and screenshots use placeholder names such as "Alex Example" and `example.com`, never a real person's name.

## Licence

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You may
use, change and share it for personal, research, educational and other
noncommercial purposes; commercial use is not permitted.

Required Notice: Copyright 2026 Nishant (https://github.com/nishantnkumar-cell)
