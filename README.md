# PasswordVault

A local-first password vault in Rust. Linux first, then Windows and macOS.

Status: v1 feature-complete on Linux, not yet audited. Do not trust it with real secrets yet.

| Crate | What |
| --- | --- |
| `vault-core` | File format, key hierarchy, keyslots, items, TOTP, generator, origin policy. Pure, no I/O. |
| `vault-import` | Bitwarden JSON and browser CSV import. |
| `vault-ipc` | Wire protocol between the daemon and clients. |
| `vaultd` | The daemon: storage, unlock, FIDO2 and TPM factors, socket server. |
| `vault-cli` | The `vault` command. |
| `vault-native-host` | Native messaging host for the browser extension. |
| `extension/` | Browser autofill extension (Manifest V3). |

Start with [`docs/vaultd.md`](docs/vaultd.md) to build and run it, then [`docs/browser.md`](docs/browser.md) for autofill.

- [`docs/brief.md`](docs/brief.md): project brief, the source of truth for scope and design.
- [`docs/threat-model.md`](docs/threat-model.md): v1 threat model.
- [`docs/format.md`](docs/format.md): vault file format, version 1.
- [`docs/items.md`](docs/items.md): item data, TOTP and autofill origin policy.
- [`docs/architecture-review.md`](docs/architecture-review.md): the review that produced brief Revision 2.

## Licence

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You may
use, change and share it for personal, research, educational and other
noncommercial purposes; commercial use is not permitted.

Required Notice: Copyright 2026 Nishant (https://github.com/nishantnkumar-cell)
