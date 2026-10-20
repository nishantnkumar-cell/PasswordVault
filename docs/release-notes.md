# Release notes

## Unreleased

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
