# 5. Desktop app

The desktop app (`vault-gui`) does day-to-day vault work in a window:
create the vault, unlock it, find, copy, add and edit logins, generate
passwords, import, and manage unlock methods. It is a window onto `vaultd`
like the CLI: it never opens the vault file itself and holds no keys.

| | Linux | Windows | macOS |
|---|---|---|---|
| Desktop app | Yes (X11 or Wayland, OpenGL) | Yes | Not yet |
| Copied secrets kept out of clipboard history and cloud clipboard | No such feature on Linux desktops | Yes | Not yet |

Some things are only in the command line: creating, importing and using
SSH and OpenPGP keys ([chapters 6](06-ssh-and-git.md) and
[7](07-openpgp.md)), revoking unlock methods with key rotation, and finding
items for a website. The app lists key items and shows their fingerprint.

For a tour of the window (sidebar, item list, details), the **Ctrl K**
command palette and keyboard shortcuts, with screenshots, see
[The desktop window and command palette](desktop-window-and-palette.md).
This chapter covers setting up the app and each task step by step.

## Start it

`vaultd` must be running ([chapter 1](01-getting-started.md)).

- **Linux:** run `vault-gui`. To put it in your applications menu, copy
  `contrib/desktop/dev.passwordvault.app.desktop` to
  `~/.local/share/applications/` and make sure `vault-gui` is on your
  `PATH`.
- **Windows:** the installer adds **Secret Vault** to the Start menu (see
  [Installing and running on Windows](windows-install.md)). From a source
  build, run `target\release\vault-gui.exe` and pin it to Start or the
  taskbar from its right-click menu.

If the app says it cannot reach `vaultd`, start the daemon
(`systemctl --user start vaultd` on Linux; on Windows run `vaultw.exe`, or sign out and back in) and
press **Try again**.

## First run

### No vault yet

1. Type a master password of at least 8 characters, then repeat it.
2. Press **Create vault**. It takes a few seconds.
3. The app shows the **recovery code** once. Write it down and keep it
   offline (see [chapter 1](01-getting-started.md#2-write-down-the-recovery-code)),
   then press **I've written it down**.

The app is paired and the vault is unlocked.

### A vault already exists

The app has to be paired with the vault once. Choose one:

- **Ask for approval:** press it, and allow the request in the window
  `vaultd` opens. Nothing to type.
- **Prove an unlock method:** pick Password, Security key, TPM or Recovery
  code, fill it in and press **Pair**. This also unlocks the vault.

The app keeps its own pairing, separate from the CLI's and the browser's.

## Unlock and lock

In the **Unlock with** list pick Password, Security key, This device (TPM)
or Recovery code, fill in what it asks and press **Unlock** (or Enter). For a security key, touch it when it
blinks. On Windows, TPM is listed but cannot work yet, and for a security
key Windows opens its own window for the touch and PIN (leave the PIN field
empty).

Lock with the **Lock** button or **Ctrl+L**. The vault also locks when idle,
when the screen locks or the computer sleeps, or when another program locks
it; the app follows within two seconds and forgets everything it showed.

## Items

The middle column lists your items, with a **Search** box above it.
**All items**, **Logins**, **One-time codes** and **SSH and PGP keys** in
the sidebar filter the list. Select an item to see it on the right.

- **Copy username**, **Copy password**, **Copy code** (when the item has a
  one-time code). **Show** reveals the password in place; **Hide** covers
  it again.
- **Edit** opens the form. **Delete** asks **Yes, delete** to confirm;
  there is no undo.

**New item** opens an empty form:

1. **Title** (required), **Username**.
2. **Password**: type it, or press **Generate** to make one with the
   Generator's settings.
3. **Websites**: type the address, then choose **This site only** (exact
   origin, the safe default) or **Whole domain** (all `https` subdomains).
   Tick **Allow http** only for an old site that has no `https`. **Add
   website** adds another address; **Remove** deletes one. See
   [Websites and matching](03-items.md#websites-and-matching).
4. **One-time codes**: paste the secret or the `otpauth://` link from the
   site's QR code. An invalid secret is refused with a message.
5. **Notes**, then **Save**.

### Clipboard

A copied username, password or code is cleared from the clipboard after
30 seconds, when the vault locks and when the app closes, unless you have
copied something else since. On Windows it is also kept out of the
clipboard history (Win+V) and cloud clipboard sync.

## Generator

**Generator**, under Tools in the sidebar, makes passwords of 8 to 64 characters, with or
without **Symbols**, optionally avoiding look-alike characters. **Copy
password** copies the result. New items use these settings when you press
**Generate** in the item form.

## Import

1. Export from your old password manager
   ([how](03-items.md#import-from-another-password-manager)).
2. Open **Import** under Tools in the sidebar and choose the format: Bitwarden (unencrypted
   `.json`) or browser passwords (`.csv`, which also covers Safari).
3. Type or paste the full path of the file into **File** (there is no file
   picker yet) and press **Import**.
4. Delete the export file afterwards: it holds your passwords in plain text.

## Unlock methods

**Unlock methods**, under Tools in the sidebar, lists the vault's slots. **Remove** deletes one
after a confirmation (this does not rotate the vault key; for a lost or
stolen factor use `vault revoke`, see
[chapter 2](02-unlocking.md#revoke-a-lost-or-stolen-factor)).

Under **Add a method**, pick Password, Security key, TPM or Recovery code,
give it a **Name**, and fill in what it asks:

- **Password:** the new password, twice.
- **Security key:** your master password; tick **Also ask for the key's PIN
  every time** if you want the PIN required. Touch the key twice.
- **TPM** (Linux): your master password, an optional **PIN**, and
  optionally **Stop working if Secure Boot settings change (PCR 7)**.
- **Recovery code:** the new code is shown once; write it down.

Each new method is test-unlocked before the app reports success.

## Good to know

- The app checks the vault's state every 2 seconds without counting as
  activity, so the idle lock still happens while the window is open.
- Secrets you type or reveal pass through the window toolkit, which keeps
  short-lived copies it does not wipe. Lock the app when you step away.
