# The desktop app: window layout and the command palette

This guide is for people opening the desktop app (`vault-gui`) for the
first time. It covers how the window is laid out, how to find and copy
things quickly, and how to unlock. For installing the daemon and the app,
see [vaultd.md](../vaultd.md) and [desktop.md](../desktop.md).

The examples use a sample vault for "Alex Example".

## Before you start

The app is a window onto `vaultd`, the background service that holds your
vault. The app never reads the vault file itself. If the app says it can't
reach vaultd, start the service first:

- **Linux:** `systemctl --user start vaultd`
- **Windows:** if you used the installer, vaultd starts by itself when you
  sign in; otherwise start `vaultw.exe` (see
  [installing on Windows](windows-install.md)).
- **macOS:** not supported yet. The app and the daemon run on Linux and
  Windows today.

## Unlocking

![The unlock card](images/desktop-4-locked.png)

When the vault is locked, the window shows one card. Pick how you want to
unlock in the **Unlock with** list, fill in what it asks for, and press
**Unlock** (or Enter).

| Method | What you need | Linux | Windows |
| --- | --- | --- | --- |
| Password | Your master password | Yes | Yes |
| Security key | Your master password, then a touch on the key (and its PIN if it has one) | Yes | Yes (Windows shows its own window for the touch and PIN) |
| This device (TPM) | Your master password and, if you set one, the TPM PIN | Yes | Yes |
| Unlock with Windows Hello | Your face, fingerprint or Windows PIN; shown only while quick unlock is available | No | Yes |
| Recovery code | The code from your printed recovery sheet | Yes | Yes |

Only methods you have added under **Unlock methods** will work. The first time you open the app on a vault that already exists,
the same card pairs the app with the vault: unlock once, or press **Ask for
approval** and allow the app in the window vaultd opens.

## The window

![The three-pane window](images/desktop-1-list.png)

Once unlocked, the window has three columns.

1. **Sidebar (left).** At the top, a status box shows that the vault is
   unlocked and when it will lock itself if you leave it idle. Below that:
   - **All items**, **Logins**, **Secure notes**, **Cards**,
     **Identities**, **One-time codes** and **SSH and PGP keys** filter the
     item list. *One-time codes* shows only items with a two-factor code
     set up; *SSH and PGP keys* shows only keys. The chosen category's
     name heads the item list, and an empty category says so and offers a
     button to make its first item.
   - **Tools**: **Generator** (make a strong password), **Import** (bring
     items in from Bitwarden or a browser export), **Unlock methods**
     (add or remove ways to unlock) and **Sync** (keep the vault in step
     with your other devices).
   - **Lock** at the bottom locks the vault straight away.
2. **Item list (middle).** Type in **Search** to filter by title, user
   name or website. Each row shows the title and, under it, the user name,
   the card's network and last four digits, or the identity's name. A
   **2FA** tag means the item has one-time codes; **Key** means it is an
   SSH or PGP key. **New item** asks which kind of item to start, including
   a new **SSH key** or **OpenPGP key**.
3. **Details (right).** The item you picked.

### Item details

![An item's details](images/desktop-2-detail.png)

- **Username** and **Password** each have a copy button. The password stays
  hidden until you press **Show**. Cards and identities show their own
  fields the same way; a card's number, security code and PIN, and any
  hidden custom field, stay hidden until **Show**.
- **One-time code** shows the current code with a ring that empties as the
  code nears its end. It turns orange in the last five seconds, so wait for
  the next code if you are typing it by hand.
- A **secure note** shows its text only after **Show**; **Copy note**
  copies it without showing it.
- **Autofill is bound to** (logins only) lists the websites the browser extension may
  fill this item on. *This site only* means exactly that address; *the
  whole domain* also covers its subdomains. An item with no websites is
  never offered for autofill.
- For SSH and PGP keys, the **Key** card shows the key type and
  fingerprint, the public key with a **Copy public key** button, and an
  **Ask before each use** tick box. The private key itself is never shown:
  vaultd signs and decrypts for you. See
  [SSH and PGP keys](05-desktop-app.md#ssh-and-pgp-keys).
- **Edit** and **Delete** sit at the top right. Delete asks you to confirm.

## The command palette (Ctrl K)

![The command palette](images/desktop-3-palette.png)

Press **Ctrl K** anywhere in the unlocked window to open a search box over
the window. It is the fastest way to work without the mouse.

1. Start typing part of a title, user name or website, for example `git`.
2. **Items** lists the matches. Press **Enter** to copy the highlighted
   item's password (for a key, card, identity or secure note, Enter opens
   it instead).
3. **Actions** offers more for the best match: copy the user name, copy the
   one-time code, or show the item.
4. **Vault** actions are always there: *New item* (a new login), *New SSH key*,
   *New OpenPGP key*, *Generate a password*, *Import items*, *Unlock methods* and *Lock now*. Type `lock` and press
   Enter to lock.

Use the **Up** and **Down** arrow keys to move, **Enter** to run, and **Esc**
(or a click outside the box) to close it. You can also click any row.

Everything you copy, from the palette or the buttons, is cleared from the
clipboard after 30 seconds, when the vault locks and when the app closes.

## Keyboard shortcuts

| Action | Linux and Windows | macOS (when supported) |
| --- | --- | --- |
| Open or close the command palette | Ctrl K | Cmd K |
| Lock the vault | Ctrl L | Cmd L |
| Move in the palette | Up / Down | Up / Down |
| Run the highlighted row | Enter | Return |
| Close the palette | Esc | Esc |

## Differences between platforms

- **Clipboard history.** On Windows, copied secrets are marked so clipboard
  history (Win + V) and cloud clipboard sync skip them. On Linux the app
  can't mark them, so a clipboard manager may keep a copy even after the app
  clears the clipboard 30 seconds later. Turn off history in your clipboard
  manager, or exclude the app, if you use one.
- **Unlock methods.** TPM unlock works on Linux and Windows, but a TPM
  method added on one system does not open on the other. Security keys
  work on both; on Windows, Windows itself asks for the touch and the PIN in
  its own window. Quick unlock with Windows Hello is Windows only (see the
  table under *Unlocking*).
- **macOS** is not supported yet.
