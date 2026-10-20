# 4. Browser autofill

The browser extension fills your username and password into a login form
when you ask it to. It is built so that a malicious or hacked website cannot
trick it into handing over a login:

- It never fills anything on its own when a page loads. You always click or
  press the shortcut.
- It offers and fills a login only on the website saved in that item (see
  [Websites and matching](03-items.md#websites-and-matching)).
- It fills only visible, enabled fields: hidden or invisible decoy fields
  are skipped.
- The extension's pairing is limited to autofill. Even if the browser were
  compromised, it cannot list your whole vault, export it or change it.

## Which browsers

| Browser | Linux | Windows | macOS |
|---|---|---|---|
| Google Chrome | Yes | Yes | Not yet |
| Chromium | Yes | Not registered by the installer | Not yet |
| Microsoft Edge | Yes | Yes | Not yet |
| Firefox 128 or newer | Yes | Yes | Not yet |

Other Chromium-based browsers (Brave, Vivaldi) are not set up by the
installer.

## Set it up

You need `vaultd` running, a vault created, and `vault-native-host`
built ([chapter 1](01-getting-started.md)). The *native host* is the small
program the browser starts to talk to `vaultd`.

### 1. Load the extension

The extension is not in the browser stores yet, so you load it from the
source folder.

**Chrome, Chromium or Edge**

1. Open `chrome://extensions` (Edge: `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose the `extension` folder inside
   `PasswordVault`.
4. Copy the **ID** shown on the extension's card (32 letters).

**Firefox**

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on** and choose `extension/manifest.json`.
3. Its ID is always `autofill@passwordvault.dev`.

Firefox removes temporary add-ons when it closes, so you load it again after
each restart until the extension is signed.

### 2. Register the native host

Tell the browser where `vault-native-host` is and which extension may start
it. Use the Chrome/Edge ID from step 1, and add the Firefox ID if you use
Firefox:

Linux:

```sh
vault-native-host --install CHROME_EXTENSION_ID autofill@passwordvault.dev
```

Windows (PowerShell, in the `PasswordVault` folder):

```powershell
target\release\vault-native-host.exe --install CHROME_EXTENSION_ID autofill@passwordvault.dev
```

On Linux this writes `dev.passwordvault.host.json` into the Chrome,
Chromium, Edge and Firefox configuration folders. On Windows it writes the
files to `%APPDATA%\vault\` and registers them for Chrome, Edge and Firefox
in your user's registry. Leave out the second ID if you do not use Firefox.

If you rebuild or move `vault-native-host`, or the Chrome extension ID
changes (it can when you load it from another folder), run `--install`
again.

### 3. Connect the extension to the vault

1. Click the Secret Vault icon in the toolbar (pin it from the puzzle-piece
   menu if you do not see it).
2. Click **Connect**.
3. `vaultd` opens a window asking whether to allow **"browser"** with
   **autofill** access, and names the program asking. Click **Allow**.

No desktop available? Run `vault-native-host --pair --password` in a
terminal and type your master password instead.

## Fill a login

1. Go to the site's login page.
2. Click the Secret Vault icon. If the vault is locked, type your master
   password and press **Unlock**.
3. The popup shows the site's address at the top and the logins saved for
   it. Click **Fill** next to the one you want.

**Shortcut:** press **Ctrl+Shift+L** on a login page. It fills straight
away when exactly one login matches the site; otherwise open the popup and
choose. You can change the shortcut in `chrome://extensions/shortcuts` or
Firefox's add-on settings.

The username goes into the visible text field just before the first
visible password field, and the password into that field. Forms split over
two pages (username first, then password) need one fill per page.

### Login forms inside another site's frame

Some sites embed their login form from another domain, for example a bank
that uses a separate sign-in provider. If the page has no visible form of
its own but contains frames from other sites, the popup says so and shows a
**Fill in https://...** button for each one.

Click one only if you trust that site with this login. The browser then asks
you to grant the extension access to that site; the access is removed again
right after the fill. The vault still releases the login only for the site
of the tab you are on.

## Fill a card or an address

On an `https` checkout or address form, the popup also lists **Cards** and
**Addresses** (your identities). They appear only when the page has fields
for them: a card number field for cards, a name or address field for
addresses.

- **Address:** click **Fill** and the name, email, phone and address go
  into the matching fields.
- **Card:** click **Fill**. The popup says *Confirm in the Secret Vault
  window*, and a Secret Vault window opens naming the card (for example
  *Travel (Visa •••• 1111)*), the site and the program asking. Press
  **Allow** to fill it, or **Deny**. **Deny** has the focus, so pressing
  Enter does not allow by accident. Opening the window may close the popup;
  the fill still completes.

Why the extra step for cards: a login is only ever filled on its own
website, but a card is not tied to any site, so the vault asks you each
time instead. A program holding the browser's pairing therefore cannot
read your cards without you seeing it.

Things to know:

- Only the page's top frame is filled. Many checkouts put the card fields
  inside the payment provider's own frame (Stripe and similar); those are
  not filled yet, so copy the number from the desktop app instead.
- Notes and custom fields are never sent to the browser.
- On Linux and Windows alike, the approval window needs `vaultd` to run in
  your desktop session. A `vaultd` started with `--no-prompt` cannot fill
  cards; addresses still work.

## One-time codes and generated passwords

- **Code** next to a login copies its current one-time code to the
  clipboard.
- **Generate password** at the bottom copies a new random password to the
  clipboard, to paste into a sign-up or change-password form. Then save it
  in the vault with `vault add` or the desktop app.

The extension does not save new logins on its own.

## Lock

Click **Lock** at the top of the popup. This locks the whole vault, for
every program, not only the browser.

## Things to know

- When you unlock from the popup, your master password passes through the
  browser. Unlocking with `vault unlock` or the desktop app keeps it out of
  the browser entirely.
- Passkeys are not handled yet.
- To stop the browser using the vault, remove the extension. See
  [Unpair a program](08-troubleshooting.md#unpair-a-program) to also
  invalidate its pairing.
