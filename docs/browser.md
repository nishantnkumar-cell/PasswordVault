# Browser autofill

Two parts: the extension in `extension/` (Manifest V3, Chrome, Chromium, Edge and Firefox 128+) and `vault-native-host`, which the browser starts over native messaging and which relays to `vaultd`.

## Install (Linux)

```sh
cargo install --path crates/vault-native-host
```

Load the extension unpacked: `chrome://extensions`, Developer mode, Load unpacked, pick `extension/`. Copy the extension ID it shows, then:

```sh
vault-native-host --install <EXTENSION_ID> [autofill@passwordvault.dev]   # second ID for Firefox
```

This writes `dev.passwordvault.host.json` into the browsers' `NativeMessagingHosts` folders, allowing only that extension to start the host.

Then open the extension and press **Connect**: vaultd opens a window asking you to allow "browser" with autofill access. That gives the host an autofill-only token. Without a desktop, run `vault-native-host --pair --password` in a terminal instead.

## How a fill happens

1. You open the popup or press Ctrl+Shift+L. Either is a user gesture; nothing is ever filled on page load.
2. The background script reads the page origin from the browser's tab data. Pages never send it messages: it accepts messages only from its own popup.
3. The host asks `vaultd` for logins that may be filled on that origin (`docs/items.md`, origin policy). The keyboard command fills only when exactly one matches.
4. On Fill, `vaultd` releases the username and password only if the item is bound to that origin (`GetForFill`). The host's token cannot list, export or edit items.
5. The fill function is injected into the top frame and into child frames whose URL has the same origin. It checks the frame's origin again, then fills only the first visible password field and the visible text field before it. Hidden, zero-size, off-screen, transparent, disabled and read-only fields are skipped.

If the page itself has no visible login form but contains https frames from other sites, the popup names each frame's site and fills there only when you pick one; the browser then asks you to grant the extension access to that site, which is removed again right after the fill. The item is still released only for the tab's own site.

TOTP codes and generated passwords are copied to the clipboard from the popup.

## Limits

- The master password typed into the popup passes through the extension and the host. Unlocking with `vault unlock` in a terminal avoids that.
- Passkeys are not handled (post-v1).

## Tests

`npm test` in `extension/` runs the policy tests. `test/fill.browser.mjs` loads the extension in Chromium and checks that the fill function fills the real form and none of four decoy fields; it needs `playwright-core` and a full Chromium (see the file header).
