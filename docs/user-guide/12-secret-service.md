# Keep apps' passwords in the vault (Linux)

Many Linux apps don't keep passwords themselves. They hand them to the
desktop's **Secret Service**, which is usually GNOME Keyring or KWallet.
Secret Vault can be that service instead, so those passwords live in your
vault: encrypted with your vault key, locked when the vault locks, and
synced with your other computers.

Apps that use it include Evolution and Geary (mail), Fractal and other
chat clients, GNOME Online Accounts, Remmina, `git` with the
`libsecret` credential helper, Python's `keyring` package and the
`secret-tool` command.

This is a Linux feature. On Windows and macOS, apps use Credential Manager
and the Keychain, which Secret Vault does not replace.

## What apps can and can't do

- An app can save, find, change and delete **its own kind of entries**,
  the ones apps saved through the Secret Service. It can never see your
  own logins, cards, identities, notes or keys.
- **You allow each program once.** The first time a program asks, Secret
  Vault's approval window shows the program and its command line. Allow it,
  and that program can use app passwords until vaultd restarts. Deny it,
  and it is refused (it won't ask again for a minute).
- **Nothing while locked.** While the vault is locked, apps find nothing
  and can't save. An app that asks to unlock opens the Secret Vault desktop
  app; unlock there (or with `vault unlock`) and the app carries on.
- Apps use an encrypted session by default, so passwords aren't readable
  by programs watching the bus.

> Allowing a program allows every copy of it. For `python3` or another
> interpreter, that means every script it runs. The approval window shows
> the command line so you can tell what is asking.

## Turn it on

1. **Stop the other Secret Service.** Only one program can be the Secret
   Service. On GNOME:

   ```sh
   # Keep GNOME Keyring for SSH if you use it, but drop its secrets part.
   mkdir -p ~/.config/autostart
   cp /etc/xdg/autostart/gnome-keyring-secrets.desktop ~/.config/autostart/
   echo 'Hidden=true' >> ~/.config/autostart/gnome-keyring-secrets.desktop
   ```

   On KDE Plasma, open **System Settings → KWallet** and untick
   **Use KWallet for the Secret Service interface** (or disable KWallet).
   Log out and back in.

2. **Start vaultd with `--secret-service`.** If you run vaultd as a user
   service, edit it:

   ```sh
   systemctl --user edit --full vaultd
   ```

   change the `ExecStart=` line to

   ```
   ExecStart=%h/.cargo/bin/vaultd --secret-service
   ```

   and restart it:

   ```sh
   systemctl --user restart vaultd
   journalctl --user -u vaultd -n 5
   ```

   The log says `Secret Service on the session bus`. If it says another
   Secret Service is running, step 1 didn't take; see
   [Troubleshooting](08-troubleshooting.md#common-problems) ("Apps don't save passwords in the vault").

3. **Try it** (with the vault unlocked):

   ```sh
   secret-tool store --label="Test" app test user alex@example.com
   # type a password, press Enter
   secret-tool lookup app test
   ```

   The first command opens the approval window for `secret-tool`. Choose
   **Allow**. The second prints the password back. Remove it again with
   `secret-tool clear app test`.

## Where the passwords show up

Each app password is a **login** in your vault, titled with the name the
app gave it (for example "Mail"). Its details are in custom fields:

- **Secret Service** marks it as an app password (its value is the type of
  the secret, usually `text/plain`);
- fields starting with **ss:** are the app's labels for it, such as
  `ss:user` or `ss:server`.

You can copy the password from the desktop app like any other. If you
edit it there, keep the **Secret Service** and **ss:** fields, or the app
won't find it any more. Deleting it in the desktop app deletes it for the
app too.

## Platform differences

| | Linux | Windows | macOS |
|---|---|---|---|
| Apps save passwords in the vault | Yes, with `--secret-service` | No (Credential Manager) | No (Keychain) |

## Turn it off

Remove `--secret-service` from `ExecStart=`, restart vaultd, and turn
GNOME Keyring's or KWallet's Secret Service back on. App passwords stay in
your vault as logins; apps will ask for them again.
