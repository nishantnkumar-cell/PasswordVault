# 8. Troubleshooting, backups and safety tips

## Where your files are

| What | Linux | Windows |
|---|---|---|
| Vault file | `~/.local/share/vault/vault.svault` | `%LOCALAPPDATA%\vault\vault.svault` |
| Daemon state (pairings, rollback counter) | `~/.local/state/vault/` | `%LOCALAPPDATA%\vault\state\` |
| CLI pairing token | `~/.config/vault/token` | `%APPDATA%\vault\token` |
| Desktop app token | `~/.config/vault/desktop-token` | `%APPDATA%\vault\desktop-token` |
| Browser host token | `~/.config/vault/native-host-token` | `%APPDATA%\vault\native-host-token` |
| Daemon address | `$XDG_RUNTIME_DIR/vault/vaultd.sock` | `\\.\pipe\vaultd-<your SID>` |

The Linux paths follow `XDG_DATA_HOME`, `XDG_STATE_HOME` and
`XDG_CONFIG_HOME` when those are set. `vaultd --vault PATH` uses another
vault file, and `VAULT_SOCKET` points clients at another daemon address.

## Back up your vault

The vault file is encrypted, so a copy is as safe as the original. Copy it
to a USB drive or another disk now and then:

```sh
cp ~/.local/share/vault/vault.svault /media/usb/vault-2026-10-20.svault
```

```powershell
Copy-Item "$env:LOCALAPPDATA\vault\vault.svault" E:\vault-2026-10-20.svault
```

Keep your recovery code separately from the backup. A backup can be opened
with any slot it had when it was copied, including ones you later removed;
after `vault revoke`, replace your backups too.

## Move the vault to another computer

If you use [sync](10-sync.md), install Secret Vault on the new computer
and **join** the synced vault instead; there is nothing to copy. Otherwise:

1. Install Secret Vault on the new computer ([chapter 1](01-getting-started.md)).
2. Copy the vault file to the path in the table above (Linux and Windows
   use the same format, so it can go either way).
3. Start `vaultd`, then pair each program again (`vault pair --password`).
4. A TPM slot belongs to the old computer and will not work on the new
   one. Unlock with the password or recovery code, remove the old TPM slot
   and add a new one.

## Common problems

**The build fails with "requires rustc 1.xx or newer" or an edition error**

Your Rust is older than the project's crates expect. Run `rustup update`
(all systems) and build again. `rustc --version` shows what you have; the
project is tested with the latest stable release.

**"cannot reach vaultd ... Is it running?"**
Start the daemon: `vaultd`, `systemctl --user start vaultd`, or
`vaultw.exe` on Windows (or sign out and back in, if it starts at sign-in).
On Windows, `%LOCALAPPDATA%\vault\state\vaultd.log` says why it stopped. If it runs as the Linux system user, set
`VAULT_SOCKET=/run/vault/$USER/vaultd.sock`.

**"no vault; run `vault init`"**
There is no vault file at the expected path. Create one, or start `vaultd
--vault PATH` with the path of your existing file.

**The client says it is not paired, or "The vault no longer knows this app"**
Pair it again: `vault pair`, the desktop app's pairing screen, or the
extension's **Connect** button.

**No approval window appears when pairing**
The window is `vault-prompt`, which must be in the same folder as `vaultd`
(or named by the `VAULT_PROMPT` variable) and needs a desktop session. If
`vaultd` runs as a systemd user service, the session must have passed
`DISPLAY` or `WAYLAND_DISPLAY` to it (desktop environments normally do).
A `vaultd` started with `--no-prompt` or running as the Linux system user
never shows it. In all these cases, pair by proving an unlock method:
`vault pair --password`.

**"a request is already waiting" or pairing refused right after a denial**
Only one approval window is open at a time, and after a denial or timeout
new requests are refused for 10 seconds. Wait and try again.

**"too many failed attempts; try again in N s"**
After 3 wrong unlock attempts each failure doubles a wait, up to 5 minutes.
Wait it out; restarting `vaultd` also clears it.

**Security key not found or not responding**
- Windows: the touch and PIN happen in Windows' own security key window,
  which may open behind other windows; check the taskbar. On a Windows 10
  build too old for Windows' security key service, vaultd needs to run as
  administrator, or update Windows.
- Linux: check that your user can open `/dev/hidraw*`; for the system-user
  setup, install `contrib/udev/70-vault-fido.rules`.
- Run `cargo run -p vault-hw --example fido2-check` to test the key on its
  own.

**TPM slot stopped working**
If it was added with `--pcr7`, a change to Secure Boot or a firmware update
makes it unusable. Unlock with another slot, `vault rm-slot` the TPM slot and
add it again. With a PIN, too many wrong PINs put the TPM into its own
lockout for a while.
On Windows, a TPM slot made under Linux on the same computer does not open
(and the other way round); the error says which system made it. Add a TPM
slot from each system.

**"no usable TPM 2.0" on Windows**
Press Win+R, run `tpm.msc` and check that the TPM is ready and its
specification version is 2.0. If no TPM is found, turn it on in the
firmware settings (often called fTPM, PTT or Security Device). Then run
`cargo run -p vault-hw --example tpm-check` from the source folder.

**No "Unlock with Windows Hello" button, or `vault unlock --hello` says quick unlock is not available**
- Quick unlock must be on: `vault quick-unlock` shows the setting.
- It only works after a full unlock (password, security key, TPM or
  recovery code) since `vaultd` started, and only for the hours you chose.
- Three failed or cancelled Windows Hello checks switch it off until the
  next full unlock, and so does `vault lock --full`.
- If Windows says Windows Hello is not set up, add a PIN, face or
  fingerprint in Settings > Accounts > Sign-in options. `cargo run -p
  vault-hw --example hello-check` tests it on its own.
- If the Windows Security window doesn't come to the front, look for it on
  the taskbar.

**`vault status` warns that the vault file is older than one vaultd saw before**
`vaultd` remembers how many times the vault has been saved. A file with a
lower count means an older copy replaced the current one, which is how an
attacker could bring back a password you changed or a slot you revoked.
Items can still be read, but every change is refused.

- If you did not restore anything, treat it as tampering: find out where
  the file came from before using it.
- If you restored a backup on purpose, stop `vaultd`, delete the
  `generations` file in the daemon state folder (table above), and start
  `vaultd` again. It then accepts the restored file.

**ssh says "Permission denied (publickey)" or `ssh-add -L` shows nothing**
The vault is locked, or `SSH_AUTH_SOCK` does not point at the vault's agent.
Unlock, run `eval "$(vault ssh agent)"` (or the PowerShell line on Windows)
and try again. On Windows use `C:\Windows\System32\OpenSSH\ssh.exe`, not the
`ssh` from Git for Windows.

**The browser says "Specified native messaging host not found"**
Run `vault-native-host --install` again with the extension ID shown in the
browser ([chapter 4](04-browser-autofill.md#2-register-the-native-host)).

## Unpair a program

There is no command to unpair a single program yet. To make the vault
forget **all** pairings:

1. Stop `vaultd`.
2. Delete the `clients` file in the daemon state folder (table above).
3. Start `vaultd` and pair the programs you still use again.

Deleting a program's token file only makes that program forget its pairing;
the daemon would still accept a copy of that token.

## Safety tips

- **Lock when you step away.** `vault lock`, Ctrl+L in the app, or lock your
  screen; the vault locks with it on Linux and Windows.
- **Keep the recovery code offline.** It opens the vault on its own.
- **Approve only what you started.** If an approval window appears and you
  did not just pair something, sign, or log in, press **Deny**.
- **Unlock outside the browser** when you can. Typing the master password in
  the extension's popup works, but it passes through the browser.
- **Delete import files** right after importing.
- **Windows:** the daemon's memory is not yet protected from the page file
  and crash dumps. Do not leave the vault unlocked longer than you need to.
- **Linux, stronger setup:** run `vaultd` as its own system user
  (`contrib/systemd/vaultd@.service`) so programs running as you cannot read
  its memory.

## Licence

Secret Vault is licensed under the
[PolyForm Noncommercial License 1.0.0](../../LICENSE.md). You may use,
change and share it for personal, research, educational and other
noncommercial purposes. Commercial use is not permitted.
