# 13. Installing and running on macOS

This chapter takes you from nothing to a working vault on a Mac: installing
Secret Vault, starting `vaultd`, turning on Touch ID, and connecting your
browser. It also lists what works differently from Linux and Windows.

Secret Vault runs on macOS 11 (Big Sur) or newer, on Apple silicon and on
Intel Macs.

- [Install from a release](#install-from-a-release)
- [Build from source instead](#build-from-source-instead)
- [Create your vault](#create-your-vault)
- [Quick unlock with Touch ID](#quick-unlock-with-touch-id)
- [Security keys](#security-keys)
- [Browser autofill](#browser-autofill)
- [SSH keys](#ssh-keys)
- [Where your files are](#where-your-files-are)
- [Upgrading and removing](#upgrading-and-removing)
- [Differences from Linux and Windows](#differences-from-linux-and-windows)
- [Troubleshooting](#troubleshooting)

## Install from a release

1. Download `secret-vault-<version>-macos-arm64.tar.gz` (Apple silicon:
   M1 and newer) or `...-macos-x86_64.tar.gz` (Intel) from the project's
   [Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases).
   To check which Mac you have, open the Apple menu > About This Mac: "Chip
   Apple M…" means Apple silicon.
2. Double-click the file in Finder to unpack it.
3. Open **Terminal** (Applications > Utilities), type `cd ` (with a space),
   drag the unpacked folder onto the Terminal window, and press Return.
4. Run:

   ```sh
   ./install.sh
   ```

This needs no administrator password. It does three things:

- puts **Secret Vault.app** in the `Applications` folder inside your home
  folder (`~/Applications`), where Launchpad and Spotlight find it;
- puts the `vault`, `vaultd` and `vault-gpg` commands in `~/.local/bin`;
- adds a **launch agent**, so `vaultd` starts now and every time you sign
  in, and starts again if it stops.

If it says to add `~/.local/bin` to your `PATH`, run the command it prints,
then open a new Terminal window.

> **Why Terminal, and not a double-click?** The app is not signed with an
> Apple developer ID yet, so macOS would refuse to open a downloaded copy
> ("Secret Vault can't be opened because Apple cannot check it"). The
> install script clears that download flag on the copy it installs. If you
> ever see that message anyway, right-click (or Control-click) the app in
> Finder, choose **Open**, then **Open** again.

## Build from source instead

1. Install Apple's command line tools: `xcode-select --install` (accept the
   window that appears). You do not need the full Xcode app.
2. Install Rust from [rustup.rs](https://rustup.rs).
3. Build and package:

   ```sh
   git clone https://github.com/nishantnkumar-cell/PasswordVault.git
   cd PasswordVault
   cargo build --release
   contrib/macos/package.sh 0.0.0-local
   ```

4. Unpack `target/packages/secret-vault-0.0.0-local-macos-*.tar.gz` and run
   its `./install.sh`, as in [Install from a release](#install-from-a-release).

To try things without installing, you can also run
`target/release/vaultd` in one Terminal window and `target/release/vault`
or `target/release/vault-gui` in another.

## Create your vault

Open **Secret Vault** from Launchpad or Spotlight. With no vault yet, the
setup wizard opens and walks you through the master password, the recovery
code, Touch ID and the browser
([desktop app, chapter 5](05-desktop-app.md#no-vault-yet-the-setup-wizard)).
Or use the command line: `vault init`
([Getting started](01-getting-started.md#create-your-vault)).

The steps are the same as on Linux and Windows, with two differences in the
wizard's **Unlock methods** step:

- **Touch ID** is offered instead of Windows Hello.
- **This computer's TPM chip** is not offered: Macs have no TPM.

## Quick unlock with Touch ID

Typing a long master password many times a day is tiresome. Quick unlock
lets Touch ID open the vault again after it locks, for a few hours after
you last unlocked it with your password.

How it works, in short: when the vault locks with quick unlock on, `vaultd`
keeps the vault key in its memory, wrapped under a random key. Touch ID
lets `vaultd` use it again. Touch ID never opens a vault on its own: after
the hours run out, after `vaultd` restarts (or the Mac restarts), or after
three failed tries, you need your password again.

**Turn it on**, after unlocking with your password:

- In the desktop app: **Unlock methods** > **Quick unlock with Touch ID**,
  pick the number of hours, press **Apply** and touch the sensor.
- Or on the command line:

  ```sh
  vault quick-unlock 8      # 8 hours after each full unlock (1 to 24)
  ```

**Use it:** when the vault is locked, press **Unlock with Touch ID** in the
app, or run `vault unlock --touch-id` (`--hello` works too).

The macOS window that appears says "vaultd is trying to unlock Secret
Vault". It accepts your fingerprint, a paired Apple Watch, or your Mac
login password if neither is there. Macs without Touch ID can still use
quick unlock with the login password.

**Turn it off:** pick **Off** in the app, or run `vault quick-unlock off`.
`vault lock --full` locks and forgets the quick unlock key right away.

## Security keys

FIDO2 security keys (YubiKey, Nitrokey, Google Titan and others) work as on
Linux: plug the key in, then add it in the app (**Unlock methods** > **Add**
> **Security key**) or with `vault add-slot fido2`. The app asks for the
key's PIN itself; macOS shows no window of its own. No extra permission is
needed. A key slot added on a Mac unlocks on Linux and Windows too, and the
other way round. Chapter 2 has the details:
[Add a security key](02-unlocking.md#add-a-security-key-fido2).

To check a key before you add it:

```sh
cargo run -p vault-hw --example fido2-check
```

## Browser autofill

Chrome, Chromium, Microsoft Edge and Firefox work. Follow
[Browser autofill](04-browser-autofill.md). The setup wizard's browser step
registers the browser host for you; on the command line it is:

```sh
"$HOME/Applications/Secret Vault.app/Contents/MacOS/vault-native-host" --install <extension-id>
```

That writes the host's manifest into each browser's folder under
`~/Library/Application Support/` (`Google/Chrome`, `Chromium`,
`Microsoft Edge` and `Mozilla`). Safari is not supported: it needs an app
extension built with Xcode.

## SSH keys

`vaultd` serves the ssh-agent protocol at
`~/Library/Application Support/vault/state/ssh-agent.sock`. Point SSH at it
in `~/.zprofile`:

```sh
export SSH_AUTH_SOCK="$HOME/Library/Application Support/vault/state/ssh-agent.sock"
```

The quotes matter, because the path has a space in it. In `~/.ssh/config`
the same goes for `IdentityAgent`:

```
Host *
    IdentityAgent "~/Library/Application Support/vault/state/ssh-agent.sock"
```

Setting `SSH_AUTH_SOCK` replaces macOS's own agent for that shell. Chapter
6 covers the rest: [SSH keys and git signing](06-ssh-and-git.md).

## Where your files are

| What | Where |
|---|---|
| The vault file | `~/Library/Application Support/vault/vault.svault` |
| Pairing tokens and client settings | `~/Library/Application Support/vault/` |
| Daemon state, socket and ssh-agent socket | `~/Library/Application Support/vault/state/` |
| The app and its programs | `~/Applications/Secret Vault.app` |
| The launch agent | `~/Library/LaunchAgents/dev.passwordvault.vaultd.plist` |
| vaultd's messages | `~/Library/Logs/vaultd.log` (open it with the Console app) |

If you set `XDG_DATA_HOME`, `XDG_CONFIG_HOME` or `XDG_STATE_HOME`, Secret
Vault uses those folders instead, as on Linux.

The `Library` folder is hidden in Finder: press Command-Shift-G and type
`~/Library/Application Support/vault`.

Back up `vault.svault` the way you back up other files. Time Machine copies
it too; the file is encrypted, so that is safe.

## Upgrading and removing

**Upgrade:** download the newer release and run its `./install.sh`. It
replaces the app, keeps your vault and settings, and restarts `vaultd`.
See [Versions, downloads and upgrading](11-versions-and-upgrades.md).

**Stop vaultd** for now (it starts again at the next sign-in):

```sh
launchctl bootout gui/$(id -u)/dev.passwordvault.vaultd
```

**Remove Secret Vault** (your vault file stays, so copy it somewhere first
if you need it, or delete the `vault` folder too):

```sh
launchctl bootout gui/$(id -u)/dev.passwordvault.vaultd
rm ~/Library/LaunchAgents/dev.passwordvault.vaultd.plist
rm -r "$HOME/Applications/Secret Vault.app"
rm ~/.local/bin/vault ~/.local/bin/vaultd ~/.local/bin/vault-gpg
```

## Differences from Linux and Windows

| | macOS | Linux | Windows |
|---|---|---|---|
| Install | `.tar.gz` with `install.sh`, no admin rights | `.deb`, or `.tar.gz` with `install.sh` | Installer, no admin rights |
| Starts at sign-in | Launch agent | systemd user service | Run key (`vaultw.exe`) |
| Quick unlock | Touch ID, Apple Watch or login password | Not yet | Windows Hello |
| TPM slot | Not applicable (no TPM) | Yes | Yes |
| Secure Enclave slot | Not yet | Not applicable | Not applicable |
| Security key PIN | Typed in the app | Typed in the app | Windows asks in its own window |
| Browsers | Chrome, Chromium, Edge, Firefox (not Safari) | Chrome, Chromium, Edge, Firefox | Chrome, Edge, Firefox |
| Copied secrets kept out of clipboard history | Yes (marked so clipboard managers skip them) | No such feature | Yes |
| Locks on screen lock and sleep | Not yet: it locks after 15 idle minutes | Yes | Yes |
| Keys kept out of crash dumps | Yes | Yes | Not yet |
| Keys kept out of swap | Swap is always encrypted by macOS | Yes (memory locked) | Not yet |
| Debuggers kept out of vaultd | Yes (`PT_DENY_ATTACH`) | Yes | Not yet |
| Apps keep passwords in the vault (Secret Service) | Not applicable | Yes, opt-in | Not applicable |

The vault file is the same everywhere: one made on a Mac opens on Linux and
Windows, and you can [sync](10-sync.md) it between them. TPM slots made on
another computer are skipped on a Mac; use the password, a security key or
the recovery code there.

## Troubleshooting

**`vault` says it can't reach vaultd.** Check that it runs:
`launchctl print gui/$(id -u)/dev.passwordvault.vaultd | grep state`. If it
isn't running, look at the end of `~/Library/Logs/vaultd.log`. To start it
again: `launchctl kickstart gui/$(id -u)/dev.passwordvault.vaultd`.

**Touch ID says it cannot ask from here.** `vaultd` must run in your
desktop session. The launch agent does; a `vaultd` started over SSH does
not.

**Touch ID is locked.** After too many failed fingerprints, macOS needs
your login password once. Lock the screen and sign in with your password,
then try again.

**The approval window doesn't appear when pairing.** It is a separate
program, `vault-prompt`, which must be next to `vaultd`. In the installed
app it always is; if you run programs from a build folder, run `vaultd`
from `target/release` too.

**"Secret Vault can't be opened."** See the note under
[Install from a release](#install-from-a-release).
