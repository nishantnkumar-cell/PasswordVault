# 1. Getting started

By the end of this chapter you will have `vaultd` running, a new vault
created and unlocked, your recovery code written down, and the `vault`
command paired with the vault.

There are no ready-made installers yet, so you build Secret Vault from its
source code. That takes one command once the tools are installed.

- [Linux](#linux)
- [Windows](#windows)
- [macOS](#macos)
- [Create your vault](#create-your-vault) (all systems)

**Tool versions.** Secret Vault follows the latest stable Rust (tested with
Rust 1.99). If you installed Rust a while ago, run `rustup update` before
you build; an old compiler fails with errors such as "package requires
rustc 1.xx or newer" or "feature `edition2024` is required". The same
command works on Linux, Windows and macOS.

## Linux

### 1. Install the build tools

Install Rust from [rustup.rs](https://rustup.rs), then the libraries that the
security key and TPM support need. On Debian or Ubuntu:

```sh
sudo apt-get install git pkg-config libtss2-dev libudev-dev libhidapi-dev
```

On other distributions, install the packages that provide `tss2-esys`,
`libudev` and `hidapi` development files. If you do not want security key or
TPM support at all, you can skip them and build `vaultd` with
`--no-default-features` instead.

For the desktop app and the approval window you also need a desktop session
(X11 or Wayland) with OpenGL.

### 2. Build and install

```sh
git clone https://github.com/nishantnkumar-cell/PasswordVault.git
cd PasswordVault
cargo install --path crates/vaultd
cargo install --path crates/vault-cli
cargo install --path crates/vault-gui            # the desktop app and vault-prompt
cargo install --path crates/vault-native-host    # only if you want browser autofill
cargo install --path crates/vault-gpg            # only for git, pass or mail through gpg (chapter 9)
```

The programs land in `~/.cargo/bin`. `vault-prompt` (the small window that
asks you to approve things) must stay in the same folder as `vaultd`; `cargo
install` takes care of that.

### 3. Start the daemon

To try it out, run it in a terminal:

```sh
vaultd
```

To have it start with your session, install it as a user service:

```sh
mkdir -p ~/.config/systemd/user
cp contrib/systemd/vaultd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now vaultd
```

The service also locks the daemon's memory so keys never reach swap.

> **Stronger option (Linux only).** `contrib/systemd/vaultd@.service` runs
> `vaultd` as a separate `vault` system user, so even programs running as
> you cannot read its memory. Its install steps are at the top of the file.
> In that mode there is no approval window (the daemon has no desktop), so
> you pair programs by proving an unlock method, and you must set
> `VAULT_SOCKET=/run/vault/$USER/vaultd.sock` in your shell profile.

Now go to [Create your vault](#create-your-vault).

## Windows

### The easy way: the installer

Download and run `SecretVault-Setup-<version>.exe`. "Install for me only"
needs no administrator rights, and vaultd then starts by itself, with no
window, every time you sign in. Follow
[Installing and running on Windows](windows-install.md), then come back to
[Create your vault](#create-your-vault).

The rest of this section builds the programs from source instead.

### 1. Install the build tools

1. Install [Git for Windows](https://git-scm.com/download/win).
2. Install Rust from [rustup.rs](https://rustup.rs). When it asks, let it
   install the Visual Studio "Desktop development with C++" build tools.

### 2. Build

In PowerShell:

```powershell
git clone https://github.com/nishantnkumar-cell/PasswordVault.git
cd PasswordVault
cargo build --release
```

The programs are in `target\release\`: `vaultd.exe`, `vaultw.exe`,
`vault.exe`, `vault-gui.exe`, `vault-prompt.exe` and
`vault-native-host.exe`. Add that
folder to your `PATH`, or run them with their full path.

### 3. Start the daemon

Run `target\release\vaultw.exe`. It starts `vaultd.exe` in the background,
with no window, and writes its messages to
`%LOCALAPPDATA%\vault\state\vaultd.log`. (Running `vaultd.exe` directly
keeps it in a console window instead; closing that window stops it.)

To start it every time you sign in, run this once in PowerShell from the
`PasswordVault` folder. It is the same entry the installer adds:

```powershell
$exe = (Resolve-Path target\release\vaultw.exe).Path
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run "Secret Vault daemon" "`"$exe`""
```

> **Security keys on Windows.** vaultd uses Windows' own security key
> service, so it does not need administrator rights; Windows shows its own
> window for the touch and the PIN. This needs Windows 11 or Windows 10 with
> current updates. TPM slots and quick unlock with Windows Hello work
> without administrator rights too; see [chapter 2](02-unlocking.md).

## macOS

The daemon, the `vault` command, the desktop app and the browser host do
not run on macOS yet. What you can try today is checking that your security
key works with the vault's key code:

```sh
cargo run -p vault-hw --example fido2-check
```

## Create your vault

Do this once, with `vaultd` running. You can use the command line (below)
or the [desktop app](05-desktop-app.md#first-run), which walks you through
the same steps in a window.

### 1. Choose a master password

```sh
vault init
```

Type a master password of at least 8 characters, twice. Pick a long
passphrase you can remember: it protects everything in the vault. Creating
the vault takes a few seconds on purpose, because the password is stretched
with Argon2id to make guessing slow.

### 2. Write down the recovery code

`vault init` prints a **recovery code** exactly once: 58 letters and
digits in groups of six, like `4K7QZD-M2XH9A-...`. It can unlock the vault on its own, without the password.

- Write it on paper, or store it somewhere offline you trust.
- Do not keep it on the same computer as the vault.
- Anyone who has it can read your vault. If you lose both the password and
  the recovery code, nobody can open the vault, including the developers.

The command that ran `vault init` is now paired automatically, and the vault
is unlocked.

### 3. Check that it worked

```sh
vault status
```

```
vault:     unlocked
generation: 1
auto-lock in: 899 s
paired:    yes
```

### 4. Add your first login

```sh
vault add --generate
```

Answer the questions (title, username, website). `--generate` makes a
strong 24-character password for you. Then list your items:

```sh
vault ls
```

The next chapter covers locking, unlocking and adding more ways to unlock.

## Pairing other programs

Every program that talks to `vaultd` must be paired once. `vault init`
pairs the CLI for you. If the CLI ever loses its pairing (for example its
token file was deleted), pair it again:

```sh
vault pair
```

`vaultd` opens a window that names the program asking and what it would be
allowed to do. **Deny** is selected by default; press **Allow** only if you
started that request yourself. If you do not answer within a minute, it is
denied. After a denial, new requests are refused for 10 seconds.

If you have no desktop (for example over SSH), prove an unlock method
instead: `vault pair --password` (or `--fido2`, `--tpm`, `--recovery`).

The browser extension and the desktop app pair the same way; their
chapters show where to click.
