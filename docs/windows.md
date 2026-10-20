# Windows

`vaultd`, `vault`, `vault-gui` and `vault-native-host` build and run on
Windows 10 and 11. The vault file format is the same on every system, so a
vault file can be copied between machines.

## Install

Download `SecretVault-Setup-<version>.exe` (the `windows-installer` artifact
of a CI run, until there are releases) and run it. "Install for me only"
needs no administrator rights; "Install for all users" asks once, during
setup. Step by step: [user-guide/windows-install.md](user-guide/windows-install.md).

To build the installer yourself, build the programs and compile
`contrib\windows\vault.iss` with Inno Setup 6:

    cargo build --release --locked
    iscc contrib\windows\vault.iss /DAppVersion=0.1.0

It lands in `target\installer\`.

## Build

Install Git, and Rust from rustup.rs with the "Desktop development with C++"
build tools, then in PowerShell:

    git clone https://github.com/nishantnkumar-cell/PasswordVault.git
    cd PasswordVault
    cargo build --release

The programs are in `target\release\`: `vaultd.exe`, `vaultw.exe`,
`vault.exe`, `vault-gui.exe`, `vault-prompt.exe`, `vault-native-host.exe`,
`vault-gpg.exe`.

## Run

`vaultw.exe` starts `vaultd.exe` in the background, with no window, and
returns. vaultd's messages go to `%LOCALAPPDATA%\vault\state\vaultd.log`
(the previous log is kept as `vaultd.log.old` once it passes 1 MiB). Any
arguments are passed on to vaultd. This is what the installer runs at
sign-in, from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (HKLM
for an all-users install), value `Secret Vault daemon`.

To watch the messages instead, run `vaultd.exe` in a terminal; closing the
terminal stops it. To stop a background vaultd:

    Stop-Process -Name vaultd

The keys go with the process; the vault file is unaffected.

vaultd is not a Windows service, on purpose. A service runs in session 0 as
a system account, with no desktop: it could not show the pairing approval
window, would not see your screen lock, and would hold every user's keys in
one privileged process. vaultd runs as each signed-in user instead, and only
that user can open its pipe.

## Where things are

| What | Path |
|---|---|
| Vault file | `%LOCALAPPDATA%\vault\vault.svault` |
| Daemon state | `%LOCALAPPDATA%\vault\state\` |
| CLI, app and browser-host tokens | `%APPDATA%\vault\token`, `desktop-token`, `native-host-token` |
| Daemon endpoint | `\\.\pipe\vaultd-<your user SID>` |

`VAULT_SOCKET` overrides the pipe name, as it overrides the socket on Linux.

## How the pipe is protected

- The pipe's ACL grants access to your user only, and it refuses remote
  (SMB) clients.
- The daemon creates it with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so it refuses
  to start if anything already holds the name.
- The daemon checks each client's process token: a client running as another
  user gets "this vault belongs to another user".
- Clients check the server's process token the same way before sending
  anything, so another account that squats the pipe name cannot collect
  passwords. Clients connect with identification-level impersonation only.

## Browser autofill

    target\release\vault-native-host.exe --install CHROME_EXTENSION_ID [FIREFOX_EXTENSION_ID]

`--install` writes the host manifests to `%APPDATA%\vault\` and registers
them for Chrome, Edge and (with an ID) Firefox under
`HKCU\Software\...\NativeMessagingHosts`. Then press Connect in the extension and allow it in the window vaultd opens.

## Security keys

vaultd uses Windows' WebAuthn API (webauthn.dll), so it needs no
administrator rights. Windows shows its own window for the touch and, for a
slot made with `--uv`, the key's PIN; the `vault` command does not ask for
the PIN on Windows, and the PIN field in the desktop app can stay empty.

The API needs version 4 (Windows 11, or Windows 10 with current updates).
On older builds vaultd falls back to talking to the key over USB HID, which
Windows allows only to administrators, as before. `VAULT_FIDO2=hid` forces
that path.

The secret is the same either way: the vault stores a PRF input, and both
paths turn it into the hmac-secret salt with the WebAuthn PRF construction
(format.md 4.2). Windows applies it itself, vault-hw does on Linux. A slot
made on one system unlocks on the other, with one exception: when the key
has a PIN, Windows verifies it on every request even when asked not to
(tested 2026-10-20 on Windows 11). The key then returns its with-UV secret,
so a touch-only slot (`require_uv = false`) cannot be read on Windows with
such a key. vault-hw checks the UV flag in the authenticator data and
refuses a mismatch with a clear error instead of failing as a wrong
password. Use `--uv` slots for keys with a PIN. To check a key, and that both paths
agree, run in an administrator terminal:

    cargo run -p vault-hw --example fido2-check -- --compare

## Locking

The vault locks when idle, when you lock the screen (Win+L) and when the
machine goes to sleep, through session and power notifications to a hidden
window.

## Not on Windows yet

- **TPM and Windows Hello unlock.** The TPM slot uses the Linux TPM stack;
  Windows needs its own backend (TBS or the Platform Crypto Provider) and a
  Windows Hello slot. Password, security key and recovery code work.
- **Memory hardening.** On Linux the daemon locks its memory and disables core
  dumps. On Windows keys can reach the page file and crash dumps for now.
