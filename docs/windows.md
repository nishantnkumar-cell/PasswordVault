# Windows

`vaultd`, `vault`, `vault-gui` and `vault-native-host` build and run on
Windows 10 and 11. The vault file format is the same on every system, so a
vault file can be copied between machines.

## Build

Install Git, and Rust from rustup.rs with the "Desktop development with C++"
build tools, then in PowerShell:

    git clone https://github.com/nishantnkumar-cell/PasswordVault.git
    cd PasswordVault
    cargo build --release

The programs are in `target\release\`: `vaultd.exe`, `vault.exe`,
`vault-gui.exe`, `vault-native-host.exe`.

## Run

Start `vaultd.exe` (it stays in its console window), then use `vault init`
or the desktop app. To start it at sign-in, minimized:

    $exe = (Resolve-Path target\release\vaultd.exe).Path
    $lnk = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vaultd.lnk"
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $s.TargetPath = $exe; $s.WindowStyle = 7; $s.Save()

Closing the window stops the daemon; the keys go with the process.

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
    target\release\vault-native-host.exe --pair

`--install` writes the host manifests to `%APPDATA%\vault\` and registers
them for Chrome, Edge and (with an ID) Firefox under
`HKCU\Software\...\NativeMessagingHosts`.

## Locking

The vault locks when idle, when you lock the screen (Win+L) and when the
machine goes to sleep, through session and power notifications to a hidden
window.

## Not on Windows yet

- **TPM and Windows Hello unlock.** The TPM slot uses the Linux TPM stack;
  Windows needs its own backend (TBS or the Platform Crypto Provider) and a
  Windows Hello slot. Password, security key and recovery code work.
- **Security keys need an elevated daemon.** Windows only lets administrator
  processes talk to FIDO2 keys directly. Run `vaultd.exe` as administrator to
  use a security key; otherwise unlock with the password or recovery code.
  Going through Windows' own WebAuthn API instead is the planned fix.
- **Memory hardening.** On Linux the daemon locks its memory and disables core
  dumps. On Windows keys can reach the page file and crash dumps for now.
