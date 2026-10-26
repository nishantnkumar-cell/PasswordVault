# Windows

`vaultd`, `vault`, `vault-gui` and `vault-native-host` build and run on
Windows 10 and 11. The vault file format is the same on every system, so a
vault file can be copied between machines.

## Install

Download `SecretVault-Setup-<version>.exe` from the GitHub Releases page (or
a development build: the `windows-installer` artifact of a CI run) and run
it. "Install for me only"
needs no administrator rights; "Install for all users" asks once, during
setup. Step by step: [user-guide/windows-install.md](user-guide/windows-install.md).

To build the installer yourself, build the programs and compile
`contrib\windows\vault.iss` with Inno Setup 7 (the build also works with
Inno Setup 6.x if that is what you have):

    cargo build --release --locked
    iscc contrib\windows\vault.iss /DAppVersion=0.2.0

It lands in `target\installer\`. CI and the release workflow
(`.github/workflows/package.yml`) pass `/DAppVersion` from
`contrib/release/version.sh --build` and `/DNumVersion` (its numeric part,
for the file's version resource).

A newer installer upgrades in place: Inno Setup keeps the previous folder,
install mode (`UsePreviousPrivileges`) and tasks, the script stops vaultd,
vault-gui and vault-prompt before copying, and `[Run]` starts vaultd again.
The script reads the installed version from the uninstall key
(`DisplayVersion`) to name the upgrade on the Ready page and to ask before
installing an older version over a newer one.

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

## TPM

`vault-hw/src/wintpm.rs` seals the slot's random secret in the TPM the same
way Linux does, through TPM Base Services (`tbs.dll`), which any user may
call: no administrator rights and no TPM driver of our own. A small TPM 2.0
client (`vault-hw/src/tpm2.rs`) builds the commands itself. It seals the
secret as a keyed-hash object under the storage key Windows creates at
`0x81000001` when it sets up the TPM, so nothing new persists in the TPM.
The object's private part is encrypted by the TPM's own symmetric key, and
only this TPM can load it.

- The PIN is the object's authValue, so the TPM's dictionary-attack lockout
  limits guesses. An object without a PIN is exempt (nothing to guess).
- `--pcr7` makes the object policy-only: `PolicyPCR(sha256:7) +
  PolicyAuthValue`, as on Linux.
- Every command that carries the secret or the PIN runs in a session salted
  to the storage key (RSA-OAEP through CNG, `bcrypt.dll`), with AES-128-CFB
  parameter encryption both ways, and the TPM's response HMAC is checked.

The slot blob starts with `VWTPM2`, so the Linux and Windows backends can
tell each other's slots apart and say so instead of failing obscurely.

**Older slots (`VWTPM1`).** These wrapped the secret instead:
an RSA-2048 key of the Microsoft Platform Crypto Provider (CNG,
`ncrypt.dll`) and RSA-OAEP (SHA-256), with the key's opaque blob and the
ciphertext in the slot. They still unlock. The key blob includes the RSA
public key, so a future quantum computer could recover the secret from a
copy of the vault file and leave only the password. `vault slots` and the
desktop app mark these slots; the user guide explains how to replace them
([Post-quantum protection](user-guide/02-unlocking.md#post-quantum-protection)).

If a group policy blocks TPM commands for programs ("Configure the list of
blocked TPM commands"), enrolling fails with a message that says so.
CI runners have no TPM; `tpm2.rs` is tested against swtpm on Linux. Check a
real machine with `cargo run -p vault-hw --example tpm-check -- 1234`.

## Windows Hello quick unlock

`vault-hw/src/hello.rs` calls `UserConsentVerifier` through
`IUserConsentVerifierInterop::RequestVerificationForWindowAsync`, owned by
the foreground window like the security key prompt. It returns no secret,
so it is an approval gate for a key vaultd still holds, never a keyslot.
On lock, with quick unlock on and within its window, vaultd keeps the
vault key sealed under a random wrap key (`Vault::park`, format.md 4.6), and
keeps the wrap key under `CryptProtectMemory(SAME_PROCESS)`, so a crash
dump, the page file or a scan of the process from outside does not show
it. `UnlockMethod::Hello` unwraps it after Windows Hello says `Verified`.
Check with `cargo run -p vault-hw --example hello-check`.

## Locking

The vault locks when idle, when you lock the screen (Win+L) and when the
machine goes to sleep, through session and power notifications to a hidden
window.

## Not on Windows yet

- **Memory hardening.** On Linux the daemon locks its memory and disables core
  dumps. On Windows keys can reach the page file and crash dumps for now.
