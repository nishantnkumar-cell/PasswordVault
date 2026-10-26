# Installing and running on Windows

This guide is for people setting up Secret Vault on a Windows PC for the
first time. It covers which install to pick, running the installer, what
starts when you sign in, using a security key, and how to update or remove
the app. Linux and macOS work differently; see the end of this guide.

The examples use a Windows account called "Alex Example".

## What gets installed

| Program | What it does |
|---|---|
| `vaultd.exe` | The daemon. It holds your unlocked vault in memory and is the only program that reads the vault file. |
| `vaultw.exe` | Starts vaultd in the background, with no window. This is what runs when you sign in. |
| `vault-gui.exe` | The desktop app (*Secret Vault* in the Start menu). |
| `vault.exe` | The `vault` command for PowerShell. |
| `vault-prompt.exe` | The small window vaultd opens to ask you to approve a new app or browser. |
| `vault-native-host.exe` | Connects the browser extension to vaultd. |
| `vault-gpg.exe` | Lets git sign commits with the OpenPGP keys in your vault ([chapter 9](09-gpg-programs.md)). |

Your vault itself lives in `%LOCALAPPDATA%\vault\vault.svault`, separate
from the programs, so updating or removing the app never touches it.

## Before you start

- **Windows 10 version 1903 or later, 64-bit.** Windows 11 is best: on
  Windows 11 (and Windows 10 with current updates) security keys work
  without administrator rights.
- **The installer file**, `SecretVault-Setup-<version>.exe`. Until there are
  published releases, download it from the project's GitHub page: open the
  **Actions** tab, pick the latest green **CI** run on `main`, and download
  **windows-installer** under *Artifacts* (it is a zip with the installer
  inside).

## Which install to choose

The installer's first page asks how to install.

- **Install for me only** (recommended). Puts the programs in
  `%LOCALAPPDATA%\Programs\Secret Vault` and needs **no administrator
  rights at all**. Pick this on your own PC, or on a work PC where you are
  not an administrator.
- **Install for all users.** Puts the programs in
  `C:\Program Files\Secret Vault` so every account on the PC can use them.
  Windows asks for an administrator password **once, during setup**. Pick
  this on a shared family PC, or when your organisation wants programs in
  Program Files.

Either way, vaultd always runs as the person who is signed in, never as
administrator. Each account gets its own vaultd and its own vault; one
account cannot open another account's vault.

## Installing, step by step

1. Double-click `SecretVault-Setup-<version>.exe`.
2. **SmartScreen.** The installer is not code-signed yet, so Windows may say
   "Windows protected your PC". Click **More info**, check that the file is
   the one you downloaded, then click **Run anyway**.
3. **Install mode.** Choose **Install for me only** or **Install for all
   users** (see above). Only the second asks for an administrator.
4. **Licence.** Read it and click **I accept the agreement**, then **Next**.
   The app is free for non-commercial use.
5. **Folder.** Keep the suggested folder unless you have a reason not to.
6. **Additional tasks.** Both are ticked by default:
   - *Start the vault daemon at sign-in*: keep this, or the app has nothing
     to talk to after a restart.
   - *Add the vault command to PATH*: lets you type `vault` in PowerShell.
7. Click **Install**, then **Finish**. Leave *Open Secret Vault* ticked to
   start the desktop app straight away. vaultd is already running.

## First run

1. Open **Secret Vault** from the Start menu.
2. If this is a new vault, create it: the app walks you through choosing a
   master password and saving a recovery code. From PowerShell you can run
   `vault init` instead.
3. The first time the app (or the `vault` command, or the browser) connects,
   a small **approval window** from vaultd asks whether to allow it. Check
   the program name it shows, then click **Allow**.

To check that vaultd is running, open a **new** PowerShell window and run
the command below. A terminal that was already open during the install
doesn't see the new PATH; in Windows Terminal, close the whole app first,
since new tabs keep the old PATH too.

    vault status

## What happens when you sign in

When Alex Example signs in, Windows runs `vaultw.exe`, which starts vaultd in
the background. There is no window and nothing in the taskbar; vaultd is
listed in Task Manager under *Background processes*. The vault stays
**locked** until you unlock it in the app.

vaultd locks the vault when:

- it has been idle for 15 minutes,
- you lock the screen (Win + L), or
- the PC goes to sleep.

If something goes wrong, vaultd writes what happened to
`%LOCALAPPDATA%\vault\state\vaultd.log`. Open it in Notepad.

To turn off the start at sign-in without uninstalling, open **Task
Manager > Startup apps**, select **vaultw**, and click **Disable**.

### Starting and stopping vaultd by hand

- **Start it:** run *vaultw* (in the install folder), or sign out and back
  in.
- **Stop it:** in PowerShell, `Stop-Process -Name vaultd`. The vault locks
  and its keys leave memory; nothing in the vault file is lost.
- **See its messages live:** stop it, then run `vaultd.exe` in a PowerShell
  window. It keeps running until you close that window.

### Why vaultd is not a Windows service

A Windows service runs under a system account in a separate session with no
desktop. It couldn't show the approval window, wouldn't notice when you lock
your screen, and would hold every user's unlocked vault in a single
privileged process. Running vaultd as you, started at sign-in, avoids all of
that.

## Using a security key (FIDO2)

A security key (such as a YubiKey) can be required as well as your password
to unlock the vault. On Windows, **vaultd uses Windows' own security key
service**, so it does not need administrator rights.

To add a security key:

1. Plug the key in.
2. In the app, open the unlock settings and add a **security key** slot, or
   in PowerShell run:

       vault add-slot fido2 --label "Blue key"

   Add `--uv` to also require the key's PIN every time you unlock.
3. Windows opens its own **security key window**. Touch the key when it
   blinks. If the slot uses the PIN, Windows asks for it in that same
   window. On Windows, the `vault` command doesn't ask for the PIN itself,
   and the PIN field in the desktop app can be left empty.
4. Windows asks for a second touch to confirm the slot works.

To unlock with the key, pick **Security key** in the app's unlock card,
type your master password, and touch the key when Windows asks.

A security key slot works on every system: a slot added on Linux unlocks the
same vault file on Windows, and the other way round.

**Keys that have a PIN: use a PIN slot on Windows.** If your key has a PIN
set, Windows insists on checking it whenever the vault reads the key's
secret, even for a touch-only slot. A key that has checked its PIN gives a
different secret than a touch alone, so a touch-only slot can't work on
Windows with such a key: adding one stops with "Windows checked the key's
PIN for a touch-only slot", and a touch-only slot made on Linux won't unlock
on Windows. Add the slot with `--uv` (in the app, tick *Also ask for the
key's PIN every time*) and it works the same on every system. Keys without
a PIN are not affected.

**Older Windows 10.** If Windows' security key service is too old, vaultd
talks to the key directly over USB, which Windows only allows to
administrators. Update Windows, or unlock with your password or recovery
code instead.

## Connecting the browser

After installing, connect the browser extension once; see
[Browser autofill](04-browser-autofill.md). Run the host registration from PowerShell with
your extension's ID (shown on the browser's extensions page):

    vault-native-host --install CHROME_EXTENSION_ID

This registers the host for your account only and needs no administrator
rights, whichever install mode you chose.

## Updating

Run the newer installer. It stops vaultd, replaces the programs and starts
vaultd again. Your vault is not touched. Unlock again after the update.

## Uninstalling

Open **Settings > Apps > Installed apps**, find **Secret Vault**, click
**...** and **Uninstall**. An all-users install asks for an administrator
again, because it removes files from Program Files.

Uninstalling stops vaultd and removes the programs, the Start menu entry, the
sign-in entry and the PATH entry. It **keeps your vault** in
`%LOCALAPPDATA%\vault\`. Delete that folder yourself only if you are sure
you no longer need the vault or have a copy of it.

## Differences between Windows, Linux and macOS

| | Windows | Linux | macOS |
|---|---|---|---|
| How to install | The installer described here | Build with `cargo` and install the systemd unit ([vaultd.md](../vaultd.md)) | Not supported yet |
| Administrator rights | None for "me only"; once during setup for "all users" | None for a per-user unit; root to install the system unit | |
| How vaultd starts | `vaultw.exe` at sign-in, no window | systemd user unit (`systemctl --user`) | |
| vaultd log | `%LOCALAPPDATA%\vault\state\vaultd.log` | `journalctl --user -u vaultd` | |
| Security key PIN | Asked by Windows in its own window | Asked by the `vault` command or the app | |
| Security keys need admin | No (Windows 11 or current Windows 10) | No (needs the udev rule in `contrib/udev`) | |
| TPM unlock | Yes, no administrator rights needed | Yes | |
| Quick unlock (Windows Hello) | Yes | Not yet | |
