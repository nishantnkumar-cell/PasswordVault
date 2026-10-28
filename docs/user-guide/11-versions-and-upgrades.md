# 11. Versions, downloads and upgrading

This chapter explains how Secret Vault versions are numbered, where to
download a version, how to see which one you have, and how to upgrade to a
newer one without losing anything. The examples use Alex Example's PC.

## How versions are numbered

Every part of Secret Vault (the daemon, the `vault` command, the desktop
app, the browser host, `vault-gpg`, the browser extension and the
installers) carries **one version number**, such as `0.2.0`. They are
released together, so a 0.2.0 installer contains 0.2.0 of everything.

The three numbers are *major.minor.patch*:

- **minor** goes up for a release with new features (0.2.0 → 0.3.0),
- **patch** goes up for a release that only fixes problems (0.2.0 → 0.2.1),
- **major** stays at 0 until the vault has had a security audit.

A version like **`0.2.0-dev.1a2b3c4`** is a **development build**: it was
built from the code on its way to 0.2.0, at commit `1a2b3c4`, and is not a
release. Development builds are for testing. A development build counts as
older than the release with the same number, so installing 0.2.0 over
0.2.0-dev.1a2b3c4 is an upgrade.

A version like **`0.2.0-beta.1`** is a **public beta** of 0.2.0: a
preview published on the Releases page for anyone to try before 0.2.0 is
final (see [Betas](#betas-pre-releases) below). Like a development build, it
counts as older than 0.2.0 itself.

Programs you build yourself from source show the plain version (for example
`0.2.0`), because only the project's build machines add the `-dev` part.

## Which version do I have?

- **Command line**, on any system: `vault --version` (or `vault version`)
  and `vaultd --version`. `vault-native-host --version` and
  `vault-gpg --version` work too.
- **Desktop app**: the version is at the bottom of the sidebar, under
  *Ctrl K finds items and actions*.
- **Windows**: *Settings > Apps > Installed apps* lists **Secret Vault
  0.2.0** with its version.
- **Debian or Ubuntu**: `apt policy secret-vault` or `dpkg -s secret-vault`.
- **Browser extension**: the browser's extensions page shows its version.

## Where to download

### Releases (recommended)

Each release is published on the project's
[Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases).
No GitHub account is needed. Each release has:

| File | For |
|---|---|
| `SecretVault-Setup-<version>.exe` | Windows 10 (1903 or later) and 11, 64-bit |
| `secret-vault_<version>_amd64.deb` | Debian 13, Ubuntu 24.04 and newer |
| `secret-vault-<version>-linux-x86_64.tar.gz` | Other Linux distributions (64-bit) |
| `SecretVault-<version>-macos.pkg` | macOS 11 and newer, Apple silicon and Intel: the installer ([chapter 13](13-macos.md)) |
| `secret-vault-<version>-macos-universal.tar.gz` | macOS without an administrator password, with `install.sh` |
| `secret-vault-extension-<version>.zip` | The browser extension, to load unpacked |
| `secret-vault-<version>-android.apk` | Android 9 and newer, phones and tablets ([chapter 14](14-phone-apps.md#android)); from 0.2.0-beta.2 on |
| `SHA256SUMS.txt` | A fingerprint of every file above, to check a download (below) |

The release's description is that version's section of the
[release notes](../release-notes.md): what's new and what differs between
systems. The newest full release is always at
<https://github.com/nishantnkumar-cell/PasswordVault/releases/latest>; that
link skips betas, so while only betas exist use the
[Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases)
itself.

### Betas (pre-releases)

Before a version is final, it can be published as a **public beta**, for
example `0.2.0-beta.1`, then `0.2.0-beta.2` with fixes. On the Releases page
a beta is labelled **Pre-release**, and its description starts with a
warning and lists everything new since the last full release.

- **Who it is for:** anyone who wants to try Secret Vault early and report
  problems. A beta has not had a security audit: try it with test data, do
  not trust it with real secrets yet, and keep a backup of your vault file
  (see [Upgrading](#upgrading)).
- **What you get:** the same files as a full release (the table above),
  named with the beta version, for example `SecretVault-Setup-0.2.0-beta.1.exe`
  or `secret-vault_0.2.0-beta.1_amd64.deb`, plus `SHA256SUMS.txt`.
- **Installing:** exactly as for a full release, on every system:
  [Linux](01-getting-started.md#linux),
  [Windows](windows-install.md) and [macOS](13-macos.md). Windows and macOS
  show the same one-time warning (below).
- **Moving on to the final version:** install it over the beta like any
  upgrade. Your vault, unlock methods and settings stay. On Debian and
  Ubuntu, `apt` knows that `0.2.0-beta.1` comes before `0.2.0`
  (`apt policy secret-vault` shows the beta as `0.2.0~beta.1`).
- **Phones and tablets:** from `0.2.0-beta.2` on, betas include the Android
  app (`secret-vault-<version>-android.apk`); `0.2.0-beta.1` does not. The
  iPhone and iPad app is not on the Releases page (it needs a paid Apple
  developer account); see [Phone and tablet apps](14-phone-apps.md).

### Checking a download (optional)

`SHA256SUMS.txt` lists a SHA-256 fingerprint for each file. If the
fingerprint of the file you downloaded matches its line, the file arrived
complete and is the one the release built. Put both files in the same
folder, open a terminal there, and run:

- **Linux:** `sha256sum --ignore-missing -c SHA256SUMS.txt` prints
  `OK` next to each file you downloaded.
- **macOS:** `shasum -a 256 --ignore-missing -c SHA256SUMS.txt` prints `OK`
  the same way.
- **Windows** (PowerShell):
  `Get-FileHash .\SecretVault-Setup-0.2.0.exe` prints a long hash; check it
  is the same as the one on the `SecretVault-Setup-0.2.0.exe` line of
  `SHA256SUMS.txt` (capital or small letters don't matter).

### Warnings the first time you open a download

The installers are not signed with a paid code-signing certificate yet, so
Windows and macOS don't know who made them and warn once. This is expected.

- **Windows:** "Windows protected your PC" (SmartScreen). Click **More
  info**, then **Run anyway**. See [Installing on Windows](windows-install.md).
- **macOS 15 and newer:** "SecretVault-…pkg Not Opened". Click **Done**, open
  System Settings > Privacy & Security, scroll down and click **Open
  Anyway**. On macOS 11 to 14, right-click the `.pkg` and choose **Open**.
  See [chapter 13](13-macos.md).
- **Linux:** no warning. `apt` and `install.sh` install the files as they are.
- **Android:** the phone asks once whether your browser or file manager may
  install apps, and Google Play Protect may say it doesn't recognise the
  developer. See [Install the Android app](14-phone-apps.md#android).
- **Browsers** may say the file "isn't commonly downloaded". Choose **Keep**
  (Edge: **…** > **Keep**; Chrome: **Keep anyway**).

### Development builds

Every change to the code also builds all of these files. To try one before
it is released:

1. Sign in to GitHub (development downloads need an account).
2. Open the project's
   [Actions tab](https://github.com/nishantnkumar-cell/PasswordVault/actions/workflows/ci.yml?query=branch%3Amain)
   and click the newest run with a green tick.
3. Under **Artifacts** at the bottom, download **windows-installer**,
   **linux-packages**, **macos-package** or **browser-extension**. Each is a
   zip containing the files above, with a `-dev` version.

Development downloads are kept for 90 days.

## Upgrading

Upgrading keeps **everything you have**: the vault file, your unlock
methods, paired apps and browsers, sync settings and the start-at-sign-in
choice. The vault file lives apart from the programs (for example
`%LOCALAPPDATA%\vault\` on Windows and `~/.local/share/vault/` on Linux), so
replacing the programs never touches it. The vault locks during the
upgrade; unlock it again afterwards.

Before a big upgrade, it is still a good idea to keep a copy of the vault
file (see [Troubleshooting, backups and safety tips](08-troubleshooting.md)).

### Windows

1. Download the newer `SecretVault-Setup-<version>.exe`.
2. Run it. It finds the installed version and installs into the same folder,
   in the same mode ("for me only" or "for all users"), with the same
   choices as before, so it doesn't ask those questions again. An all-users
   install asks for an administrator, as it did the first time.
3. The **Ready to install** page says *Upgrade Secret Vault from 0.2.0 to
   0.3.0*. Click **Install**.
4. The installer closes the desktop app and vaultd, replaces the programs
   and starts vaultd again. Click **Finish**.

If the installer is **older** than what is installed, it asks first
("Secret Vault 0.3.0 is installed, which is newer than this installer"),
with **No** as the default. An older version may not be able to open a
vault that a newer one has saved, so only say yes if you know why you're
going back.

### Debian and Ubuntu (.deb)

```sh
sudo apt install ./secret-vault_0.3.0_amd64.deb
```

apt replaces the older package in place. Then, as each person who uses the
vault on the computer, restart the daemon so it runs the new version:

```sh
systemctl --user restart vaultd
```

apt also refuses to install an older package over a newer one unless you
ask it to (`--allow-downgrades`).

### Other Linux (.tar.gz)

```sh
tar -xzf secret-vault-0.3.0-linux-x86_64.tar.gz
cd secret-vault-0.3.0-linux-x86_64
./install.sh
```

`install.sh` installs into `~/.local` for you alone (no root). The first
time it installs the programs, the systemd user service and the desktop
entry. Run it again from a newer archive and it replaces the programs and
restarts vaultd if it is running. It asks first before installing an older
version over a newer one.

The first time, start the daemon with `systemctl --user enable --now vaultd`
and make sure `~/.local/bin` is on your `PATH`.

### From source

```sh
git pull
cargo install --path crates/vaultd   # and the other crates you installed
systemctl --user restart vaultd      # Linux
```

### The browser extension

Load the new `secret-vault-extension-<version>.zip` the same way as the
first time (unpack it over the old folder, then click **Reload** on the
browser's extensions page). It keeps its pairing.

## Differences between systems

| | Windows | Linux | macOS |
|---|---|---|---|
| Release download | Installer (`.exe`) | `.deb`, or `.tar.gz` with `install.sh` | Installer (`.pkg`), or `.tar.gz` with `install.sh` ([chapter 13](13-macos.md)) |
| Upgrade | Run the newer installer | `apt install ./new.deb`, or `./install.sh` from the new archive | Open the newer `.pkg`, or `./install.sh` from the new archive |
| Daemon restarted for you | Yes | `.tar.gz`: yes; `.deb`: run `systemctl --user restart vaultd` | Yes |
| Older over newer | Asks first (default No) | apt refuses; `install.sh` asks first | `.pkg` refuses; `install.sh` asks first |
| Administrator rights | Only for an all-users install | `sudo` for the `.deb`; none for the `.tar.gz` | For the `.pkg`; none for the `.tar.gz` |
| Warning on first open | SmartScreen: **More info** > **Run anyway** | None | **Open Anyway** in Privacy & Security |

## For maintainers: making a release

Releases are made from `main` with two scripts in `contrib/release/`.
Nothing is published until the tag is pushed.

1. Check that `## Unreleased` in `docs/release-notes.md` describes
   everything in the release.
2. Run `contrib/release/release.sh`. It renames `## Unreleased` to
   `## 0.2.0 (date)`, commits that as *Release 0.2.0* and tags it `v0.2.0`.
   Then it moves `main` on to the next minor version (0.3.0) with a new,
   empty `## Unreleased`. For a fix release next, pass
   `--next 0.2.1` instead.
3. Push both: `git push origin main v0.2.0`.
4. The **Release** workflow builds every package from the tag, checks that
   the tag matches the version in `Cargo.toml` and that all six downloads
   were built, adds `SHA256SUMS.txt`, and publishes them on the Releases
   page with that version's release notes. It takes about 20 minutes; follow
   it on the [Actions tab](https://github.com/nishantnkumar-cell/PasswordVault/actions/workflows/release.yml).
   Anyone can download a release without a GitHub account, because the
   repository is public.

### Publishing a beta

A beta is published from `main` without changing the version in
`Cargo.toml` or the release notes. With `main` at 0.2.0:

1. Check that `## Unreleased` in `docs/release-notes.md` describes what is
   in the beta: it becomes the beta's description.
2. Tag the commit and push the tag:
   `git tag -a v0.2.0-beta.1 -m "Secret Vault 0.2.0 beta 1"` then
   `git push origin v0.2.0-beta.1`.
3. The **Release** workflow builds and checks everything as for a full
   release and publishes it marked **Pre-release**, titled
   *Secret Vault 0.2.0-beta.1 (public beta)*.

The tag must be the version in `Cargo.toml` followed by `-beta.N` (or
`-alpha.N`, `-rc.N`); any other tag fails the workflow before anything is
published. The next beta is `-beta.2`. When 0.2.0 is ready, release it with
`release.sh` as above.

If the workflow fails, nothing is published. A failure that looks like a
hiccup (a download timeout, a test that passes on `main`) usually goes away
with **Re-run failed jobs** on the run's page. If it fails for a real reason,
fix it on `main` and release the fix as the next patch version (0.2.1).
Once a release is published, never move or reuse its tag.

### Signing the installers (optional, costs money)

Unsigned installers work, but Windows and macOS warn once (see above).
Signing removes the warnings:

| | What it takes | Rough cost |
|---|---|---|
| macOS | Apple Developer Program: a Developer ID certificate and notarization. Steps in [macos-signing.md](../macos-signing.md). | USD 99 a year |
| Windows | A code-signing certificate. Microsoft's Azure Artifact Signing (formerly Trusted Signing) is the cheapest, if your country and account type are eligible; otherwise an OV certificate from a certificate authority, delivered on a hardware token or cloud HSM. | About USD 10 a month (Azure), or roughly USD 200 to 400 a year (OV certificate) |
| Linux | Nothing needed. | Free |

On Windows, even a signed installer can show SmartScreen for a while until
enough people have downloaded it; the warning fades as the file builds a
reputation. Check current prices and eligibility before buying: they change.

`contrib/release/bump.sh X.Y.Z` changes the version on its own, and
`contrib/release/version.sh` prints it. CI fails if the extension's
version and `Cargo.toml` disagree.
