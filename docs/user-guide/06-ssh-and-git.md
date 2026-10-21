# 6. SSH keys and git signing

The vault can hold your SSH keys and act as an **ssh-agent**, the standard
helper that `ssh`, `git` and `ssh-keygen` already know how to use. The
private key stays inside `vaultd`; it is never written to `~/.ssh`, and
programs only ever get signatures from it.

Use cases:

- Logging in to servers with `ssh`.
- Pushing to GitHub, GitLab and other git hosts over SSH.
- Signing git commits and tags so they show as **Verified**.
- Signing files with `ssh-keygen -Y sign`.

| | Linux | Windows | macOS |
|---|---|---|---|
| SSH agent | Yes (tested with OpenSSH 9) | Yes, through the Windows OpenSSH client; untested on real hardware | Not yet |
| Agent address | `$XDG_RUNTIME_DIR/vault/ssh-agent.sock` | `\\.\pipe\vaultd-ssh-<your SID>` | |
| Key types | Ed25519, ECDSA P-256 | Ed25519, ECDSA P-256 | |

RSA keys are not supported, for creating or for importing.

## 1. Create or import a key

The vault must be unlocked.

**Make a new key** (Ed25519, the modern default):

```sh
vault ssh new laptop
```

Use `--ecdsa` for a NIST P-256 key if a server cannot take Ed25519. The
command prints the public key.

**Or move an existing key into the vault:**

```sh
vault ssh import work ~/.ssh/id_ed25519
```

If the key file has a passphrase you are asked for it once; the vault
stores the key without it, protected by the vault's own encryption. Once
`ssh` works through the vault (step 3), you can delete the old key file.

List your keys with `vault ssh ls`.

## 2. Give the public key to the server or git host

```sh
vault ssh pub laptop
```

You can name a key by its title or its ID. Paste the line into:

- a server's `~/.ssh/authorized_keys`, or
- GitHub: Settings, **SSH and GPG keys**, **New SSH key**, type
  **Authentication Key**. GitLab: Preferences, **SSH Keys**.

In the desktop app, choose **SSH and PGP keys** in the sidebar, select the
key and press **Copy public key**
([chapter 5](05-desktop-app.md#ssh-and-pgp-keys)).

## 3. Point your shell at the vault's agent

**Linux:**

```sh
eval "$(vault ssh agent)"
```

Add that line to `~/.bashrc` or `~/.zshrc` so every new terminal uses it.

**Windows (PowerShell):**

```powershell
vault ssh agent          # prints a line like  $env:SSH_AUTH_SOCK = '\\.\pipe\vaultd-ssh-S-1-5-...'
```

Run the printed line, and add it to your PowerShell profile
(`notepad $PROFILE`) to keep it. Use the OpenSSH client that comes with
Windows (`C:\Windows\System32\OpenSSH\ssh.exe`). The `ssh` bundled with Git
for Windows cannot talk to a named pipe, so tell git to use Windows'
client:

```powershell
git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
```

Windows' own "OpenSSH Authentication Agent" service can stay as it is:
`ssh` uses the agent that `SSH_AUTH_SOCK` names.

**Check it:**

```sh
ssh-add -L            # lists the vault's keys while it is unlocked
ssh -T git@github.com
```

When the vault is locked the agent lists no keys and `ssh` falls back to
asking for a password or fails.

## 4. Approve each use

New keys ask before every use. When a program wants a signature, `vaultd`
opens a window that names the key, what it is for and the program asking:

- *log in over SSH as "user"*: an SSH login.
- *sign a git commit or tag*: `git commit -S` or a signed tag.
- *sign a file*: `ssh-keygen -Y sign -n file`.

**Deny** is selected by default, Escape denies, and no answer within a
minute denies. The purpose is read from what the program sent, so treat it
as a hint.

To stop being asked for one key:

```sh
vault ssh confirm laptop off       # and `on` to turn it back on
```

or untick **Ask before each use** on the key in the desktop app, or create
it with `--no-confirm`. Without confirmation, any program running
as you can use the key while the vault is unlocked, just as with a key
loaded into the usual `ssh-agent`.

If `vaultd` runs with `--no-prompt`, or as the separate system user on Linux
(no desktop), keys that need confirmation are never used. Turn confirmation
off for those keys, or run the daemon in your session.

## Sign git commits

This signs with an SSH key. To sign with an OpenPGP key instead (GitHub's
"GPG key"), see [chapter 9](09-gpg-programs.md#2-sign-git-commits).

1. Tell git to sign with SSH and which key to use:

   ```sh
   git config --global gpg.format ssh
   git config --global user.signingkey "key::$(vault ssh pub laptop)"
   git config --global commit.gpgsign true
   git config --global tag.gpgsign true      # optional: sign tags too
   ```

   The same lines work in PowerShell, which also expands `$( )`.
2. Add the same public key on GitHub as a **Signing Key** (Settings, SSH and
   GPG keys, New SSH key, type **Signing Key**). GitLab accepts it under SSH
   Keys with usage "Authentication & Signing".
3. Commit as usual. Approve the prompt. GitHub shows the commit as
   **Verified**.

To verify signatures locally, list trusted keys in a file:

```sh
echo "alex@example.com $(vault ssh pub laptop)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
git log --show-signature
```

## Export a key

If you need the private key file again (for a machine without the vault):

```sh
vault ssh export laptop > id_laptop
```

You must prove an unlock method again (the password by default, or
`--fido2`, `--tpm`, `--recovery`). The key is printed without a passphrase:
protect the file.

## Limits

- No RSA keys.
- `ssh-add` cannot add keys to the vault's agent or remove them; manage
  keys with `vault ssh`.
- The desktop app lists key items with their type and fingerprint but
  cannot create, import or export keys. `vault show` and the app never see
  the private key, and editing the item keeps it.
- Change the agent's address with `vaultd --ssh-agent PATH`, or turn it off
  with `vaultd --no-ssh-agent`.
