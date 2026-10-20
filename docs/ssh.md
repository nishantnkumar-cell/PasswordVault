# SSH keys and git signing

SSH keys can live in the vault. `vaultd` serves the standard ssh-agent protocol, so `ssh`, `git` and `ssh-keygen -Y sign` use them without the private key ever being written to `~/.ssh`.

## Set up

```sh
vault ssh new laptop            # Ed25519; --ecdsa for NIST P-256
vault ssh import work ~/.ssh/id_ed25519   # or store an existing key (asks its passphrase)
vault ssh pub laptop            # public key (by title or ID) for authorized_keys or GitHub
eval "$(vault ssh agent)"       # sets SSH_AUTH_SOCK; put this in your shell profile
ssh-add -L                      # the vault's keys, while it is unlocked
```

On Windows, `vault ssh agent` prints a PowerShell line. Use the Windows OpenSSH client (`C:\Windows\System32\OpenSSH`); Git for Windows' bundled ssh cannot use a named pipe, so set `git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe`. Windows support is untested on real hardware.

## Git commit signing

```sh
git config --global gpg.format ssh
git config --global user.signingkey "key::$(vault ssh pub ID)"
git config --global commit.gpgsign true
```

GitHub and GitLab verify SSH signatures: add the same public key as a **signing** key in your account settings. To verify locally, list it in an allowed-signers file and set `gpg.ssh.allowedSignersFile`.

## Approval before each use

New keys ask before every use (`--no-confirm` turns that off at creation; `vault ssh confirm ID on|off` changes it later). vaultd opens `vault-prompt`, which names the key, what the signature is for and the program asking:

- `log in over SSH as "user"`: an SSH login (the host is not in the signed data).
- `sign a git commit or tag`, `sign a file`: `ssh-keygen -Y sign` with the `git` or `file` namespace.

The purpose comes from the data the program sent, so it is a hint, not proof. Deny is the default, Escape denies, and no answer within a minute denies. If vaultd runs with `--no-prompt` or cannot find `vault-prompt`, keys that need approval are never used.

With confirmation off, any program running as you can sign with the key while the vault is unlocked, exactly like a key loaded into `ssh-agent`.

## What the agent does and does not do

- Lists and signs with Ed25519 and ECDSA (P-256) keys from the vault, only while it is unlocked. Locked, it lists nothing.
- Does not accept keys from `ssh-add`, does not remove or lock keys on request, and has no RSA support (the `rsa` crate has no constant-time fix for the Marvin attack).
- Checks the peer's user on every connection, like the main socket. The agent socket is `$XDG_RUNTIME_DIR/vault/ssh-agent.sock` (`\\.\pipe\vaultd-ssh-<SID>` on Windows); change it with `vaultd --ssh-agent PATH` or turn it off with `--no-ssh-agent`.

## Storage and export

A key is part of a vault item (`docs/items.md`, schema 2) in OpenSSH format without a passphrase; the vault's encryption protects it. Clients never receive it: `vault show` and the desktop app see the item without its key, and editing an item keeps its key. `vault ssh export ID` prints the private key only after you prove an unlock factor again.
