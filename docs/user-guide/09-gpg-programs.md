# 9. Programs that call gpg: git, pass and mail

Many programs never handle OpenPGP themselves: they run the `gpg` command.
git signs commits that way, `pass` encrypts each password that way, and
mail programs such as NeoMutt sign and decrypt mail that way.

`vault-gpg` answers those programs in gpg's own language, using the OpenPGP
keys in your vault. The secret key stays inside `vaultd`; `vault-gpg` only
passes the data across and returns the result, and you approve each use as
usual.

Use cases:

- **Sign git commits and tags with your OpenPGP key**, so GitHub and GitLab
  show them as *Verified*, without the key in `~/.gnupg`.
- **Keep a `pass` password store** whose entries only the vault can decrypt.
- **Sign, encrypt and decrypt mail** in NeoMutt or Mutt with vault keys.

It does not replace GnuPG for everything: see [What it does not do](#what-it-does-not-do).

| | Linux | Windows | macOS |
|---|---|---|---|
| git commit and tag signing, `git log --show-signature` | Yes (tested with git 2.43) | Yes, untested on real hardware | Not yet |
| `pass` | Yes (tested with pass 1.7.4) | No: `pass` is a Unix shell script | Not yet |
| NeoMutt and Mutt | Commands tested by hand | Not applicable | Not yet |
| Evolution, KMail, Thunderbird with GnuPG keys | Not yet | Not yet | Not yet |

macOS waits for `vaultd` itself to run on macOS.

Before you start you need an OpenPGP key in the vault
([chapter 7](07-openpgp.md)), for example:

```sh
vault pgp new me 'Alex Example <alex@example.com>'
```

## 1. Install vault-gpg

**Linux:**

```sh
cargo install --path crates/vault-gpg
```

**Windows:** the installer ([installing on Windows](windows-install.md))
puts `vault-gpg.exe` next to `vault.exe`, already on your `PATH`. If you
build from source instead, `cargo build --release` makes
`target\release\vault-gpg.exe`; keep it in the same folder as `vault.exe`.

`vault-gpg` uses the same pairing as the `vault` command (the token in
`~/.config/vault/token`, or `%APPDATA%\vault\token` on Windows), so there is
nothing more to pair. The vault must be unlocked when a program signs or
decrypts.

Check it:

```sh
vault-gpg --list-secret-keys
```

You should see your vault keys, marked `[ultimate]` (they are your own).

## 2. Sign git commits

Tell git to use `vault-gpg` and which key to sign with:

```sh
git config --global gpg.format openpgp
git config --global gpg.program vault-gpg
git config --global user.signingkey 'alex@example.com'
git config --global commit.gpgsign true
git config --global tag.gpgsign true      # optional: sign tags too
```

`user.signingkey` may be the address, the full user ID, the fingerprint or
the key ID (`vault-gpg -K` shows them). On Windows, if `vault-gpg.exe` is
not on your `PATH`, give its full path:
`git config --global gpg.program 'C:/Tools/vault/vault-gpg.exe'`.

Commit as usual (`git commit -m "..."`). The approval window opens, naming
the key and the purpose "sign data with OpenPGP"; press **Allow**.

Then put your public key on GitHub (Settings, SSH and GPG keys, **New GPG
key**) or GitLab (Preferences, GPG Keys):

```sh
vault pgp pub me
```

Paste the whole block, including the `-----BEGIN` and `-----END` lines.
Commits made with that key now show **Verified**.

Check signatures locally:

```sh
git log --show-signature -1
git verify-commit HEAD
git verify-tag v1.0
```

Signatures by your own vault keys are reported as `[ultimate]`. To check
other people's signatures, import their public keys (see
[step 5](#5-other-peoples-public-keys)).

> **SSH or OpenPGP signing?** [Chapter 6](06-ssh-and-git.md) signs commits
> with an SSH key instead. Both work and both show *Verified*. Use OpenPGP
> if your project or employer expects GPG signatures; use SSH if you already
> use a vault SSH key and want one key for everything.

## 3. A pass password store

`pass` runs `gpg2` if it exists, otherwise `gpg`. Give it `vault-gpg` under
both names in a folder of its own, so the rest of your system keeps the
real GnuPG:

```sh
mkdir -p ~/.local/lib/vault-gpg
ln -s "$(command -v vault-gpg)" ~/.local/lib/vault-gpg/gpg
ln -s "$(command -v vault-gpg)" ~/.local/lib/vault-gpg/gpg2
echo "alias pass='PATH=\$HOME/.local/lib/vault-gpg:\$PATH pass'" >> ~/.bashrc
```

Open a new terminal, then create the store for your key and use `pass` as
normal:

```sh
pass init alex@example.com
pass insert web/example.com
pass show web/example.com
pass generate web/shop.example.com 20
```

Each `pass show` decrypts in the vault, so it asks for approval each time.
If that is too often for a key you use only for `pass`, turn the question
off for it with `vault pgp confirm me off` (anyone who can run programs as
you can then read the store while the vault is unlocked).

**Moving an existing store** encrypted to a GnuPG key: first import that
secret key into the vault (`gpg --export-secret-keys --armor OLDKEY >
old.asc`, then `vault pgp import old old.asc`), then run
`pass init alex@example.com` to re-encrypt every entry to the vault key.

## 4. NeoMutt and Mutt

The repository has a ready-made set of mail commands in
[`contrib/neomutt/vault-gpg.rc`](../../contrib/neomutt/vault-gpg.rc). Copy
it, check the path to `pgpewrap` at its top, and load it from your muttrc:

```muttrc
source ~/.config/neomutt/vault-gpg.rc
set pgp_default_key = alex@example.com
set crypt_autosign = yes          # optional: sign every message
```

Signing (PGP/MIME), encrypting, decrypting and checking signatures work,
and signatures verify in GnuPG-based mail programs. Inline "clear-signed"
messages cannot be made or checked. When a message is both signed and
encrypted, it decrypts but the signature inside it is not checked.

Each command in the file was tested by hand; NeoMutt itself has not yet been
driven end to end with it.

## 5. Other people's public keys

To encrypt to someone, or to check their signatures, import their public
key:

```sh
vault-gpg --import bo.asc
vault-gpg --list-keys
```

Imported keys are kept as files in `~/.local/share/vault/pgp-certs/`
(`%LOCALAPPDATA%\vault\pgp-certs\` on Windows), not in the vault: they are
not secret. Set `VAULT_GPG_KEYRING` to use another folder. Their signatures
verify as `[unknown]` trust, and `vault-gpg` reminds you to compare the
fingerprint with the owner, the same caution GnuPG asks for.

If you import a secret key, only its public half is kept; store the secret
key with `vault pgp import`.

## What it does not do

`vault-gpg` covers what git, pass and gpg-based mail use. These are not
supported:

- **Evolution, KMail and Thunderbird with an external GnuPG key.** They
  talk to GnuPG's own services (GPGME and `gpg-agent`), not the `gpg`
  command. This is the next step.
- Making keys (`--gen-key`), editing or certifying keys (`--edit-key`,
  `--sign-key`), deleting keys: use `vault pgp` instead.
- Exporting secret keys (`--export-secret-keys`): use `vault pgp export`.
- Clear-signed or inline-signed messages (`--clearsign`, `--sign` without
  `--detach-sign`) and password-only encryption (`--symmetric`).
- Key servers, trust databases and web of trust.
- Files and messages over 16 MiB.

Verifying signatures by your own keys needs the vault unlocked; while it is
locked, only imported keys can be checked.

## If something goes wrong

| Message | What to do |
|---|---|
| `cannot reach vaultd` | Start `vaultd` (chapter 1). |
| `vault is locked; run vault unlock` | Unlock it, then retry. |
| `not paired` | Pair the `vault` command once (`vault pair`); `vault-gpg` shares its pairing. |
| `No secret key in the vault` | `user.signingkey` or `-u` names a key that is not in the vault. Check `vault-gpg -K`. |
| `this key asks before each use, but vaultd cannot show the approval window` | `vaultd` runs without a desktop. Run it in your session, or turn confirmation off for the key. |
| git: `gpg failed to sign the data` | Run `echo test \| vault-gpg -bsau alex@example.com` to see the error itself. |
| git: `gpg.ssh.allowedSignersFile needs to be configured` | `gpg.format` is still `ssh`; set it to `openpgp` (step 2). |
