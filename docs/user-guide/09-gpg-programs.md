# 9. Programs that call gpg: git, pass and mail

Many programs never handle OpenPGP themselves: they run the `gpg` command.
git signs commits that way, `pass` encrypts each password that way, and
mail programs such as NeoMutt sign and decrypt mail that way. Thunderbird
does the same for keys it is told live in GnuPG ("external keys"), through
GnuPG's GPGME library.

`vault-gpg` answers those programs in gpg's own language, using the OpenPGP
keys in your vault. The secret key stays inside `vaultd`; `vault-gpg` only
passes the data across and returns the result, and you approve each use as
usual.

Use cases:

- **Sign git commits and tags with your OpenPGP key**, so GitHub and GitLab
  show them as *Verified*, without the key in `~/.gnupg`.
- **Keep a `pass` password store** whose entries only the vault can decrypt.
- **Sign, encrypt and decrypt mail** in NeoMutt or Mutt with vault keys.
- **Sign and read encrypted mail in Thunderbird** with a vault key, so the
  secret key is never stored in Thunderbird's own key manager.

It does not replace GnuPG for everything: see [What it does not do](#what-it-does-not-do).

| | Linux | Windows | macOS |
|---|---|---|---|
| git commit and tag signing, `git log --show-signature` | Yes (tested with git 2.43) | Yes, untested on real hardware | Yes, untested on real hardware |
| `pass` | Yes (tested with pass 1.7.4) | No: `pass` is a Unix shell script | Should work (`brew install pass`); untested |
| NeoMutt and Mutt | Commands tested by hand | Not applicable | Should work; untested |
| Thunderbird (external GnuPG key) | Yes: tested with GPGME 1.18 making Thunderbird's calls, results checked with RNP 0.17; not yet clicked through in Thunderbird itself | Should work with Gpg4win; untested | Should work with Homebrew's GPGME; untested |
| Evolution and KMail | Not yet | Not applicable | Not applicable |

On macOS, `vault-gpg` is linked into `~/.local/bin` by the installer
([chapter 13](13-macos.md)).

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
and signatures verify in GnuPG-based mail programs. When a message is both
signed and encrypted, the signature inside is checked as it is decrypted
(import the sender's public key first, [step 5](#5-other-peoples-public-keys)).
Inline "clear-signed" messages can be made (`vault-gpg --clearsign`) and
checked (`vault-gpg --verify`).

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

## 6. Thunderbird

Thunderbird has its own OpenPGP engine and normally keeps your secret key in
its own key manager. It can instead be told that a key is "external": then
it hands every signature and decryption with that key to GnuPG, through a
library called GPGME. Point that at `vault-gpg` and Thunderbird signs and
decrypts with the key in your vault. Thunderbird never sees the secret key,
and each use opens the vault's approval window.

Encrypting to other people and checking their signatures stays inside
Thunderbird, with their public keys in Thunderbird's key manager, as
before.

What you need:

- Thunderbird 102 or later (free), and a **classic** OpenPGP key in the
  vault. Thunderbird cannot read post-quantum (v6) keys yet.
- GnuPG's GPGME library (free). Thunderbird only loads it; it is not used
  for anything else.
- `vaultd` running and the vault unlocked while you read or send mail.

### Step 1: install GPGME

**Linux:** it is usually installed already with GnuPG. If not:

```sh
sudo apt install libgpgme11t64     # Ubuntu 24.04 and later, Debian 13
sudo apt install libgpgme11        # older Ubuntu and Debian
sudo dnf install gpgme             # Fedora
```

Thunderbird from a Snap or Flatpak cannot see programs outside its sandbox;
use the distribution's Thunderbird package (or Mozilla's own download).

**Windows:** install [Gpg4win](https://gpg4win.org) (free; the default
choices are fine, you do not need Kleopatra). For 64-bit Thunderbird, add
Gpg4win's 64-bit folder to the **system** `Path`, before any other Gpg4win
entry: open **Edit the system environment variables**, **Environment
Variables**, select `Path` under *System variables*, **Edit**, **New**, and
enter `C:\Program Files (x86)\Gpg4win\bin_64` (move it up to the top).
Sign out and back in.

**macOS:** install GPGME with [Homebrew](https://brew.sh) (free):

```sh
brew install gpgme
```

Thunderbird finds it in `/opt/homebrew/lib` (Apple silicon) or
`/usr/local/lib` (Intel) by itself.

### Step 2: tell Thunderbird to use vault-gpg

1. Find where `vault-gpg` is:
   - Linux: `command -v vault-gpg` (for example `/usr/bin/vault-gpg` from
     the `.deb`, or `~/.cargo/bin/vault-gpg`).
   - Windows: in a Command Prompt, `where vault-gpg` (usually
     `C:\Users\<you>\AppData\Local\Programs\Secret Vault\vault-gpg.exe`).
   - macOS: `/usr/local/bin/vault-gpg` (`.pkg`) or `~/.local/bin/vault-gpg`
     (`.tar.gz`); write `~` out in full, such as `/Users/alex/.local/bin/vault-gpg`.
2. In Thunderbird open **Settings**, scroll to the bottom of **General** and
   press **Config Editor**. Accept the warning.
3. Search for `mail.openpgp.allow_external_gnupg` and set it to `true`
   (double-click it).
4. Search for `mail.openpgp.alternative_gpg_path`, press the pencil, enter
   the full path from 1, and press the tick. If it does not exist yet,
   choose **String** and press **+** to create it.
5. Quit Thunderbird completely and start it again.

### Step 3: give Thunderbird your public key

Thunderbird needs your own public key in its key manager, both to show
your signatures as valid and to encrypt a copy of sent mail to yourself.

1. Save it to a file:

   ```sh
   vault pgp pub me > me.asc
   ```

2. In Thunderbird: **Tools**, **OpenPGP Key Manager**, **File**, **Import
   Public Key(s) From File**, and choose `me.asc`.
3. Double-click the key in the key manager, open **Your Acceptance**, choose
   **Yes, I've verified in person this key has the correct fingerprint**,
   and press **OK**. (It is your own key, from your own vault.)

### Step 4: use the vault key for your account

1. Find the key ID: the last 16 characters of the fingerprint that
   `vault-gpg --list-secret-keys` prints under the `sec` line. Or print just
   the ID:

   ```sh
   vault-gpg --list-secret-keys --with-colons | grep '^sec' | cut -d: -f5
   ```

   In PowerShell on Windows:
   `(vault-gpg --list-secret-keys --with-colons | Select-String '^sec').Line.Split(':')[4]`
2. In Thunderbird open **Account Settings**, then **End-To-End Encryption**
   under your mail account.
3. Press **Add Key**, choose **Use your external key through GnuPG (e.g.
   from a smartcard)**, press **Continue**, enter the key ID and press
   **Save key ID**. Thunderbird does not check the ID, so copy it exactly.
4. Select the new entry (it shows the key ID) so it becomes the account's
   key.

### Step 5: send and read mail

- **Sign or encrypt:** write a message and turn on **Encrypt** or
  **Digitally Sign** (the **Security** menu or the toolbar). When you send
  it, the approval window opens and names your key and "sign data with
  OpenPGP". Press **Allow**. Encrypting needs the recipient's public key in
  Thunderbird's key manager, as always.
- **Read encrypted mail:** open the message. Thunderbird first tries its own
  keys, then asks `vault-gpg`; the approval window opens with "decrypt an
  OpenPGP message". Thunderbird checks the sender's signature itself and
  shows it as usual.

Thunderbird decrypts again each time you open an encrypted message, so you
are asked each time. If that is too often, turn the question off for this
key with `vault pgp confirm me off`. Then anything that runs as you can
decrypt with it while the vault is unlocked, so keep it on if you can.

**Check the set-up without Thunderbird:** the repository has
[`contrib/thunderbird/gpgme-check.py`](../../contrib/thunderbird/gpgme-check.py),
which loads GPGME and makes the same calls Thunderbird makes (Python 3, no
extra packages):

```sh
python3 contrib/thunderbird/gpgme-check.py "$(command -v vault-gpg)" alex@example.com
python3 contrib/thunderbird/gpgme-check.py "$(command -v vault-gpg)" alex@example.com mail.asc
```

It prints `Signed: OK` (and `Decrypted: OK` for the second form, given an
encrypted message), or the step that failed.

**What differs between systems**

| | Linux | Windows | macOS |
|---|---|---|---|
| GPGME comes from | The distribution (`libgpgme11`) | Gpg4win | Homebrew (`brew install gpgme`) |
| Extra step | Not with Snap or Flatpak Thunderbird | Add `Gpg4win\bin_64` to the system `Path` | None |
| `alternative_gpg_path` example | `/usr/bin/vault-gpg` | `C:\Users\<you>\AppData\Local\Programs\Secret Vault\vault-gpg.exe` | `/usr/local/bin/vault-gpg` |
| Tested | GPGME 1.18 and RNP 0.17, as above | Not yet | Not yet |

**Thunderbird problems**

| What you see | What to do |
|---|---|
| The **external key** choice is missing in Account Settings | `mail.openpgp.allow_external_gnupg` is not `true`, or Thunderbird was not restarted. |
| "Unable to sign message" or "Sending of the message failed" | Run `gpgme-check.py` (above). Usually GPGME is not installed, the path in `alternative_gpg_path` is wrong, or the vault is locked. |
| An encrypted message stays unreadable, with no approval window | Check that the mail was encrypted to your vault key (`vault-gpg -d --list-only -v mail.asc` names the key IDs), and that the vault is unlocked. |
| Your own signatures show as unverified | Import your public key and accept it (step 3). |
| Mail from a GnuPG user shows an invalid signature | Their GnuPG signed with SHA-1, which Thunderbird refuses. GnuPG does that when your key lists no preferred algorithms: vault keys made before this release list none. Make a new key (`vault pgp new`) and send people its public key, or ask the sender to add `digest-algo SHA512` to their `gpg.conf`. |

## What it does not do

`vault-gpg` covers what git, pass and gpg-based mail use. These are not
supported:

- **Evolution and KMail.** They use GPGME too, but with settings and
  agent features (`gpg-agent`, S/MIME through `gpgsm`) that have not been
  tried with `vault-gpg` yet.
- Making keys (`--gen-key`), editing or certifying keys (`--edit-key`,
  `--sign-key`), deleting keys: use `vault pgp` instead.
- Exporting secret keys (`--export-secret-keys`): use `vault pgp export`.
- Password-only encryption (`--symmetric`).
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
