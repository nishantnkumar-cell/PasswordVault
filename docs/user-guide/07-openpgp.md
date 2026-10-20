# 7. OpenPGP keys

OpenPGP is the standard behind GnuPG (`gpg`) and encrypted email. With
`vault pgp` the vault can hold your OpenPGP secret keys and do the signing
and decrypting itself, so the secret key never sits in `~/.gnupg`.

Use cases:

- **Encrypt a file** so only you, or only certain people, can open it.
- **Decrypt** files and mail encrypted to you.
- **Sign** a file or release so others can check it came from you, and
  **verify** other people's signatures.
- **Post-quantum protection** for things that must stay secret for many
  years, with a `--pq` key.

| | Linux | Windows | macOS |
|---|---|---|---|
| `vault pgp` | Yes (tested against GnuPG 2.4) | Yes | Not yet |

The vault must be unlocked for every command. Wherever a
command takes a `FILE`, leaving it out reads standard input; leaving out
`-o OUT` writes to standard output.

## 1. Make or import a key

**A classic key**, which works with GnuPG, Thunderbird and every current
OpenPGP program:

```sh
vault pgp new me 'Alex Example <alex@example.com>'
```

`me` is the title you use for the key in later commands.

**A post-quantum key** (see [Which kind of key](#which-kind-of-key)):

```sh
vault pgp new me-pq 'Alex Example <alex@example.com>' --pq
```

**Or import an existing secret key** exported from GnuPG
(`gpg --export-secret-keys --armor alex@example.com > old.asc`):

```sh
vault pgp import old old.asc
```

You are asked for the key's passphrase once; the vault then keeps it
without one, protected by the vault's encryption. Delete `old.asc`
afterwards. RSA, DSA and ElGamal secret keys are refused.

List keys with `vault pgp ls`.

## 2. Share your public key

```sh
vault pgp pub me > me.asc
```

Send `me.asc` to people who should write to you or check your signatures,
or upload it to a key server or your website. It contains no secret.

Keep the public keys (*certificates*) other people send you as files, for
example `friend.asc`. The vault does not store them yet.

## 3. Encrypt

```sh
vault pgp encrypt -R friend.asc -r me letter.txt -o letter.txt.asc
```

- `-R FILE` encrypts to someone's certificate file. Repeat it for several
  people.
- `-r KEY` encrypts to a key in the vault, by title or ID. Add `-r me` so
  you can still read what you sent.
- `--sign me` also signs the message.
- `--binary` writes binary output instead of ASCII text.

To encrypt a file just for yourself:

```sh
vault pgp encrypt -r me secrets.tar -o secrets.tar.asc
```

## 4. Decrypt

```sh
vault pgp decrypt letter.txt.asc -o letter.txt
```

The vault tries each of its keys that the message may be for; you do not
need to say which. If the key asks for confirmation, approve the window
`vaultd` opens.

## 5. Sign and verify

Make a detached signature (a separate `.asc` file next to the original):

```sh
vault pgp sign me release.tar.gz -o release.tar.gz.asc
```

Check someone's signature:

```sh
vault pgp verify release.tar.gz.asc -R friend.asc release.tar.gz
```

Verify checks against the certificates you give with `-R` and against the
keys in the vault.

## Approve each use

Like SSH keys, OpenPGP keys ask before every signature and decryption.
`vaultd` does the work first, then opens a window naming the key, the
purpose and the program asking; the result is released only if you press
**Allow**. Encrypting (without `--sign`) and verifying use no secret key and
never ask.

```sh
vault pgp confirm me off     # stop asking for this key; `on` turns it back on
```

or create the key with `--no-confirm`. When several keys could decrypt a
message, keys that need no confirmation are tried first.

## Which kind of key

| | Classic (default) | Post-quantum (`--pq`) |
|---|---|---|
| Format | OpenPGP v4 | OpenPGP v6 (RFC 9580) |
| Signing | Ed25519 | ML-DSA-65 + Ed25519 |
| Encryption | Curve25519 | ML-KEM-768 + X25519 |
| Who can use it | GnuPG, Thunderbird, Sequoia, everything current | Programs with RFC 9980 support (Sequoia's PQC builds, rPGP). GnuPG 2.4 cannot import it. |

The post-quantum algorithms are paired with classic ones, so a key stays
secure as long as either half holds. Until the people you write to can use
v6 keys, keep a classic key for them and use the post-quantum key for
yourself (for example, encrypting your own long-term archives) and for
people whose software supports it.

## Using it for email

- **Mail programs you can script** (NeoMutt, aerc, your own scripts): call
  `vault pgp encrypt`, `decrypt`, `sign` and `verify` directly.
- **Evolution, KMail and others that call `gpg`**: not connected yet. A
  `gpg`-compatible front end is planned.
- **Thunderbird** uses its own OpenPGP engine. You can give it a copy of the
  key with `vault pgp export me > me-secret.asc` and import that in
  Thunderbird's key manager, but that copy is then protected by
  Thunderbird, not by the vault.

## Export a secret key

```sh
vault pgp export me > me-secret.asc
```

You must prove an unlock method again (password by default, or `--fido2`,
`--tpm`, `--recovery`). The key is written without a passphrase: protect
the file and delete it when done.

## Limits

- Messages and files up to 16 MiB.
- Decrypting does not check a signature inside the message; verify detached
  signatures with `vault pgp verify`.
- Certificates of other people are files, not vault items.
- No key expiry, revocation certificates or subkey management yet.
- The desktop app lists OpenPGP keys with their fingerprint but cannot
  create, import or use them.
