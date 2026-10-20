# OpenPGP keys

OpenPGP secret keys can live in the vault. `vaultd` signs, decrypts, encrypts and verifies with them itself (rPGP, MIT/Apache-2.0), so the secret key is never written to `~/.gnupg`. Without `-o`, input comes from stdin and output goes to stdout.

```sh
vault pgp new me 'Your Name <you@example.com>'     # classic key, works with GnuPG and Thunderbird
vault pgp new me-pq 'Your Name <you@example.com>' --pq   # post-quantum key (below)
vault pgp import old ~/old-secret-key.asc         # asks the key's passphrase, then drops it
vault pgp pub me > me.asc                         # certificate to give to correspondents

vault pgp encrypt -R friend.asc -r me --sign me letter.txt -o letter.txt.asc
vault pgp decrypt letter.txt.asc                  # tries each vault key the message may be for
vault pgp sign me release.tar.gz -o release.tar.gz.asc
vault pgp verify release.tar.gz.asc -R friend.asc release.tar.gz
```

`-r` names a key in the vault (title or ID), `-R` a certificate file. Encrypting to yourself as well (`-r me`) keeps the message readable by you. Output is ASCII-armored unless `--binary` is given. Messages and files are limited to 16 MiB for now, because each request is a single frame.

## Kinds of key

| | Classic (default) | Post-quantum (`--pq`) |
|---|---|---|
| Format | v4 | v6 (RFC 9580) |
| Primary (certify, sign) | Ed25519 | ML-DSA-65 + Ed25519 |
| Encryption subkey | Curve25519 ECDH | ML-KEM-768 + X25519 |
| Works with | GnuPG, Thunderbird, Sequoia, everything current | implementations with RFC 9980 support (Sequoia's PQC builds, rPGP). GnuPG 2.4 refuses to import it. |

Both post-quantum algorithms are hybrids: they stay secure if either half does. Until correspondents can use v6 keys, keep a classic key for them and the post-quantum key for yourself and others who can.

Encrypting to only v6 keys uses SEIPDv2 (AES-256-OCB); any v4 recipient makes it SEIPDv1 (AES-256 with MDC) so that recipient can read it.

RSA, DSA and ElGamal secret keys are refused (the `rsa` crate has no constant-time fix for the Marvin attack). Encrypting to RSA certificates and verifying RSA signatures are public operations and work.

## Tested with GnuPG 2.4

GnuPG encrypts to a vault key and the vault decrypts. The vault encrypts and signs to a GnuPG key and GnuPG decrypts and reports a good signature. Detached signatures verify in both directions. A key exported with `vault pgp export` imports into GnuPG.

## Approval

Keys ask before each signature and decryption, like SSH keys (`--no-confirm` at creation, or `vault pgp confirm ID on|off`). The daemon does the work, then shows `vault-prompt` with the key, the purpose and the program asking; the result is released only if you allow it. When several keys could decrypt a message, keys that need no approval are tried first. Verifying and encrypting without `--sign` need no secret key and never ask.

## Mail

- NeoMutt and Mutt call `gpg` commands: point them at `vault-gpg` with [`contrib/neomutt/vault-gpg.rc`](../contrib/neomutt/vault-gpg.rc). See below.
- Other clients you can script (aerc, scripts) can call `vault-gpg` or `vault pgp encrypt|decrypt|sign|verify` directly.
- Clients that use GPGME and `gpg-agent` (Evolution, KMail, Thunderbird with an external key) are not connected yet: they need GnuPG's Assuan services, not the `gpg` command.
- Thunderbird uses its own OpenPGP engine. `vault pgp export ID` gives an armored secret key that Thunderbird can import. That copy is protected by Thunderbird, not by the vault.

## gpg-compatible front end (`vault-gpg`)

`vault-gpg` accepts the subset of gpg's command line that git, pass and gpg-based mail clients use, and answers with gpg's `[GNUPG:]` status lines on `--status-fd`. Secret-key operations go to the daemon (`PgpSign`, `PgpDecrypt`, `PgpEncrypt` with `sign_with`), so they ask for approval as usual. Everything else (verification, listings, import, export) works on certificates in the process itself.

| gpg command | What vault-gpg does | Status lines |
|---|---|---|
| `-b`/`--detach-sign` (`-s` with it is ignored), `-u KEY`, `-a`, `-t`/`--textmode` | detached signature by a vault key; `--textmode` makes a text signature (class 0x01), which mail needs | `KEY_CONSIDERED`, `BEGIN_SIGNING`, `SIG_CREATED D ...` |
| `--verify SIG DATA` (`DATA` may be `-`) | detached signatures only, against vault keys and imported certificates | `NEWSIG`, then `GOODSIG` + `VALIDSIG` + `TRUST_ULTIMATE` (vault key) or `TRUST_UNDEFINED` (imported); `BADSIG` (exit 1); `ERRSIG` + `NO_PUBKEY` (exit 2) |
| `-e -r KEY...` (`-s` to sign too) | encrypt in the daemon to vault keys and imported certificates | `BEGIN_ENCRYPTION`, `END_ENCRYPTION`; `INV_RECP` for an unknown recipient |
| `-d`, or no command | decrypt with whichever vault key can | `ENC_TO`, `BEGIN_DECRYPTION`, `DECRYPTION_OKAY`, `GOODMDC`, `END_DECRYPTION`, or `DECRYPTION_FAILED` |
| `-d --list-only` | names the recipients (`gpg: public key is KEYID`), decrypts nothing; `pass init` uses it | `ENC_TO` |
| `-k`/`--list-keys`, `-K`/`--list-secret-keys`, `--fingerprint`, `--with-colons` | listings in gpg's formats; the colon format matches GnuPG 2.4 field for field | |
| `--import`, `--export [-a]` | certificates in and out of the keyring directory | `IMPORT_OK`, `IMPORT_RES` |
| `--list-config` | prints nothing (no groups) | |

Keys are named the way gpg names them: fingerprint, long or short key ID (of the primary key or a subkey, `0x` and a trailing `!` allowed), `<address>`, an address alone, `=exact user ID`, `@part of an address`, or any part of a user ID (ignoring case).

Options that only tune GnuPG itself (`--batch`, `--yes`, `--quiet`, `--use-agent`, `--no-encrypt-to`, `--compress-algo`, `--trust-model`, `--pinentry-mode`, `--passphrase-fd` and others) are accepted and ignored. Unknown options are errors, as in gpg. `--gen-key`, `--edit-key`, `--export-secret-keys`, `--clearsign`, inline `--sign` and `--symmetric` are refused with a pointer to the `vault pgp` command that does the job, where there is one.

**Keyring.** Imported certificates are stored as `<FINGERPRINT>.asc` in `VAULT_GPG_KEYRING`, or `pgp-certs` in the data directory (`~/.local/share/vault/pgp-certs`, `%LOCALAPPDATA%\vault\pgp-certs`). Their self-signatures are checked on import. A secret key given to `--import` has only its public half stored. Vault keys are read from the daemon on each run (`ListItems`, then `PublicKey`), so they are available only while the vault is unlocked.

**Trust.** Vault keys are reported as ultimately trusted (they are your own). Imported certificates have undefined trust, and a good signature by one is printed with a warning to check the fingerprint. There is no web of trust, expiry or revocation checking yet.

**Version.** `--version` prints `gpg (GnuPG) 2.4.4` on its first line, for programs that check it, and says on the next line that this is vault-gpg, not GnuPG.

**Status fd.** `--status-fd` 1 and 2 work everywhere; other descriptors only on Unix (through `/dev/fd/N`).

**Pairing.** `vault-gpg` uses the `vault` command's token (`VAULT_TOKEN_FILE`), so it needs no pairing of its own; the approval window names the program that ran it.

Tested: git 2.43 (`commit -S`, `tag -s`, `verify-commit`, `verify-tag`, `log --show-signature`, `%G?`), pass 1.7.4 (`init`, re-encrypting to added keys, `insert`, `show`, `generate`, `grep`, `init -p` for a subfolder), the `contrib/neomutt/vault-gpg.rc` commands by hand, and GnuPG 2.4 verifying vault-gpg signatures (binary and text) and decrypting its messages. `crates/vault-gpg/tests/frontend.rs` runs the git and pass command lines against a real daemon.

## Not yet

Decrypting does not check signatures inside the message (verify detached signatures with `vault pgp verify` or `vault-gpg --verify`). Certificates of correspondents are files, not vault items. There is no key expiry, revocation or subkey management yet.

## Export

`vault pgp export ID` prints the secret key, armored and without a passphrase, after you prove an unlock factor again.
