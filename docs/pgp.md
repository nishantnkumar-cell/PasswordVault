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
- Thunderbird: the vault key is an "external GnuPG key" and Thunderbird's `mail.openpgp.alternative_gpg_path` points at `vault-gpg`. See [Thunderbird through GPGME](#thunderbird-through-gpgme).
- Evolution and KMail also use GPGME but have not been tried; they may expect `gpg-agent` or `gpgsm` features that `vault-gpg` does not have.
- `vault pgp export ID` gives an armored secret key that any client can import, but that copy is then protected by the client, not by the vault.

## gpg-compatible front end (`vault-gpg`)

`vault-gpg` accepts the subset of gpg's command line that git, pass and gpg-based mail clients use, and answers with gpg's `[GNUPG:]` status lines on `--status-fd`. Secret-key operations go to the daemon (`PgpSign`, `PgpSignMessage`, `PgpUnwrap`, `PgpEncrypt` with `sign_with`), so they ask for approval as usual. Everything else (verification, listings, import, export) works on certificates in the process itself.

| gpg command | What vault-gpg does | Status lines |
|---|---|---|
| `-b`/`--detach-sign` (`-s` with it is ignored), `-u KEY`, `-a`, `-t`/`--textmode` | detached signature by a vault key; `--textmode` makes a text signature (class 0x01), which mail needs | `KEY_CONSIDERED`, `BEGIN_SIGNING`, `SIG_CREATED D ...` |
| `-s`/`--sign` (no `-b`), `--clearsign` | a signed message with the data inside (one-pass signed, `PgpSignMessage`), or a clear-signed text (always armored) | as for `-b`, with `SIG_CREATED S` or `C` |
| `--verify SIG DATA` (`DATA` may be `-`) | detached signatures, against vault keys and imported certificates | `NEWSIG`, then `GOODSIG` + `VALIDSIG` + `TRUST_ULTIMATE` (vault key) or `TRUST_UNDEFINED` (imported); `BADSIG` (exit 1); `ERRSIG` + `NO_PUBKEY` (exit 2) |
| `--verify [FILE]` | a signed or clear-signed message; `-o FILE` also writes its data (the text, for a clear-signed one) | as above, one `NEWSIG` per signature |
| `-e -r KEY...` (`-s` to sign too) | encrypt in the daemon to vault keys and imported certificates | `BEGIN_ENCRYPTION`, `END_ENCRYPTION`; `INV_RECP` for an unknown recipient |
| `-d` | decrypt with whichever vault key can, then check any signature inside against vault keys and imported certificates (exit 1 if one is bad, after the data) | `ENC_TO`, `BEGIN_DECRYPTION`, `DECRYPTION_OKAY`, `GOODMDC`, `PLAINTEXT`, the signature lines as for `--verify`, `END_DECRYPTION`; or `DECRYPTION_FAILED` |
| `-d --unwrap` | decrypt, but print the OpenPGP message that was inside the encryption (uncompressed, signatures kept) instead of its data; GPGME's `GPGME_DECRYPT_UNWRAP` | as for `-d`, without the signature lines |
| no command | what gpg guesses: verify a signed or clear-signed message, else decrypt | |
| `-d --list-only` | names the recipients (`gpg: public key is KEYID`), decrypts nothing; `pass init` uses it | `ENC_TO` |
| `-k`/`--list-keys`, `-K`/`--list-secret-keys`, `--fingerprint`, `--with-colons` | listings in gpg's formats; the colon format matches GnuPG 2.4 field for field | |
| `--import`, `--export [-a]` | certificates in and out of the keyring directory | `IMPORT_OK`, `IMPORT_RES` |
| `--list-config` | prints nothing (no groups) | |

Keys are named the way gpg names them: fingerprint, long or short key ID (of the primary key or a subkey, `0x` and a trailing `!` allowed), `<address>`, an address alone, `=exact user ID`, `@part of an address`, or any part of a user ID (ignoring case).

Options that only tune GnuPG itself (`--batch`, `--yes`, `--quiet`, `--use-agent`, `--no-encrypt-to`, `--compress-algo`, `--trust-model`, `--pinentry-mode`, `--passphrase-fd`, and GPGME's `--no-sk-comments`, `--logger-fd`, `--request-origin`, `--input-size-hint` and others) are accepted and ignored. `--detach` is `--detach-sign`, as GPGME spells it. Unknown options are errors, as in gpg. `--gen-key`, `--edit-key`, `--export-secret-keys` and `--symmetric` are refused with a pointer to the `vault pgp` command that does the job, where there is one.

**Keyring.** Imported certificates are stored as `<FINGERPRINT>.asc` in `VAULT_GPG_KEYRING`, or `pgp-certs` in the data directory (`~/.local/share/vault/pgp-certs`, `%LOCALAPPDATA%\vault\pgp-certs`). Their self-signatures are checked on import. A secret key given to `--import` has only its public half stored. Vault keys are read from the daemon on each run (`ListItems`, then `PublicKey`), so they are available only while the vault is unlocked.

**Trust.** Vault keys are reported as ultimately trusted (they are your own). Imported certificates have undefined trust, and a good signature by one is printed with a warning to check the fingerprint. There is no web of trust, expiry or revocation checking yet.

**Version.** `--version` prints `gpg (GnuPG) 2.4.4` on its first line, for programs that check it, and says on the next line that this is vault-gpg, not GnuPG.

**Status fd and special file names.** `--status-fd N` and, with `--enable-special-filenames`, file names `-&N` (input files and `--output`) name a descriptor the caller passed: on Unix it is opened again through `/dev/fd/N` (Linux and macOS); on Windows N is an inherited handle, as gpg and GPGME treat it there (0, 1 and 2 are the standard streams), and `fds::open` takes it over (the crate's only `unsafe`).

**Pairing.** `vault-gpg` uses the `vault` command's token (`VAULT_TOKEN_FILE`), so it needs no pairing of its own; the approval window names the program that ran it.

Tested: GPGME 1.18 driving `vault-gpg` with exactly Thunderbird's calls (see below), git 2.43 (`commit -S`, `tag -s`, `verify-commit`, `verify-tag`, `log --show-signature`, `%G?`), pass 1.7.4 (`init`, re-encrypting to added keys, `insert`, `show`, `generate`, `grep`, `init -p` for a subfolder), the `contrib/neomutt/vault-gpg.rc` commands by hand, and GnuPG 2.4 verifying vault-gpg signatures (binary and text) and decrypting its messages. `crates/vault-gpg/tests/frontend.rs` runs the git, pass and GPGME command lines against a real daemon.

## Thunderbird through GPGME

Thunderbird keeps its own OpenPGP engine (RNP) for everything except secret-key operations on keys marked "external": for those it loads GPGME and calls `gpgme_get_key(…, secret=1)` + `gpgme_op_sign` (detached, armored, text mode for PGP/MIME signatures; normal and binary before it encrypts a signed message itself with `RNP_ENCRYPT_NOWRAP`), and `gpgme_op_decrypt_ext(…, GPGME_DECRYPT_UNWRAP)` for incoming mail, after which RNP checks the inner signature. The pref `mail.openpgp.alternative_gpg_path` makes it call `gpgme_set_engine_info(OpenPGP, path)`, so GPGME runs `vault-gpg` in place of gpg. GPGME's command lines (1.18) are:

```text
gpg --version
gpg --batch --no-sk-comments --status-fd 4 --no-tty --charset utf8 --enable-progress-filter --exit-on-status-write-error --logger-fd 8 --with-colons --list-secret-keys -- KEYID
gpg --enable-special-filenames … --sign --detach --armor --textmode -u KEYID -- -&7
gpg --enable-special-filenames … --sign -u KEYID -- -&7
gpg --enable-special-filenames … --decrypt --unwrap --output - -- -&9
```

**Why this route.** The alternatives were (a) emulating `gpg-agent`'s Assuan protocol so the real gpg asks `vaultd` for `PKSIGN`/`PKDECRYPT`, which is internal to GnuPG, version-coupled, and would have to proxy every other key to the real agent; (b) an OpenPGP-card emulation for `scdaemon`, which limits keys to the card spec; (c) importing the secret key into Thunderbird, which takes it out of the vault. GPGME's gpg command line is stable, already mostly what `vault-gpg` spoke for git and NeoMutt, needs nothing installed beyond the free GPGME library, and keeps the secret key in `vaultd` with the same approval window. Everything here is free software: GPGME (LGPL) is loaded by Thunderbird, not linked into the vault.

**Unwrap.** `PgpUnwrap` decrypts in the daemon and returns the message inside the encryption, which rPGP's streaming reader cannot hand out as raw bytes. It is rebuilt: prefixed signature packets and one-pass signature packets of each signed layer (outermost first), a literal data packet with the original mode, file name and date, then the trailing signatures in reverse order. Compression is removed. Signatures cover only the literal data's body, so they verify unchanged; RNP and GnuPG both accept the result (tested with messages made by RNP, GnuPG with compression, and rPGP, classic and post-quantum).

**Inner signatures.** Plain `vault-gpg -d` now also uses `PgpUnwrap` and checks the signatures here, against certificates, so NeoMutt and other `gpg` callers get `GOODSIG`/`BADSIG` for signed-and-encrypted mail. The daemon still does only the secret-key part.

**Algorithm preferences.** Generated keys now carry preferred hash (SHA-512, SHA-384, SHA-256), cipher (AES-256, AES-192, AES-128) and compression (ZLIB, ZIP) lists, and v6 keys also the SEIPDv2 feature and AES-256/OCB. Before, the lists were empty, and GnuPG, which picks from the recipients' preferences, fell back to the implicit SHA-1 when signing mail that it also encrypted to a vault key; RNP (Thunderbird) and rPGP reject SHA-1 data signatures. Keys made earlier keep empty lists until they are replaced; refreshing their self-signatures is possible later.

**Checking a set-up.** `contrib/thunderbird/gpgme-check.py` loads GPGME through ctypes and makes the same calls, so a broken library path, engine path or locked vault shows up without Thunderbird.

**Not tried yet:** Thunderbird itself on any system (the calls were reproduced with GPGME 1.18 and the results checked with RNP 0.17), Gpg4win's GPGME on Windows (handles), Homebrew's on macOS. Post-quantum keys cannot be used in Thunderbird until its RNP reads v6 RFC 9980 keys.

## Not yet

Certificates of correspondents are files, not vault items. There is no key expiry, revocation or subkey management yet.

## Export

`vault pgp export ID` prints the secret key, armored and without a passphrase, after you prove an unlock factor again.
