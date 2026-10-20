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

- Clients you can script (NeoMutt, aerc, scripts) can call `vault pgp encrypt|decrypt|sign|verify` directly.
- Clients that call `gpg` or GPGME (Evolution, KMail, Thunderbird with an external key) are not connected yet. The next step is a gpg-compatible front end, so they can use vault keys without the key leaving the vault.
- Thunderbird uses its own OpenPGP engine. Until then, `vault pgp export ID` gives an armored secret key that Thunderbird can import. That copy is protected by Thunderbird, not by the vault.

## Not yet

Decrypting does not check signatures inside the message (verify detached signatures with `vault pgp verify`). Certificates of correspondents are files, not vault items. There is no key expiry, revocation or subkey management yet.

## Export

`vault pgp export ID` prints the secret key, armored and without a passphrase, after you prove an unlock factor again.
