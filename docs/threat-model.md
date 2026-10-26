# Threat model

Version: 1 (2026-10-17). Scope: v1 as defined in the Vault Project Brief, Revision 2, section 13 (`vault-core`, `vaultd`, `vault-cli`, password / FIDO2 / recovery / TPM slots, browser autofill, TOTP, generator, import). Linux first.

This document is versioned with the code. Any change to the format, IPC, or factor set must update it in the same change.

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| Item data (passwords, TOTP seeds, notes) | The thing users store |
| Item metadata (titles, URLs, usernames) | Reveals accounts and habits |
| Vault key and item keys | Unlock everything |
| Unlock factors (password, FIDO2 credential, TPM-sealed secret, recovery code) | Lead to the vault key |
| Integrity of the vault file | Tampering could plant credentials (phishing via autofill) or remove slots |
| Integrity of autofill decisions | Filling on the wrong origin hands credentials to an attacker |

## 2. Actors

- **A1, offline thief.** Has the disk or the vault file, not the running session. May have a lost FIDO2 key, or the whole laptop including its TPM.
- **A2, remote phisher.** Controls a web origin the user visits, possibly a lookalike domain or a page with injected iframes.
- **A3, same-user malware.** Runs code as the logged-in user, without root.
- **A4, root or kernel attacker** on a running machine.
- **A5, file tamperer.** Can modify the vault file at rest (shared folder, backup medium, the synced copy in a cloud folder) but does not know the factors.
- **A6, future quantum adversary** recording ciphertext today.

## 3. Trust boundaries

1. `vaultd` (dedicated system user) and everything else on the machine.
2. `vaultd` and its clients (`vault-cli`, `vault-native-host`), over a Unix socket.
3. Browser extension background script and web page content.
4. `vaultd` and hardware (FIDO2 over HID, TPM over `/dev/tpmrm0`).
5. The vault file at rest and `vaultd`'s in-memory state.

## 4. Assumptions

- The OS kernel, `vaultd`'s binary and its update channel are not compromised.
- The CSPRNG (`getrandom`) works.
- The browser enforces its own origin model and gives the extension correct `sender` information.
- The user checks the approval prompts that `vaultd` draws (pairing, secret release).
- Audited crates behave as documented. Items marked (verify) in the brief are not yet confirmed.

## 5. Threats and mitigations

Status: **M** = mitigated by the design, **P** = partially mitigated, **A** = accepted residual risk.

### A1, offline thief

| Threat | Mitigation | Status |
| --- | --- | --- |
| Brute-force the password from the file | Argon2id (≥ 256 MiB desktop default, bounded 64 MiB to 4 GiB), all daily-use KEKs mix in a hardware factor | M |
| Has the FIDO2 key but not the password | Password is part of every daily-use KEK; FIDO2 key requires PIN with on-device retry limit | M |
| Has the whole laptop including TPM | TPM secret needs authValue (PIN) with TPM dictionary-attack lockout, and the password is still required. Same on Windows, where the secret is wrapped to a TPM-bound RSA key with the PIN as its usage auth | M |
| Steals the laptop while quick unlock is available (Windows) | The vault key is in `vaultd` memory, wrapped under a key held with `CryptProtectMemory`; opening it needs Windows Hello (face, fingerprint or Windows PIN, with Windows' own retry limits), and quick unlock ends after its time limit (at most 24 h after a full unlock), on restart, after 3 failed checks and on `vault lock --full`. A thief who can sign in as the user, or read RAM of the running machine, gets what they would get from an unlocked vault | P (opt-in, off by default) |
| Sniffs the discrete TPM bus | Salted, encrypted HMAC sessions for every unseal (verify `tss-esapi`) | M |
| Finds the recovery code | Recovery code is a full 256-bit secret and unlocks alone, by design. Users are told to store it offline | A |
| Reads metadata without unlocking | All item metadata and slot labels encrypted; the plaintext header holds only what is needed to try an unlock. Body is padded to hide item count roughly | P (file size and slot count leak) |
| Uses an old copy of the file with a since-revoked factor | Revoking a factor rotates the vault key, so new data is safe. Old copies stay readable with old factors | A (inherent) |

### A2, remote phisher

| Threat | Mitigation | Status |
| --- | --- | --- |
| Lookalike domain | Full-origin match by default, punycode normalization, homograph warnings | M |
| Subdomain takeover on a site using eTLD+1 matching | eTLD+1 matching is opt-in per item only | P |
| Hidden or invisible form harvesting | Fill needs a user gesture; hidden and zero-size fields never filled | M |
| Cross-origin iframe on a trusted page | Top frame or same-origin frames only; a cross-origin frame is filled only after the user picks its origin in the popup and the browser's permission prompt | M |
| Origin spoofed from page content | Origin taken only from browser-provided `sender` data in the background script | M |
| XSS on the legitimate origin | Out of reach: the origin is genuinely correct | A |
| Downgrade to `http` | `https` only unless a per-item override | M |

### A3, same-user malware

| Threat | Mitigation | Status |
| --- | --- | --- |
| Read `vaultd` memory while quick unlock is available (Windows) | The parked vault key and its protected wrap key are in the process, as the vault key is while unlocked. `CryptProtectMemory` keeps it out of crash dumps and the page file, not away from code running in or debugging the process | A (opt-in) |
| Read `vaultd` memory or attach ptrace | Separate system user (`vaultd@.service`; the per-user unit does not give this), `PR_SET_DUMPABLE=0`, Yama ptrace scope, no core dumps | M with the system unit, P with the user unit |
| Connect to the socket and request secrets | One-time client pairing, by proving an unlock method or approved in `vaultd`'s own prompt (one at a time, 10 s cooldown after a decline); fresh user presence for non-allowlisted release; rate limit. The prompt names the peer by PID-derived path, not yet by pidfd | P |
| Impersonate a paired client binary | Pairing key stored in the client's own storage, readable by the same user | A on Linux (no per-app isolation) |
| Keylog the master password | Wayland: partially mitigated by compositor isolation. X11: any client can keylog | A on X11, P on Wayland |
| Read the clipboard | Prefer autofill; auto-clear; password-manager MIME hint (verify) | P |
| Modify the browser extension or profile | Out of scope: same-user code owns the browser profile | A |

### A4, root or kernel attacker

Out of scope for v1. Root can read `vaultd` memory while unlocked. The vault is safe only while locked and keys are zeroized. The TPM still rate-limits PIN guesses against the TPM slot.

### A5, file tamperer

| Threat | Mitigation | Status |
| --- | --- | --- |
| Swap or replay individual records | Item AAD binds vault ID, item ID, item version, format version | M |
| Add, remove or edit keyslots | Header MAC under a key derived from the vault key, verified on every unlock | M |
| Set enormous KDF parameters (DoS) | Parameters bounded before Argon2id runs | M |
| Craft ciphertext valid under several keys (partitioning oracle) | Key commitment on every keyslot, the body and every item | M |
| Roll back the whole file to an older version | Generation counter inside the encrypted body; `vaultd` keeps the last seen generation in its state directory and warns on regression. A TPM NV counter is a later hardening option | P |
| Corrupt the file | Atomic write with directory fsync; commit tag separates "wrong factor" from "corrupt" | M |
| Feed an old or doctored synced copy (folder sync, docs/sync.md) | A synced copy is opened only under the vault key already held (header MAC) or with the user's own factor. Merging is monotone: an old copy cannot bring back deleted items or removed slots, or undo a revoke (the higher key epoch wins). A copy of another vault is refused | M |
| Swap or withhold the synced copy so devices stop seeing each other's edits | Not prevented: the folder's owner controls delivery. Each device keeps its own file and merges again when the copy changes, so nothing is lost locally | Accepted |

### A6, quantum adversary

The attacker copies the vault file today (for example from a sync folder or a backup) and waits for a quantum computer.

| What | Protection | Status |
| --- | --- | --- |
| Vault file, items, keyslots, recovery code, sync copies | Symmetric only, 256-bit keys: XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, Argon2id | M |
| FIDO2 slot | hmac-secret: the key's secret is symmetric and never in the file. CTAP's PIN protocol uses ECDH P-256 on the USB link, so a recorded USB trace could be opened later | M at rest; bus accepted (CTAP spec) |
| TPM slot, Linux and Windows (`VWTPM2`) | Sealed object, private part under the TPM's own AES key. The session salt uses the storage key's ECC or RSA, so a recorded TPM bus trace could be opened later (discrete TPMs only; firmware TPMs have no bus) | M at rest; bus accepted |
| Windows TPM slot made by earlier versions (`VWTPM1`) | RSA-2048 wrap with the public key in the file: breaking it leaves only the password | Accepted for old slots; flagged in `vault slots` and the app, replaced by enrolling again and revoking |
| OpenPGP keys | `vault pgp new --pq`: ML-DSA-65 + Ed25519, ML-KEM-768 + X25519 (RFC 9980). Classic keys, and messages encrypted to them, are not post-quantum | M with `--pq` |
| SSH keys | Ed25519, ECDSA P-256 signatures. A signature cannot be harvested; a quantum attacker with your public key could later forge logins. Key exchange is the ssh client's (OpenSSH 10 uses ML-KEM hybrid by default) | Accepted until OpenSSH has a post-quantum key type |
| Pairing, browser host, IPC | Random tokens over local sockets, no public keys | M |
| Sharing, device enrollment, phone pairing, release signing | Not built. Must use hybrid PQ when built: X-Wing (ML-KEM-768 + X25519) for the reserved `RecipientHybrid` slot, ML-DSA-65 + Ed25519 for signatures (brief section 11) | Open |

## 6. Memory and process hygiene

- All secret types use `zeroize` / `secrecy` wrappers that do not implement `Debug`, `Clone` or `Serialize` except where explicitly needed. Enforced by wrapper types, not review alone.
- All daemon memory `mlockall`ed when `RLIMIT_MEMLOCK` allows (the shipped units set it); `RLIMIT_CORE=0`; `PR_SET_DUMPABLE=0`.
- Keys are zeroized on lock, suspend and screen lock (logind D-Bus signals; session and power notifications on Windows), idle timeout and SIGTERM. Exception: with quick unlock on (Windows, opt-in), a lock within its window keeps the vault key parked (format.md 4.6) until the window ends, three Windows Hello checks fail, `vault lock --full`, or the daemon stops.

## 7. Explicitly out of scope for v1

- Root or kernel compromise, firmware attacks, evil-maid attacks on a running unlocked machine.
- Same-user malware on X11.
- Side channels (power, EM, cache timing) beyond using constant-time crates.
- Face unlock, phone factors, Secret Service, passkey storage, server sync, sharing. Each gets a section here before it is built. Folder sync (docs/sync.md) is covered under A5.

## 8. Open items

- Verify `tss-esapi` session encryption API, `SO_PEERPIDFD` kernel availability, and clipboard hint conventions (brief section 9 and 12).
- Decide whether the rollback counter moves into TPM NV storage once the TPM slot exists.
