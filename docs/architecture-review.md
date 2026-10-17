# Vault architecture review

Reviewed: *Vault Project Brief* (design phase, no code), 2026-10-17.
Scope: crypto choices, key hierarchy and keyslots, unlock factors, process isolation, autofill origin binding, post-quantum plan, platform layers, roadmap.

## Verdict

The overall shape is sound and close to established prior art (LUKS2 keyslots, `age`, KeePassXC, `systemd-cryptenroll`): one random vault key, independently wrapped per factor, password always mixed into daily-use KEKs, audited primitives, a pure `vault-core`. Nothing needs a redesign.

There are **five issues to fix before the file format is frozen** (they are expensive to change later), a handful of threat-model claims that are stronger than the design delivers, and a roadmap that is too large for a first release.

Severity: **Must fix** = change the brief before writing `docs/format.md`. **Should fix** = address before the relevant milestone. **Note** = record in the threat model or as a (verify) item.

---

## 1. Must fix before the format is frozen

### 1.1 `header_hash` in keyslot AAD breaks multi-device slots
The brief binds `header_hash || slot.id` into every keyslot's AAD, and the header contains the slot list. Adding or removing any slot changes the header hash, so every other slot must be re-wrapped. Re-wrapping a slot needs that slot's KEK, which for a device-local slot (TPM, Secure Enclave, Windows key) only exists on the enrolling machine. Result: enrolling laptop B silently bricks laptop A's TPM slot, contradicting "adding factors never re-encrypts" and "each device enrolls its own slot".

**Fix.** Split integrity into two layers, as LUKS2 does:
- Keyslot AAD covers only immutable data: `vault_id || format_version || slot.id || slot.factor_type || canonical(slot.kdf params)`.
- The whole header (slot list included) is authenticated after unlock with `HMAC-SHA256(K_header, canonical_header)`, where `K_header = HKDF(vault_key, info="vault/header-mac/v1")`. Any unlocked client can recompute it after editing slots. Tampering with the slot list or downgrading it is detected on every unlock.

### 1.2 Removing a compromised factor does not revoke it
Because slots never re-encrypt, deleting a slot after a factor is compromised (lost FIDO2 key plus a phished password, stolen laptop with TPM) leaves the vault key unchanged. Anyone holding an older copy of the vault file (backup, sync history, the stolen disk) plus that factor can still decrypt current data written with the same vault key.

**Fix.** Make the hierarchy three-level so rotation is cheap:
`KEK (per slot) → vault key → item keys (random, per item) → item data`.
"Revoke factor" = generate a new vault key, re-wrap item keys (small, fast), re-wrap the remaining slots that this machine can unlock, and mark device-local slots from other machines as needing re-enrollment. Document that old file copies stay readable with old factors; that is inherent and belongs in the threat model.

Also settle "per-item keys derived or randomly generated" on **random and wrapped**. Derived keys cannot be re-parented for sharing or rotation.

### 1.3 Neither AEAD is key-committing
XChaCha20-Poly1305 and AES-256-GCM-SIV both allow a ciphertext that decrypts validly under more than one key (partitioning-oracle attacks, Len/Grubbs/Ristenpart 2021). For a local file this is low risk, but it becomes real once sync or sharing lets someone else hand you ciphertext, and it is a format decision.

**Fix.** Add a key-commitment tag to every keyslot and item record, for example `commit = HMAC-SHA256(HKDF(key, "vault/commit/v1"), nonce)` stored next to the ciphertext and checked before decryption. This also gives a clean "wrong factor" versus "corrupted file" distinction.

Also pick **one** AEAD for v1 (XChaCha20-Poly1305: 24-byte random nonces, no AES-NI dependency). Keep the algorithm ID in the header for agility, but do not ship two code paths that both need test vectors, fuzzing and audit.

### 1.4 FIDO2 `hmac-secret` output depends on UV, and other inputs must be pinned
CTAP2 authenticators keep two per-credential secrets, `CredRandomWithUV` and `CredRandomWithoutUV`. The same salt returns **different** outputs depending on whether user verification happened. If one unlock path does PIN and another does touch-only, the KEK will not match. The brief has a `require_uv` field but does not say this.

**Fix.** Treat `require_uv` as part of the slot's identity, include it in the slot AAD (1.1), and refuse to unlock with a mismatched UV mode. Same for `rp_id` and the PRF-style salt construction, which the brief already pins correctly. Put a known-answer test against a real key in CI-adjacent tests.

### 1.5 Bound and validate KDF parameters on parse
Argon2id parameters live in the (unauthenticated-before-unlock) header. A tampered header can set `m = 64 GiB, t = 10^6` and turn every unlock attempt into a denial of service or an OOM kill of `vaultd`.

**Fix.** Enforce a minimum and maximum (for example 64 MiB to 4 GiB, t ≤ 20, p ≤ 16) before running the KDF. Raise the default on desktop to 256 MiB+ if the 0.5 to 1 s target allows.

---

## 2. Threat-model claims that are stronger than the design

### 2.1 A separate UID for `vaultd` does not stop same-user malware from *asking* for secrets (Should fix)
The brief calls the dedicated system user "the main defense against same-user malware". It protects `vaultd`'s **memory**. It does not control **access**: malware running as the user can connect to the socket exactly like `vault-cli` does, and `SO_PEERCRED` only tells you the UID, not which program. On X11 it can also keylog the master password as it is typed into `vault-gui`.

**Fix in the design:**
- Per-client authorization: clients pair with `vaultd` once (key exchange, approval prompt shown by `vaultd`'s own UI), like KeePassXC-Browser association.
- Identify peers with `SO_PEERPIDFD` / pidfd rather than racy `/proc/<pid>/exe` (verify kernel version support).
- Secret release requires a fresh user-presence confirmation for clients outside a small allowlist, rate-limited.
- Threat model states plainly: on X11, same-user malware is out of scope; on Wayland it is partially mitigated.

### 2.2 Warm re-unlock session key is a policy gate, not a cryptographic one (Note)
The ephemeral session key lives in the same `vaultd` process as the wrapped vault key, so anyone who can read `vaultd` memory gets both. That is fine as an authorization gate, but describe it as such. Stronger option for later: seal the session key to the TPM with a short-lived policy, or hold it in the kernel keyring of the `vaultd` user.

### 2.3 Face unlock on Linux has no frame authenticity (Note)
Without SDCP, anything that can open or emulate the V4L2 device (root, or the user via a virtual camera) can inject frames. Warm-gate-only is the right restriction. It also costs a lot (helper, models, sandbox, liveness) relative to the security it adds; see roadmap below.

### 2.4 Encrypted metadata leaks via the header (Note)
`credential_id`, `rp_id`, `label` and `platform` sit in the plaintext header, which reveals which security keys and machines are enrolled ("Nishant's work laptop"). Encrypt labels under `K_header`-derived keys or drop them; keep only what is needed to attempt unlock.

### 2.5 TPM bus sniffing (Should fix)
Discrete TPMs on an LPC/SPI bus can be sniffed on a stolen laptop. Use salted/encrypted HMAC sessions (parameter encryption) for every unseal; `tss-esapi` supports this (verify API).

---

## 3. Autofill origin binding

"Exact-origin matching" and "public suffix handling with `psl`" pull in opposite directions. Pin the policy:

- **Default:** match on the full origin (scheme + host + port). `https` only; no fill on `http` without an explicit per-item override.
- **Opt-in per item:** registrable-domain (eTLD+1 via PSL) matching for sites that span subdomains. Ship the PSL inside signed releases, never fetch it at runtime.
- Normalize hosts to punycode (IDNA/UTS-46) before comparing; display Unicode with homograph warnings.
- The origin comes from the **browser** (`sender.origin` / `sender.tab.url` in the extension background), never from page content or the content script.
- Fill only in the top frame or same-origin frames; cross-origin iframes need an explicit prompt.
- Require a user gesture to fill; never fill hidden or zero-size fields (blocks "invisible form" credential exfiltration).
- Native messaging host to `vaultd` uses the pairing from 2.1. The manifest's `allowed_origins` restricts which extension can launch the host, not which process can talk to `vaultd`.

**Passkey storage:** on Linux there is no OS passkey-provider API, so the extension must wrap `navigator.credentials` in the page (as Bitwarden does). RP ID validation against the tab origin must run in the extension background, not the content script. Windows and macOS have provider APIs (verify current versions). Keep the vault-unlock credential separate, as the brief says.

**Secret Service:** D-Bus sender identity is no stronger than 2.1. Per-application approval there is advisory; say so.

---

## 4. Post-quantum plan

Correct and appropriately scoped. Points to tighten:

- A local vault is already PQ-safe; keep all PQ work out of v1 so it does not gate the core.
- Use X-Wing (X25519 + ML-KEM-768) for KEMs and Ed25519 + ML-DSA-65 composite signatures, as planned. X-Wing was an IETF draft at my last information (verify status and that the chosen crate matches the final text).
- `libcrux-ml-kem` as first pick is right; confirm constant-time claims cover the target platforms.
- The `RecipientHybrid` slot belongs in the enum now (format stability), but it should be rejected by v1 readers until implemented, gated by `format_version`.
- Phone Route A: for a non-browser client using hybrid transport, the RP ID is asserted by the client. Check whether iCloud Keychain / Google Password Manager accept an arbitrary RP ID from a CTAP client without a browser (verify); this decides whether Route A works on Linux at all.

---

## 5. Smaller gaps

- **Storage (open question 1):** recommend a **single encrypted file** for v1. Atomic replace is simple, the format is easy to specify and fuzz, and per-record SQLite leaks item count, sizes and edit patterns. Revisit for sync.
- **Atomic writes:** after `rename`, also `fsync` the directory. Take an advisory lock; only `vaultd` writes.
- **Backups:** define how backups work and that they inherit the slot set at backup time (ties to 1.2).
- **Recovery key:** encode with a checksum (e.g. Base32 groups + CRC) and test-unlock at enrollment, as the brief already requires for all slots.
- **Clipboard:** on Wayland, auto-clear is best-effort; set the password-manager hint MIME type so clipboard managers skip history (verify current KDE and GNOME conventions).
- **Format migrations:** specify how a v1 reader handles a v2 file (refuse) and how upgrades happen (explicit, with backup).
- **`Debug`/`Clone` on secret types:** enforce with a lint or wrapper types that do not implement them, not just review.

---

## 6. Roadmap

Eleven milestones including face unlock, two phone routes, a passkey provider, Secret Service and sync is several person-years. Suggested v1 cut:

**v1:** `vault-core` + `vaultd` + `vault-cli`, slots: password, FIDO2 (two keys), recovery, TPM. Browser autofill with the origin policy above. TOTP, generator, import.

**Later, in order:** Secure Enclave and Windows backends, GUI, PRF passkey slot, passkey storage, Secret Service, face unlock, PQ pairing/sharing, sync.

Face unlock moves from step 6 to the end: highest effort, lowest security gain, Linux-only.
