# Vault Project Brief

A handoff document for Claude sessions working on a secure, Rust-based password and passkey manager (an Apple Passwords-style utility, Linux first, then Windows and macOS). Add this to your Claude Project's knowledge, and paste the short "Project instructions" section into the project's custom instructions.

Status: design phase, no code yet. Items marked **(verify)** come from memory and must be checked against current docs before they are relied on.

Revision 2 (2026-10-17): applied the architecture review (`reviews/architecture-review.md`). Changes: header MAC instead of header hash in keyslot AAD, three-level key hierarchy with vault-key rotation on factor revocation, key commitment, single AEAD for v1, UV mode pinned per FIDO2 slot, bounded KDF parameters, client pairing for IPC, an explicit autofill origin policy, single-file storage, and a reduced v1 scope.

## 1. Project instructions (paste into the Project's custom instructions)

You are helping design and build a security-critical password manager in Rust. Rules:

1. Treat the Vault Project Brief as the source of truth. If a request conflicts with it, say so and propose an update to the brief rather than silently diverging.
2. Security over convenience. Never propose rolling our own cryptographic primitives. Use audited crates only.
3. Biometrics (face, fingerprint) are authorization gates, never key material, and never the sole factor.
4. Keep `vault-core` pure: no I/O, no hardware access, `#![forbid(unsafe_code)]`, minimal dependencies.
5. Flag anything you are unsure about as **(verify)** instead of guessing, especially crate APIs, versions, OS API behavior, and standards status.
6. Prefer small, reviewable steps with tests (test vectors, property tests, fuzz targets) alongside code.
7. At the end of each working session, produce a handoff note using the template in section 14.

## 2. Goals and non-goals

**Goals**

- Local-first vault that is as secure as practical, written in Rust.
- Cross-platform: Linux first, then Windows and macOS.
- Multiple unlock factors: password, TPM / Secure Enclave / Windows device keys, FIDO2 security key, phone passkey (PRF), recovery key.
- Browser autofill with strict origin binding, TOTP, passkey storage, and Secure Service integration on Linux.
- Post-quantum readiness for anything involving public-key cryptography.

**Non-goals (for now)**

- Defending against a fully compromised, already-unlocked session.
- Building our own hypervisor-isolated biometric stack (Windows ESS equivalent). Documented as a possible later hardening tier.
- Cloud sync and multi-user sharing in v1 (designed for, not built).

## 3. Threat model summary

| Threat | Mitigation |
| --- | --- |
| Stolen laptop or disk image (offline attack) | Argon2id, hardware-bound factors, encrypted metadata |
| Malware as the same user | Daemon under a separate OS identity protects key memory; paired clients plus user-presence confirmation control access to secrets. On X11, same-user malware can keylog and is out of scope; on Wayland it is partially mitigated |
| Memory scraping, swap, core dumps | `mlock`, `zeroize`, no core dumps, non-dumpable process |
| Phishing | Exact-origin autofill, passkeys |
| Sync server compromise | End-to-end encryption, server sees ciphertext only |
| Clipboard sniffing | Auto-clear, prefer autofill over clipboard |
| Harvest now, decrypt later | 256-bit symmetric keys, hybrid post-quantum KEM for public-key flows |
| Compromised factor (lost key plus phished password) | Revoking the slot rotates the vault key; old file copies stay readable with old factors (inherent, documented) |
| Tampered header (slot injection, DoS parameters) | Header MAC verified after unlock; KDF parameters bounded before use |

A written, versioned threat model (`docs/threat-model.md`) must exist before substantial code.

## 4. Workspace layout (Cargo workspace)

- `vault-core`: file format, key hierarchy, keyslots, crypto. No I/O. This is the audit target.
- `vaultd`: daemon holding keys; IPC; hardware factor implementations; hardening.
- `vault-cli`, `vault-gui`: thin clients that never see the master key.
- `vault-native-host`: browser native messaging bridge.
- `vault-face-helper` (Linux, optional): sandboxed face-match helper.
- `vault-sync` (later): E2EE sync.

UI preference: Rust-native toolkit (iced or slint) over a webview, to limit attack surface.

## 5. Cryptographic design

**Primitives (use audited crates)**

- KDF: Argon2id (`argon2`), roughly 0.5 to 1 second on target hardware, at least 64 MiB memory; parameters stored per keyslot.
- AEAD: XChaCha20-Poly1305 (`chacha20poly1305`) only in v1, with 24-byte random nonces. The algorithm ID stays in the header for agility, but a second AEAD is not shipped until needed.
- Key commitment: every keyslot and item record carries `commit = HMAC-SHA256(HKDF(key, info="vault/commit/v1"), nonce)`, checked before decryption. Neither candidate AEAD is key-committing on its own, and this also separates "wrong factor" from "corrupted file".
- Key derivation: HKDF-SHA256 (`hkdf`, `sha2`).
- Secrets handling: `zeroize`, `secrecy`.
- Randomness: OS CSPRNG via `getrandom`.

**Key hierarchy**

Three levels: `KEK (per slot) -> vault key -> item keys -> item data`.

- One random 256-bit **vault key**, wrapped independently by each **keyslot** (LUKS2-style), so adding or changing factors never re-encrypts item data.
- Per-item keys are **random** 256-bit keys wrapped by the vault key (not derived, so they can be re-parented for sharing and rotation).
- **Revoking a factor rotates the vault key:** generate a new vault key, re-wrap all item keys (small and fast), re-wrap every remaining slot this machine can unlock, and mark device-local slots from other machines as needing re-enrollment. Old copies of the file remain readable with the old factors; this is inherent and stated in the threat model.
- All metadata (titles, URLs, usernames) is encrypted, not just passwords. Slot labels are encrypted too; the plaintext header holds only what is needed to attempt an unlock.
- Item AAD binds vault ID, item ID, item version and format version to prevent swapping and rollback.
- **Keyslot AAD covers only immutable data:** `vault_id || format_version || slot.id || slot.factor_type || canonical(slot.kdf) || canonical(slot.factor params)`. It does not include a hash of the whole header, because that would force every slot to be re-wrapped whenever any slot is added, which is impossible for device-local slots enrolled on other machines.
- **Header MAC:** after unlock, the whole header (slot list included) is verified with `HMAC-SHA256(K_header, canonical_header)`, where `K_header = HKDF(vault_key, info="vault/header-mac/v1")`. Any unlocked client can recompute it after editing slots. A mismatch is a hard error.

**KEK derivation per slot**

```
pw_key = Argon2id(password, slot.salt, slot.params)
hw_key = device unwrap | FIDO2 hmac-secret | PRF output | recovery secret
KEK    = HKDF-SHA256(ikm = pw_key || hw_key,
                     salt = slot.salt,
                     info = "vault/kek/v1" || slot.id)
check_commit(KEK, slot.nonce, slot.commit)
vault_key = AEAD_decrypt(KEK, slot.wrapped_key, aad = slot_aad(slot))
verify_header_mac(vault_key, header)
```

For `PasswordOnly` slots `hw_key` is 32 zero bytes, so the IKM length is always 64 bytes. The factor type is part of `slot_aad`, so slots cannot be confused.

The password is always part of the KEK for daily-use slots, so a stolen hardware factor alone is not enough. The recovery slot is the exception: it is a 256-bit random secret shown once at setup.

**File format**

- Versioned header with magic bytes, format version, algorithm IDs, and a list of keyslots.
- Serialization: `serde` with `postcard` or `ciborium`; keep the format specified in `docs/format.md` before implementing.
- Storage: **a single encrypted file** for v1 (decided 2026-10-17). Atomic replace is simple, the format is easy to specify and fuzz, and per-record SQLite would leak item count, sizes and edit patterns. Revisit when sync is designed.
- A v1 reader refuses files with a newer `format_version`. Upgrades are explicit and take a backup first.

## 6. Keyslot types and sketch

```rust
#[derive(Serialize, Deserialize)]
struct Header {
    magic: [u8; 8],
    format_version: u16,
    vault_id: [u8; 16],
    aead: AeadId,
    slots: Vec<Keyslot>,
    header_mac: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Keyslot {
    id: [u8; 16],
    kdf: Argon2Params,
    factor: Factor,
    nonce: [u8; 24],
    commit: [u8; 32],
    wrapped_vault_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum Factor {
    PasswordOnly,
    PasswordFido2 { credential_id: Vec<u8>, rp_id: String, prf_salt: [u8; 32], require_uv: bool },
    PasswordPasskeyPrf { credential_id: Vec<u8>, rp_id: String, prf_salt: [u8; 32] },
    PasswordDevice { platform: Platform, blob: Vec<u8>, label: String },
    PasswordPhone { device_pub: Vec<u8>, wrapped_secret: Vec<u8> },
    RecipientHybrid { kem: KemId, recipient_pk: Vec<u8>, encapsulated: Vec<u8>, wrapped_key: Vec<u8> },
    Recovery,
}
```

Hardware access goes through traits implemented outside `vault-core`:

```rust
trait HardwareFactor {
    fn derive(&self, slot: &Keyslot) -> Result<Zeroizing<[u8; 32]>, FactorError>;
}

trait DeviceKeystore {
    fn wrap(&self, secret: &[u8; 32]) -> Result<Vec<u8>>;
    fn unwrap(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}
```

**Slot classes**

- Portable (work on any machine): password, FIDO2 key, passkey PRF, recovery key.
- Device-local (work only on the enrolling machine): TPM, Secure Enclave, Windows device key. Each device enrolls its own slot into the same vault; clients skip slots they cannot use.

**Rules**

- Always require at least one backup factor (second FIDO2 key or recovery key) during enrollment.
- Bound KDF parameters on parse, before running Argon2id: memory 64 MiB to 4 GiB, iterations 1 to 20, parallelism 1 to 16. Default to 256 MiB or more on desktop if the 0.5 to 1 s target allows. A tampered header must not be able to hang or OOM `vaultd`.
- `RecipientHybrid` is in the enum for format stability but rejected by v1 readers.
- After enrolling any slot, immediately test-unlock from it before reporting success.
- Header writes are atomic (write temp, fsync file, rename, fsync directory). Only `vaultd` writes, under an advisory lock.
- Backups inherit the slot set at backup time; restoring an old backup brings back any factors revoked since.

## 7. Factors in detail

### Password

Argon2id, long passphrases encouraged. Strength meter using `zxcvbn`-style estimation.

### TPM 2.0 (Linux)

- Crate: `tss-esapi` (needs `tpm2-tss` installed). Use `/dev/tpmrm0` (kernel resource manager).
- Create a non-exportable sealed secret with an authValue (PIN) and optionally a PCR 7 policy. The TPM's dictionary-attack lockout provides hardware rate limiting.
- Combine with the password; never use the TPM as the sole factor.
- Use salted, encrypted HMAC sessions (parameter encryption) for every unseal, so a discrete TPM's bus cannot be sniffed on a stolen laptop **(verify `tss-esapi` API)**.
- Expect PCR-bound secrets to break after firmware or bootloader changes; the recovery slot and a second slot cover this.

### FIDO2 security key (hmac-secret)

- The `hmac-secret` extension returns a deterministic 32-byte secret from a per-credential secret on the key plus a salt we supply.
- Create non-discoverable credentials, require user verification (PIN) and touch, and use credProtect where supported.
- The credential ID and salt live in the slot; `rp_id` is fixed forever (changing it changes the derived secret).
- **UV mode is part of the slot's identity.** Authenticators keep separate `CredRandomWithUV` and `CredRandomWithoutUV` secrets, so the same salt yields different outputs with and without PIN. `require_uv` is bound into the slot AAD and an unlock with a mismatched UV mode is refused. Add a known-answer test against a real key.
- Crates to evaluate: `ctap-hid-fido2` (pure Rust, easiest to prototype) and `libfido2` bindings (`libfido2-sys` / `fido2-rs`, mature C library). Decide after reviewing maintenance and hmac-secret support **(verify)**.
- Check key capability with `fido2-token -L` and `fido2-token -I <device>`.
- Windows note: non-admin processes cannot open FIDO HID directly; use the Windows WebAuthn API **(verify libfido2 support for hmac-secret there)**.

### Phone passkey (two routes)

- **Route A, PRF passkey:** phone acts as authenticator via the hybrid (QR plus Bluetooth proximity) flow. The WebAuthn PRF extension maps onto hmac-secret. Always compute the salt the WebAuthn way, `SHA-256("WebAuthn PRF" || 0x00 || input)`, from day one so every access path yields the same secret. Synced passkeys move part of the trust root into iCloud or Google account recovery, so the password stays in the KEK. PRF support varies by provider **(verify)**. Requires a domain we own for the RP ID. On Linux, the hybrid transport would need an implementation such as `libwebauthn` **(verify maturity)**.
- **Route B, companion app:** our own iOS and Android app holding a hardware-backed key (Secure Enclave or StrongBox), sharing `vault-core` via UniFFI. Pairing by QR code plus a Noise handshake (`snow`) over an E2EE relay or LAN, with BLE proximity and number matching against approval-fatigue attacks. More work, full control over key custody.
- Recommendation: start with Route A, build Route B only if PRF support or custody concerns require it.
- Open check for Route A: with hybrid transport from a non-browser client, the RP ID is asserted by the client. Confirm whether iCloud Keychain and Google Password Manager accept that without a browser **(verify)**; this decides whether Route A works on Linux at all.

### Face unlock (Linux, Windows Hello-class camera)

- Face is a **warm re-unlock gate only**, never key material and never for a cold vault.
- Tiered unlock: cold unlock (boot, long idle, after N face unlocks) needs password plus hardware factor; warm re-unlock (screen lock, short timeout) may use a face match; sensitive actions (export, add device, change settings, create passkey) require password or FIDO2 touch plus PIN again.
- Status: deferred to after v1 (highest effort, lowest security gain, Linux only). Without SDCP, anything that can open or emulate the V4L2 device can inject frames, so this is an authorization gate only.
- Mechanism: after a password unlock, `vaultd` holds the vault key in `mlock`ed memory. On lock it wraps the key under an ephemeral in-memory session key and zeroizes the plaintext. A face verdict authorizes unwrapping. Reboot or session expiry destroys the session key. Limit failed attempts (3 to 5), then fall back to password.
- Implementation: `vault-face-helper`, sandboxed with landlock and seccomp, IR camera only (reject RGB), `v4l` for capture, `ort` or `tract` for inference, SCRFD or RetinaFace for detection, ArcFace or MobileFaceNet for embeddings, cosine similarity with a strict threshold, liveness checks as mitigation only. Templates stored inside the encrypted vault. The helper returns a signed, nonce-bound verdict over a socketpair so the backend can later be swapped for a micro-VM without changing `vaultd`.
- Howdy is acceptable for confirming the camera works, not as the foundation.
- Camera checks: `v4l2-ctl --list-devices`, `v4l2-ctl -d <node> --list-formats-ext`; the IR emitter may need `linux-enable-ir-emitter`.

### Windows Hello and Touch ID

On Windows and macOS the OS enforces biometrics in hardware on key access controls, so they can be real cryptographic gates via `DeviceKeystore`. On macOS, Touch ID needs the user session, so a user-session helper performs the Secure Enclave unwrap and hands the secret to the daemon.

## 8. Why not full Enhanced Sign-in Security

Windows ESS rests on three things: a VBS trustlet isolating the matcher, SDCP (a camera with a device key that signs and encrypts frames), and TPM-bound credentials. SDCP needs camera firmware support and cannot be replicated in software. Linux can approximate the isolation with a KVM micro-VM and VFIO camera passthrough (Rust VMMs: `cloud-hypervisor`, `crosvm`), and confidential VMs (SEV-SNP, TDX) go further but are rarely available on consumer laptops. Treat this as an optional later hardening tier. Check whether the camera supports SDCP before investing. The Microsoft SDCP specification is public and should be read directly.

## 9. Process and memory hardening

- `zeroize` and `secrecy` on all secret types; watch for hidden copies (`Vec` reallocation, `Clone`, `Debug`).
- `mlock` key pages, `RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE, 0)` on Linux.
- Dedicated system user for `vaultd`; this is the main defense against same-user malware.
- Linux sandboxing: `landlock`, `seccompiler`, systemd unit hardening (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `MemoryDenyWriteExecute`, empty `CapabilityBoundingSet`).
- IPC: Unix socket with `SO_PEERCRED` checks or D-Bus via `zbus`; never TCP on localhost.
- **Client authorization.** The UID check alone cannot tell `vault-cli` from malware running as the same user. Clients pair with `vaultd` once (key exchange, approved in a prompt drawn by `vaultd`'s own UI, as KeePassXC-Browser does). Peers are identified by pidfd (`SO_PEERPIDFD`) rather than racy `/proc/<pid>/exe` **(verify kernel support)**. Releasing a secret to a client outside a small allowlist needs fresh user presence and is rate-limited.
- The warm re-unlock session key lives in `vaultd` memory next to the wrapped vault key, so it is a policy gate, not a cryptographic one. Stronger option later: seal it to the TPM with a short-lived policy, or hold it in the `vaultd` user's kernel keyring.
- Auto-lock on timeout, suspend and screen lock (logind signals), zeroizing keys on lock.
- `#![forbid(unsafe_code)]` in `vault-core`; confine other `unsafe` to small, documented modules.

## 10. Platform mapping

| Concern | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Device-bound key | TPM2 (`tss-esapi`) | TPM-backed CNG key (`windows` crate) | Secure Enclave (`security-framework`) |
| Biometric | gate only (fprintd, face helper) | Windows Hello | Touch ID (LocalAuthentication) |
| IPC | Unix socket, `SO_PEERCRED` | named pipe with strict ACLs | Unix socket or XPC with peer credentials |
| Daemon isolation | dedicated UID, systemd | service under a virtual account | launchd daemon, dedicated user |
| Memory hygiene | `mlock`, non-dumpable | `VirtualLock`, exclude from WER dumps | `mlock`, hardened runtime |
| Sandbox | landlock, seccomp | job objects, AppContainer | App Sandbox |

Key gotcha: the Secure Enclave holds only P-256 keys and ECDSA signatures are non-deterministic, so a stable secret cannot be derived from a signature. Use the uniform pattern: generate a random device secret and wrap it under a hardware key (ECIES on the Secure Enclave, RSA-OAEP or similar on a Windows TPM key, TPM seal on Linux). Packaging: Authenticode signing on Windows, notarization on macOS, signed update channel everywhere. Native messaging works on all three but manifest locations differ.

## 11. Post-quantum plan

- Symmetric parts (256-bit AEAD keys, Argon2id, HKDF, SHA-256) remain acceptable under Grover. A local-only vault is essentially post-quantum already, so no PQ work is in v1.
- Vulnerable parts are anything using public-key cryptography: sync transport, sharing, device enrollment, phone pairing, OPAQUE, release signing.
- NIST standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205). Falcon-based FN-DSA and the HQC KEM were still in progress when I last had information **(verify)**.
- Always **hybrid**: X25519 plus ML-KEM-768, preferably through X-Wing (IETF draft KEM combiner) rather than a hand-rolled combiner. Signatures: Ed25519 plus ML-DSA-65, requiring both.
- Crates to evaluate: `libcrux-ml-kem` and `libcrux-ml-dsa` (formally verified, first pick), RustCrypto `ml-kem` / `ml-dsa` / `slh-dsa`, `aws-lc-rs`, `x-wing` (check it matches the current draft), `oqs` for experiments only. Verify audit and constant-time status. Add NIST ACVP test vectors.
- TLS: X25519MLKEM768 hybrid group via `rustls` with `aws-lc-rs` **(verify)**.
- OPAQUE (`opaque-ke`) has no standardized PQ equivalent; sync authentication is open design work.
- FIDO2 keys, TPMs and the Secure Enclave mostly use classical ECC internally; because we derive secrets symmetrically and mix in the password, this mostly does not weaken the vault key. Check vendor PQC status **(verify)**.

## 12. Feature set (Apple Passwords-like)

- Autofill via browser extension plus native messaging, with this origin policy:
  - Default: match the full origin (scheme, host, port). `https` only; `http` fill needs an explicit per-item override.
  - Opt-in per item: registrable-domain (eTLD+1) matching with the `psl` crate. The public suffix list ships inside signed releases and is never fetched at runtime.
  - Hosts are normalized to punycode (IDNA/UTS-46) before comparison; Unicode is displayed with homograph warnings.
  - The origin comes from the browser (`sender.origin` / `sender.tab.url` in the extension background), never from page content or the content script.
  - Fill only in the top frame or same-origin frames; cross-origin iframes need an explicit prompt.
  - Fill requires a user gesture; never fill hidden or zero-size fields.
  - The native host pairs with `vaultd` like any other client (section 9). The manifest's `allowed_origins` limits which extension launches the host, not which process talks to `vaultd`.
- Clipboard: on Wayland auto-clear is best effort; set the password-manager hint MIME type so clipboard managers skip history **(verify current KDE and GNOME conventions)**.
- Linux Secret Service (`org.freedesktop.secrets`) implementation with per-application approval prompts; widens attack surface, so ship after the core is solid. D-Bus sender identity is no stronger than the IPC client check, so per-application approval there is advisory.
- Passkeys (WebAuthn/FIDO2): evaluate `passkey-rs`; keep the vault-unlock credential separate from anything websites can request. Linux has no OS passkey-provider API, so the extension wraps `navigator.credentials` in the page; RP ID validation against the tab origin runs in the extension background, never the content script. Windows and macOS have provider APIs **(verify current versions)**.
- TOTP (`totp-rs`), password generator (OS CSPRNG), breach checks via k-anonymity (HIBP range API), import and export (KDBX, Bitwarden JSON, browser CSV).
- Sync later: E2EE, server stores ciphertext only, per-item versioning and conflict resolution.

## 13. Roadmap and quality gates

**Roadmap**

v1 scope (decided 2026-10-17): `vault-core`, `vaultd`, `vault-cli`; slots for password, FIDO2 (two keys), recovery and TPM; browser autofill with the origin policy in section 12; TOTP, generator and import. Everything else waits until v1 is solid.

v1:

1. Write `docs/threat-model.md` and `docs/format.md`.
2. `vault-core`: header and header MAC, Argon2id plus HKDF plus AEAD with key commitment, keyslots, vault-key rotation, test vectors, fuzzing.
3. `vaultd` and `vault-cli`: socket IPC, client pairing, hardening, password-only slot end to end.
4. FIDO2 factor: enroll, unlock, backup key, recovery key.
5. TPM factor (Linux).
6. Browser extension with origin-bound autofill.
7. TOTP, generator, import.

After v1, in order:

8. Secure Enclave and Windows device-key backends.
9. GUI.
10. PRF passkey slot.
11. Passkey storage.
12. Secret Service.
13. Warm-session face unlock (Linux).
14. Hybrid PQ for pairing and sharing; hybrid release signatures.
15. Sync (last).

**Quality gates**

- `cargo-fuzz` on the file parser and IPC handlers; `proptest` for crypto round trips.
- CI: `cargo audit`, `cargo deny`, `clippy -D warnings`, pinned dependencies, reproducible builds, signed releases.
- Independent security audit before any claim of being "secure".
- Prior art to study: KeePassXC, Bitwarden Rust SDK, `rbw`, `gopass`, `age`, LUKS2 keyslots, `systemd-cryptenroll`, `systemd-creds`.

## 14. Working with Claude sessions

**Suggested session starters**

- "Read the Vault Project Brief. Write `vault-core` keyslot types and Argon2id/HKDF/AEAD wrapping with tests and test vectors. Do not add I/O."
- "Review `docs/threat-model.md` against the brief and list gaps."
- "Write the `vaultd` socket server with `SO_PEERCRED` checks and a systemd unit with the hardening options in section 9."
- "Implement the FIDO2 hmac-secret factor behind the `HardwareFactor` trait using `ctap-hid-fido2`; compare with libfido2."
- "Design the verdict protocol (nonce, signature, framing) between `vaultd` and `vault-face-helper`."

**Handoff note template (end of every session)**

```
## Session handoff, <date>
- Done: <what changed, files touched>
- Decisions made: <and why>
- Open questions / (verify) items: <list>
- Next step: <one concrete task>
- Brief updates needed: <sections to amend>
```

Keep the latest handoff notes in a separate project file so each new session can read the brief plus the most recent handoff.

## 15. Open questions

1. ~~Storage: single encrypted file versus SQLite with per-record encryption.~~ Decided: single encrypted file for v1.
2. Single-user with device-to-device transfer, or multi-user sharing and cloud sync? This decides when the hybrid KEM work is needed.
3. Which security key (model, hmac-secret support, PIN retry count, fingerprint UV)?
4. Phone platform (iPhone or Android) and which desktop OS comes second; this decides Route A versus Route B.
5. Camera model and whether it supports SDCP.
6. Domain ownership for the fixed FIDO2 and passkey RP ID.
7. Licensing and distribution model.
