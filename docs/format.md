# Vault file format, version 1

Version: draft 1 (2026-10-17). Status: proposed; frozen when `vault-core` passes its test vectors.
Source of truth for `vault-core`. Implements the Vault Project Brief, Revision 2, sections 5 and 6.

## 1. Conventions

- Integers are little-endian unless stated otherwise.
- `||` is byte concatenation. String literals are ASCII with no terminator.
- Structured fields are encoded with `postcard` (serde, version 1.x). Postcard is deterministic for a given struct and has no maps. MACs and AAD are always computed over **the exact stored bytes**, never over a re-serialization, so canonicalization never matters.
- `HKDF(ikm, salt, info)` is HKDF-SHA256 with a 32-byte output unless stated otherwise.
- `AEAD` is XChaCha20-Poly1305 (`chacha20poly1305` crate). Nonces are 24 random bytes from `getrandom`, fresh for every encryption.
- All random values come from `getrandom`.

## 2. File layout

A vault is one file, replaced atomically on every write.

```
offset  size        field
0       8           magic = "SVAULT\x00\x01"
8       2           format_version = 1 (u16)
10      4           header_len (u32)
14      header_len  header_bytes   (postcard: Header)
..      32          header_mac
..      8           body_len (u64)
..      body_len    body_bytes     (postcard: SealedBody)
```

Readers reject: a wrong magic, `format_version` other than 1, `header_len` above 1 MiB, `body_len` that does not match the remaining file length, and any trailing bytes.

## 3. Header

```rust
struct Header {
    vault_id: [u8; 16],          // random, fixed for the vault's life
    aead: AeadId,                // 1 = XChaCha20-Poly1305; anything else rejected in v1
    slots: Vec<Keyslot>,         // 1..=32 slots
}

struct Keyslot {
    meta: KeyslotMeta,
    nonce: [u8; 24],
    commit: [u8; 32],
    wrapped_vault_key: [u8; 48], // 32-byte key + 16-byte tag
}

struct KeyslotMeta {
    id: [u8; 16],                // random
    kdf: Option<Argon2Params>,   // None only for Recovery
    salt: [u8; 32],              // HKDF salt for the KEK, random per slot
    factor: Factor,
}

struct Argon2Params {
    m_kib: u32,                  // memory in KiB
    t: u32,                      // iterations
    p: u32,                      // lanes
    salt: [u8; 32],              // Argon2 salt, random per slot
}                                // Argon2 version is always 0x13

enum Factor {
    PasswordOnly,
    PasswordFido2 {
        credential_id: Vec<u8>,  // max 1023 bytes
        rp_id: String,           // max 253 bytes
        prf_input: [u8; 32],     // random
        require_uv: bool,
    },
    PasswordTpm {
        blob: Vec<u8>,           // max 4 KiB: marshalled TPM2B_PUBLIC || TPM2B_PRIVATE
        pcr_policy: Option<PcrPolicy>,
        has_pin: bool,
    },
    Recovery,
    // Reserved for later versions; v1 readers reject a slot of these kinds
    // but still parse the file and may unlock with another slot.
    PasswordPasskeyPrf,          // variant index reserved
    PasswordDevice,              // variant index reserved
    PasswordPhone,               // variant index reserved
    RecipientHybrid,             // variant index reserved
}

struct PcrPolicy { bank: u8 /* 1 = SHA-256 */, pcrs: Vec<u8> /* e.g. [7] */ }
```

Reserved variants carry no data in v1. A later format version gives them fields and bumps `format_version`.

No human-readable labels live in the header. Slot labels ("work laptop", "blue YubiKey") are stored encrypted in the body (section 6).

### 3.1 Parse-time bounds

Checked before any KDF runs. Violations are a hard error for that slot.

| Field | Min | Max |
| --- | --- | --- |
| `m_kib` | 65 536 (64 MiB) | 4 194 304 (4 GiB) |
| `t` | 1 | 20 |
| `p` | 1 | 16 |
| slots | 1 | 32 |

Writers default to `m_kib = 262 144`, `t = 3`, `p = 4`, then calibrate upward to about 0.5 to 1 s on the enrolling machine.

## 4. Unlocking a keyslot

### 4.1 Password input

The password is normalized to Unicode NFC and encoded as UTF-8. No trimming, no case folding.

### 4.2 Hardware secret per factor

| Factor | `hw_key` (32 bytes) |
| --- | --- |
| `PasswordOnly` | 32 zero bytes |
| `PasswordFido2` | hmac-secret output for `salt1 = SHA-256("WebAuthn PRF" || 0x00 || prf_input)`, with UV performed if and only if `require_uv` |
| `PasswordTpm` | Random secret sealed in `blob`, unsealed with the PIN (if `has_pin`) and PCR policy (if set), over a salted, encrypted session |
| `Recovery` | Not used, see 4.3 |

The FIDO2 salt construction matches the WebAuthn PRF extension, so a later PRF passkey path yields the same secret for the same credential.

### 4.3 KEK

```
slot_aad = "vault/slot-aad/v1" || vault_id || u16(format_version) || postcard(meta)

daily-use slots:
  pw_key = Argon2id(password, meta.kdf.salt, meta.kdf.{m_kib,t,p}, out = 32)
  KEK    = HKDF(ikm  = pw_key || hw_key,
                salt = meta.salt,
                info = "vault/kek/v1" || meta.id)

Recovery:
  KEK    = HKDF(ikm  = recovery_secret,
                salt = meta.salt,
                info = "vault/kek-recovery/v1" || meta.id)
```

`postcard(meta)` is taken from the stored header bytes, so it covers the factor type, KDF parameters, `require_uv`, `rp_id`, the PCR policy and every other field that decides how the KEK is derived.

### 4.4 Key commitment and unwrap

For any key `K` used with the AEAD in this format:

```
K_enc    = HKDF(K, salt = none, info = "vault/enc/v1")
K_commit = HKDF(K, salt = none, info = "vault/commit/v1")
commit   = HMAC-SHA256(K_commit, nonce)
```

The AEAD always runs under `K_enc`, never under `K` directly. Decryption first recomputes `commit` and compares it in constant time; a mismatch means "wrong key for this record" and the AEAD is not run.

Unwrapping a slot:

```
check commit(KEK, slot.nonce) == slot.commit           else: wrong factor
vault_key = AEAD_open(K_enc(KEK), slot.nonce, slot.wrapped_vault_key, aad = slot_aad)
                                                        else: corrupt slot
```

### 4.5 Header MAC

```
K_header   = HKDF(vault_key, salt = vault_id, info = "vault/header-mac/v1")
header_mac = HMAC-SHA256(K_header, bytes[0 .. 14 + header_len])
```

The MAC covers the magic, version, length and the full header bytes. It is verified immediately after a slot unwraps. A mismatch is a hard error and the vault key is zeroized: someone with write access to the file has edited the slot list.

## 5. Body

```rust
struct SealedBody {
    nonce: [u8; 24],
    commit: [u8; 32],
    ciphertext: Vec<u8>,          // AEAD output of padded postcard(Body)
}

body_key = HKDF(vault_key, salt = vault_id, info = "vault/body/v1")
body_aad = "vault/body-aad/v1" || vault_id || u16(format_version) || header_mac
```

Binding `header_mac` into the body AAD ties the body to exactly this header, so a body cannot be moved onto a different header of the same vault.

The plaintext is `postcard(Body)` followed by zero padding to the next size bucket: the next multiple of 4 KiB up to 64 KiB, then the next multiple of 64 KiB. The true length is the first field of `Body`.

```rust
struct Body {
    plaintext_len: u64,
    generation: u64,              // +1 on every write; rollback detection (threat model A5)
    slot_labels: Vec<([u8; 16], String)>, // slot id -> label
    items: Vec<ItemRecord>,
}

struct ItemRecord {
    item_id: [u8; 16],
    version: u64,                 // +1 on every edit of this item
    key_nonce: [u8; 24],
    key_commit: [u8; 32],
    wrapped_item_key: [u8; 48],
    data_nonce: [u8; 24],
    data_commit: [u8; 32],
    data_ciphertext: Vec<u8>,     // postcard(ItemData)
}
```

The whole body is re-encrypted with a fresh nonce on every write. Per-item keys exist so that items can later be shared or synced individually without re-encrypting the vault.

```
item_key_aad  = "vault/item-key/v1"  || vault_id || item_id
item_data_aad = "vault/item-data/v1" || vault_id || item_id || u64(version) || u16(format_version)
```

`wrapped_item_key` is the AEAD of a random 32-byte item key under `vault_key`. `data_ciphertext` is the AEAD of `postcard(ItemData)` under the item key. Both use the commitment rule in 4.4.

`ItemData` (title, URLs, username, password, TOTP, notes, custom fields, timestamps) is specified in `docs/items.md` and is not part of this document's freeze.

## 6. Operations

### 6.1 Create

Generate `vault_id` and `vault_key`, enroll a password slot and a backup slot (second FIDO2 key or recovery), write the file, then test-unlock every slot before reporting success.

### 6.2 Add a slot

Requires an unlocked vault. Derive the new KEK, wrap the current `vault_key`, append the slot, recompute `header_mac`, re-encrypt the body (because `body_aad` includes `header_mac`), write, then test-unlock the new slot. No other slot changes.

### 6.3 Remove a slot (no compromise)

Delete the slot, recompute `header_mac`, re-encrypt the body, write. The vault key is unchanged. Must leave at least one daily-use slot and one backup.

### 6.4 Revoke a factor (suspected compromise)

1. Generate a new `vault_key`.
2. Re-wrap every item key under the new vault key.
3. Re-wrap every remaining slot whose factor is available on this machine.
4. Device-local slots enrolled on other machines cannot be re-wrapped; they are removed and listed to the user for re-enrollment.
5. Recompute `header_mac`, re-encrypt the body, write, test-unlock.

Old copies of the file stay readable with the old factors. The UI says so.

### 6.5 Atomic write

Write to `<file>.tmp` in the same directory, fsync the file, rename over the original, fsync the directory. Only `vaultd` writes, holding an advisory lock (`flock`) on `<file>.lock`.

### 6.6 Rollback check

`vaultd` stores `(vault_id, generation)` in its private state directory after every unlock and write. If an unlocked body's `generation` is lower than the stored value, `vaultd` refuses to write and warns the user.

## 7. Recovery code

The recovery secret is 32 random bytes. It is shown once, encoded as Crockford Base32 of `secret || SHA-256("vault/recovery-check/v1" || secret)[0..4]` (36 bytes, 58 characters), in groups of six separated by hyphens. Input is case-insensitive and ignores hyphens and spaces; the checksum catches typos before any KDF runs.

## 8. Domain-separation labels

Every HKDF `info` and AAD prefix used in v1. New labels must be added here.

```
vault/slot-aad/v1      vault/kek/v1           vault/kek-recovery/v1
vault/enc/v1           vault/commit/v1        vault/header-mac/v1
vault/body/v1          vault/body-aad/v1      vault/item-key/v1
vault/item-data/v1     vault/recovery-check/v1
```

## 9. Test vectors (to produce with `vault-core`)

- KEK derivation for each factor type with fixed inputs (FIDO2 and TPM using fixed `hw_key` values).
- Commit and AEAD for a fixed key, nonce and AAD.
- A complete minimal vault file (one password slot, one recovery slot, two items) as hex, with every intermediate key.
- Negative vectors: tampered header, swapped item, wrong UV mode, out-of-bound KDF parameters, rolled-back generation, wrong recovery checksum.

## 10. Open items

- Confirm `postcard` 1.x encoding stability guarantees across minor versions (verify), or pin the exact version in `Cargo.lock` and keep a golden-file test.
- TPM blob structure and SRK template (verify against `tss-esapi` and `systemd-cryptenroll`'s choices).
