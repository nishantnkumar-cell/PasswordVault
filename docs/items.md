# Item payload, schema 2

Each vault item's data (format.md section 5, `ItemData`) is `0x02 || postcard(ItemData)`. The leading byte is the item schema version, independent of the file format version. Readers reject an unknown schema byte and non-canonical encodings. Schema 1 (`0x01`, the same struct without `key`) is still read; items are rewritten as schema 2 when next saved.

```rust
struct ItemData {
    title: String,
    username: String,
    password: String,
    urls: Vec<UrlEntry>,
    totp: Option<TotpConfig>,
    notes: String,
    created: u64,   // seconds since the Unix epoch
    modified: u64,
    key: Option<KeyData>,  // schema 2; never sent to clients
}

enum KeyData {
    Ssh { openssh: String, confirm: bool },   // OpenSSH private key, no passphrase
    OpenPgp { tsk: Vec<u8>, confirm: bool },  // transferable secret key, no passphrase
}

struct UrlEntry {
    url: String,          // matched by origin; path and query ignored
    mode: MatchMode,      // Origin (default) | RegistrableDomain
    allow_http: bool,     // per-entry override, default false
}

struct TotpConfig {
    secret: Vec<u8>,      // raw bytes, decoded from Base32
    digits: u8,           // 6..=8
    period: u32,          // seconds, usually 30
    algorithm: TotpAlgorithm, // Sha1 (default) | Sha256 | Sha512
}
```

## Origin policy

Implemented in `vault_core::origin::may_fill` (brief section 12):

- `Origin` mode: scheme, host and port must be equal after normalization (lowercase, UTS-46 punycode, default ports).
- `RegistrableDomain` mode: both sides `https` and the same eTLD+1 under the public suffix list compiled into the release (`psl` crate). IP addresses and bare suffixes fall back to exact matching.
- `http` pages are filled only when the stored entry is itself `http` and has `allow_http` set.
- Hosts containing punycode labels are flagged so the UI can warn about homographs.

Frame and user-gesture rules are enforced by the browser extension, which is also the only source of the page origin.
