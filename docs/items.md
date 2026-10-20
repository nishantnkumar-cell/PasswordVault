# Item payload, schema 2

Each vault item's data (format.md section 5, `ItemData`) is `0x02 || postcard(ItemData)`. The leading byte is the item schema version, independent of the file format version. Readers reject an unknown schema byte and non-canonical encodings.

Schema 1 (`0x01`, logins only, below) is still read: such an item comes back as a `Login` and is written as schema 2 the next time it is saved. Nothing rewrites the vault just to upgrade.

```rust
struct ItemData {
    kind: ItemKind,             // Login | Note | Card | Identity
    title: String,
    username: String,           // Login
    password: String,           // Login
    urls: Vec<UrlEntry>,        // Login
    totp: Option<TotpConfig>,   // Login
    card: Option<Card>,         // Card
    identity: Option<Identity>, // Identity
    fields: Vec<CustomField>,   // any kind
    notes: String,
    created: u64,               // seconds since the Unix epoch
    modified: u64,
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

struct Card {
    holder: String,
    number: String,       // digits only
    exp_month: u8,        // 1..=12, 0 = not set
    exp_year: u16,        // four digits, 0 = not set
    cvv: String,
    pin: String,
}

struct Identity {
    honorific, given_name, middle_name, family_name, company, email, phone,
    address1, address2, address3, city, region, postcode, country: String,
}

struct CustomField {
    name: String,
    value: String,
    kind: FieldKind,      // Text | Hidden | Url
}
```

`vaultd` normalizes every item it saves (`ItemData::normalize`): a card always has `card` and an identity always has `identity`; the parts another kind uses are cleared, so no secret is stored where no screen shows it; card numbers keep only their digits; empty custom fields are dropped.

Listings (`ItemSummary`) carry the kind and a subtitle that never holds a secret: the username, the card network and last four digits ("Visa •••• 1111"), or the identity's name.

Card numbers get a Luhn check and a network guess from the issuer prefix. Both only help catch typos; a number that fails is still saved.

## Origin policy

Implemented in `vault_core::origin::may_fill` (brief section 12):

- `Origin` mode: scheme, host and port must be equal after normalization (lowercase, UTS-46 punycode, default ports).
- `RegistrableDomain` mode: both sides `https` and the same eTLD+1 under the public suffix list compiled into the release (`psl` crate). IP addresses and bare suffixes fall back to exact matching.
- `http` pages are filled only when the stored entry is itself `http` and has `allow_http` set.
- Hosts containing punycode labels are flagged so the UI can warn about homographs.

Only logins are bound to sites, and only logins are released by the origin lookups (`FindForOrigin`, `GetForFill`, `TotpForFill`). Cards and identities are filled into any `https` page, top frame only (docs/browser.md); a card is released only after the user confirms in vaultd's own window.

Frame and user-gesture rules are enforced by the browser extension, which is also the only source of the page origin.
