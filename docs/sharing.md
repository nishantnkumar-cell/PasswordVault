# Shared collections (family sharing)

Share some items with a few people, such as a family of two to four, while
everything else stays private. Each person keeps their own vault, master
password and unlock methods. A **shared collection** is a small vault of its
own, kept on the owner's cloud sync server, that only its members can open.
An item is either in your own vault or in one shared collection, never both.

The step-by-step guide is [user guide, chapter 17](user-guide/17-family-sharing.md).
This page is how it works. The file format is in [format.md](format.md)
sections 3.2 and 5.3, and the threats in [threat-model.md](threat-model.md), A8.

## The rules

- **The person who makes a collection is its owner.** Only the owner can add
  or remove people, rename it or delete it. Members can read, add, change and
  delete items in it.
- **Everyone in it sees everything in it.** There are no per-item rights.
- **Removing someone changes the collection's key.** They keep what they
  already had on their devices, and get nothing new.
- **People check each other once, by voice.** Each person has a six-group
  safety code. The owner reads theirs to the new member and the member reads
  theirs back, in person or on a call, before anything goes in.
- A collection holds up to 16 people. A person can be in several collections.

## Parts

| Part | Where | What it does |
| --- | --- | --- |
| X-Wing KEM | `crates/vault-core/src/xwing.rs` | ML-KEM-768 + X25519 hybrid (draft-connolly-cfrg-xwing-kem), checked against the draft's test vector |
| Sharing identity | `crates/vault-core/src/identity.rs` | One 32-byte seed per person, kept in their own vault; gives an X-Wing key and ML-DSA-65 + Ed25519 signing keys |
| Collections | `crates/vault-core/src/collection.rs` | Member slots, the owner-signed member list, add, remove (with key rotation), rename |
| `vaultd` | `crates/vaultd/src/shared.rs`, `daemon.rs` | Opens each collection when the person's vault unlocks, routes item reads and writes to the right file, syncs them every 5 s |
| `vault-cloud` | `crates/vault-cloud/src/share.rs` | Create, add, invite, join, remove and leave, shared by `vault share` and the desktop app |
| `vault-sync` | `crates/vault-cloud/src/bin/vault-sync.rs` | Mirrors every collection's mailbox, next to the person's own |
| `vault share` | `crates/vault-cli/src/share.rs` | The command line |
| Desktop app | `crates/vault-gui/src/app/sharing.rs` | The Sharing page, and Move to on an open item |

## Keys

**Sharing identity.** The first time someone shares, `vaultd` makes a random
32-byte seed and keeps it, with the name they chose, in their own vault (the
encrypted setting `sharing-identity`). Every device of theirs has it after
the next sync. From the seed:

```
kem_seed    = HKDF(seed, info = "vault/identity/v1/" || "kem")       → X-Wing secret key
mldsa_xi    = HKDF(seed, info = "vault/identity/v1/" || "mldsa")     → ML-DSA-65 key pair
ed25519_sk  = HKDF(seed, info = "vault/identity/v1/" || "ed25519")   → Ed25519 key pair
```

The public identity is the three public keys (1216 + 1952 + 32 bytes). Its
**fingerprint** is `SHA-256("vault/identity-fp/v1" || postcard(public identity))`,
and the **safety code** is the first 24 bytes of it as six groups of four
digits (each group a little-endian u32 mod 10 000).

**Sharing card.** `svcard1.` followed by base64url (no padding) of
`postcard({ name, public identity })`. It holds only public keys, so it can go
by email or chat; the safety code is what proves it was not swapped on the way.

**Signatures** are hybrid: `ML-DSA-65 (3309 bytes) || Ed25519 (64 bytes)`,
both over `"vault/signed/v1" || u16 LE context length || context || message`
(ML-DSA also with the context as its own context string). A signature counts
only if both halves verify.

**Collection key.** A collection is an ordinary vault file with its own
random 256-bit vault key. Each member has one keyslot of the kind
`RecipientHybrid` that wraps it:

```
(ct, ss) = X-Wing.Encapsulate(member's X-Wing public key)
KEK      = HKDF(ikm = ss, salt = slot salt,
                info = "vault/kek-recipient/v1" || slot id || member fingerprint)
```

and the slot stores `ct` (1120 bytes) and the member's fingerprint; the
wrapped key, nonce and key commitment are as for every other slot. There is no
password and no Argon2 in these slots.

## The member list

The setting `collection` holds the list, signed by the owner:

```
{ vault_id, key fingerprint, epoch, name, owner fingerprint,
  members: [(fingerprint, display name)] (owner first),
  slots:   [(slot id, member fingerprint)] (exactly the header's) }
```

Each member's public identity is in the setting `member/<first 16 bytes of
the fingerprint, hex>`. A reader accepts the collection only if:

1. the owner's public identity is stored and its fingerprint is the list's owner;
2. the signature verifies with it;
3. `vault_id` and the key fingerprint match this file and its current key, so a
   list cannot be moved to another collection or to an older key;
4. the header's slots are exactly the list's slots, each for a listed member
   whose public identity is stored;
5. the owner is the one this person **pinned** when they joined.

The last check is what stops a member from making their own keys the
"owner": a list a member signs is consistent on its own, but names the wrong
owner. A slot added by anyone but the owner fails check 4, so the file is
refused rather than trusted.

## Steps

**Create** (owner; needs cloud sync on this computer). `vault-cloud` makes a
new mailbox on the owner's own sync server with the admin key, and registers
the owner's access to it under the name `member-<first 8 bytes of the
fingerprint, hex>`. `vaultd` makes the collection with the owner as its only
member, keeps it at `<vault folder>/shared/<id>/vault.svault`, and adds it to
the owner's list of collections (the setting `shared-collections`, with the
mailbox access). The owner's other devices pick it up from there.

**Add** (owner). The owner pastes the new member's card. `vaultd` checks it,
adds a slot for them, stores their public identity, signs the new list, and
saves. Then the owner gets a one-time **invite link** (`/join#s1.…`, valid 10
minutes) to the collection's mailbox, and both read each other their safety
codes before the owner sends it.

**Join** (member). With the link, `vault-cloud` registers one access for this
person (named after their fingerprint), downloads the collection, and hands
it to `vaultd`, which opens it with the person's identity, checks the list,
and pins its owner. The member's other devices get the access and the pinned
owner through their own vault's sync, so they need no link.

**Move an item.** `MoveItem` reads it from where it is, writes it in the
other vault (with that vault's item key), and deletes it from the first.

**Remove** (owner). `vaultd` takes the member's slot and identity out, makes a
new collection key, wraps it for everyone left, re-encrypts every item,
retires the old key (so a copy under it is refused, as after a revoke), bumps
the epoch and signs the new list. `vault-cloud` then deletes every access on
the mailbox that is not a current member's.

**Leave.** A member gives up their own access; the items go from their
devices. When the owner leaves, the collection is **deleted** for everyone:
its items first come back into the owner's own vault, then the mailbox is
deleted from the server.

## Sync

Each collection syncs on its own, like a second vault: `vault-sync` mirrors
every `shared/<id>/cloud` folder to its mailbox, and `vaultd` merges
`shared/<id>/cloud/vault.svault` into its copy every 5 seconds while the
person's vault is unlocked (format.md 5.1, the same merge as folder sync).
A collection whose sync fails, or which this person was removed from, shows
its problem on the Sharing page and in `vault share list`.

## What differs between systems

The same on Linux, Windows and macOS: the files, commands and app page.
Only how `vault-sync` is started differs, as for cloud sync
([chapter 15](user-guide/15-cloud-sync.md)). Phone apps cannot join a
shared collection yet.
