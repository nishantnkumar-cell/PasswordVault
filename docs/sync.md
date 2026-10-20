# Folder sync

Keep one vault on several devices through a folder that a cloud service already syncs: OneDrive, Google Drive, Dropbox, iCloud Drive, Syncthing, or a network share. The service only ever holds the encrypted vault file; no account, server or key is shared with it.

## Using it

On the first device, with the vault unlocked:

```sh
vault sync on ~/OneDrive/vault.svault
```

or in the desktop app: **Sync** under *Tools* in the sidebar, enter the file path, **Turn on**. The daemon writes the vault there and keeps it merged from then on.

On each other device, before creating a vault there (with vaultd running and the folder synced):

```sh
vault sync on ~/OneDrive/vault.svault   # joins the vault in that file
vault pair --password                   # pair this client by unlocking it
```

or in the desktop app, on the "No vault yet" screen: **Join**, then pair with the master password. Every device unlocks with the same slots (the password, the recovery code, any security key enrolled on any device). A TPM slot only works on the machine whose TPM sealed it.

`vault sync` shows the state, `vault sync now` merges at once, `vault sync off` stops (the file in the folder stays). `vault status` and the status box at the top of the app's sidebar say when the last merge was and whether something is wrong.

## How it works

Each device keeps its own vault file, as before, and treats the copy in the folder as a mailbox:

- **While unlocked**, the daemon checks the copy's modified time and size every 5 seconds, and reads it in full once a minute regardless. When it changed, the daemon opens it with the vault key it already holds, merges it into its own vault, and writes the result to both files if either was behind.
- **Before every save**, it merges whatever changed in the folder first, then writes both files, so one device does not overwrite another's edit.
- **When locked**, nothing is read or written; the next unlock catches up.
- A copy that does not parse (half-downloaded) is skipped and tried again; a copy of a different vault is refused.
- **Cloud conflict copies.** When two devices write before the service syncs, services keep both as `vault (1).svault`, `vault-LAPTOP.svault` or `vault (conflicted copy).svault`. The daemon merges every file next to the synced one whose name starts with the same name and has the same extension, and lists them in `vault sync` as safe to delete. It never deletes files in the folder itself.

## Merging

The merge is in `vault-core` (`Vault::merge`, format.md section 5.1) and needs no network or clock agreement:

- Every item carries a version vector: one counter per device that edited it. The vector says whether one copy's edit already includes the other's, or whether two devices edited the same item without seeing each other.
- **One side newer:** it wins.
- **Both edited:** the edit with the later modified time wins and the other is kept as a new item titled "... (conflict)". Both devices pick the same winner and make the same copy, so the copies do not multiply.
- **Edited on one device, deleted on another:** the edit wins; the item stays. A delete removes only edits it had seen.
- **Deletes stick.** A deleted item leaves a small marker (its ID and vector) so an old copy of the file cannot bring it back.
- **Slots** enrolled on any device are added everywhere; removed slots are recorded and stay removed.
- Merging is commutative and idempotent: devices that exchange files in any order end up with the same items (checked by a property test with random edits, deletes and partial syncs across three devices).

## Revoking a factor

`vault revoke` rotates the vault key. The other devices can no longer open the synced copy with the key they hold, so their status says the copy was re-keyed on another device and they stop writing to it. At their next unlock they open the copy with the factor just used, take the new key and the remaining slots, and merge their own edits in. Their old slots that the revoke removed are gone from that point on.

If two devices revoke at the same time, the later rotation wins (each vault counts its rotations), with a fixed tie-break, so both agree.

A device that is never unlocked again keeps the old key and the old slots in its own file: syncing cannot reach into a copy that stays offline. That is the same limit as any backup (threat-model.md, A5).

## Limits

- Merges happen only on a device that is unlocked. Edits on two devices that never overlap in unlocked time still merge, at the next unlock of either.
- Files are whole-vault, so every save uploads the whole (padded) file. Fine for thousands of items; not designed for very large attachments.
- The cloud service sees when the file changes and its padded size, as with any copy of the file.
- Conflicts compare modified times, which come from each device's clock. A device with a wrong clock can win a conflict it should have lost; the other edit is still kept as a copy.
