# 2. Unlocking and unlock methods

The vault can be opened in several ways. Each way is stored as a **slot**:
a separate lock on the same vault. You can have as many slots as you like,
and any one of them opens the vault.

| Slot | What you need to unlock | Good for | Linux | Windows | macOS |
|---|---|---|---|---|---|
| `password` | The master password | Everyday use | Yes | Yes | Not yet |
| `fido2` | Password **and** a FIDO2 security key (touch, optionally its PIN) | Protection if your password leaks | Yes | Daemon must run as administrator | Not yet |
| `tpm` | Password **and** this computer's TPM chip (optionally a TPM PIN) | Making a stolen copy of the vault file useless on another machine | Yes | Not yet | Not applicable |
| `recovery` | The recovery code alone | When you forget the password or lose the key | Yes | Yes | Not yet |

A new vault starts with one `password` slot and one `recovery` slot.

## Lock and unlock

```sh
vault unlock                # with the master password
vault unlock --fido2        # password, then touch your security key
vault unlock --tpm          # password, plus the TPM PIN if the slot has one
vault unlock --recovery     # the recovery code
vault lock                  # lock now and wipe the keys from memory
```

The vault also locks by itself:

- after 15 minutes without use (start `vaultd --idle-secs N` to change it),
- when you lock the screen or the computer suspends (Linux and Windows),
- when `vaultd` stops.

**Wrong guesses.** The first 3 wrong attempts are free. After that, each
further failure doubles a waiting time, from 2 seconds up to 5 minutes,
before `vaultd` accepts the next attempt. Restarting `vaultd` resets it.

## Add a security key (FIDO2)

Use this when you want the vault to need something you *have* as well as
something you *know*. A key that supports the `hmac-secret` extension is
required; most current FIDO2 keys (YubiKey 5, SoloKey, Nitrokey 3, Google
Titan v2 and similar) do.

1. Plug in the key. On Windows, make sure `vaultd.exe` runs as
   administrator. On Linux, your user needs access to `/dev/hidraw*`
   (desktop distributions usually give it to the logged-in user).
2. Run:

   ```sh
   vault add-slot fido2 --label "blue key"
   ```

   Add `--uv` if you want the key's PIN to be required too.
3. Enter your master password (and the key's PIN with `--uv`).
4. Touch the key when it blinks, **twice**: once to create the credential
   and once to confirm it.
5. The command test-unlocks the new slot before it reports success.

From now on, `vault unlock --fido2` asks for the password, then the key.
The plain `password` slot still works too. If you want the key to be
required every time, remove the password slot afterwards (see below).

To check a key before enrolling it, run
`cargo run -p vault-hw --example fido2-check` from the source folder. It
works on Linux, Windows (as administrator) and macOS, and prints PASS if
the key gives the same secret every time.

## Add the TPM (Linux)

The TPM is a chip in most PCs made since 2016. A TPM slot can only be
opened on this one computer, so a copy of the vault file is useless
elsewhere even if someone knows your password.

1. Make sure your user can use the TPM (on most distributions, membership
   of the `tss` group).
2. Run:

   ```sh
   vault add-slot tpm --pin --label "this laptop"
   ```

   - `--pin` adds a separate TPM PIN. The TPM itself then limits how fast
     anyone can guess it.
   - `--pcr7` also ties the slot to the computer's Secure Boot state. If
     someone disables Secure Boot or changes its keys, the slot stops
     working. A firmware update can do the same: then unlock with another
     slot, remove this one and add it again.
3. Enter the master password and choose the PIN.

Unlock with `vault unlock --tpm`.

On Windows the TPM slot is not available yet. On a Mac there is no TPM;
Secure Enclave support is planned.

## Add another password or a new recovery code

```sh
vault add-slot password --label "long passphrase"
vault add-slot recovery --label "safe deposit box"
```

A new recovery slot prints its own code once. Keep each code separately.

## See your slots

```sh
vault slots
```

```
3fa91c02  password  
8be41d77  recovery  
c0a1e5f9  fido2     blue key
```

The first column is the slot ID. Any unique beginning of it works in the
commands below.

## Remove a slot

```sh
vault rm-slot c0a1
```

This removes the slot from the file, but the vault's key stays the same.
That is fine when you simply stop using a method. You cannot remove the last
everyday slot (password, security key or TPM); the recovery slot does not
count.

## Revoke a lost or stolen factor

If a security key is lost, a password may have leaked, or a recovery code
was seen by someone, removing the slot is not enough: an old copy of the
vault file still has that slot. **Revoke** gives the vault a new key and
keeps only the slots you name:

```sh
vault revoke --keep 3fa9,8be4
```

You prove each slot you keep (password, recovery code, touch the key). Every
other slot is removed and the vault key is replaced. Old copies and backups
of the file can still be opened with the old factors, so delete those
copies too.

Revoking is only in the command line; the desktop app can add and remove
slots but not revoke.

## Platform differences

- **Windows:** no TPM or Windows Hello slot yet. Security keys work only
  when `vaultd.exe` runs as administrator; using Windows' own WebAuthn
  service instead is planned.
- **macOS:** the daemon is not ported yet.
- **Linux:** when `vaultd` runs as the separate `vault` system user, install
  `contrib/udev/70-vault-fido.rules` so it can reach security keys.
