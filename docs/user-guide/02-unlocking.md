# 2. Unlocking and unlock methods

The vault can be opened in several ways. Each way is stored as a **slot**:
a separate lock on the same vault. You can have as many slots as you like,
and any one of them opens the vault.

| Slot | What you need to unlock | Good for | Linux | Windows | macOS |
|---|---|---|---|---|---|
| `password` | The master password | Everyday use | Yes | Yes | Not yet |
| `fido2` | Password **and** a FIDO2 security key (touch, optionally its PIN) | Protection if your password leaks | Yes | Yes | Not yet |
| `tpm` | Password **and** this computer's TPM chip (optionally a TPM PIN) | Making a stolen copy of the vault file useless on another machine | Yes | Yes | Not applicable |
| `recovery` | The recovery code alone | When you forget the password or lose the key | Yes | Yes | Not yet |

A new vault starts with one `password` slot and one `recovery` slot.

**Windows Hello** is not a slot. It is [quick unlock](#quick-unlock-with-windows-hello-windows):
after you unlock with one of the slots above, Windows Hello (face,
fingerprint or your Windows PIN) can open the vault again when it locks,
for a time you choose.

## Lock and unlock

```sh
vault unlock                # with the master password
vault unlock --fido2        # password, then touch your security key
vault unlock --tpm          # password, plus the TPM PIN if the slot has one
vault unlock --recovery     # the recovery code
vault unlock --hello        # Windows Hello, if quick unlock is on (Windows)
vault lock                  # lock now and wipe the keys from memory
vault lock --full           # the same, and also forget the quick unlock key
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

1. Plug in the key. On Linux, your user needs access to `/dev/hidraw*`
   (desktop distributions usually give it to the logged-in user). On
   Windows nothing is needed: vaultd uses Windows' own security key
   service, without administrator rights.
2. Run:

   ```sh
   vault add-slot fido2 --label "blue key"
   ```

   Add `--uv` if you want the key's PIN to be required too.
3. Enter your master password and the key's PIN. With `--uv` the PIN is
   required; without it, press Enter if the key has no PIN. Many keys with
   a PIN set want it to register any new credential, even one you will
   later unlock with a touch alone. On Windows
   the command doesn't ask for the PIN: Windows asks for it in its own
   security key window.
4. Touch the key when it blinks, **twice**: once to create the credential
   and once to confirm it. On Windows, its security key window tells you
   when.
5. The command test-unlocks the new slot before it reports success.

From now on, `vault unlock --fido2` asks for the password, then the key.
The plain `password` slot still works too. If you want the key to be
required every time, remove the password slot afterwards (see below).

To check a key before enrolling it, run
`cargo run -p vault-hw --example fido2-check` from the source folder. It
works on Linux, Windows and macOS, and prints PASS if the key gives the
same secret every time. On Windows, add `-- --compare` and run it in an
administrator terminal to also check that Windows' security key service and
direct USB access give the same secret (they must, so a slot works on every
system).

## Add the TPM

The TPM is a chip in most PCs made since 2016 (every PC that runs Windows 11
has one). A TPM slot can only be opened on this one computer, so a copy of
the vault file is useless elsewhere even if someone knows your password.

1. Make sure your user can use the TPM.
   - **Linux:** on most distributions, membership of the `tss` group.
   - **Windows:** nothing to do. vaultd uses Windows' own TPM service (the
     Platform Crypto Provider) and needs no administrator rights. If you
     are not sure the PC has a TPM, press Win+R and run `tpm.msc`: it
     should say "The TPM is ready for use" and "Specification Version: 2.0".
2. Run:

   ```sh
   vault add-slot tpm --pin --label "this laptop"
   ```

   - `--pin` adds a separate TPM PIN. The TPM itself then limits how fast
     anyone can guess it: after a few wrong PINs it locks for a while (the
     length depends on the TPM and the system, often 10 minutes to 2 hours).
   - `--pcr7` also ties the slot to the computer's Secure Boot state. If
     someone disables Secure Boot or changes its keys, the slot stops
     working. A firmware update can do the same: then unlock with another
     slot, remove this one and add it again.
3. Enter the master password and choose the PIN.
4. The command test-unlocks the new slot before it reports success.

Unlock with `vault unlock --tpm`. In the desktop app, pick **This device
(TPM)** in the unlock list.

To check the TPM before adding a slot, run
`cargo run -p vault-hw --example tpm-check -- 1234` from the source folder
(`1234` is a throwaway test PIN; leave it out to be asked). It prints PASS
when wrapping and unwrapping a test secret works without a PIN, with a PIN
and bound to PCR 7. Nothing is stored.

**Linux and Windows TPM slots are separate.** On a computer that starts
both Linux and Windows, a TPM slot added under one system does not open
under the other, even though the chip is the same: each system uses the TPM
in its own way. Add one TPM slot from each system if you want both.

On a Mac there is no TPM; Secure Enclave support is planned.

## Quick unlock with Windows Hello (Windows)

Typing a long master password every time the screen locks gets old. Quick
unlock lets Windows Hello (your face, fingerprint or Windows PIN) open the
vault again, but only for a while after a full unlock:

- **Full unlock first.** After `vaultd` starts (at sign-in or after a
  restart), the first unlock always needs one of your slots: password,
  security key, TPM or recovery code.
- **Then Windows Hello.** Each time the vault locks (idle timeout, screen
  lock, sleep, or `vault lock`), Windows Hello can open it again.
- **Until the time runs out.** Quick unlock lasts the number of hours you
  choose (1 to 24), counted from the last full unlock. Unlocking with
  Windows Hello does not extend it. After that, or after a restart, the
  next unlock needs your password again.

Turn it on (the vault must be unlocked):

```sh
vault quick-unlock 8        # Windows Hello for 8 hours after each full unlock
```

Windows asks you to confirm with Windows Hello once, so no other program can
turn it on without you. Then:

```sh
vault lock
vault unlock --hello        # Windows Security asks for your face, fingerprint or PIN
vault status                # shows how long quick unlock stays available
vault quick-unlock off      # turn it off again
```

In the desktop app: **Unlock methods**, then **Quick unlock with Windows
Hello**, pick a time and press **Apply**. While quick unlock is available,
the lock screen shows an **Unlock with Windows Hello** button above the
usual methods.

Good to know:

- Windows Hello must be set up for your Windows account (Settings >
  Accounts > Sign-in options). A Windows PIN is enough; a camera or
  fingerprint reader is optional.
- Three failed or cancelled Windows Hello checks in a row switch quick
  unlock off until your next full unlock.
- `vault lock --full` locks and forgets the quick unlock key at once, for
  example before you hand the computer to someone.
- Windows Hello only reopens a vault this computer has already unlocked. It
  cannot pair a new app, export a key or revoke slots; those always ask for
  a full method.
- How it works: when the vault locks, vaultd keeps the vault key, encrypted
  under a random key that Windows protects in memory, instead of wiping it.
  That is a convenience trade-off: while quick unlock is available,
  someone who can read vaultd's memory (malware running as you or as an
  administrator) could get the vault key, just as they could while the
  vault is unlocked. Leave quick unlock off if that matters more to you
  than typing the password.

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

- **Windows:** TPM slots use Windows' Platform Crypto Provider and need no
  administrator rights; they do not open under Linux on the same computer
  (and the other way round). Quick unlock with Windows Hello is
  Windows-only. Security keys go through
  Windows' own WebAuthn service, which needs no administrator rights and
  asks for the touch and the PIN in its own window. On Windows 10 builds
  too old for it, vaultd falls back to direct USB access, which needs
  vaultd to run as administrator. A security key slot works on every
  system: one added on Linux unlocks on Windows and the other way round.
  One exception: if the key has a PIN, Windows always checks it, which
  changes the key's secret, so on Windows only `--uv` slots work with such
  a key. Use `--uv` for keys with a PIN if you use Windows.
- **macOS:** the daemon is not ported yet. When it is, Touch ID is planned
  to work like Windows Hello quick unlock, and the Secure Enclave like the
  TPM.
- **Linux:** no Windows Hello equivalent yet. Face and fingerprint unlock
  are planned as the same kind of quick unlock.
- **Linux:** when `vaultd` runs as the separate `vault` system user, install
  `contrib/udev/70-vault-fido.rules` so it can reach security keys.
