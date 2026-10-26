# 2. Unlocking and unlock methods

The vault can be opened in several ways. Each way is stored as a **slot**:
a separate lock on the same vault. You can have as many slots as you like,
and any one of them opens the vault.

| Slot | What you need to unlock | Good for | Linux | Windows | macOS |
|---|---|---|---|---|---|
| `password` | The master password | Everyday use | Yes | Yes | Yes |
| `fido2` | Password **and** a FIDO2 security key (touch, optionally its PIN) | Protection if your password leaks | Yes | Yes | Yes |
| `tpm` | Password **and** this computer's TPM chip (optionally a TPM PIN) | Making a stolen copy of the vault file useless on another machine | Yes | Yes | Not applicable |
| `recovery` | The recovery code alone | When you forget the password or lose the key | Yes | Yes | Yes |

A new vault starts with one `password` slot and one `recovery` slot.

**Windows Hello** and **Touch ID** are not slots. They are
[quick unlock](#quick-unlock-with-windows-hello-windows): after you unlock
with one of the slots above, Windows Hello (face, fingerprint or your
Windows PIN) or, on a Mac, Touch ID can open the vault again when it locks,
for a time you choose.

## Lock and unlock

```sh
vault unlock                # with the master password
vault unlock --fido2        # password, then touch your security key
vault unlock --tpm          # password, plus the TPM PIN if the slot has one
vault unlock --recovery     # the recovery code
vault unlock --hello        # Windows Hello (Windows) or Touch ID (macOS), if quick unlock is on
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

## Unlock with your phone

Use your phone when you want a second factor but do not want to carry a
security key. Someone who learns your master password still cannot open
the vault without your phone, and someone who takes your phone still needs
your password.

**What you need**

- An iPhone (iOS 18 or later) or an Android phone (Android 9 or later with
  Google Play services) with a screen lock set.
- A password manager on the phone that supports passkeys with the PRF
  extension. iCloud Keychain and Google Password Manager do.
- Bluetooth switched on on the phone and the computer, and an internet
  connection on both. The phone and the computer pass the request through
  the phone maker's relay; the relay never sees the secret.
- **Linux:** a Bluetooth adapter and the BlueZ service (`bluetoothd`)
  running. `bluetoothctl show` should list a powered adapter.
- **Windows:** Windows 11 version 23H2 or later.

**Add your phone in the desktop app**

1. Unlock the vault and open **Unlock methods**.
2. Under **Add a method**, choose **Phone**.
3. Give it a name, such as "Alex's phone", and type your master password
   twice.
4. Press **Add**.
   - **Linux:** the app shows a QR code. Point the phone's camera at it and
     tap the link that appears.
   - **Windows:** a Windows window opens. Choose **iPhone, iPad or Android
     device**, then scan the QR code it shows with the phone's camera.
5. On the phone, save the passkey for **vault.local** ("Secret Vault
   unlock") and confirm with your face, fingerprint or screen lock.
6. Some phones (and always Windows) ask you to confirm a second time. This
   lets the vault check that the new method really opens it before saving
   it.
7. The new method shows in the list as "Security key or phone".

**Add your phone from the command line**

```sh
vault add-slot phone --label "Alex's phone"
```

Type your master password. On Linux, a QR code is printed in the terminal;
scan it with the phone. On Windows, follow the Windows window.

**Unlock with your phone**

- **Desktop app:** on the lock screen choose **Phone**, type your master
  password, press **Unlock**, then scan the QR code (Linux) or follow the
  Windows window. Confirm on the phone.
- **Command line:** `vault unlock --phone`.
- To pair a new copy of the app or the command line with the phone:
  `vault pair --phone`, or choose **Phone** on the app's pairing screen.

**Good to know**

- The passkey is listed in your phone's password manager under
  **vault.local**. Do not delete it while you use the method; if you did,
  remove the method in the app and add the phone again.
- If the passkey syncs to your other Apple or Google devices, each of them
  can unlock the vault the same way.
- A phone method is a kind of security key method: `vault slots` lists it as
  `fido2`, and a security key that holds the same passkey also opens it.
- If the vault has no phone method, the app says so and does not start the
  phone.
- If it fails: check that Bluetooth is on on both, that the phone has an
  internet connection, and that you confirmed on the phone within two
  minutes.

## Add the TPM

The TPM is a chip in most PCs made since 2016 (every PC that runs Windows 11
has one). A TPM slot can only be opened on this one computer, so a copy of
the vault file is useless elsewhere even if someone knows your password.

1. Make sure your user can use the TPM.
   - **Linux:** on most distributions, membership of the `tss` group.
   - **Windows:** nothing to do. vaultd uses Windows' own TPM service (TPM
     Base Services) and needs no administrator rights. If you
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

### Post-quantum protection

Someone could copy your vault file today, for example from a sync folder
or a backup, and keep it until quantum computers can break the public-key
cryptography in use today. Secret Vault is built so that such a copy stays
useless:

| Unlock method | Safe against a future quantum computer? |
| --- | --- |
| Password, recovery code | Yes |
| Security key (FIDO2) | Yes |
| TPM on Linux | Yes |
| TPM on Windows, added with this update or later | Yes |
| TPM on Windows, added before this update | **No**: the TPM part can be broken, so only your password protects that copy |

To find an old Windows TPM slot, run `vault slots`. It shows a note under
such a slot:

```
5d20aa31  tpm       this laptop
          note: made with an RSA key a future quantum computer could break; ...
```

In the desktop app, open **Unlock methods**: the slot says **Not
post-quantum** in orange.

To replace it, on that Windows PC:

1. Add the TPM again, with the same options you used before:

   ```sh
   vault add-slot tpm --pin --label "this laptop"
   ```

   or in the desktop app, **Unlock methods > Add a method > This device
   (TPM)**.
2. Lock and unlock once with the new TPM slot to be sure it works
   (`vault unlock --tpm`).
3. Get rid of the old slot:
   - If the vault file never left this PC (no sync folder, no backups),
     remove it: `vault rm-slot 5d20` (use your slot's ID), or **Remove** in
     the desktop app.
   - If the file was ever synced or backed up, **revoke** instead and keep
     every slot except the old one:

     ```sh
     vault revoke --keep 3fa9,8be4,c0a1,9e77
     ```

     Revoking gives the vault a new key, so an old copy of the file that
     still has the old slot cannot open copies made from now on. Delete
     old copies and backups you no longer need.

Other things that use public-key cryptography:

- **OpenPGP keys**: make new keys with `--pq` (or **Post-quantum** in the
  desktop app) when the people you write to can use them. See
  [OpenPGP keys](07-openpgp.md).
- **SSH keys** (Ed25519, ECDSA): a future quantum computer could not read
  past sessions through your key, but could pretend to be you with it. No
  post-quantum SSH key type exists in OpenSSH yet; Secret Vault will offer
  one when it does.

## Quick unlock with Windows Hello (Windows)

On a Mac, Touch ID does the same job and the steps below are the same, with
"Touch ID" in place of "Windows Hello" and `vault unlock --touch-id` (or
`--hello`) to use it. The Mac's window accepts a fingerprint, a paired Apple
Watch, or the login password. See
[Quick unlock with Touch ID](13-macos.md#quick-unlock-with-touch-id).

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
- **Phone passkeys:** on Linux, Secret Vault draws the QR code itself and
  talks to the phone through BlueZ. On Windows, Windows draws the QR code
  and talks to the phone, and may offer a phone you used before directly.
  Not available on macOS yet.
- **macOS:** quick unlock uses Touch ID (or an Apple Watch, or the login
  password) the way Windows uses Windows Hello. Macs have no TPM, so there
  is no `tpm` slot; TPM slots made elsewhere are skipped. Security keys go
  over USB directly, with the PIN typed in the app or the `vault` command,
  as on Linux, and need no extra permission. A Secure Enclave slot (the
  Mac's counterpart of the TPM) is not supported yet. See
  [Installing and running on macOS](13-macos.md).
- **Linux:** no Windows Hello equivalent yet. Face and fingerprint unlock
  are planned as the same kind of quick unlock.
- **Linux:** when `vaultd` runs as the separate `vault` system user, install
  `contrib/udev/70-vault-fido.rules` so it can reach security keys.
