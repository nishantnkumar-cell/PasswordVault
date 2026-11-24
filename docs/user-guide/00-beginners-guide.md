# Secret Vault for beginners

This is the short, plain version. It covers what you need on day one: make
a vault, put passwords in it, and use it on more than one device. Every
step says what to type and what you should see. When you want more, each
step points to the full chapter.

> Secret Vault has not been audited yet. Try it with test data first.

## What it is

Secret Vault is a locked box for your passwords. The box is one encrypted
file on your computer. A small program called **`vaultd`** guards it. You
use the box through **`vault`** (typed commands), the desktop app, or the
browser extension.

Three words you will see:

- **Locked / unlocked.** Locked means nobody can read the box. You unlock
  it with your master password.
- **Paired.** Each program must be introduced to `vaultd` once, so a random
  program cannot ask for your passwords.
- **Recovery code.** A long code shown once, when you create the vault. If
  you forget your master password, it is the only way back in. Write it on
  paper and keep it somewhere safe. Do not keep it only on the computer.

## Step 1. Make your vault

Make sure `vaultd` is running (the installer starts it for you), then:

```sh
vault init
```

It asks for a master password (at least 8 characters; a few random words is
good) and shows your recovery code. **Write the code down now.** You will
not see it again.

## Step 2. Use it

```sh
vault add            # save a login (it asks for each part)
vault ls             # list what you saved
vault show ID        # look at one (ID can be the first few characters)
vault gen            # make a strong random password
vault lock           # lock the box; `vault unlock` opens it again
```

Coming from a browser or another password manager? Export a file from it,
then `vault import csv FILE` (also `bitwarden`, `apple`, `zoho`), and
delete the file afterwards, because it holds passwords in plain text.

More: [chapter 3](03-items.md).

## Step 3. Use it on more than one device (sync)

Skip this if you only have one computer. Otherwise, **pick ONE** of these
three ways. If you are not sure, ask yourself the questions in order and
stop at the first "yes".

| Question | Your way | What it needs |
|---|---|---|
| Do you already use **OneDrive, Google Drive, Dropbox or Syncthing** on every device? | **A. A folder** | Nothing new. |
| Do you have a **computer that is always on** at home (or a small server) and can run Docker? | **B. Your own server** | Docker on that computer. |
| Neither, and you are happy to make a **free Cloudflare account**? | **C. Cloudflare** | A free Cloudflare account. |

In every case, your passwords stay encrypted. The service or server only
ever holds the locked file, never your master password.

Never use two of these at once on the same device.

### Way A: a folder you already sync

On the **first** device:

```sh
vault sync on ~/Dropbox/vault.svault
```

Change the path to a folder your service syncs. On each **other** device,
wait until the file has arrived there, then run the same command with that
device's path to the same file. Then pair and unlock:

```sh
vault pair --password
vault unlock
```

Full steps: [chapter 10](10-sync.md).

### Way B: your own server (Docker)

Run the server on the always-on computer, then on your first device:

```sh
vault cloud setup --server https://THE-SERVER:8443 --fingerprint FINGERPRINT
```

It asks for the server's **admin key**. The server prints the address,
fingerprint and admin key when you run `vault-server show` (or
`docker compose exec vault-sync show`). Then go to
["Add another device"](#add-another-device-ways-b-and-c) below.

Full steps: [chapter 16](16-cloud-sync-docker.md).

### Way C: your free Cloudflare account

```sh
vault cloud setup
```

It asks for your Cloudflare account ID and an API token, and puts the sync
server in your account for you. Then go to
["Add another device"](#add-another-device-ways-b-and-c) below.

Full steps: [chapter 15](15-cloud-sync.md).

### Start the sync helper (ways B and C)

On every device that uses way B or C, start the background helper once:

| Your system | Command |
|---|---|
| Linux, own-user service (the `install.sh` default) | `systemctl --user enable --now vault-sync` |
| Linux, system service (`.deb`, Arch package, `get.sh`) | `sudo systemctl enable --now vault-sync@$USER` |
| macOS, Windows | see [chapter 15](15-cloud-sync.md#step-3-start-the-sync-helper) |

Without the helper, changes do not travel between devices.

### Add another device (ways B and C)

1. On a device that already has the vault, with the vault unlocked:

   ```sh
   vault cloud link
   ```

   It prints a link and a QR code. The link works **once** and for **10
   minutes**. Treat it like a key: send it only to yourself.

2. On the new device (with `vaultd` running):

   ```sh
   vault cloud join 'PASTE-THE-LINK-HERE'
   ```

   Keep the quote marks around the link.

3. Start the sync helper on the new device (see the table above).
4. Pair and unlock, using the **same master password** as on your first
   device:

   ```sh
   vault pair --password
   vault unlock
   ```

5. Check it worked: `vault ls` shows your items. Add an item on one device
   and look for it on the other within about 30 seconds.

`vault cloud` shows the state, and `vault cloud devices` lists every device.
Lost a phone or laptop? `vault cloud remove ID` cuts that device off.

### Not sure what is on?

Type `vault sync`. If sync is off, it lists the three ways above with the
exact command for each.

## When something goes wrong

| What you see | What to do |
|---|---|
| `cannot reach vaultd` | `vaultd` is not running. Start it (the installer sets this up), then try again. |
| `this client is not paired` | Run `vault pair --password`. |
| `the vault is locked` | Run `vault unlock`. |
| `no vault exists yet` after joining | On a new device, wait a few seconds for the helper to download the vault, then try again. Check that `vault-sync` is running. |
| An item is missing on the other device | Both devices must be unlocked and running the helper (ways B and C). Run `vault sync now` (way A) or wait half a minute. |
| Forgot the master password | Use the recovery code: `vault unlock --recovery`. |

More help: [chapter 8](08-troubleshooting.md).

## Good habits

- Keep the recovery code on paper, somewhere safe.
- Make a backup now and then: `vault backup FILE`.
- Delete import files and join links after you use them.
- Use a long master password that you do not use anywhere else.
