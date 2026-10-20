# 3. Items, one-time codes, the generator and import

An **item** is one entry in the vault, usually a login. It has:

| Field | Notes |
|---|---|
| Title | Required. Shown in lists and in the browser popup. |
| Username | |
| Password | Hidden unless you ask to see it. |
| Websites | Where the login may be filled. See [Websites and matching](#websites-and-matching). |
| One-time code (TOTP) | Optional. See [One-time codes](#one-time-codes-totp). |
| Notes | Free text, also encrypted. |

Items can also hold an SSH or OpenPGP key; those are covered in chapters
[6](06-ssh-and-git.md) and [7](07-openpgp.md).

Everything here works the same on Linux and Windows, from the command line
and from the [desktop app](05-desktop-app.md). The vault must be unlocked.

## Add, view, edit and delete

### Add

```sh
vault add               # you type the password
vault add --generate    # a random 24-character password is made for you
```

You are asked, in order:

1. **Title**, for example `GitHub`.
2. **Username**, for example `alex@example.com`.
3. **URL**: the address of the login page, for example
   `https://github.com/login`. Only the site part counts; the path is
   ignored.
4. **Match the whole site including subdomains? [y/N]**: see below. If
   unsure, press Enter for No.
5. **Password** (skipped with `--generate`). Typing is hidden.
6. **TOTP secret or otpauth:// URI**: press Enter if the site has no
   two-factor codes.
7. **Notes**.

### List and find

```sh
vault ls
```

```
1c9e04aa  GitHub                       alex@example.com           https://github.com/login  [totp]
7b20f3d1  Bank                         12345678                 https://bank.example
```

The first column is the item's ID. Any unique beginning of it works, so
`vault show 1c9` is enough.

To see which items the browser would offer on a site:

```sh
vault find https://github.com
```

### View

```sh
vault show 1c9            # password hidden
vault show 1c9 --reveal   # password shown
```

### Edit

```sh
vault edit 1c9
vault edit 1c9 --generate   # also replace the password with a new random one
```

Each question shows the current value in brackets. Press Enter to keep it.
For the one-time code, Enter keeps it and `-` removes it.

### Delete

```sh
vault rm 1c9
```

There is no undo.

## Websites and matching

The vault fills a login only on the website it belongs to. This protects
you from look-alike phishing sites: a login for `https://github.com` is never
offered on `https://github.com.evil.example`.

Each website on an item has a **match mode**:

| Mode | Fills on | Example: saved as `https://accounts.example.com` |
|---|---|---|
| Exact origin (default) | The same scheme, host and port only | Fills on `https://accounts.example.com`, not on `https://www.example.com` |
| Whole site | Any `https` page under the same registered domain | Fills on `https://www.example.com` and `https://login.example.com` |

Use **whole site** only for sites that move your login between subdomains.
It never applies to `http` pages, to IP addresses or across different
domains such as `example.com` and `example.co.uk`.

**Plain `http` sites.** A login is never filled on an `http://` page unless
it was saved with an `http://` address. The CLI and the import set that up
automatically when the address you type starts with `http://`; in the
desktop app it is a checkbox.

**Look-alike letters.** Internationalised domain names are compared in
their `xn--` form, and such names are flagged so you can spot a homograph
(for example a Cyrillic "а" in place of a Latin "a").

## One-time codes (TOTP)

Many sites offer two-step login with a 6-digit code from an authenticator
app. The vault can be that app.

1. On the site, turn on two-step login with an "authenticator app".
2. The site shows a QR code. Look for "can't scan it?" or "enter key
   manually" to get the text secret (a string like `JBSWY3DPEHPK3PXP`). If
   you can read the QR code with another tool, its `otpauth://totp/...` link
   works too and carries the digits, period and algorithm.
3. Run `vault edit ID` and paste the secret or the link at the TOTP
   question (or use the desktop app's edit form).
4. Get a code to finish setting it up on the site:

   ```sh
   vault totp 1c9
   ```

   ```
   492039 (17 s left)
   ```

Codes of 6 to 8 digits with SHA-1, SHA-256 or SHA-512 are supported. In the
browser, the popup's **Code** button copies the code for the current site.

Keeping the password and the one-time code in the same vault is convenient,
but it means one vault protects both. If you want them separate, keep the
code in a different authenticator.

## Password generator

```sh
vault gen                       # 24 characters with symbols
vault gen --length 32
vault gen --no-symbols          # letters and digits only, for picky sites
vault gen --no-ambiguous        # leaves out look-alikes such as 0/O and 1/l/I
```

Length can be 8 to 256. Every password has at least one character of each
kind selected (lower case, upper case, digits and, unless turned off,
symbols). The desktop app has the same options with a length slider from
8 to 64. The browser popup's **Generate password** button makes a password
with the default settings and copies it.

## Import from another password manager

The vault can import:

| From | How to export it there | Import command |
|---|---|---|
| Bitwarden | Settings, Export vault, format **.json** (not "encrypted json") | `vault import bitwarden FILE.json` |
| Chrome, Edge | Settings, Passwords, Export passwords (CSV) | `vault import csv FILE.csv` |
| Firefox | Passwords (about:logins), the "..." menu, Export passwords (CSV) | `vault import csv FILE.csv` |
| Safari | File, Export, Passwords (CSV) | `vault import csv FILE.csv` |

What is brought over:

- **Bitwarden:** logins (title, username, password, websites, TOTP, notes)
  and secure notes. Cards and identities are skipped. Encrypted exports are
  refused; export unencrypted.
- **CSV:** the URL, username and password columns, plus name, notes and
  one-time code columns when the file has them. Column order does not
  matter.

Imported websites use the exact-origin match mode. Edit an item to switch
it to whole-site matching.

**Delete the export file right after importing.** It holds every password
in plain text. Empty the recycle bin or trash too.

The desktop app can import as well; it asks for the file's path.
