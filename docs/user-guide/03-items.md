# 3. Items, one-time codes, the generator and import

An **item** is one entry in the vault. There are four kinds, described in
[Item types](#item-types); the most common is a **login**, which has:

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


## Item types

| Kind | Holds | Shown in lists as |
|---|---|---|
| Login | Username, password, websites, one-time code | The username |
| Secure note | Just the title and the note | The title only |
| Card | Name on card, number, expiry (MM/YY), security code, PIN | The network and last four digits, e.g. *Visa •••• 1111* |
| Identity | Title (Mr, Ms, Dr...), first, middle and last name, company, email, phone, address, city, state or region, postcode, country | The name, e.g. *Alex Example* |

Every kind can also have **notes** and **custom fields**: extra name and
value pairs, such as a membership number or a security question. Mark a
custom field **hidden** to treat its value like a password.

Some things to know:

- **A secure note's text is hidden** until you ask to see it, because notes
  often hold secrets. The notes on the other kinds are shown as usual.
- **Card numbers** may be typed with spaces or dashes; only the digits are
  kept. A number that fails the card checksum is still saved, with a
  warning, so check it for typos. The network is recognised from the first
  digits.
- **Only logins are tied to websites.** Cards and identities can be filled
  into any `https` page; a card only after you approve it. See
  [Fill a card or an address](04-browser-autofill.md#fill-a-card-or-an-address).
- **A key** (SSH or OpenPGP) is listed with the type *Key* and the filter
  *SSH and PGP keys*, whatever kind it was stored as.

Everything here works the same on Linux and Windows, from the command line
and from the [desktop app](05-desktop-app.md). The vault must be unlocked.

## Add, view, edit and delete

### Add

```sh
vault add               # a login; you type the password
vault add --generate    # a login with a random 24-character password
vault add note          # a secure note
vault add card          # a payment card
vault add identity      # a name and address
```

For a login you are asked, in order:

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

A card asks for the name on the card, number, expiry as `MM/YY` (for
example `07/31`), security code and PIN; the secret ones are typed hidden.
An identity asks for each part of the name and address; press Enter to skip
any. Every kind then offers **custom fields** (a name, whether to hide the
value, then the value; Enter on the name finishes) and the notes.

### List and find

```sh
vault ls
```

```
1c9e04aa  login    GitHub                       alex@example.com         https://github.com/login  [totp]
7b20f3d1  card     Travel                       Visa •••• 1111
e5a0c912  identity Home                         Alex Example
```

`vault ls cards` lists only cards; `logins`, `notes` and `identities` work
the same way. The first column is the item's ID. Any unique beginning of it works, so
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

Without `--reveal`, every secret is replaced by stars: a password, a card
number, security code and PIN, a hidden custom field, and the text of a
secure note.

### Edit

```sh
vault edit 1c9
vault edit 1c9 --generate   # also replace the password with a new random one
```

Each question shows the current value in brackets. Press Enter to keep it.
For the one-time code, Enter keeps it and `-` removes it. A custom field is
cleared with `-`. An item keeps its kind; to change it, make a new item.

### Delete

```sh
vault rm 1c9
```

The item goes to the **trash** for 30 days. It no longer shows in lists, in
autofill, to the SSH agent or to other programs, but you can bring it back:

```sh
vault trash            # what is there, and when each item will be gone
vault restore 1c9
vault purge 1c9        # delete one for good
vault empty-trash      # delete everything in the trash for good
```

After 30 days `vaultd` deletes a trashed item for good the next time the
list is read. In the desktop app, **Trash** is in the sidebar under Tools.
A delete on one computer reaches your other computers through sync as a move
to the trash, so a mistake there can still be undone. Older versions of
Secret Vault, on a computer you have not updated, show a trashed item as a
normal one.

### Earlier passwords

When you change a login's password, the old one is kept (the last 10) so
you can get back in if a site did not take the new one:

```sh
vault history 1c9
```

It prints each earlier password and when it was replaced. The history lives
inside the encrypted item and is not shown with the item; there is no way to
see it in the desktop app yet. Deleting the item for good deletes its
history. Passwords that apps save through the Secret Service keep no history.

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
2. The site shows a QR code. Under it, look for "can't scan it?" or
   "enter key manually" to see the setup key (a string like
   `JBSW Y3DP EHPK 3PXP`). Copy it. Or take a screenshot of the QR code
   and save it as an image: the QR code holds an `otpauth://totp/...` link
   that also carries the site's name, your account, and the code's digits,
   period and algorithm.
3. Add the code to the vault, in whichever app is to hand:
   - **Desktop app:** **One-time codes** > **Add code**. See
     [Add a one-time code](05-desktop-app.md#add-a-one-time-code).
   - **Phone or tablet:** **Codes** > **+** or **Add code**, then scan the
     QR code with the camera. See
     [One-time codes on phones](14-phone-apps.md#one-time-codes).
   - **Command line:** `vault code add`, then paste the setup key or link
     when asked (it isn't shown as you type):

     ```sh
     vault code add
     ```

     ```
     Setup key or otpauth:// link:
     Current code: 492039 (17 s left). Type it on the site to finish turning on two-step sign-in.
     Put it on your login Example Mail (1c9e04aa)? [Y/n]:
     Added the code to Example Mail (1c9e04aa). See it with `vault totp 1c9e04aa`.
     ```

     It asks about an existing login only when the link names a site and
     exactly one of your logins without a code matches it; otherwise it
     makes a new login named after the site. Options:

     | Option | Does |
     | --- | --- |
     | `--qr IMAGE` | Read the QR code from a screenshot (PNG, JPEG, GIF or BMP) instead of asking for the key |
     | `--to ID` | Put the code on this login (any unique start of its ID) |
     | `--title T`, `--account A` | Name a new login and its username, for a bare setup key that names nothing |
     | `--replace` | Swap the code a login already has (without it, `vault` asks, or refuses in a script) |

     In a script, pipe the key in: `printf '%s\n' "$KEY" | vault code add
     --title "Example Bank"`.
4. Type the current code the vault shows into the site to finish turning
   on two-step login. Later, get a code with:

   ```sh
   vault totp 1c9
   ```

   ```
   492039 (17 s left)
   ```

   or see every code at once with `vault code ls`:

   ```
   1c9e04aa  492039      17 s  Example Mail                 alex@example.com
   7b2d0f13  118220      17 s  Example Bank                 alex
   ```

You can also add or change a code by editing a login: `vault edit ID`
asks for it after the password, and the desktop edit form has a **One-time
codes** box. A code goes on a login; secure notes, cards and identities
can't keep one.

Codes of 6 to 8 digits with SHA-1, SHA-256 or SHA-512 are supported. In the
browser, the popup's **Code** button copies the code for the current site.

Delete the QR screenshot once the code is added: anyone who has it can make
your codes. Google Authenticator's "Transfer accounts" QR code isn't
supported yet; add each code from its site instead.

Keeping the password and the one-time code in the same vault is convenient,
but it means one vault protects both. If you want them separate, keep the
code in a different authenticator.

## Password generator

The generator makes three styles of password. Pick the one that suits where
the password goes:

| Style | Looks like | Strength | Best for |
| --- | --- | --- | --- |
| Random characters | `q8!Zr-Vw2#nT7@LpX4$eK9` | About 156 bits at 24 characters | Anything the vault fills in for you; you never type it |
| Three random words | `CupFishBiscuit` | About 39 bits for 3 words, 13 more per word | Passwords you must remember or type, such as a Wi-Fi password; use 4 or more words for anything important |
| Apple style | `fokjyb-Xewpud-hamu4s` | About 74 bits | Passwords you type on a phone keyboard, and sites that demand a capital and a digit |

**Three random words** is the advice of the UK National Cyber Security
Centre (NCSC): three words picked at random are easy to remember and hard
to guess, much harder than a single word with a few letters swapped for
symbols. The words are picked by the computer from the EFF's list of 7,772
common English words, so they really are random. That matters: words you
choose yourself are far easier to guess. Three words is fine for a website,
because websites slow guessing down; for a password that protects a lot,
such as an email account or a vault's master password, use four or more.

**Apple style** makes the kind of password iPhones and Macs suggest: three
groups of six lower-case letters joined by hyphens, with one capital letter
and one digit somewhere in them. The letters alternate between consonants
and vowels so they are easy to read out and type.

From the command line:

```sh
vault gen                       # 24 random characters with symbols
vault gen --length 32
vault gen --no-symbols          # letters and digits only, for picky sites
vault gen --no-ambiguous        # leaves out look-alikes such as 0/O and 1/l/I

vault gen --words               # three random words, e.g. CupFishBiscuit
vault gen --words 4             # four words
vault gen --words --separator -           # Cup-Fish-Biscuit
vault gen --words --no-capitals --separator " "   # cup fish biscuit
vault gen --words --number-and-symbol     # CupFishBiscuit7!, for sites that demand them

vault gen --apple               # e.g. fokjyb-Xewpud-hamu4s
```

For random characters the length can be 8 to 256, and every password has at
least one character of each kind selected (lower case, upper case, digits
and, unless turned off, symbols). Words can be 3 to 10, with up to three
characters between them.

The desktop app ([Generator](05-desktop-app.md#generator)) and the phone
apps ([Generator tab](14-phone-apps.md#password-generator)) have the same
three styles and show how strong each is. The browser popup has a style menu
next to **Generate password**: random characters (24), three random words,
or Apple style.

## Import from another password manager

The vault can import:

| From | How to export it there | Import command |
|---|---|---|
| Bitwarden | Settings, Export vault, format **.json** (not "encrypted json") | `vault import bitwarden FILE.json` |
| Chrome, Edge | Settings, Passwords, Export passwords (CSV) | `vault import csv FILE.csv` |
| Firefox | Passwords (about:logins), the "..." menu, Export passwords (CSV) | `vault import csv FILE.csv` |
| Safari | File, Export, Passwords (CSV) | `vault import csv FILE.csv` |

What is brought over:

- **Bitwarden:** logins (title, username, password, websites, TOTP, notes),
  secure notes, cards and identities, with their custom fields. Encrypted
  exports are refused; export unencrypted.
- **CSV:** the URL, username and password columns, plus name, notes and
  one-time code columns when the file has them. Column order does not
  matter.

Imported websites use the exact-origin match mode. Edit an item to switch
it to whole-site matching.

**Delete the export file right after importing.** It holds every password
in plain text. Empty the recycle bin or trash too.

The desktop app can import as well; it asks for the file's path.
On iPhone and iPad, use **Settings > Import from Another App**
([chapter 14](14-phone-apps.md#import-from-another-app)). It also reads the
CSV that Apple's Passwords app exports.
