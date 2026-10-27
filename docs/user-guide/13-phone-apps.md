# 13. Phone and tablet apps

Secret Vault has apps for iPhone and iPad and for Android phones and
tablets, including foldables such as the Galaxy Z Fold and Flip and the
Pixel Fold. They keep the same encrypted vault as your computer, so you
can look up a password, copy a one-time code or fill a login in your
phone's browser.

Use them when:

- you want your logins and two-factor codes with you, not only at your desk;
- you want the phone's own AutoFill to fill passwords from Secret Vault in
  Safari, Chrome or another browser;
- you want a phone-only vault, without a computer at all.

> The phone apps are new and have not been tried on every device yet.
> Keep using test data, as for the rest of Secret Vault.

## Before you start

- **iPhone and iPad:** iOS or iPadOS 26 or later. The app isn't in the App
  Store yet; for now it is built from source with Xcode on a Mac (see
  [mobile.md](../mobile.md#ios)).
- **Android:** Android 9 or later. The app isn't on Google Play yet;
  download the `secret-vault-android` APK from the latest *Mobile* run on
  the project's GitHub Actions page and open it on the phone. Android asks
  you to allow installing apps from your browser or file manager once.
- **To use your computer's vault**, turn on sync on the computer first
  ([chapter 10](10-sync.md)) with a folder in iCloud Drive, OneDrive,
  Google Drive or Dropbox, and install that service's app on the phone.
  The phone uses the same synced file.

## Set up the app

The first screen offers two choices. Button names below are the iPhone's;
Android uses the same words in sentence case (for example *Use a vault from
my computer*).

### Use the vault from your computer

1. Tap **Use a Vault from My Computer**.
2. The file picker opens. Go to the synced folder (for example *iCloud
   Drive*, *OneDrive* or *Drive*) and pick the vault file, for example
   `vault.svault`.
3. Type your master password and tap **Unlock**. This takes a few seconds:
   the phone does the same slow, deliberate key check as your computer.
4. The app offers Face ID, Touch ID or your fingerprint for next time.
   Turn it on if you like (see [Unlocking](#unlocking)).

From now on the app merges with that file whenever you open it, so an
item you add on the computer shows up on the phone and the other way round.

### Start a new vault on the phone

1. Tap **Create a New Vault**.
2. Choose a master password and type it twice. Use at least 12 characters,
   or four random words.
3. The next screen shows your **recovery code**. Write it on paper and keep
   it somewhere safe. It is the only way in if you forget the password, and
   it is shown only now. Tick **I wrote it down** to go on.
4. Choose whether to unlock with Face ID, Touch ID or your fingerprint.

To use this vault on a computer later, turn on sync in **Settings > Sync**
(below), then join it from the computer as described in
[chapter 10](10-sync.md#join-from-another-device).

## Unlocking

The app is locked when it starts, and locks itself 5 minutes after you
leave it (change this in **Settings > Lock After**).

- **Face ID, Touch ID or fingerprint.** If you turned it on, the app asks
  as soon as it opens. Cancel to type the password instead.
- **Master password.** Type it and tap **Unlock**.
- **Recovery code.** Tap **Use recovery code instead**.

Your face or fingerprint stands in for the password for up to 14 days.
After that, and whenever you add a new face or fingerprint to the phone,
the app asks for the master password once more. If an unlock method was
removed on another device, the vault gets a new key and the phone asks
for the password again too.

Security keys, TPM and phone passkeys are unlock methods of a particular
computer. The phone app lists them under **Settings > Unlock Methods** as
"on another device" and doesn't use them.

## Find and use your items

**On a phone**, the tabs at the bottom are **Items**, **Codes**,
**Generator**, **Settings** and a search button. On iPhone the tab bar
shrinks while you scroll.

**On a tablet, an unfolded foldable, or a wide split-screen window**, the
app shows the list and the item side by side. On iPad there are three
columns, as in the desktop app: categories, items, and the chosen item.
Folding or unfolding the phone switches between the two layouts without
losing your place.

To use an item:

1. Find it: scroll, tap a filter such as **Logins** or **Cards**, or search
   by name, username or website.
2. Tap it to open it.
3. Tap the copy button next to a field. Passwords, card numbers and codes
   are cleared from the clipboard after 60 seconds (change this in
   **Settings**). Tap the eye to show a hidden value.

To add an item, tap **+** (iPhone and iPad) or **New item** (Android) and pick
**Login**, **Secure note**, **Card** or **Identity**. A new login comes with
a strong generated password; tap the dice to make another.

To edit or delete an item, open it and tap **Edit**, or **Delete**. A
deleted item is deleted on every device that syncs this vault.

### One-time codes

The **Codes** tab shows the current code for every login that has one, with
a ring that empties as the code ages. Tap a code to copy it.

To add one, edit the login, and under **One-Time Codes** scan the QR code
the website shows (tap the QR button) or paste its setup key. The app shows
the current code so you can check it before you save.

On a half-folded Android foldable (tabletop position), the Codes tab shows
the chosen code large on the top half and the list on the bottom half.

### Password generator

The **Generator** tab makes a random password. Move the slider for length
and switch kinds of characters on or off to suit a site's rules, then tap
**Copy**.

## Fill passwords in other apps (AutoFill)

### Turn it on

- **iPhone and iPad:** in the app go to **Settings > Turn On AutoFill**,
  or open the Settings app, go to **General > AutoFill & Passwords** and
  switch on **Secret Vault**.
- **Android:** in the app go to **Settings > Use Secret Vault for
  autofill** and choose **Secret Vault**. (In Android's own settings this is under *Passwords,
  passkeys and accounts* or *Autofill service*, depending on the phone.)

### Fill a login

1. Open the website's sign-in page in your browser and tap the username
   field.
2. **iPhone:** a suggestion for the site may appear above the keyboard; tap
   it and confirm with Face ID or Touch ID. Or tap **Passwords** above the
   keyboard and pick **Secret Vault**.
   **Android:** tap the Secret Vault suggestion. If the vault is locked, tap
   **Unlock Secret Vault** first.
3. Pick the login. Secret Vault fills the username and password.

Secret Vault offers a login only on the websites saved in it (the **Websites**
section of the login), the same rule the browser extension uses, so a
look-alike site gets no suggestion. In apps that aren't web pages, nothing
is suggested automatically: search for the login, and if it is saved for a
different site, the app asks you to confirm before filling.

On iPhone and iPad, AutoFill unlocks only with Face ID or Touch ID. If
those are off, or the 14-day password check is due, open Secret Vault and
unlock it there once.

## Sync settings

**Settings > Sync** shows when the vault last synced.

- **Sync Now** merges straight away. Pulling down on the item list does the
  same.
- **Use My Computer's Synced File** (Android: *Sync with my computer*),
  shown when sync is off, picks a synced vault file in the file picker.
- **Save a Synced Copy to iCloud Drive** (Android: *Start a new synced
  copy*), shown when sync is off, puts this phone's vault in a folder you
  choose, for your other devices to join.
- If an item was changed on two devices at once, both versions are kept and
  one gets "(conflict)" after its title. Keep the right one and delete the
  other.
- If an unlock method was removed on another device, the app asks for your
  master password to take the new key.

## Differences between phones, tablets and computers

| | iPhone and iPad | Android | Linux and Windows desktop |
| --- | --- | --- | --- |
| Unlock with face or fingerprint | Face ID, Touch ID | Fingerprint, face (strong biometrics only) | Windows Hello on Windows |
| Unlock with security key, TPM, phone passkey | No | No | Yes |
| AutoFill in browsers | Yes, Face ID or Touch ID to unlock inside AutoFill | Yes, full unlock inside AutoFill | Browser extension |
| One-time codes in AutoFill | Yes | Not yet | No |
| Save a new login when you sign up in another app | Not yet | Not yet | Browser extension |
| Sync | iCloud Drive, OneDrive, Dropbox through Files | Google Drive, OneDrive, Dropbox through the file picker | Any synced folder |
| SSH and OpenPGP keys | Shown, not used | Shown, not used | Yes |
| Screenshots of the app | Allowed; hidden in the app switcher | Blocked | Allowed |
| Side-by-side layout | iPad, wide windows | Tablets, unfolded foldables, wide windows | Always |

## Things to know

- **Remove the vault from a phone** in **Settings > Remove Vault from This
  Device** (Android: *Remove the vault from this device*). Items that were never synced are lost. Your computer and the
  synced copy are not changed.
- **A lost or stolen phone** can't open the vault without your face,
  fingerprint or master password. The phone limits face and fingerprint
  attempts and then asks for its passcode.
- **Phone backups.** Android backups leave the vault out. iPhone backups
  include the encrypted vault file but not the Face ID or Touch ID key, so a
  phone restored from a backup asks for the master password. Sync, or the
  backups in [chapter 8](08-troubleshooting.md#back-up-your-vault), are the
  reliable way to keep a copy.
