# 14. Phone and tablet apps

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
- **Android:** Android 9 or later. The app isn't on Google Play; install
  it from the project's Releases page as described in
  [Install the Android app](#android) below.
- **To use your computer's vault**, turn on sync on the computer first
  ([chapter 10](10-sync.md)) with a folder in iCloud Drive, OneDrive,
  Google Drive or Dropbox, and install that service's app on the phone.
  The phone uses the same synced file.

## Install the Android app

The Android app is published on the project's
[Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases)
as an APK file (an Android app package), from version `0.2.0-beta.2` on.
Installing an app from outside Google Play is called *sideloading*. It is
free and needs no Google account.

### Android

1. On the phone, open the
   [Releases page](https://github.com/nishantnkumar-cell/PasswordVault/releases)
   in Chrome (or any browser). The newest version is at the top.
2. Under **Assets**, tap `secret-vault-<version>-android.apk`, for example
   `secret-vault-0.2.0-beta.2-android.apk`. If Chrome says the file may be
   harmful, tap **Download anyway**.
3. When the download finishes, tap **Open** (or open it later from the
   *Files* app, under *Downloads*).
4. The first time, Android says that for your security the phone isn't
   allowed to install unknown apps from this source. Tap **Settings**, turn
   on **Allow from this source**, then go back. You only do this once for
   each browser or file manager; you can turn it off again afterwards in
   *Settings > Apps > Special app access > Install unknown apps*.
5. Tap **Install**. Google Play Protect may say it hasn't seen this app
   before or that the developer is unrecognised; tap **More details** and
   then **Install anyway**. (It may offer to send the app for a scan; that
   is up to you.)
6. Tap **Open**, or find **Secret Vault** in your apps, and carry on with
   [Set up the app](#set-up-the-app).

Menu names differ a little between phone makers (Samsung calls the switch
*Allow permission*), but the steps are the same.

**Checking the app (optional).** Every Secret Vault APK is signed with the
same project key. The release's description ends with the key's SHA-256
fingerprint, and the APK is listed in `SHA256SUMS.txt` like every other
download (see [Checking a download](11-versions-and-upgrades.md#checking-a-download-optional)).
On a computer with Java or Android Studio installed you can compare the
key yourself: `keytool -printcert -jarfile secret-vault-<version>-android.apk`
prints a *SHA256* line that must match the fingerprint in the release
description.

**Updating.** Download and install the newer APK the same way, over the top
of the old one. Your vault, quick unlock and settings stay. The app doesn't
check for updates itself; watch the Releases page (on GitHub, **Watch >
Custom > Releases** sends you an email for each new version).

**If Android says "App not installed" or that the package conflicts with
an existing one,** you have a copy from somewhere else: one built by hand,
or downloaded from a GitHub Actions run before the app was on the Releases
page. Those are signed with a different key, so Android won't update them.
Make sure everything on that phone is synced to your computer
([Sync settings](#sync-settings)) or that you have a backup, because
uninstalling deletes the vault on the phone. Then uninstall the old Secret
Vault, install the APK from the Releases page, and set it up again with
**Use a vault from my computer**.

Google has announced that certified Android phones will only install apps
from verified developers, rolling out country by country from late 2026.
If your phone refuses to install the APK for that reason, please report
it on the project's Issues page.

There's no app store version for iPhone and iPad yet; on those the app is
built from source (see [mobile.md](../mobile.md#ios)).

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

While the vault is unlocked, the app icon (the white keyhole) shows in
green: at the top left of the Items screen on iPhone and Android, and in the
status pill at the bottom of the sidebar on iPad. Tap it on the Items screen
to lock the vault. On the lock screen the icon is red.

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

To add a code from the Codes tab:

1. On the website, turn on two-factor sign-in (it may be called 2-step
   verification or an authenticator app). The site shows a QR code.
2. In Secret Vault, open **Codes** and tap **+** (iPhone and iPad) or
   **Add code** (Android). With no codes yet, the button is in the middle
   of the screen.
3. Tap **Scan QR Code** (iPhone and iPad) or the QR button (Android) and
   point the camera at the site's QR code. If you can't scan it, tap "Can't
   scan?" (or similar) on the website and paste the setup key it shows
   instead.
4. The app shows the current code so you can check it. Type it into the
   website to finish turning on two-factor sign-in.
5. Under **Save To**, keep **A new login** and give it a name and account,
   or pick the login you already have for that site. A login only shows
   in the list if it has no code yet. When the QR code names the site, the
   name and account are filled in for you, and if exactly one of your
   logins matches, it is picked.
6. Tap **Save**.

Keeping the code on the same login as the password lets AutoFill offer the
code right after the password (iPhone and iPad).

You can also add or replace a code by editing a login: under **One-Time
Codes**, scan the QR code or paste the setup key.

**iPhone and iPad:** you can also set up a code straight from a website's
QR code or setup link. Open the Settings app, go to **General > AutoFill &
Passwords > Set Up Codes In** and choose **Secret Vault**. From then on,
when you point the Camera at a setup QR code (or tap a setup link) and
choose **Set up verification code**, Secret Vault opens a new login with
the code, the site's name and your account already filled in. Add the
password if you want it saved too, then tap **Save**. If the vault is
locked, it asks you to unlock first. Android has no system-wide setting
like this; scan the QR code from the login's edit screen instead.

On a half-folded Android foldable (tabletop position), the Codes tab shows
the chosen code large on the top half and the list on the bottom half.

### Password generator

The **Generator** tab makes a password in one of three styles. Pick one at
the top ([which to choose](03-items.md#password-generator)):

- **Random**: move the slider for length and switch kinds of characters on
  or off to suit a site's rules.
- **3 Words** (Android: **3 words**): three random words, the UK NCSC's
  advice, such as `CupFishBiscuit`. Change the number of words, what goes
  between them, capitals, and an optional digit and symbol at the end.
- **Apple Style** (Android: **Apple style**): such as
  `fokjyb-Xewpud-hamu4s`, easy to type on a phone keyboard.

The text under the choice says how strong the style is. Tap **New** for
another password and **Copy** to copy it. The dice button in the item
editor, and the password a new login starts with, use the style you picked
here. On Android the random style's own settings are not remembered for the
editor, which uses 20 characters of every kind.

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

If no suggestion appears, check that **Unlock with Face ID** (or Touch ID)
and **Suggest Logins Above the Keyboard** are on in the app's
**Settings**, and that the login's website is the site you are on. Then
open the app once: it tells iOS about your logins each time it opens
unlocked.

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

| | iPhone and iPad | Android | Computers (Linux, Windows, macOS) |
| --- | --- | --- | --- |
| Unlock with face or fingerprint | Face ID, Touch ID | Fingerprint, face (strong biometrics only) | Windows Hello on Windows, Touch ID on a Mac |
| Unlock with security key, TPM, phone passkey | No | No | Yes |
| AutoFill in browsers | Yes, Face ID or Touch ID to unlock inside AutoFill | Yes, full unlock inside AutoFill | Browser extension |
| One-time codes in AutoFill | Yes | Not yet | No |
| Set up a code from the camera or a link | Yes ("Set Up Codes In") | No, scan in the app | No, paste in the app |
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
