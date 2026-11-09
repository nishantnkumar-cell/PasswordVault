# Setting up the Apple Developer account

This is for the project owner. With a paid Apple Developer Program
membership, the project's GitHub Actions can:

- **sign and notarize the macOS downloads** (the `.pkg` and the app in the
  `.tar.gz`), so they open with a double-click instead of **Open Anyway**
  ([macos-signing.md](macos-signing.md));
- **build the iPhone and iPad app for TestFlight** and upload it to App
  Store Connect, so it installs from Apple's TestFlight app on a real
  iPhone, with **AutoFill** working ([mobile.md](mobile.md#ios)).

The Secure Enclave unlock method on Macs does not need the account at all:
it works in any build, signed or not.

Not covered by an Apple account, and unchanged: **Windows code signing**
(SmartScreen still warns once; it needs a separate certificate) and the
**Google Play Store** (needs a Google Play developer account). The Android
app stays on the Releases page.

Everything below is done once, by the account holder, in a web browser and
in Xcode on the Mac. It takes about an hour. Nothing here is a secret
except where it says so; never paste a secret into an issue, a pull request
or a chat.

Throughout, `ABCDE12345` stands for your **team ID** and "Alex Example" for
the name on the account.

## 1. Find your team ID

1. Sign in at <https://developer.apple.com/account>.
2. Scroll to **Membership details**. Copy the **Team ID**: ten letters and
   digits, like `ABCDE12345`.

It is not secret (it appears in every app you sign), but it is needed in
step 6.

## 2. Make the two Developer ID certificates (macOS downloads)

These sign the Mac app and the installer. Only the **Account Holder** can
make them, which on an individual membership is you.

1. On the Mac, open **Xcode**, then **Xcode > Settings… > Accounts**.
2. If your Apple Account is not listed, click **+**, choose **Apple
   Account**, and sign in.
3. Select your team (it shows "Alex Example (Personal Team)" only for a
   free account; a paid one shows your name and **Individual**), then click
   **Manage Certificates…**.
4. Click **+** at the bottom left and choose **Developer ID Application**.
   Wait until it appears in the list.
5. Click **+** again and choose **Developer ID Installer**.
6. Click **Done**.

Both certificates and their private keys are now in your login keychain.
They last five years.

## 3. Export them for GitHub (secret)

GitHub's Mac runner needs a copy of the two certificates with their
private keys, in one password-protected `.p12` file.

1. Open **Keychain Access** (Applications > Utilities).
2. In the sidebar pick **login**, and at the top pick **My Certificates**.
3. Find **Developer ID Application: Alex Example (ABCDE12345)** and
   **Developer ID Installer: Alex Example (ABCDE12345)**. Each has a
   disclosure triangle with a private key under it; that's what you want.
4. Select both certificates (Command-click the second), then right-click
   and choose **Export 2 items…**.
5. Save as `developer-id.p12` on the Desktop, format **Personal Information
   Exchange (.p12)**, and click **Save**.
6. Make up a long password for the file (for example from the vault's
   generator) and enter it twice. Keep it for step 6. Then enter your Mac
   login password to allow the export.
7. In **Terminal**, turn the file into text for GitHub:

   ```sh
   base64 -i ~/Desktop/developer-id.p12 | pbcopy
   ```

   The text is now on the clipboard for step 6.

After step 6, delete `developer-id.p12` from the Desktop and empty the
Trash. The certificates stay in your keychain.

## 4. Make an App Store Connect API key (secret)

One key does both jobs: notarizing the Mac downloads and uploading the
iPhone app.

1. Sign in at <https://appstoreconnect.apple.com>. The first time, accept
   the agreements it shows.
2. Go to **Users and Access**, then the **Integrations** tab, then **App
   Store Connect API** on the left, then **Team Keys**.
3. If asked, click **Request Access** and accept; then click **Generate API
   Key** (or **+**).
4. Name it `GitHub Actions` and give it the **Admin** role. Admin is
   needed so that Xcode on the runner can make the iPhone app's
   distribution certificate and provisioning profiles by itself; with a
   lower role the TestFlight upload fails with a signing error.
5. Click **Generate**. Copy these from the page:
   - the **Issuer ID** at the top of the list (a long ID with dashes);
   - the key's **Key ID** (ten characters).
6. Click **Download** next to the key. You get `AuthKey_<KeyID>.p8`. Apple
   lets you download it **only once**; keep it in your vault as a file
   attachment or a secure note.
7. In Terminal:

   ```sh
   base64 -i ~/Downloads/AuthKey_XXXXXXXXXX.p8 | pbcopy
   ```

If the key ever leaks, revoke it on the same page and make a new one.

## 5. Register the iPhone app (TestFlight and AutoFill)

The app and its AutoFill extension need App IDs with two capabilities, and
the App Store needs an app record. Do it by hand once so nothing is left
to chance.

**App Group.**

1. At <https://developer.apple.com/account/resources/identifiers/list>,
   click **+**, choose **App Groups**, **Continue**.
2. Description `Secret Vault`, identifier `group.dev.passwordvault.app`.
   **Continue**, **Register**.

**The app's ID.**

1. Click **+** again, choose **App IDs**, then **App**, **Continue**.
2. Description `Secret Vault`, **Explicit** Bundle ID
   `dev.passwordvault.app`.
3. Under **Capabilities**, tick **App Groups** and **AutoFill Credential
   Provider**. Click **Continue**, then **Register**.
4. Open the new ID again, click **Configure** next to **App Groups**, tick
   `group.dev.passwordvault.app`, **Continue**, **Save**.

**The AutoFill extension's ID.** Repeat the four steps above with
description `Secret Vault AutoFill` and bundle ID
`dev.passwordvault.app.autofill`, with the same two capabilities and the
same group.

If Apple says a bundle ID is already taken, someone else registered it
first; tell the maintainers, as the IDs are set in `mobile/ios/project.yml`
and the App Group in `mobile/ios/Shared/AppGroup.swift`.

**The app record.**

1. In App Store Connect go to **Apps**, click **+**, **New App**.
2. Platform **iOS**; name `Secret Vault` (if taken, try `Secret Vault
   Password Manager`; the name on the home screen stays "Secret Vault");
   primary language **English (U.K.)** or your choice; bundle ID
   `dev.passwordvault.app`; SKU `secret-vault`; **Full Access**.
3. Click **Create**.

## 6. Add the GitHub secrets

1. Open <https://github.com/nishantnkumar-cell/PasswordVault/settings/secrets/actions>
   (**Settings > Secrets and variables > Actions** in the repository).
2. For each row, click **New repository secret**, type the name exactly,
   paste the value, and click **Add secret**.

| Name | Value | Used for |
|---|---|---|
| `APPLE_TEAM_ID` | Team ID from step 1 | iPhone app |
| `MACOS_CERTS_P12` | The base64 text from step 3 | Mac downloads |
| `MACOS_CERTS_PASSWORD` | The `.p12` password from step 3 | Mac downloads |
| `APPLE_API_KEY_P8` | The base64 text from step 4 | Both |
| `APPLE_API_KEY_ID` | Key ID from step 4 | Both |
| `APPLE_API_ISSUER_ID` | Issuer ID from step 4 | Both |

GitHub never shows a secret again, and pull requests from forks don't get
them. Each one can be replaced later with **Update**.

## 7. Try it

**Mac downloads.** Every push to a pull request or to `main` now builds a
signed and notarized `.pkg`. Open any recent **CI** run in the **Actions**
tab, the **Packages / macos-package** job, and look at the **Notarize**
step: it ends with `source=Notarized Developer ID`. Download the
`macos-package` artifact at the bottom of the run, double-click the
`.pkg`: it should open straight into the installer.

**iPhone app.**

1. In the **Actions** tab pick **TestFlight** on the left, then **Run
   workflow**. Untick **Upload** for a first try, which only builds and
   signs; tick it to upload. Click **Run workflow**.
2. The run takes about 20 minutes. If it fails, open the job: the last
   lines name the problem, and the `testflight` artifact has the full logs.
3. After an upload, App Store Connect takes 5 to 30 minutes to process the
   build. You get an email; the build then shows under **Apps > Secret
   Vault > TestFlight**.
4. The first time, App Store Connect may show **Missing Compliance** next
   to the build. See [Export compliance](#export-compliance) below.
5. Under **TestFlight > Internal Testing**, click **+**, make a group
   called `Me`, and add yourself. Internal testers (up to 100 people on
   your team) need no review by Apple.
6. On the iPhone, install **TestFlight** from the App Store, open the
   invitation email on the phone, and tap **View in TestFlight**, then
   **Install**.
7. Open Secret Vault, then turn on AutoFill:
   [Fill passwords in other apps](user-guide/14-phone-apps.md#fill-passwords-in-other-apps-autofill).

Every version tag (`v0.2.0`, `v0.2.0-beta.2`, ...) now also uploads to
TestFlight. A TestFlight build expires after 90 days.

## Export compliance

Apple asks every app whether it uses encryption, because of US export
rules. `mobile/ios/project.yml` currently declares
`ITSAppUsesNonExemptEncryption: false`, which skips the question. Secret
Vault does use encryption (XChaCha20-Poly1305, Argon2id, AES-GCM), all
standard published algorithms, as a password manager whose main purpose is
protecting your own data. Whether that counts as exempt is a legal question
for you as the publisher. Apple's guide is at
<https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations>.
If you decide the app is not exempt, change the value to `true` in a pull
request; App Store Connect then asks a few questions per build, and France
needs an extra declaration. Internal TestFlight testing works either way.

## Later: the App Store

TestFlight is enough to use the app on your own devices. Putting it in the
App Store for everyone is a separate step, and Apple reviews every
version. When you are ready:

1. In App Store Connect, **Apps > Secret Vault > App Store**: fill in the
   description, keywords, support URL (the GitHub page works) and a
   privacy policy URL. The app collects nothing, so **App Privacy** is
   "Data Not Collected".
2. Add screenshots: 6.9-inch iPhone and 13-inch iPad. The CI tour
   (`ios-screenshots` artifact of the **Mobile** workflow) makes them, with
   placeholder data only.
3. Choose the build from TestFlight, answer the age rating questions, and
   click **Add for Review**, then **Submit**.

Remember the project's status note: the vault has not had a security
audit, so say so in the description if you publish before one.

## Renewals

The membership renews every year (USD 99). If it lapses, the Developer ID
certificates stop being usable for new builds (already notarized
downloads keep working), TestFlight builds stop installing, and the app is
removed from the App Store until you renew. The API key and Developer ID
certificates don't need renewing within five years.
