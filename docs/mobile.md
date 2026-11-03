# Phone and tablet apps

Secret Vault for iPhone, iPad and Android phones and tablets. This page is
the technical reference: how the apps are built, how they keep the vault
safe, and how to build them. The user-facing walkthrough is
[Phone and tablet apps](user-guide/14-phone-apps.md).

## Architecture

```
mobile/
  android/   Kotlin, Jetpack Compose, Material 3 (Gradle project)
  ios/       Swift, SwiftUI, iOS 26 (XcodeGen spec; the .xcodeproj is generated)
  scripts/   build-android.sh, build-ios.sh
crates/vault-mobile/   Rust core shared by both apps, exposed with UniFFI
```

There is no `vaultd` on a phone. Each app links `vault-mobile`, a thin
UniFFI layer over `vault-core`, and holds the open vault in its own process
while it is unlocked. The vault file format, the crypto, merging and the
autofill origin rules are the same code as on the desktop, so a vault made
on a phone opens on a computer and the other way round.

`vault-mobile` exposes:

| Object or function | What it does |
| --- | --- |
| `LockedVault(bytes)` | Parses a vault file; lists unlock methods; `unlock_password`, `unlock_recovery`, `resume` (quick unlock) |
| `VaultSession` | An unlocked vault: `items`, `item`, `save_item`, `delete_item`, `totp`, `logins_for` (origin-matched, for AutoFill), `to_bytes`, `park`, `merge` |
| `create_vault` | A new vault with a password slot and a recovery code, at the desktop's default Argon2id cost |
| `generate_password`, `generate_styled`, `password_strength` | The generator: random characters, three random words or Apple style (vault-core `generator::Style`), and its strength in bits |
| `preview_totp`, `code_label`, `VaultSession::add_code` | One-time codes: check a setup key, read the issuer and account from an `otpauth://` link, and add a code to a login or a new login from the Codes screen |
| `host_of` | Helper for the editor |

Errors arrive as one `MobileError` type whose message is a finished sentence
for the user.

The apps only open password and recovery-code slots. Security-key, TPM and
phone-passkey slots belong to the computer they were made on and are listed
as "on another device".

## Quick unlock on phones

On a computer, quick unlock parks the vault key in `vaultd`'s memory. A phone
app can be closed by the system at any time, so the phone apps keep the
parked key on disk, encrypted, and the key that opens it in the platform
keystore:

1. After an unlock, `VaultSession.park(wrap)` seals the vault key under a
   fresh 32-byte `wrap` key ([format.md section 4.6](format.md)). The
   128-byte result goes to app-private storage (Android `noBackupFilesDir`,
   the iOS App Group container).
2. `wrap` goes into the keystore:
   - **Android:** an AES-256-GCM key in the Android Keystore
     (StrongBox when the phone has one) that needs `BIOMETRIC_STRONG` for
     every use and is invalidated by a new enrollment. `wrap` is stored
     encrypted under it.
   - **iOS:** a Keychain item with `.biometryCurrentSet` and
     `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, shared with the
     AutoFill extension through a keychain access group.
3. To unlock, the app asks for Face ID, Touch ID or the fingerprint,
   receives `wrap`, and calls `LockedVault.resume(parked, wrap)`. That
   checks the parked key against the current file's header MAC and body, so
   it fails after a key rotation (a revoke synced from another device) or
   if the file was replaced; the app then turns quick unlock off.
4. Quick unlock needs the master password again 14 days after the last
   full unlock, like Windows Hello's time limit on the desktop.

Nothing about quick unlock is written to the vault file or synced.

## Sync

The apps use the same folder sync as the desktop ([sync.md](sync.md)): one
encrypted copy in a folder a cloud drive keeps in sync. Each app keeps its
own local file and merges the copy:

- **Android:** the Storage Access Framework. The user picks the copy (or
  creates one) in the system file picker, which works with Google Drive,
  OneDrive, Dropbox and any other installed document provider; the app keeps
  a persisted URI permission.
- **iOS:** the Files picker with a security-scoped bookmark, read and
  written through `NSFileCoordinator` so iCloud Drive downloads the newest
  version first. OneDrive and Dropbox work through their Files extensions.

The apps merge when unlocked, when they come back to the foreground, on
pull to refresh and before each save. A copy that was re-keyed on another
device needs the master password once (`merge(bytes, password)`).

## AutoFill

| | Android | iOS |
| --- | --- | --- |
| API | `AutofillService` | AuthenticationServices credential provider extension |
| Page identity | `webDomain` from the browser's view structure | Service identifiers iOS passes in |
| Suggestions | Up to five origin-matched logins while the vault is unlocked, plus "Search Secret Vault"; while locked, one "Unlock Secret Vault" entry | QuickType bar from `ASCredentialIdentityStore` (usernames and domains only), and the list in the AutoFill sheet |
| Unlock inside AutoFill | Full unlock screen, biometrics or password | Face ID or Touch ID only (see below) |
| One-time codes | Not yet | Yes (`ProvidesOneTimeCodes`) |
| Saving new logins from other apps | Not yet | Not yet |

Matching uses `logins_for`, which applies the browser extension's origin
rules ([browser.md](browser.md)). Native apps, and pages for which the
browser reports no domain, get no automatic suggestions; the user searches,
and choosing a login saved for another site asks for confirmation first.

The iOS AutoFill extension does not offer the master password: an
Argon2id unlock uses 256 MiB, more than iOS allows an extension, which
would be killed mid-unlock. It unlocks with Face ID or Touch ID, and
otherwise tells the user to open the app.

## Screens and layouts

Both apps follow the desktop app's palette and item tiles.

| Window | Android | iOS / iPadOS |
| --- | --- | --- |
| Phone, folded foldable | Navigation bar, list then detail | Liquid Glass tab bar with a search tab, list then detail |
| Tablet, unfolded foldable, wide split screen | Navigation rail, list and detail side by side (`ListDetailPaneScaffold`, which avoids the hinge) | Three columns (`NavigationSplitView`): categories, list, detail |
| Half-folded (tabletop) | Codes screen shows the chosen code large above the fold and the list of codes below | Not applicable |

Window size classes, not device models, choose the layout, so split
screen, Stage Manager, desktop-mode Android and future foldables get the
right one.

## Protections on the device

- The vault file is in app-private storage: Android excludes it from
  backups (`allowBackup=false`, data extraction rules); iOS stores it with
  `completeFileProtectionUntilFirstUserAuthentication`.
- The app locks after the auto-lock time in the background (default 5
  minutes, or immediately).
- Android sets `FLAG_SECURE`, so screenshots, screen recording and the
  recents thumbnail show nothing. iOS covers the window in the app
  switcher; iOS has no way to block screenshots.
- Copied secrets clear after the chosen time (default 60 s). iOS marks them
  local-only so Universal Clipboard does not send them to a Mac; Android 13+
  marks them sensitive so the clipboard preview hides them.

## Building

### Toolchain

Keep these at the latest stable releases. Android library versions are in
`mobile/android/gradle/libs.versions.toml`; the Mobile CI workflow prints
the newest Google Maven versions in its "Latest library versions" step.

| | Version |
| --- | --- |
| Rust | stable, with the Android or iOS targets |
| UniFFI | 0.32 |
| Android | JDK 21, Gradle 9.8, Android Gradle plugin 9.4 (built-in Kotlin), compile SDK 37, target SDK 36, NDK (latest), `cargo-ndk`; minimum Android 9 (API 28) |
| iOS | Xcode 26 or later (tested with 27.1), XcodeGen; minimum iOS and iPadOS 26 |

### Android

```sh
cargo install cargo-ndk
cd mobile/android
./gradlew assembleDebug          # runs mobile/scripts/build-android.sh first
```

The APK is in `app/build/outputs/apk/`. The release build is signed with
the debug key unless a release key is given (below).

### Release signing

Releases attach `secret-vault-<version>-android.apk`, signed with the
project's own release key: a free, self-made key, not a Google Play key.
Android only installs an update signed with the same key as the installed
app, so **every release must be signed with this one key, forever**. If
it is lost, nobody can update their installed app; they have to uninstall
(losing anything not synced) and install again.

The key is kept in two GitHub Actions secrets, never in the repository.
`.github/workflows/release.yml` decodes it for the `android` job only, runs
`mobile/scripts/build-android-release.sh`, and deletes it. The script
refuses an APK signed with a debug key and puts the certificate's SHA-256
fingerprint in the release description. Without the secrets, a release is
still published, without the APK, and the run shows a warning. The Mobile
workflow checks the same signing path on every change with a throwaway key.

To set it up once, on the Mac (Android Studio's Java has `keytool`) or any
computer with a JDK:

1. Make the key. Pick a long password and type it when asked (twice):

   ```sh
   export PATH="/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin:$PATH"   # macOS, if keytool isn't found
   keytool -genkeypair -keystore secret-vault-release.jks -alias secret-vault \
     -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Secret Vault"
   ```

   Keep it out of the repository folder (for example in `~/Documents`).
2. Copy the key as text: `base64 -i secret-vault-release.jks | pbcopy`
   (macOS) or `base64 -w0 secret-vault-release.jks` (Linux).
3. Back it up: paste that text and the password into a secure note in your
   vault, and keep a copy of the `.jks` file somewhere off this computer
   (for example a USB stick). GitHub never shows a secret again.
4. On GitHub open the repository's **Settings > Secrets and variables >
   Actions** and click **New repository secret** twice:
   - `ANDROID_KEYSTORE_BASE64`: paste the text from step 2.
   - `ANDROID_KEYSTORE_PASSWORD`: the password from step 1.

   With another alias, add `ANDROID_KEY_ALIAS` too (default
   `secret-vault`). Keys made with the command above have one password;
   the build uses the keystore password for the key.
5. Note the fingerprint, for checking releases against:
   `keytool -list -keystore secret-vault-release.jks -alias secret-vault`
   prints *Certificate fingerprint (SHA-256)*.

To build a signed APK by hand:

```sh
VAULT_ANDROID_KEYSTORE=~/Documents/secret-vault-release.jks \
VAULT_ANDROID_KEYSTORE_PASSWORD=... \
mobile/scripts/build-android-release.sh /tmp/secret-vault-android.apk
```

`versionCode` comes from the version (0.2.0 is 200), so betas of a version
share the code of the final release; Android installs those over each other
but refuses an older version over a newer one.

### iOS

```sh
brew install xcodegen
mobile/scripts/build-ios.sh      # XCFramework and Swift bindings into mobile/ios/Generated
cd mobile/ios && xcodegen generate && open SecretVault.xcodeproj
```

Set your team under Signing for both targets (the app and
`SecretVaultAutoFill`). The App Group `group.dev.passwordvault.app` and the
keychain group need a paid developer account; on a free account the app
runs without AutoFill and keeps its files in its own container.

### Trying it on a Mac by hand

`mobile/scripts/run-sim.sh` builds the app and opens it on one simulator
or emulator, shutting down any others first so it fits a Mac with 8 GB of
memory:

```sh
mobile/scripts/run-sim.sh ios                    # iPhone 18 Pro; or name another
mobile/scripts/run-sim.sh ios "iPad Pro 13-inch (M5)"
mobile/scripts/run-sim.sh android vault_pixel_fold   # an emulator from Android Studio
mobile/scripts/run-sim.sh stop                   # shut everything down
```

The iOS build is signed "to run locally" without a developer account. The
simulator honours those entitlements, so Secret Vault shows up under
Settings › General › AutoFill & Passwords; a build with
`CODE_SIGNING_ALLOWED=NO` (as CI uses) runs, but iOS doesn't list it as
an AutoFill provider. The Android app blocks screenshots; a debug build
allows them when started with
`adb shell am start -n dev.passwordvault.app/.MainActivity --ez dev.passwordvault.app.ALLOW_SCREENSHOTS true`.

Xcode 27 replaces the Simulator app with Device Hub (Xcode › Open
Developer Tool › Device Hub). Face ID is simulated from its Device menu:
choose Enrolled, then Matching Face or Non-matching Face. Xcode 27 also
adds an iPhone Duo simulator for the foldable layout.

### CI

`.github/workflows/mobile.yml` builds the Android debug and release APKs
with unit tests and lint on Linux, and the iOS app and its AutoFill
extension for the simulator on macOS. The release APK, signed with the
debug key, is uploaded as a build artifact; the workflow then rebuilds it
with a throwaway release key to check [release signing](#release-signing).

The same workflow then walks through each app the way a first-time user
would (create a vault, add a login with a one-time code and a card, open
Codes, Generator and Settings, lock and unlock) and saves a screenshot of
every screen:

- Android: `mobile/scripts/android-ui-test.sh` runs
  `app/src/androidTest/.../TourTest.kt` on phone, tablet and foldable
  emulators, the foldable both unfolded and folded.
- iOS: `mobile/scripts/ios-ui-test.sh` runs `UITests/TourTests.swift` on an
  iPhone and an iPad simulator, the iPad in landscape and portrait.

Each run makes up its own throwaway master password. The screenshots are
uploaded as build artifacts. Debug builds let a test turn off Android's
screenshot blocking; release builds never do.

These runs can't check Face ID, Touch ID or fingerprint unlock, AutoFill in
a real browser, the cloud file pickers, QR scanning with the camera, or the
half-folded (tabletop) posture. Try those on a real device.
