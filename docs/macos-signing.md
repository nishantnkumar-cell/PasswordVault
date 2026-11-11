# Signing and notarizing the macOS packages

CI signs the macOS packages with the project's Apple **Developer ID** and
notarizes them when the Apple secrets are set (see
[apple-account.md](apple-account.md) for setting them up). A signed and
notarized `.pkg` opens with a double-click, and the app in the `.tar.gz`
opens without the "cannot be checked" message.

Without the secrets (forks, or before the account was set up) the build
falls back to what it did before: the app is signed **ad hoc** (Apple
silicon needs a signature to run it, but it names no developer) and the
`.pkg` is not signed, so users allow it once under System Settings >
Privacy & Security (see [user-guide/13-macos.md](user-guide/13-macos.md)).
The job then shows a warning on the run.

This is for maintainers. Nothing here is needed to build or use Secret Vault.

## What the project owner needs

1. **Apple Developer Program membership** (individual or organisation),
   USD 99 a year, at <https://developer.apple.com/programs/>. An individual
   membership signs as the member's own legal name, which macOS shows to
   users; an organisation needs a D-U-N-S number.
2. Two certificates, made in Xcode (Settings > Accounts > Manage
   Certificates) or on the developer website, by the account holder:
   - **Developer ID Application**: signs the app and its programs.
   - **Developer ID Installer**: signs the `.pkg`.
3. Credentials for Apple's notary service, one of:
   - an **App Store Connect API key** (Users and Access > Integrations >
     Keys: the `.p8` file, its key ID and the issuer ID), recommended for CI;
   - or the Apple ID, an **app-specific password** (account.apple.com >
     Sign-In and Security) and the **team ID**.

## Signing a build

With both certificates in the login keychain:

```sh
export DEVELOPER_ID_APP="Developer ID Application: Alex Example (ABCDE12345)"
export DEVELOPER_ID_INSTALLER="Developer ID Installer: Alex Example (ABCDE12345)"
contrib/macos/package.sh 0.3.0
```

`package.sh` then signs every program and the app with the hardened runtime
and a secure timestamp, and signs the `.pkg`. No entitlements are needed:
vaultd uses Touch ID (LocalAuthentication), USB security keys (IOKit HID)
and `PT_DENY_ATTACH`, none of which the hardened runtime blocks. `vault-se`,
the Secure Enclave helper, uses CryptoKit keys that are not stored in the
keychain, so it needs no keychain-access-groups entitlement or
provisioning profile either.

## Notarizing

```sh
xcrun notarytool submit target/packages/SecretVault-0.3.0-macos.pkg \
    --key AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-uuid> --wait
xcrun stapler staple target/packages/SecretVault-0.3.0-macos.pkg
spctl --assess --type install --verbose target/packages/SecretVault-0.3.0-macos.pkg
```

Stapling attaches the notary ticket, so the installer opens without asking
Apple first. The `.tar.gz` cannot be stapled; the app inside it is checked
online the first time it opens.

## In CI

The `macos-package` job in `.github/workflows/package.yml` (run by CI for
every push and pull request, and by the release workflow for a tag) does
this with `contrib/macos/ci-signing.sh`:

1. `ci-signing.sh import` puts the certificates from `MACOS_CERTS_P12` into
   a keychain made for the run and sets `DEVELOPER_ID_APP` and
   `DEVELOPER_ID_INSTALLER`, so `package.sh` signs.
2. `package.sh` builds and signs both packages.
3. `ci-signing.sh notarize` submits the `.pkg` with the App Store Connect
   API key, waits for Apple, staples the ticket to the `.pkg` and to the app
   inside the `.tar.gz`, and checks both with `spctl`. If Apple rejects the
   submission, the job prints Apple's log and fails.
4. The keychain is deleted at the end of the job.

| Secret | What |
|---|---|
| `MACOS_CERTS_P12` | Both Developer ID certificates with their private keys, exported as one `.p12`, base64 |
| `MACOS_CERTS_PASSWORD` | The `.p12` password |
| `APPLE_API_KEY_P8` | The App Store Connect API key (`.p8`), base64 |
| `APPLE_API_KEY_ID`, `APPLE_API_ISSUER_ID` | Its key ID and issuer ID |

**Pull requests never get these secrets.** A pull request builds the code,
which runs every dependency's build script, so the workflows pass the
secrets only to pushes, tags and manual runs: on a pull request the Mac
packages are signed ad hoc and the iPhone app is archived without signing.
Third-party actions in the workflows are pinned to commit SHAs, which
Dependabot (`.github/dependabot.yml`) keeps up to date.

For a second lock, make the secrets *environment* secrets: in the repository's
Settings, Environments, create `release`, allow only the `main` branch and
`v*` tags to deploy to it, tick "Required reviewers" with yourself, and move
the five secrets there; then add `environment: release` to the signing jobs.
That needs repository settings, so it is left to the owner.

The same API key uploads the iPhone app to TestFlight
([mobile.md](mobile.md#testflight)). Without the certificates the job warns
"macOS build not signed"; with them but without the API key it warns
"macOS build not notarized".
