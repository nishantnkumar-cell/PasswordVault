# Signing and notarizing the macOS packages

Release packages for macOS are signed **ad hoc** today: the app has a
signature (Apple silicon needs one to run it) but no developer identity, and
the `.pkg` is not signed. That is why users have to allow the installer once
under System Settings > Privacy & Security (see
[user-guide/13-macos.md](user-guide/13-macos.md)). Signing with an Apple
Developer ID and notarizing removes that step: the installer opens with a
double-click like any other.

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
and `PT_DENY_ATTACH`, none of which the hardened runtime blocks. (A Secure
Enclave slot would need a keychain-access-groups entitlement and a
provisioning profile; it is not built yet.)

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

To sign releases in the `macos-package` job, add these repository secrets
and import the certificates into a temporary keychain before `package.sh`
runs:

| Secret | What |
|---|---|
| `MACOS_CERTS_P12` | Both Developer ID certificates with their private keys, exported as one `.p12`, base64 |
| `MACOS_CERTS_PASSWORD` | The `.p12` password |
| `MACOS_NOTARY_KEY` | The App Store Connect API key (`.p8`), base64 |
| `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER` | Its key ID and issuer ID |

The job then sets `DEVELOPER_ID_APP` and `DEVELOPER_ID_INSTALLER`, runs
`notarytool submit --wait` and `stapler staple` on the `.pkg`. This is not
wired up yet, because the project has no Developer ID.
