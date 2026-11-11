#!/usr/bin/env bash
# Archive the iOS app for the App Store and upload it to App Store Connect
# (TestFlight), after mobile/scripts/build-ios.sh release:
#
#   APPLE_TEAM_ID=ABCDE12345 APPLE_API_KEY_P8=<base64 .p8> \
#   APPLE_API_KEY_ID=XXXXXXXXXX APPLE_API_ISSUER_ID=<uuid> mobile/scripts/testflight.sh
#
# Signing is automatic: with the App Store Connect API key, Xcode registers
# the app IDs, App Group and AutoFill capability if needed, makes the
# provisioning profiles and uses a cloud-managed distribution certificate.
# The key needs the Admin role for that (docs/apple-account.md).
#
# VAULT_UPLOAD=0 stops after making the signed .ipa in mobile/ios/build/export.
# VAULT_UNSIGNED=1 needs no secrets: it only archives for a real device
# without signing, which pull requests use to check the device build.
set -euo pipefail
cd "$(dirname "$0")/../ios"

if [ "${VAULT_UNSIGNED:-0}" = 1 ]; then
    auth=()
    signing=(CODE_SIGNING_ALLOWED=NO)
else
    : "${APPLE_TEAM_ID:?}" "${APPLE_API_KEY_P8:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER_ID:?}"
    key=${RUNNER_TEMP:-$(mktemp -d)}/AuthKey_$APPLE_API_KEY_ID.p8
    base64 --decode <<<"$APPLE_API_KEY_P8" >"$key"
    trap 'rm -f "$key"' EXIT
    auth=(-allowProvisioningUpdates
        -authenticationKeyPath "$key"
        -authenticationKeyID "$APPLE_API_KEY_ID"
        -authenticationKeyIssuerID "$APPLE_API_ISSUER_ID")
    signing=(CODE_SIGN_STYLE=Automatic DEVELOPMENT_TEAM="$APPLE_TEAM_ID")
fi

mkdir -p build/logs
xcodegen generate
xcodebuild -project SecretVault.xcodeproj -scheme SecretVault -configuration Release \
    -destination 'generic/platform=iOS' -archivePath build/SecretVault.xcarchive \
    ${auth[@]+"${auth[@]}"} "${signing[@]}" VAULT_SKIP_RUST=1 \
    archive 2>&1 | tee build/logs/archive.log | grep -E "^(\*\*|error:|warning: .*[Ss]ign)" || true
test -d build/SecretVault.xcarchive/Products/Applications/SecretVault.app ||
    { echo "archive failed; see build/logs/archive.log" >&2; tail -50 build/logs/archive.log >&2; exit 1; }

app=build/SecretVault.xcarchive/Products/Applications/SecretVault.app
echo "Version $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Info.plist")" \
    "build $(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Info.plist")"
test -d "$app/PlugIns/SecretVaultAutoFill.appex"
if [ "${VAULT_UNSIGNED:-0}" = 1 ]; then
    echo "Unsigned device archive OK"
    exit 0
fi
# The extension must be inside, with the AutoFill and App Group entitlements.
codesign -d --entitlements - --xml "$app/PlugIns/SecretVaultAutoFill.appex" >build/logs/autofill-entitlements.plist
grep -q autofill-credential-provider build/logs/autofill-entitlements.plist
grep -q group.dev.passwordvault.app build/logs/autofill-entitlements.plist

opts=build/ExportOptions.plist
cp ExportOptions.plist "$opts"
plutil -replace teamID -string "$APPLE_TEAM_ID" "$opts"
if [ "${VAULT_UPLOAD:-1}" = 0 ]; then
    plutil -replace destination -string export "$opts"
fi
xcodebuild -exportArchive -archivePath build/SecretVault.xcarchive -exportPath build/export \
    -exportOptionsPlist "$opts" "${auth[@]}" 2>&1 | tee build/logs/export.log | grep -E "^(\*\*|error:)|Upload" || true
grep -q "EXPORT SUCCEEDED" build/logs/export.log ||
    { echo "export or upload failed; see build/logs/export.log" >&2; tail -50 build/logs/export.log >&2; exit 1; }
if [ "${VAULT_UPLOAD:-1}" = 0 ]; then
    ls -l build/export
else
    echo "Uploaded. App Store Connect processes the build for a few minutes, then it appears in TestFlight."
fi
