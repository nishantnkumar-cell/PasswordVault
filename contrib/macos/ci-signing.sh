#!/usr/bin/env bash
# Developer ID signing and notarization for the macOS packages in CI
# (docs/macos-signing.md). Two steps around contrib/macos/package.sh:
#
#   contrib/macos/ci-signing.sh import     before package.sh
#   contrib/macos/ci-signing.sh notarize   after it
#
# `import` puts the Developer ID certificates from MACOS_CERTS_P12 (base64
# .p12) and MACOS_CERTS_PASSWORD into a keychain made for this run, and
# writes DEVELOPER_ID_APP and DEVELOPER_ID_INSTALLER to $GITHUB_ENV, which
# makes package.sh sign. Without the secrets it prints a warning and does
# nothing, so the build stays ad hoc signed as before.
#
# `notarize` sends the .pkg to Apple's notary service with the App Store
# Connect API key (APPLE_API_KEY_P8 base64, APPLE_API_KEY_ID,
# APPLE_API_ISSUER_ID), waits, staples the ticket to the .pkg and to the app
# inside the .tar.gz, and checks both with Gatekeeper. Without the key it
# warns and leaves them signed but not notarized.
set -euo pipefail
cd "$(dirname "$0")/../.."

warn() { echo "::warning title=$1::$2"; }
keychain=${RUNNER_TEMP:-/tmp}/vault-signing.keychain-db

import() {
    if [ -z "${MACOS_CERTS_P12:-}" ] || [ -z "${MACOS_CERTS_PASSWORD:-}" ]; then
        warn "macOS build not signed" "MACOS_CERTS_P12 and MACOS_CERTS_PASSWORD are not set, so the .pkg is unsigned and the app ad hoc signed (docs/macos-signing.md)"
        return 0
    fi
    local p12=${RUNNER_TEMP:-/tmp}/developer-id.p12
    local pass
    pass=$(openssl rand -hex 24)
    base64 --decode <<<"$MACOS_CERTS_P12" >"$p12"
    security create-keychain -p "$pass" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$pass" "$keychain"
    security import "$p12" -k "$keychain" -P "$MACOS_CERTS_PASSWORD" -f pkcs12 \
        -T /usr/bin/codesign -T /usr/bin/productbuild -T /usr/bin/productsign
    rm -f "$p12"
    # Let codesign and productbuild use the keys without a dialog.
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$pass" "$keychain" >/dev/null
    # Search this keychain first, then the usual ones.
    # shellcheck disable=SC2046
    security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')

    local ids app inst
    ids=$(security find-identity -v "$keychain")
    app=$(sed -n 's/.*"\(Developer ID Application: .*\)"$/\1/p' <<<"$ids" | head -1)
    inst=$(sed -n 's/.*"\(Developer ID Installer: .*\)"$/\1/p' <<<"$ids" | head -1)
    if [ -z "$app" ] || [ -z "$inst" ]; then
        echo "The .p12 must hold both a Developer ID Application and a Developer ID Installer certificate with their private keys; it has:" >&2
        echo "$ids" >&2
        exit 1
    fi
    echo "Signing as \"$app\" and \"$inst\""
    {
        echo "DEVELOPER_ID_APP=$app"
        echo "DEVELOPER_ID_INSTALLER=$inst"
        echo "VAULT_SIGNING_KEYCHAIN=$keychain"
    } >>"${GITHUB_ENV:-/dev/null}"
}

notarize() {
    local ver=${VAULT_VERSION:?}
    local pkg=target/packages/SecretVault-$ver-macos.pkg
    local tgz=target/packages/secret-vault-$ver-macos-universal.tar.gz
    if [ -z "${DEVELOPER_ID_INSTALLER:-}" ]; then
        return 0 # not signed, nothing to notarize (import warned)
    fi
    if [ -z "${APPLE_API_KEY_P8:-}" ] || [ -z "${APPLE_API_KEY_ID:-}" ] || [ -z "${APPLE_API_ISSUER_ID:-}" ]; then
        warn "macOS build not notarized" "APPLE_API_KEY_P8, APPLE_API_KEY_ID and APPLE_API_ISSUER_ID are not set, so the signed .pkg is not notarized (docs/macos-signing.md)"
        return 0
    fi
    local key=${RUNNER_TEMP:-/tmp}/AuthKey_$APPLE_API_KEY_ID.p8
    base64 --decode <<<"$APPLE_API_KEY_P8" >"$key"
    # Notarizing the .pkg also notarizes the app inside it, which is the same
    # signed bundle as the one in the .tar.gz.
    local out
    out=$(xcrun notarytool submit "$pkg" --key "$key" --key-id "$APPLE_API_KEY_ID" \
        --issuer "$APPLE_API_ISSUER_ID" --wait --timeout 30m --output-format json) || true
    echo "$out"
    local id status
    id=$(sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' <<<"$out" | head -1)
    status=$(sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' <<<"$out" | head -1)
    if [ "$status" != Accepted ]; then
        # Apple's log says which file and why.
        [ -z "$id" ] || xcrun notarytool log "$id" --key "$key" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" || true
        rm -f "$key"
        echo "notarization failed: ${status:-no answer}" >&2
        exit 1
    fi
    rm -f "$key"
    xcrun stapler staple "$pkg"
    xcrun stapler validate "$pkg"
    spctl --assess --type install --verbose=2 "$pkg"

    # Staple the app in the archive too, so it opens offline the first time.
    local work name
    work=$(mktemp -d)
    tar -C "$work" -xzf "$tgz"
    name=$(basename "$tgz" .tar.gz)
    if xcrun stapler staple "$work/$name/Secret Vault.app"; then
        spctl --assess --type execute --verbose=2 "$work/$name/Secret Vault.app"
        tar -C "$work" -czf "$tgz" "$name"
    else
        warn "Archive app not stapled" "Gatekeeper checks it online the first time it opens"
    fi
    rm -rf "$work"
}

case ${1:-} in
    import) import ;;
    notarize) notarize ;;
    *)
        echo "usage: ci-signing.sh import|notarize" >&2
        exit 2
        ;;
esac
