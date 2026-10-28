#!/usr/bin/env bash
# Build the Android release APK signed with the release key, for publishing.
#
#   mobile/scripts/build-android-release.sh OUT.apk
#
# Needs VAULT_ANDROID_KEYSTORE (path to the keystore) and
# VAULT_ANDROID_KEYSTORE_PASSWORD; VAULT_ANDROID_KEY_ALIAS defaults to
# secret-vault and VAULT_ANDROID_KEY_PASSWORD to the keystore password.
# VAULT_VERSION, if set, becomes the app's version name. Refuses an APK signed
# with a debug key, then prints the signing certificate's SHA-256 fingerprint
# (the one users compare, docs/user-guide/14-phone-apps.md) and writes it to
# OUT.apk.cert.txt. See docs/mobile.md#release-signing.
set -euo pipefail

out=${1:?usage: build-android-release.sh OUT.apk}
out=$(realpath -m "$out")
for var in VAULT_ANDROID_KEYSTORE VAULT_ANDROID_KEYSTORE_PASSWORD; do
    [ -n "${!var:-}" ] || { echo "build-android-release.sh: set $var (docs/mobile.md#release-signing)" >&2; exit 1; }
done
test -s "$VAULT_ANDROID_KEYSTORE" || { echo "build-android-release.sh: no keystore at $VAULT_ANDROID_KEYSTORE" >&2; exit 1; }
export VAULT_ANDROID_KEYSTORE=$(realpath "$VAULT_ANDROID_KEYSTORE")

cd "$(dirname "$0")/../android"
./gradlew --no-daemon assembleRelease

apk=app/build/outputs/apk/release/app-release.apk
sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
apksigner=$(ls -d "$sdk"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1 || true)
[ -n "$apksigner" ] || { echo "build-android-release.sh: no apksigner under $sdk/build-tools" >&2; exit 1; }

certs=$("$apksigner" verify --verbose --print-certs "$apk")
echo "$certs"
if grep -q "CN=Android Debug" <<<"$certs"; then
    echo "build-android-release.sh: $apk is signed with a debug key, not the release key" >&2
    exit 1
fi
fingerprint=$(sed -n 's/^.*Signer[^:]*:\? certificate SHA-256 digest: //p' <<<"$certs" | head -1 \
    | tr a-f A-F | sed 's/../&:/g; s/:$//')
[ -n "$fingerprint" ] || { echo "build-android-release.sh: no certificate fingerprint" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
cp "$apk" "$out"
echo "$fingerprint" > "$out.cert.txt"
echo "Signed $out"
echo "Signing certificate SHA-256: $fingerprint"
