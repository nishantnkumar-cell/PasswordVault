#!/usr/bin/env bash
# Build vault-mobile for iOS as an XCFramework and generate its Swift
# bindings, for the Xcode project in mobile/ios.
#
#   mobile/scripts/build-ios.sh [debug|release]
#
# Writes mobile/ios/Generated/VaultMobileFFI.xcframework and
# mobile/ios/Generated/Sources/vault_mobile.swift. Needs Xcode and rustup.
set -euo pipefail
cd "$(dirname "$0")/../.."

profile=${1:-release}
dir=release
flags=(--release)
if [ "$profile" = debug ]; then dir=debug; flags=(); fi

targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "${targets[@]}" >/dev/null 2>&1 || true
export IPHONEOS_DEPLOYMENT_TARGET=26.0
for t in "${targets[@]}"; do
    cargo build -p vault-mobile --locked --target "$t" ${flags[@]+"${flags[@]}"}
done

gen=mobile/ios/Generated
rm -rf "$gen"
mkdir -p "$gen/Sources" "$gen/include"

cargo build -p vault-mobile --locked
cargo run -q -p vault-mobile --features cli --bin uniffi-bindgen --locked -- \
    generate --library target/debug/libvault_mobile.dylib --language swift --no-format \
    --out-dir "$gen/bindings"
mv "$gen/bindings/vault_mobile.swift" "$gen/Sources/"
cp "$gen/bindings/vault_mobileFFI.h" "$gen/include/"
# XCFrameworks want the module map named module.modulemap.
cp "$gen/bindings/vault_mobileFFI.modulemap" "$gen/include/module.modulemap"

# One fat simulator library (Apple silicon and Intel), one device library.
lipo -create \
    target/aarch64-apple-ios-sim/$dir/libvault_mobile.a \
    target/x86_64-apple-ios/$dir/libvault_mobile.a \
    -output "$gen/libvault_mobile_sim.a"
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/$dir/libvault_mobile.a -headers "$gen/include" \
    -library "$gen/libvault_mobile_sim.a" -headers "$gen/include" \
    -output "$gen/VaultMobileFFI.xcframework"
rm -rf "$gen/bindings" "$gen/libvault_mobile_sim.a"

# The app's version is the workspace version (version.sh); the build number
# counts commits so each TestFlight upload is higher than the last.
{
    echo "VAULT_VERSION = $(contrib/release/version.sh --number)"
    echo "VAULT_BUILD = $(git rev-list --count HEAD 2>/dev/null || echo 1)"
} > "$gen/Version.xcconfig"
