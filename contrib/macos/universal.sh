#!/usr/bin/env bash
# Join the Apple silicon and Intel release builds into universal programs
# that run natively on either, after
#
#   cargo build --release --locked --target aarch64-apple-darwin --target x86_64-apple-darwin
#
# writes them to target/universal, for
#
#   BIN_DIR=target/universal ARCH=universal contrib/macos/package.sh VERSION
set -euo pipefail
cd "$(dirname "$0")/../.."

out=target/universal
mkdir -p "$out"
for b in vaultd vault vault-gui vault-prompt vault-native-host vault-gpg; do
    lipo -create -output "$out/$b" \
        "target/aarch64-apple-darwin/release/$b" "target/x86_64-apple-darwin/release/$b"
    lipo -verify_arch arm64 x86_64 "$out/$b"
done
lipo -info "$out"/*
