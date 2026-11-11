#!/usr/bin/env bash
# Build vault-se, the Secure Enclave helper (contrib/macos/secure-enclave),
# as a universal program (Apple silicon and Intel):
#
#   contrib/macos/build-se.sh [OUT_DIR]          default target/release
#   VAULT_SE_SOFTWARE=1 contrib/macos/build-se.sh OUT_DIR
#       a test build that uses a software key (for Macs or CI runners
#       without a Secure Enclave); never ship it
#
# vaultd looks for vault-se next to itself (or at $VAULT_SE_HELPER), so
# after `cargo build --release` run this with the default OUT_DIR. Needs
# Xcode or the Command Line Tools (swiftc).
set -euo pipefail
cd "$(dirname "$0")/../.."

out=${1:-target/release}
src=contrib/macos/secure-enclave/main.swift
flags=(-O -module-name VaultSE)
[ "${VAULT_SE_SOFTWARE:-0}" = 1 ] && flags+=(-D VAULT_SE_SOFTWARE)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
for a in arm64 x86_64; do
    xcrun swiftc "${flags[@]}" -target "$a-apple-macos11" "$src" -o "$work/vault-se-$a"
done
lipo -create -output "$out/vault-se" "$work/vault-se-arm64" "$work/vault-se-x86_64"
lipo "$out/vault-se" -verify_arch arm64 x86_64
# Apple silicon runs only signed code; package.sh signs it again properly.
codesign --force --sign - "$out/vault-se"
echo "built $out/vault-se"
