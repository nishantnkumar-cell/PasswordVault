#!/usr/bin/env bash
# Package the release build for macOS, after `cargo build --release --locked`
# on a Mac:
#
#   contrib/macos/package.sh VERSION
#
# writes target/packages/secret-vault-<version>-macos-<arch>.tar.gz, holding
# Secret Vault.app (every program, so vaultd finds vault-prompt and the app
# finds vault-native-host next to it), the launch agent and install.sh, which
# installs or upgrades into ~/Applications and ~/.local/bin (no admin rights).
# The app is signed ad hoc, not by a developer ID: see the macOS section of
# docs/user-guide/01-getting-started.md for opening it the first time.
set -euo pipefail
cd "$(dirname "$0")/../.."

ver=${1:?usage: package.sh VERSION}
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg)
arch=$(uname -m)
out=target/packages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

name=secret-vault-$ver-macos-$arch
root=$work/$name
app="$root/Secret Vault.app/Contents"
install -d "$app/MacOS" "$app/Resources" "$root/share"
for b in "${bins[@]}"; do
    install -m755 "target/release/$b" "$app/MacOS/"
done
sed "s|NUMBER|${ver%%-*}|; s|VERSION|$ver|" contrib/macos/Info.plist >"$app/Info.plist"
install -m644 contrib/icons/secret-vault.icns "$app/Resources/"
codesign --force --sign - "$root/Secret Vault.app"
install -m644 contrib/macos/dev.passwordvault.vaultd.plist "$root/share/"
install -m755 contrib/macos/install.sh "$root/install.sh"
install -m644 LICENSE.md "$root/"
echo "$ver" >"$root/VERSION"
tar -C "$work" -czf "$out/$name.tar.gz" "$name"

ls -l "$out"
