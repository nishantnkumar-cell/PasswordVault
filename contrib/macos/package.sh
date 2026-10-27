#!/usr/bin/env bash
# Package the release build for macOS, after `cargo build --release --locked`
# on a Mac:
#
#   contrib/macos/package.sh VERSION
#
# writes two files to target/packages:
#
#   SecretVault-<version>-macos.pkg   the installer: double-click it, and it
#       puts Secret Vault.app in /Applications, the vault, vaultd and
#       vault-gpg commands in /usr/local/bin, and a launch agent in
#       /Library/LaunchAgents (needs an administrator password)
#   secret-vault-<version>-macos-<arch>.tar.gz   the same app with install.sh,
#       which installs into ~/Applications and ~/.local/bin instead (no admin
#       rights)
#
# Both hold Secret Vault.app with every program inside, so vaultd finds
# vault-prompt and the app finds vault-native-host next to it.
#
# BIN_DIR (default target/release) is where the programs are; ARCH (default
# `uname -m`) names the archive, e.g. BIN_DIR=target/universal ARCH=universal
# after contrib/macos/universal.sh.
#
# Signing: by default the app is signed ad hoc and the .pkg is not signed;
# see the macOS section of docs/user-guide/01-getting-started.md for opening
# them the first time. With an Apple Developer ID, set
#   DEVELOPER_ID_APP="Developer ID Application: <name> (<team>)"
#   DEVELOPER_ID_INSTALLER="Developer ID Installer: <name> (<team>)"
# (certificates in the keychain) to sign both; notarize the .pkg afterwards
# as docs/macos-signing.md describes.
set -euo pipefail
cd "$(dirname "$0")/../.."

ver=${1:?usage: package.sh VERSION}
num=${ver%%-*}
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg)
bin_dir=${BIN_DIR:-target/release}
arch=${ARCH:-$(uname -m)}
out=target/packages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# The app bundle, once, then copied into each package.
bundle="$work/Secret Vault.app"
app="$bundle/Contents"
install -d "$app/MacOS" "$app/Resources"
for b in "${bins[@]}"; do
    install -m755 "$bin_dir/$b" "$app/MacOS/"
done
sed "s|NUMBER|$num|; s|VERSION|$ver|" contrib/macos/Info.plist >"$app/Info.plist"
install -m644 contrib/icons/secret-vault.icns "$app/Resources/"
install -m755 contrib/macos/uninstall.sh "$app/Resources/uninstall.sh"
# Every helper program, then the bundle (which signs its main program,
# vault-gui): lipo output carries no signature, and --strict checks the
# helpers too. Signing vault-gui on its own path would sign the whole
# bundle before the helpers are signed.
if [ -n "${DEVELOPER_ID_APP:-}" ]; then
    # Hardened runtime and a secure timestamp, which notarization requires.
    sign=(--options runtime --timestamp --sign "$DEVELOPER_ID_APP")
else
    sign=(--sign -)
fi
for b in "${bins[@]}"; do
    [ "$b" = vault-gui ] || codesign --force "${sign[@]}" "$app/MacOS/$b"
done
codesign --force "${sign[@]}" "$bundle"
codesign --verify --strict "$bundle"

# The .tar.gz with install.sh.
name=secret-vault-$ver-macos-$arch
root=$work/$name
install -d "$root/share"
cp -R "$bundle" "$root/"
install -m644 contrib/macos/dev.passwordvault.vaultd.plist "$root/share/"
install -m755 contrib/macos/install.sh "$root/install.sh"
install -m644 LICENSE.md "$root/"
echo "$ver" >"$root/VERSION"
tar -C "$work" -czf "$out/$name.tar.gz" "$name"

# The .pkg: one component package (the payload and its scripts) inside a
# product archive (the installer's pages).
pkgroot=$work/pkgroot
install -d "$pkgroot/Applications" "$pkgroot/Library/LaunchAgents"
cp -R "$bundle" "$pkgroot/Applications/"
install -m644 contrib/macos/pkg/dev.passwordvault.vaultd.plist "$pkgroot/Library/LaunchAgents/"
scripts=$work/scripts
install -d "$scripts"
sed "s|NUMBER|$num|" contrib/macos/pkg/preinstall >"$scripts/preinstall"
install -m755 contrib/macos/pkg/postinstall "$scripts/"
chmod 755 "$scripts/preinstall"
# Install where the payload says even if another copy of the app is
# somewhere else (by default Installer would "upgrade" that copy in place).
pkgbuild --analyze --root "$pkgroot" "$work/component.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$work/component.plist"
plutil -replace 0.BundleIsVersionChecked -bool NO "$work/component.plist"
pkgbuild --root "$pkgroot" --component-plist "$work/component.plist" --scripts "$scripts" \
    --identifier dev.passwordvault.pkg --version "$num" --install-location / \
    "$work/SecretVault.pkg"
res=$work/resources
install -d "$res"
sed "s|VERSION|$ver|g" contrib/macos/pkg/welcome.html >"$res/welcome.html"
install -m644 contrib/macos/pkg/conclusion.html "$res/"
cp LICENSE.md "$res/license.txt"
case $arch in
    universal) host=arm64,x86_64 ;;
    *) host=$arch ;;
esac
sed "s|VERSION|$ver|g; s|NUMBER|$num|g; s|ARCHS|$host|" contrib/macos/pkg/distribution.xml >"$work/distribution.xml"
pkg=$out/SecretVault-$ver-macos.pkg
sign=()
[ -z "${DEVELOPER_ID_INSTALLER:-}" ] || sign=(--sign "$DEVELOPER_ID_INSTALLER" --timestamp)
productbuild --distribution "$work/distribution.xml" --resources "$res" --package-path "$work" \
    ${sign[@]+"${sign[@]}"} "$pkg"

ls -l "$out"
