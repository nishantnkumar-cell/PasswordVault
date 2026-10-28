#!/usr/bin/env bash
# Package the release build for Linux, after `cargo build --release --locked`:
#
#   contrib/linux/package.sh VERSION
#
# writes to target/packages/:
#   secret-vault_<version>_amd64.deb           Debian and Ubuntu (apt installs
#                                              it over an older one in place)
#   secret-vault-<version>-linux-x86_64.tar.gz any distribution; its install.sh
#                                              installs or upgrades into ~/.local
#
# The .deb's library dependencies come from dpkg-shlibdeps, so build it on the
# oldest distribution it should install on (CI uses ubuntu-latest).
set -euo pipefail
cd "$(dirname "$0")/../.."

ver=${1:?usage: package.sh VERSION}
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg)
out=target/packages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# Debian sorts "~" before anything, so 0.2.0~dev.1a2b3c4 < 0.2.0.
debver=${ver/-/\~}
root=$work/deb
install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/systemd/user" \
    "$root/usr/share/applications" "$root/usr/share/icons" "$root/usr/share/doc/secret-vault"
for b in "${bins[@]}"; do
    install -m755 "target/release/$b" "$root/usr/bin/"
done
sed 's|^ExecStart=.*|ExecStart=/usr/bin/vaultd|; s|install to ~/.config/systemd/user/ and run|installed by the package; enable it with|' \
    contrib/systemd/vaultd.service >"$root/usr/lib/systemd/user/vaultd.service"
install -m644 contrib/desktop/dev.passwordvault.app.desktop "$root/usr/share/applications/"
cp -r contrib/icons/hicolor "$root/usr/share/icons/"
install -m644 LICENSE.md "$root/usr/share/doc/secret-vault/copyright"

mkdir -p "$work/shlibs/debian"
printf 'Source: secret-vault\n\nPackage: secret-vault\nArchitecture: amd64\n' >"$work/shlibs/debian/control"
depends=$(cd "$work/shlibs" && dpkg-shlibdeps -O "${bins[@]/#/$root/usr/bin/}" |
    sed -n 's/^shlibs:Depends=//p')
cat >"$root/DEBIAN/control" <<CONTROL
Package: secret-vault
Version: $debver
Architecture: amd64
Maintainer: PasswordVault project <noreply@example.com>
Depends: $depends
Section: utils
Priority: optional
Homepage: https://github.com/nishantnkumar-cell/PasswordVault
Description: local-first password vault
 vaultd keeps one encrypted vault file and serves the vault command, the
 desktop app (vault-gui), the browser host and the ssh-agent. Unlock with a
 password, a FIDO2 security key, the TPM or a recovery code.
CONTROL
cat >"$root/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -n "$2" ]; then
    echo "Secret Vault upgraded from $2. Each user running vaultd should run:"
    echo "    systemctl --user restart vaultd"
fi
POSTINST
chmod 755 "$root/DEBIAN/postinst"
# The file name keeps the hyphen (secret-vault_0.2.0-beta.1_amd64.deb) to match
# the other downloads; inside, Version uses "~" so apt sorts it before 0.2.0.
dpkg-deb --root-owner-group --build "$root" "$out/secret-vault_${ver}_amd64.deb" >/dev/null

name=secret-vault-$ver-linux-x86_64
tar_root=$work/$name
install -d "$tar_root/bin" "$tar_root/share/applications"
for b in "${bins[@]}"; do
    install -m755 "target/release/$b" "$tar_root/bin/"
done
install -m644 contrib/systemd/vaultd.service "$tar_root/share/vaultd.service"
install -m644 contrib/desktop/dev.passwordvault.app.desktop "$tar_root/share/applications/"
cp -r contrib/icons/hicolor "$tar_root/share/hicolor"
install -m755 contrib/linux/install.sh "$tar_root/install.sh"
install -m644 LICENSE.md "$tar_root/"
echo "$ver" >"$tar_root/VERSION"
tar -C "$work" -czf "$out/$name.tar.gz" "$name"

ls -l "$out"
