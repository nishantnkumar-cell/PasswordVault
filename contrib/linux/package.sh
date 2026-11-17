#!/usr/bin/env bash
# Package the release build for Linux, after `cargo build --release --locked`:
#
#   contrib/linux/package.sh VERSION
#
# writes to target/packages/:
#   secret-vault_<version>_amd64.deb           Debian and Ubuntu: everything in
#                                              one go, system service included
#                                              (apt upgrades it in place)
#   secret-vault-<version>-linux-x86_64.tar.gz any distribution; its install.sh
#                                              installs or upgrades into ~/.local
#
# The Arch package is made by contrib/arch/PKGBUILD (CI: the arch-package job).
#
# The .deb's library dependencies come from dpkg-shlibdeps, so build it on the
# oldest distribution it should install on (CI uses ubuntu-latest).
set -euo pipefail
cd "$(dirname "$0")/../.."

ver=${1:?usage: package.sh VERSION}
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg)
export BIN_DIR=${BIN_DIR:-target/release}
out=target/packages
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

# Debian sorts "~" before anything, so 0.2.0~dev.1a2b3c4 < 0.2.0.
debver=${ver/-/\~}
root=$work/deb
contrib/linux/stage.sh "$root" sbin
install -d "$root/DEBIAN"

mkdir -p "$work/shlibs/debian"
printf 'Source: secret-vault\n\nPackage: secret-vault\nArchitecture: amd64\n' >"$work/shlibs/debian/control"
depends=$(cd "$work/shlibs" && dpkg-shlibdeps -O "${bins[@]/#/$root/usr/bin/}" |
    sed -n 's/^shlibs:Depends=//p')
cat >"$root/DEBIAN/control" <<CONTROL
Package: secret-vault
Version: $debver
Architecture: amd64
Maintainer: PasswordVault project <noreply@example.com>
Depends: $depends, passwd, systemd
Recommends: polkitd | policykit-1
Suggests: libpam-fprintd, gnupg
Section: utils
Priority: optional
Homepage: https://github.com/nishantnkumar-cell/PasswordVault
Description: local-first password vault
 vaultd keeps one encrypted vault file and serves the vault command, the
 desktop app (vault-gui), the browser host and the ssh-agent. Unlock with a
 password, a FIDO2 security key, the TPM, a phone passkey or a recovery
 code, and quick-unlock with your login password or fingerprint.
 .
 Installed with sudo, the package sets up vaultd as a system service for
 you, running as its own account. Others on the computer run:
 sudo vault-setup-user enable THEIR-LOGIN
CONTROL
for f in postinst prerm postrm; do
    # The hooks are shared with the Arch package; dpkg wants one file each.
    awk -v hooks=contrib/linux/hooks.sh '/^# @HOOKS@/ { while ((getline l < hooks) > 0) print l; close(hooks); next } { print }' \
        "contrib/linux/deb/$f" >"$root/DEBIAN/$f"
    chmod 755 "$root/DEBIAN/$f"
done
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
install -m755 contrib/linux/get.sh "$tar_root/get.sh"
# For get.sh's system service (vaultd@you as the account vault-you).
install -m644 contrib/systemd/vaultd@.service contrib/sysusers.d/vault.conf \
    contrib/udev/70-vault-fido.rules contrib/polkit/dev.passwordvault.quick-unlock.policy \
    "$tar_root/share/"
install -m755 contrib/linux/vault-setup-user "$tar_root/share/"
install -m644 LICENSE.md "$tar_root/"
echo "$ver" >"$tar_root/VERSION"
tar -C "$work" -czf "$out/$name.tar.gz" "$name"

ls -l "$out"
