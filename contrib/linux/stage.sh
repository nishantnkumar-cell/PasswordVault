#!/usr/bin/env bash
# Lay out an installed system tree for the Linux packages (the .deb and the
# Arch package), from a release build:
#
#   contrib/linux/stage.sh ROOT [SBIN]
#
# ROOT/usr/bin                       the programs (from $BIN_DIR, default target/release)
# ROOT/usr/SBIN/vault-setup-user     sets vaultd@ up for a person (SBIN: sbin, or bin on Arch)
# ROOT/usr/lib/systemd/system        vaultd@.service, one per person, as vault-<login>; vault-sync@.service
# ROOT/usr/lib/systemd/user          vaultd.service, the per-user alternative; vault-sync.service
# ROOT/usr/lib/sysusers.d            the "vault" group
# ROOT/usr/lib/udev/rules.d          FIDO2 security keys for that group
# ROOT/usr/share/secret-vault        the quick unlock polkit policy, filled in by vault-setup-user
# ROOT/usr/share/applications, icons the app menu entry
set -euo pipefail
cd "$(dirname "$0")/../.."

root=${1:?usage: stage.sh ROOT [SBIN]}
sbin=${2:-sbin}
bin_dir=${BIN_DIR:-target/release}
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg vault-sync)

install -d "$root/usr/bin" "$root/usr/$sbin" "$root/usr/lib/systemd/system" "$root/usr/lib/systemd/user" \
    "$root/usr/lib/sysusers.d" "$root/usr/lib/udev/rules.d" "$root/usr/share/secret-vault" \
    "$root/usr/share/applications" "$root/usr/share/icons" "$root/usr/share/doc/secret-vault"
for b in "${bins[@]}"; do
    install -m755 "$bin_dir/$b" "$root/usr/bin/"
done
install -m755 contrib/linux/vault-setup-user "$root/usr/$sbin/vault-setup-user"
sed 's|/usr/local/bin/vaultd|/usr/bin/vaultd|' contrib/systemd/vaultd@.service \
    >"$root/usr/lib/systemd/system/vaultd@.service"
sed 's|/usr/local/bin/vault-sync|/usr/bin/vault-sync|' contrib/systemd/vault-sync@.service \
    >"$root/usr/lib/systemd/system/vault-sync@.service"
sed 's|^ExecStart=.*|ExecStart=/usr/bin/vault-sync|' contrib/systemd/vault-sync.service \
    >"$root/usr/lib/systemd/user/vault-sync.service"
sed 's|^ExecStart=.*|ExecStart=/usr/bin/vaultd|; s|install to ~/.config/systemd/user/ and run|installed by the package; enable it with|' \
    contrib/systemd/vaultd.service >"$root/usr/lib/systemd/user/vaultd.service"
install -m644 contrib/sysusers.d/vault.conf "$root/usr/lib/sysusers.d/secret-vault.conf"
install -m644 contrib/udev/70-vault-fido.rules "$root/usr/lib/udev/rules.d/"
install -m644 contrib/polkit/dev.passwordvault.quick-unlock.policy "$root/usr/share/secret-vault/"
install -m644 contrib/desktop/dev.passwordvault.app.desktop "$root/usr/share/applications/"
cp -r contrib/icons/hicolor "$root/usr/share/icons/"
install -m644 LICENSE.md "$root/usr/share/doc/secret-vault/copyright"
chmod 644 "$root"/usr/lib/systemd/system/*.service "$root"/usr/lib/systemd/user/*.service
