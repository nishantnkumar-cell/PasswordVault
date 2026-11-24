#!/usr/bin/env bash
# Install or upgrade Secret Vault for you, from the Linux .tar.gz. The
# programs go into ~/.local and stay yours; sudo is needed once, for the one
# system setting a user service cannot make for itself: your membership of the
# "tss" group, which lets vaultd use the computer's TPM (TPM unlock). Run it
# from the unpacked folder:
#
#   ./install.sh
#
# Upgrading is the same command from a newer archive: it replaces the
# programs, keeps your vault and settings, and restarts vaultd if it runs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
new=$(cat "$here/VERSION")

# sudo is required, and asked for first, so nothing is half installed when it
# is refused.
die() { echo "install.sh: $*" >&2; exit 1; }
command -v sudo >/dev/null || die "sudo is needed (to let you use the TPM); install sudo and run this again"
echo "Secret Vault needs sudo once, to add you to the tss group (TPM unlock)."
sudo -v || die "sudo was refused, so nothing was installed"
bin=$HOME/.local/bin
share=${XDG_DATA_HOME:-$HOME/.local/share}
units=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user

old=
if [ -x "$bin/vaultd" ]; then
    old=$("$bin/vaultd" --version 2>/dev/null | awk '{ print $2 }') || true
fi
if [ -n "$old" ] && [ "$old" != "$new" ] &&
    [ "$(printf '%s\n%s\n' "${old%%-*}" "${new%%-*}" | sort -V | tail -n1)" != "${new%%-*}" ]; then
    read -r -p "Secret Vault $old is installed, newer than $new. An older version may not open a vault the newer one saved. Install anyway? [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ] || exit 1
fi

install -d "$bin" "$units" "$share/applications" "$share/icons/hicolor"
# The service runs with the rest of the disk read-only and needs these two
# folders to exist before it starts, or systemd refuses it (status 226).
install -d -m700 "$share/vault" "${XDG_STATE_HOME:-$HOME/.local/state}/vault"
for f in "$here"/bin/*; do
    # Replace, not overwrite in place: a running vaultd keeps its old file.
    install -m755 "$f" "$bin/.$(basename "$f").new"
    mv -f "$bin/.$(basename "$f").new" "$bin/$(basename "$f")"
done
sed 's|^ExecStart=.*|ExecStart=%h/.local/bin/vaultd|' "$here/share/vaultd.service" >"$units/vaultd.service"
# Cloud sync helper; enabled by you after `vault cloud setup` or `vault cloud join`.
if [ -f "$here/share/vault-sync.service" ]; then
    sed 's|^ExecStart=.*|ExecStart=%h/.local/bin/vault-sync|' "$here/share/vault-sync.service" >"$units/vault-sync.service"
fi
sed "s|^Exec=vault-gui|Exec=$bin/vault-gui|" "$here/share/applications/dev.passwordvault.app.desktop" \
    >"$share/applications/dev.passwordvault.app.desktop"
cp -r "$here/share/hicolor/." "$share/icons/hicolor/"

# TPM unlock: /dev/tpmrm0 belongs to the "tss" group. Without this, adding the
# TPM as an unlock method fails with "no usable TPM". Only when the computer
# has a TPM and the group; the change applies at your next login.
tss_note=
if [ -e /dev/tpmrm0 ] && getent group tss >/dev/null; then
    if getent group tss | awk -F: '{print $4}' | tr ',' '\n' | grep -qx "$USER"; then
        :
    else
        sudo usermod -aG tss "$USER" || die "could not add you to the tss group"
        tss_note="Added you to the tss group so TPM unlock works. Log out and in again for it to apply, then restart vaultd (systemctl --user restart vaultd)."
    fi
elif [ ! -e /dev/tpmrm0 ]; then
    tss_note="No TPM found (/dev/tpmrm0): TPM unlock is not available on this computer."
fi

if command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null; then
    if systemctl --user -q is-active vaultd; then
        systemctl --user restart vaultd
        echo "vaultd restarted."
    fi
fi
if [ -n "$old" ] && [ "$old" != "$new" ]; then
    echo "Secret Vault upgraded from $old to $new."
else
    echo "Secret Vault $new installed in $bin."
    echo "Start vaultd at sign-in with: systemctl --user enable --now vaultd"
fi
[ -z "$tss_note" ] || echo "$tss_note"
case ":$PATH:" in *":$bin:"*) ;; *) echo "Add $bin to your PATH to run vault." ;; esac
