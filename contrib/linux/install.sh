#!/usr/bin/env bash
# Install or upgrade Secret Vault for you, from the Linux .tar.gz, into
# ~/.local (no root). Run it from the unpacked folder:
#
#   ./install.sh
#
# Upgrading is the same command from a newer archive: it replaces the
# programs, keeps your vault and settings, and restarts vaultd if it runs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
new=$(cat "$here/VERSION")
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
for f in "$here"/bin/*; do
    # Replace, not overwrite in place: a running vaultd keeps its old file.
    install -m755 "$f" "$bin/.$(basename "$f").new"
    mv -f "$bin/.$(basename "$f").new" "$bin/$(basename "$f")"
done
sed 's|^ExecStart=.*|ExecStart=%h/.local/bin/vaultd|' "$here/share/vaultd.service" >"$units/vaultd.service"
sed "s|^Exec=vault-gui|Exec=$bin/vault-gui|" "$here/share/applications/dev.passwordvault.app.desktop" \
    >"$share/applications/dev.passwordvault.app.desktop"
cp -r "$here/share/hicolor/." "$share/icons/hicolor/"

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
case ":$PATH:" in *":$bin:"*) ;; *) echo "Add $bin to your PATH to run vault." ;; esac
