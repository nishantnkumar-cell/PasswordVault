#!/usr/bin/env bash
# Install or upgrade Secret Vault for you on macOS, from the unpacked
# .tar.gz (no admin rights):
#
#   ./install.sh
#
# Secret Vault.app goes to ~/Applications, the vault, vaultd and vault-gpg
# commands to ~/.local/bin (as links into the app), and a launch agent starts
# vaultd when you sign in. Upgrading is the same command from a newer
# archive: it replaces the app, keeps your vault and settings, and restarts
# vaultd.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
new=$(cat "$here/VERSION")
apps=$HOME/Applications
app="$apps/Secret Vault.app"
bin=$HOME/.local/bin
agent=$HOME/Library/LaunchAgents/dev.passwordvault.vaultd.plist
logs=$HOME/Library/Logs
label=gui/$(id -u)/dev.passwordvault.vaultd

old=
if [ -x "$app/Contents/MacOS/vaultd" ]; then
    old=$("$app/Contents/MacOS/vaultd" --version 2>/dev/null | awk '{ print $2 }') || true
fi
if [ -n "$old" ] && [ "$old" != "$new" ] &&
    [ "$(printf '%s\n%s\n' "${old%%-*}" "${new%%-*}" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)" != "${new%%-*}" ]; then
    read -r -p "Secret Vault $old is installed, newer than $new. An older version may not open a vault the newer one saved. Install anyway? [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ] || exit 1
fi

# Stop vaultd before replacing it; it starts again below.
launchctl bootout "$label" 2>/dev/null || true

mkdir -p "$apps" "$bin" "$(dirname "$agent")" "$logs"
rm -rf "$app.new"
cp -R "$here/Secret Vault.app" "$app.new"
# Downloaded with a browser, the files carry a quarantine flag that makes
# macOS refuse unsigned programs; this copy is one you chose to install.
xattr -dr com.apple.quarantine "$app.new" 2>/dev/null || true
rm -rf "$app"
mv "$app.new" "$app"
for b in vault vaultd vault-gpg; do
    ln -sf "$app/Contents/MacOS/$b" "$bin/$b"
done

sed "s|<string>VAULTD</string>|<string>$app/Contents/MacOS/vaultd</string>|; s|<string>LOG</string>|<string>$logs/vaultd.log</string>|" \
    "$here/share/dev.passwordvault.vaultd.plist" >"$agent"
launchctl bootstrap "gui/$(id -u)" "$agent"

if [ -n "$old" ] && [ "$old" != "$new" ]; then
    echo "Secret Vault upgraded from $old to $new; vaultd restarted."
else
    echo "Secret Vault $new installed in $apps, and vaultd started (it starts at sign-in from now on)."
fi
case ":$PATH:" in *":$bin:"*) ;; *) echo "Add $bin to your PATH to run vault: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zprofile" ;; esac
