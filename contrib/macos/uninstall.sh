#!/bin/bash
# Remove Secret Vault installed by SecretVault-<version>-macos.pkg:
#
#   sudo "/Applications/Secret Vault.app/Contents/Resources/uninstall.sh"
#
# Stops vaultd, then removes the app, the launch agent, the commands in
# /usr/local/bin and the browser host registrations that point at the app.
# Your vault file and settings (~/Library/Application Support/vault) are
# kept; delete that folder yourself if you want them gone too.
#
# For a copy installed with install.sh (in ~/Applications), see "Upgrading
# and removing" in docs/user-guide/13-macos.md instead.
set -u
if [ "$(id -u)" != 0 ]; then
    echo "Run it with sudo: sudo \"$0\"" >&2
    exit 1
fi
app="/Applications/Secret Vault.app"

for uid in $(ps -axo uid=,comm= | awk '$2 ~ /loginwindow$/ { print $1 }' | sort -u); do
    launchctl bootout "gui/$uid/dev.passwordvault.vaultd" 2>/dev/null || true
done
pkill -x vault-gui 2>/dev/null || true
rm -f /Library/LaunchAgents/dev.passwordvault.vaultd.plist

for b in vault vaultd vault-gpg; do
    l=/usr/local/bin/$b
    if [ -L "$l" ] && [ "$(readlink "$l")" = "$app/Contents/MacOS/$b" ]; then
        rm -f "$l"
    fi
done

for home in /Users/*; do
    for d in "Google/Chrome" "Chromium" "Microsoft Edge" "Mozilla"; do
        m="$home/Library/Application Support/$d/NativeMessagingHosts/dev.passwordvault.host.json"
        if [ -f "$m" ] && grep -qF "$app/" "$m"; then
            rm -f "$m"
        fi
    done
done

# This script lives in the app; the shell has already opened it, so
# removing the app last is safe.
rm -rf "$app"
pkgutil --forget dev.passwordvault.pkg >/dev/null 2>&1 || true
echo "Secret Vault removed. Your vault is still in ~/Library/Application Support/vault."
