# Shared by the .deb maintainer scripts and the Arch package's install
# file (sourced, POSIX sh). SETUP is the path of vault-setup-user.

# After the files are in place, on install and upgrade.
vault_after_install() { # SETUP FRESH(1|"")
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers secret-vault.conf >/dev/null 2>&1 || systemd-sysusers || true
    fi
    getent group vault >/dev/null || groupadd --system vault
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload >/dev/null 2>&1 || true
        udevadm trigger --subsystem-match=hidraw >/dev/null 2>&1 || true
    fi
    [ -d /run/systemd/system ] && systemctl daemon-reload || true
    # Older installs move to one account per person; running instances restart.
    "$1" refresh || true
    # Whoever ran "sudo apt install" / "sudo pacman -U" gets their vaultd now,
    # unless they have one already (then the refresh above restarted it).
    # That also covers an upgrade from a package without the system service.
    who=${SUDO_USER:-}
    if [ -z "$who" ] && [ -n "${PKEXEC_UID:-}" ]; then
        who=$(getent passwd "$PKEXEC_UID" | cut -d: -f1)
    fi
    if [ -n "$who" ] && [ "$who" != root ] && [ -d /run/systemd/system ]; then
        if ! systemctl -q is-enabled "vaultd@$who.service" 2>/dev/null; then
            "$1" enable "$who" || echo "Secret Vault: set vaultd up later with: sudo vault-setup-user enable $who"
        fi
    elif [ -n "$2" ]; then
        echo "Secret Vault is installed. Each person who uses it runs once:"
        echo "    sudo vault-setup-user enable THEIR-LOGIN"
    fi
    if [ -n "$2" ]; then
        echo "Open \"Secret Vault\" from the app menu to create a vault, or run: vault init"
    fi
}

# Before the files go away (removal, not upgrade).
vault_before_remove() { # SETUP
    "$1" stop-all || true
}

# After removal: the vaults, accounts and group stay.
vault_after_remove() {
    rm -f /usr/share/polkit-1/actions/dev.passwordvault.quick-unlock.policy
    rm -rf /etc/systemd/system/vaultd@.service.d/10-no-tss.conf
    [ -d /run/systemd/system ] && systemctl daemon-reload || true
    echo "Secret Vault removed. The vaults in /var/lib/vault and the vault-<login> accounts are kept."
}
