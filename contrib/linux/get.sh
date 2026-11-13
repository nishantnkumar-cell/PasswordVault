#!/usr/bin/env bash
# Secret Vault for Linux, in one command:
#
#   curl -fsSL https://raw.githubusercontent.com/nishantnkumar-cell/PasswordVault/main/contrib/linux/get.sh | bash
#
# It downloads the newest release (betas included) from GitHub, checks it
# against the release's SHA256SUMS.txt and sets everything up. Run it again
# to upgrade: your vault and settings stay.
#
# By default vaultd runs as its own "vault" system user (vaultd@you), so
# programs running as you cannot read its memory, and its memory is always
# kept out of swap. That needs your password once (sudo). In that mode there
# is no approval window: pair programs with your password (`vault pair`),
# and keys that ask before each use and Secret Service are not available.
# --user-service installs into ~/.local without root instead, with those.
#
# Options:
#   --user-service   run vaultd as you (systemd user service), no root
#   --version V      install V (for example 0.2.0-beta.2) instead of the newest
#   --from FILE      install from a downloaded .tar.gz instead (no download;
#                    put SHA256SUMS.txt next to it to have it checked)
#   --yes            answer yes to every question (for scripts)
#   --uninstall      remove the programs and services, keep your vault
set -euo pipefail

repo=nishantnkumar-cell/PasswordVault
need=$((512 << 20)) # lockable memory vaultd wants (docs/vaultd.md)
bins=(vaultd vault vault-gui vault-prompt vault-native-host vault-gpg)
me=$(id -un)
home_share=${XDG_DATA_HOME:-$HOME/.local/share}
home_state=${XDG_STATE_HOME:-$HOME/.local/state}
units=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
sock=/run/vault/$me/vaultd.sock

mode=system version= from= yes= uninstall=
while [ $# -gt 0 ]; do
    case $1 in
        --user-service) mode=user ;;
        --version) version=${2:?--version needs a value}; shift ;;
        --from) from=${2:?--from needs a file}; shift ;;
        --yes | -y) yes=1 ;;
        --uninstall) uninstall=1 ;;
        -h | --help) sed -n '2,23p' "${BASH_SOURCE[0]}" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option $1; see --help" >&2; exit 2 ;;
    esac
    shift
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
# Questions read the terminal, since with "curl | bash" stdin is this script.
tty_ok() { { : </dev/tty; } 2>/dev/null; }
ask() {
    [ -n "$yes" ] && return 0
    tty_ok || return 1
    local a
    read -r -p "$1 [Y/n] " a </dev/tty || return 1
    case $a in "" | y | Y | yes) return 0 ;; *) return 1 ;; esac
}
user_systemd() { command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; }
# The memory lock limit a running vaultd got, in bytes or "unlimited".
lock_limit() { awk '/^Max locked memory/ { print $4 }' "/proc/$1/limits" 2>/dev/null || true; }
limit_ok() { [ "$1" = unlimited ] || { [ -n "$1" ] && [ "$1" -ge "$need" ]; }; }
add_line() { # FILE LINE: append once
    [ -f "$1" ] || return 0
    grep -qF "$2" "$1" || printf '\n# Added by the Secret Vault installer\n%s\n' "$2" >>"$1"
}
drop_socket_lines() { # take out what add_line added for VAULT_SOCKET
    local rc
    for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        [ -f "$rc" ] && grep -q '^export VAULT_SOCKET=/run/vault/' "$rc" || continue
        awk '
            /^export VAULT_SOCKET=\/run\/vault\// {
                if (n > 0 && line[n] == "# Added by the Secret Vault installer") {
                    n--
                    if (n > 0 && line[n] == "") n--
                }
                next
            }
            { line[++n] = $0 }
            END { for (i = 1; i <= n; i++) print line[i] }
        ' "$rc" >"$rc.vault-tmp" && cat "$rc.vault-tmp" >"$rc" && rm -f "$rc.vault-tmp"
    done
    rm -f "$HOME/.config/environment.d/50-secret-vault.conf"
}

[ "$(id -u)" != 0 ] || die "run this as yourself, not as root: it sets vaultd up for the signed-in user"

if [ -n "$uninstall" ]; then
    if user_systemd; then systemctl --user disable --now vaultd 2>/dev/null || true; fi
    drop_socket_lines
    system=
    find "$home_share/icons/hicolor" -name 'dev.passwordvault.app.*' -delete 2>/dev/null || true
    rm -f "${bins[@]/#/$HOME/.local/bin/}" "$units/vaultd.service" \
        "$home_share/applications/dev.passwordvault.app.desktop" "$HOME/.config/environment.d/50-secret-vault.conf"
    if { [ -f /etc/systemd/system/vaultd@.service ] || [ -e /usr/local/bin/vaultd ]; } &&
        ask "Also remove the system-wide install (vaultd@$me, /usr/local/bin; sudo)?"; then
        # Every instance, not only yours: their programs are about to go.
        instances=$({
            systemctl list-units --all --plain --no-legend 'vaultd@*.service' 2>/dev/null | awk '{ print $1 }'
            ls /etc/systemd/system/*.wants/ 2>/dev/null | grep '^vaultd@.*\.service$'
        } | sort -u)
        others=$(echo "$instances" | grep -vx "vaultd@$me.service" | sed 's/^vaultd@//; s/\.service$//' | grep . || true)
        if [ -n "$others" ]; then
            echo "Other people on this computer use it too: $(echo $others)."
            echo "Their vaultd stops as well; their vaults are kept. They can reinstall with this script."
            ask "Remove it for everyone?" || die "kept the system-wide install; nothing else was changed for others"
        fi
        for u in "vaultd@$me.service" $instances; do
            sudo systemctl disable --now "$u" 2>/dev/null || true
        done
        sudo rm -f "${bins[@]/#//usr/local/bin/}" /etc/systemd/system/vaultd@.service \
            /etc/udev/rules.d/70-vault-fido.rules
        sudo find /usr/local/share/icons/hicolor -name 'dev.passwordvault.app.*' -delete 2>/dev/null || true
        sudo systemctl daemon-reload
        system=1
    fi
    say "Secret Vault removed."
    [ ! -f "$home_share/vault/vault.svault" ] || echo "    Your vault is kept in $home_share/vault."
    if [ -n "$system" ]; then
        echo "    Kept: the vaults in /var/lib/vault (yours is $me/), the \"vault\" system user and"
        echo "    /etc/sysusers.d/vault.conf (other people on this computer may use them)."
        echo "    To delete your vault for good: sudo rm -r /var/lib/vault/$me"
    elif [ -d /var/lib/vault ]; then
        echo "    The system service is still installed; run again and answer yes to remove it."
    fi
    exit 0
fi

[ "$(uname -s)" = Linux ] || die "this script is for Linux; see the user guide for Windows and macOS"
[ "$(uname -m)" = x86_64 ] || die "the Linux download is for 64-bit Intel/AMD (x86_64); on $(uname -m), build from source (user guide, chapter 1)"
for t in tar sha256sum; do command -v $t >/dev/null || die "$t is needed"; done
if [ $mode = system ]; then
    command -v systemctl >/dev/null && [ -d /run/systemd/system ] ||
        die "the system service needs systemd; run again with --user-service"
    command -v sudo >/dev/null || die "the system service needs sudo; run again with --user-service"
fi

fetch() { # URL FILE
    if command -v curl >/dev/null; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is needed"
    fi
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. Get the archive and check it.
if [ -n "$from" ]; then
    [ -f "$from" ] || die "no such file $from"
    archive=$from
    if [ -f "$(dirname "$from")/SHA256SUMS.txt" ]; then
        (cd "$(dirname "$from")" && grep -F "  $(basename "$from")" SHA256SUMS.txt | sha256sum -c --status) ||
            die "$(basename "$from") does not match SHA256SUMS.txt"
        say "Checked $(basename "$from") against SHA256SUMS.txt."
    else
        say "No SHA256SUMS.txt next to $(basename "$from"): not checked."
    fi
else
    if [ -z "$version" ]; then
        # The newest release, betas included (/releases/latest skips betas).
        fetch "https://api.github.com/repos/$repo/releases?per_page=1" "$work/releases.json" ||
            die "could not reach GitHub to find the newest release"
        version=$(sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' "$work/releases.json" | head -n1)
        [ -n "$version" ] || die "could not find a release on github.com/$repo/releases"
    fi
    version=${version#v}
    name=secret-vault-$version-linux-x86_64.tar.gz
    base=https://github.com/$repo/releases/download/v$version
    say "Downloading Secret Vault $version..."
    fetch "$base/$name" "$work/$name" || die "could not download $base/$name"
    fetch "$base/SHA256SUMS.txt" "$work/SHA256SUMS.txt" || die "could not download SHA256SUMS.txt"
    (cd "$work" && grep -F "  $name" SHA256SUMS.txt | sha256sum -c --status) ||
        die "the download does not match the release's SHA256SUMS.txt; nothing was installed"
    say "Checked the download against SHA256SUMS.txt."
    archive=$work/$name
fi
mkdir -p "$work/x"
tar -xzf "$archive" -C "$work/x"
dir=$(find "$work/x" -mindepth 1 -maxdepth 1 -type d | head -n1)
[ -x "$dir/install.sh" ] || die "the archive has no install.sh"
version=$(cat "$dir/VERSION")

# Files for the system service. Archives from 0.2.0-beta.3 on carry them;
# older ones get them from the same release tag on GitHub.
system_file() { # NAME (path under contrib/)
    if [ -f "$dir/share/$(basename "$1")" ]; then
        cp "$dir/share/$(basename "$1")" "$work/$(basename "$1")"
    else
        fetch "https://raw.githubusercontent.com/$repo/v$version/contrib/$1" "$work/$(basename "$1")" ||
            die "could not download contrib/$1 for $version"
    fi
}

had_vault=
was_running=
if [ $mode = user ]; then
    [ ! -f "$home_share/vault/vault.svault" ] || had_vault=1
    ! user_systemd || ! systemctl --user -q is-active vaultd 2>/dev/null || was_running=1
    # A system install left VAULT_SOCKET pointing at vaultd@you; this one uses the default.
    drop_socket_lines
    unset VAULT_SOCKET
    # 2u. Into ~/.local, with the archive's own install.sh (it also upgrades).
    if tty_ok; then "$dir/install.sh" </dev/tty; else "$dir/install.sh" </dev/null; fi
    # The service may only write these folders, so they must exist first.
    install -d -m700 "$home_share/vault" "$home_state/vault"
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            touch "$HOME/.profile"
            for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
                add_line "$rc" 'export PATH="$HOME/.local/bin:$PATH"'
            done
            say "Added ~/.local/bin to your PATH (open a new terminal)."
            ;;
    esac
    user_systemd || die "no systemd user session here: start vaultd yourself with 'vaultd &' (user guide, chapter 1)"
    systemctl --user daemon-reload
    systemctl --user enable vaultd >/dev/null 2>&1
    systemctl --user restart vaultd
    sleep 1
    systemctl --user -q is-active vaultd || die "vaultd did not start; see: journalctl --user -u vaultd -n 30"
    say "vaultd is running and starts at every sign-in."
    limit=$(lock_limit "$(systemctl --user show -p MainPID --value vaultd)")
    if limit_ok "$limit"; then
        say "vaultd keeps its memory out of swap."
    else
        echo "Your system lets a user service lock only $((${limit:-0} >> 20)) MiB of memory; vaultd needs"
        echo "$((need >> 20)) MiB to keep keys out of swap. One system setting fixes that (sudo, once)."
        if ask "Raise the limit now with sudo?"; then
            sudo mkdir -p /etc/systemd/system/user@.service.d
            printf '[Service]\nLimitMEMLOCK=infinity\n' |
                sudo tee /etc/systemd/system/user@.service.d/memlock.conf >/dev/null
            sudo systemctl daemon-reload
            say "Done. Sign out and back in (on WSL: 'wsl --shutdown' in Windows) to apply it."
        else
            echo "Skipped: vaultd works, but keys could reach swap (docs/vaultd.md, \"Memory locking\")."
        fi
    fi
else
    # 2s. As the "vault" system user, one instance per person: vaultd@you.
    system_file systemd/vaultd@.service
    system_file sysusers.d/vault.conf
    system_file udev/70-vault-fido.rules
    getent group tss >/dev/null || sed -i '/^SupplementaryGroups=tss/d' "$work/vaultd@.service"

    say "Setting up the system service (sudo asks for your password)..."
    sudo -v
    ! sudo test -f "/var/lib/vault/$me/vault.svault" || had_vault=1
    ! systemctl -q is-active "vaultd@$me" 2>/dev/null || was_running=1
    # A vault made earlier by the user service moves along, with its paired apps.
    old_vault=$home_share/vault/vault.svault
    move=
    if [ -f "$old_vault" ] && ! sudo test -f "/var/lib/vault/$me/vault.svault"; then
        echo "You have a vault in $home_share/vault. The system service keeps it in /var/lib/vault/$me."
        ask "Move it there (a copy stays where it is, as a backup)?" && move=1
    fi

    sudo install -d /usr/local/bin /usr/local/share/icons /etc/sysusers.d /etc/udev/rules.d /etc/systemd/system
    for b in "${bins[@]}"; do
        # Replace, not overwrite in place: a running vaultd keeps its old file.
        sudo install -m755 "$dir/bin/$b" "/usr/local/bin/.$b.new"
        sudo mv -f "/usr/local/bin/.$b.new" "/usr/local/bin/$b"
    done
    sudo cp -r "$dir/share/hicolor" /usr/local/share/icons/
    sudo install -m644 "$work/vault.conf" /etc/sysusers.d/vault.conf
    if command -v systemd-sysusers >/dev/null; then
        sudo systemd-sysusers /etc/sysusers.d/vault.conf
    elif ! getent passwd vault >/dev/null; then
        sudo useradd --system --home-dir /var/lib/vault --no-create-home --shell /usr/sbin/nologin vault
    fi
    sudo install -m644 "$work/70-vault-fido.rules" /etc/udev/rules.d/70-vault-fido.rules
    sudo udevadm control --reload 2>/dev/null && sudo udevadm trigger --subsystem-match=hidraw 2>/dev/null || true
    sudo install -m644 "$work/vaultd@.service" /etc/systemd/system/vaultd@.service
    sudo systemctl daemon-reload

    if user_systemd && systemctl --user -q is-enabled vaultd 2>/dev/null; then
        systemctl --user disable --now vaultd >/dev/null 2>&1 || true
        say "Turned off the per-user vaultd service (the system service replaces it)."
    fi
    if [ -n "$move" ]; then
        sudo systemctl stop "vaultd@$me" 2>/dev/null || true
        sudo install -d -o vault -g vault -m700 "/var/lib/vault/$me" "/var/lib/vault/$me/state"
        sudo install -o vault -g vault -m600 "$old_vault" "/var/lib/vault/$me/vault.svault"
        if [ -d "$home_state/vault" ]; then
            sudo cp -r "$home_state/vault/." "/var/lib/vault/$me/state/"
            sudo chown -R vault:vault "/var/lib/vault/$me/state"
        fi
        say "Moved your vault to /var/lib/vault/$me (the old copy is still in $home_share/vault)."
        had_vault=1
    fi
    sudo systemctl enable "vaultd@$me" >/dev/null 2>&1
    sudo systemctl restart "vaultd@$me"
    sleep 1
    sudo systemctl -q is-active "vaultd@$me" || die "vaultd did not start; see: sudo journalctl -u vaultd@$me -n 30"
    say "vaultd runs as the vault user and starts with the computer."
    limit=$(sudo awk '/^Max locked memory/ { print $4 }' "/proc/$(systemctl show -p MainPID --value "vaultd@$me")/limits" 2>/dev/null || true)
    if limit_ok "$limit"; then say "vaultd keeps its memory out of swap."; fi

    # Clients find this daemon through VAULT_SOCKET: terminals, the desktop
    # session (environment.d) and the app menu entry.
    touch "$HOME/.profile"
    for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
        add_line "$rc" "export VAULT_SOCKET=$sock"
    done
    mkdir -p "$HOME/.config/environment.d" "$home_share/applications"
    echo "VAULT_SOCKET=$sock" >"$HOME/.config/environment.d/50-secret-vault.conf"
    sed "s|^Exec=vault-gui|Exec=env VAULT_SOCKET=$sock /usr/local/bin/vault-gui|" \
        "$dir/share/applications/dev.passwordvault.app.desktop" \
        >"$home_share/applications/dev.passwordvault.app.desktop"
    export VAULT_SOCKET=$sock
fi

echo
if [ -n "$had_vault" ]; then
    say "Secret Vault $version is installed; your vault and paired apps are kept."
    [ -z "$was_running" ] || echo "    vaultd was restarted, so the vault is locked: unlock it in the app or with: vault unlock"
else
    say "Secret Vault $version is installed."
    echo "    Open \"Secret Vault\" from your app menu to create your vault, or run: vault init"
fi
if [ $mode = system ] && [ -z "$was_running" ]; then
    echo "    Open a new terminal first (it needs VAULT_SOCKET), and sign out and in once"
    echo "    so the app menu entry and other apps see it too."
fi
echo "    Browser autofill, SSH keys and app passwords: see the user guide."
