#!/usr/bin/env bash
# CI check, as root or with sudo, after the .deb or Arch package was
# installed: the system service is set up the way the user guide says.
#
#   contrib/linux/check-system-service.sh deb|arch
#
# "deb" runs on a runner with systemd: the person who ran "sudo apt install"
# has vaultd@them running as vault-them, and a second person gets their own.
# "arch" runs in a container without systemd: the files, group and polkit
# policy only.
set -euo pipefail
kind=${1:?deb or arch}
as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
fail() { echo "FAIL: $*" >&2; exit 1; }

getent group vault >/dev/null || fail "no vault group"
test -x /usr/bin/vaultd || fail "no /usr/bin/vaultd"
command -v vault-setup-user >/dev/null || fail "no vault-setup-user"
test -f /usr/lib/systemd/system/vaultd@.service || fail "no vaultd@.service"
grep -q '^User=vault-%i$' /usr/lib/systemd/system/vaultd@.service || fail "vaultd@ does not run as vault-%i"
test -f /usr/lib/udev/rules.d/70-vault-fido.rules || fail "no udev rule"
policy=/usr/share/polkit-1/actions/dev.passwordvault.quick-unlock.policy
test -f "$policy" || fail "no quick unlock policy"

if [ "$kind" = arch ]; then
    echo "OK: package files, group and policy are in place."
    exit 0
fi

me=${SUDO_USER:-${USER:-runner}}
[ "$me" != root ] || me=runner
# apt ran under sudo, so the package set up vaultd for this person.
systemctl -q is-active "vaultd@$me" || { journalctl -u "vaultd@$me" -n 30 --no-pager; fail "vaultd@$me is not running"; }
pid=$(systemctl show -p MainPID --value "vaultd@$me")
# (ps shortens long user names, so compare UIDs.)
test "$(ps -o uid= -p "$pid" | tr -d ' ')" = "$(id -u "vault-$me")" || fail "vaultd@$me does not run as vault-$me"
test "$(as_root stat -c %U "/var/lib/vault/$me")" = "vault-$me" || fail "vault folder not owned by vault-$me"
grep -q "unix-user:vault-$me" "$policy" || fail "policy does not name vault-$me"
# Clients find the system service without VAULT_SOCKET.
env -u VAULT_SOCKET vault status || fail "vault status could not reach vaultd@$me"

# A second person gets a separate account and daemon.
as_root useradd -m alex-example 2>/dev/null || true
as_root vault-setup-user enable alex-example
pid2=$(systemctl show -p MainPID --value vaultd@alex-example)
test "$(ps -o uid= -p "$pid2" | tr -d ' ')" = "$(id -u vault-alex-example)" || fail "second vaultd is not vault-alex-example"
test "$(id -u vault-alex-example)" != "$(id -u "vault-$me")" || fail "the two share an account"
grep -q "unix-user:vault-alex-example" "$policy" || fail "policy does not name the second account"
as_root vault-setup-user list

# Removing the package stops every instance and keeps the vaults.
as_root apt-get remove -y secret-vault
! systemctl -q is-active "vaultd@$me" || fail "vaultd@$me still running after removal"
test -d "/var/lib/vault/$me" || fail "the vault folder went with the package"
test ! -f "$policy" || fail "policy left behind"
echo "OK: system service set up per person, and removed cleanly."
