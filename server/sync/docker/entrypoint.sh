#!/bin/sh
# Starts the Secret Vault sync server on your own computer (docs/cloud-sync.md,
# user guide chapter 16). It is the same server code as on Cloudflare
# (src/index.js), run by Cloudflare's open-source Workers runtime, workerd.
#
# Everything lives in /data (a Docker volume):
#   /data/admin-key        made on first start; `vault cloud setup --server` asks for it
#   /data/tls/ca.pem       this server's own certificate authority, made on first start
#   /data/tls/server.*     the server's certificate, for the names in SYNC_HOSTS
#   /data/mailboxes        the encrypted vault files (one SQLite file per mailbox)
#
# Settings (environment):
#   SYNC_HOSTS   names and addresses devices use to reach this computer,
#                comma-separated, such as "vault-sync.local,192.168.1.20"
#   SYNC_PORT    port inside the container (default 8443)
#   SYNC_PUBLIC_PORT  the port devices connect to, if compose.yaml publishes
#                another one (default: SYNC_PORT)
#   ADMIN_KEY    use this admin key instead of the one in /data/admin-key
#
# `docker compose exec vault-sync show` prints the address, the admin key and
# the certificate fingerprint again.
set -eu

data=${DATA_DIR:-/data}
app=${APP_DIR:-/app}
port=${SYNC_PORT:-8443}
public_port=${SYNC_PUBLIC_PORT:-$port}
hosts=${SYNC_HOSTS:-}
tls=$data/tls
run=$data/run
umask 077
mkdir -p "$tls" "$run" "$data/mailboxes"

say() { printf '%s\n' "$*"; }

# ---- Admin key ----
if [ -z "${ADMIN_KEY:-}" ]; then
    if [ ! -s "$data/admin-key" ]; then
        openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' >"$data/admin-key"
    fi
    ADMIN_KEY=$(cat "$data/admin-key")
fi
export ADMIN_KEY

# ---- Certificates ----
# Names for the certificate: what SYNC_HOSTS lists, plus localhost.
san="DNS:localhost,IP:127.0.0.1"
first=
old_ifs=$IFS
IFS=,
for h in $hosts; do
    h=$(printf '%s' "$h" | tr -d ' ')
    [ -n "$h" ] || continue
    [ -n "$first" ] || first=$h
    case $h in
        *[!0-9.]*) case $h in *:*) san="$san,IP:$h" ;; *) san="$san,DNS:$h" ;; esac ;;
        *) san="$san,IP:$h" ;;
    esac
done
IFS=$old_ifs

if [ ! -s "$tls/ca.pem" ] || [ ! -s "$tls/ca.key" ]; then
    say "Making this server's own certificate authority (once)..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$tls/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$tls/ca.key" -sha256 -days 7300 \
        -subj "/CN=Secret Vault sync server (own CA)" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$tls/ca.pem" 2>/dev/null
    rm -f "$tls/server.crt"
fi
# A new server certificate whenever SYNC_HOSTS changes. The authority stays,
# so devices that already joined keep trusting it.
if [ ! -s "$tls/server.crt" ] || [ "$(cat "$tls/hosts" 2>/dev/null)" != "$san" ]; then
    say "Making the server certificate for: $san"
    openssl ecparam -name prime256v1 -genkey -noout -out "$tls/server.key" 2>/dev/null
    openssl req -new -key "$tls/server.key" -subj "/CN=${first:-localhost}" -out "$run/server.csr" 2>/dev/null
    printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
        "$san" >"$run/server.ext"
    openssl x509 -req -in "$run/server.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca.key" -CAcreateserial \
        -days 3650 -sha256 -extfile "$run/server.ext" -out "$tls/server.crt" 2>/dev/null
    printf '%s' "$san" >"$tls/hosts"
    rm -f "$run/server.csr" "$run/server.ext"
fi

# base64url SHA-256 of the authority's DER: the fingerprint join links carry.
fingerprint=$(openssl x509 -in "$tls/ca.pem" -outform der | openssl dgst -sha256 -binary |
    openssl base64 -A | tr '+/' '-_' | tr -d '=')

# ---- workerd's configuration ----
# workerd reads files next to its configuration ("embed"), so they are copied
# there on every start.
cp "$app/index.js" "$run/index.js"
cp "$tls/ca.pem" "$run/ca.pem"
cp "$tls/server.crt" "$run/server.crt"
cp "$tls/server.key" "$run/server.key"
cat >"$run/config.capnp" <<EOF
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .sync),
    (name = "mailboxes", disk = (path = "$data/mailboxes", writable = true)),
  ],
  sockets = [
    (name = "https", address = "0.0.0.0:$port", service = "main",
     https = (options = (), tlsOptions = (keypair = (
       privateKey = embed "server.key", certificateChain = embed "server.crt")))),
  ],
);

const sync :Workerd.Worker = (
  modules = [(name = "index.js", esModule = embed "index.js")],
  compatibilityDate = "2026-11-01",
  bindings = [
    (name = "MAILBOX", durableObjectNamespace = "Mailbox"),
    (name = "ADMIN_KEY", fromEnvironment = "ADMIN_KEY"),
    (name = "CA_PEM", text = embed "ca.pem"),
  ],
  durableObjectNamespaces = [(className = "Mailbox", uniqueKey = "secret-vault-sync-mailbox", enableSql = true)],
  durableObjectStorage = (localDisk = "mailboxes"),
);
EOF

cat >"$run/show" <<EOF
Secret Vault sync server
  address:      https://${first:-<this computer's address>}:$public_port
  certificate:  $san
  fingerprint:  $fingerprint
  admin key:    $ADMIN_KEY
On the first computer, with the vault unlocked:
  vault cloud setup --server https://${first:-ADDRESS}:$public_port --fingerprint $fingerprint
EOF

grep -v "admin key:" "$run/show"
say "  admin key:    docker compose exec vault-sync show"
say "Listening on port $port."
exec workerd serve "$run/config.capnp"
