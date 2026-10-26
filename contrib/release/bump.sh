#!/usr/bin/env bash
# Set the version everywhere it is written: Cargo.toml (every crate takes it
# from the workspace), Cargo.lock and extension/manifest.json.
#
#   contrib/release/bump.sh 0.3.0
set -euo pipefail
cd "$(dirname "$0")/../.."

new=${1:-}
if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: bump.sh MAJOR.MINOR.PATCH" >&2
    exit 2
fi
old=$(contrib/release/version.sh)
if [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n1)" != "$new" ] || [ "$old" = "$new" ]; then
    echo "bump.sh: $new is not newer than $old" >&2
    exit 1
fi
sed -i.bak "/^\[workspace.package\]/,/^\[/s/^version = \"$old\"$/version = \"$new\"/" Cargo.toml
sed -i.bak "s/^\( *\"version\": \)\"$old\",$/\1\"$new\",/" extension/manifest.json
rm -f Cargo.toml.bak extension/manifest.json.bak
cargo update --workspace --offline --quiet
contrib/release/version.sh >/dev/null
echo "version $old -> $new"
