#!/usr/bin/env bash
# Cut a release of the current version (docs/user-guide/11-versions-and-upgrades.md):
#
#   1. turn "## Unreleased" in docs/release-notes.md into "## <version> (<date>)"
#   2. commit that and tag it v<version>
#   3. move the workspace to the next minor version, with a new empty
#      "## Unreleased", and commit that (pass --next X.Y.Z for another one,
#      e.g. a patch release)
#
# Nothing is pushed. Pushing the tag is what publishes the GitHub Release.
set -euo pipefail
cd "$(dirname "$0")/../.."

next=
if [ "${1:-}" = "--next" ]; then
    next=${2:?--next needs a version}
elif [ -n "${1:-}" ]; then
    echo "usage: release.sh [--next X.Y.Z]" >&2
    exit 2
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "release.sh: commit or stash your changes first" >&2
    exit 1
fi
ver=$(contrib/release/version.sh)
if git rev-parse -q --verify "refs/tags/v$ver" >/dev/null; then
    echo "release.sh: v$ver is already tagged; run contrib/release/bump.sh first" >&2
    exit 1
fi
if ! grep -q '^## Unreleased$' docs/release-notes.md; then
    echo "release.sh: docs/release-notes.md has no \"## Unreleased\" section" >&2
    exit 1
fi
if [ -z "$next" ]; then
    IFS=. read -r major minor _ <<<"$ver"
    next="$major.$((minor + 1)).0"
fi

sed -i.bak "s/^## Unreleased$/## $ver ($(date -u +%Y-%m-%d))/" docs/release-notes.md
rm -f docs/release-notes.md.bak
git commit -q -m "Release $ver" docs/release-notes.md
git tag -a "v$ver" -m "Secret Vault $ver"

contrib/release/bump.sh "$next" >/dev/null
awk -v first=1 '/^## / && first { print "## Unreleased\n"; first = 0 } { print }' \
    docs/release-notes.md >docs/release-notes.md.new
mv docs/release-notes.md.new docs/release-notes.md
git commit -q -m "Start $next" Cargo.toml Cargo.lock extension/manifest.json docs/release-notes.md

echo "Tagged v$ver; main is now at $next. To publish:"
echo "    git push origin HEAD v$ver"
