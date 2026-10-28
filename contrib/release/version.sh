#!/usr/bin/env bash
# Print the version.
#
#   contrib/release/version.sh           the workspace version, e.g. 0.2.0
#   contrib/release/version.sh --build   this build's version: the workspace
#                                         version for a v* tag (which must match
#                                         it), the tag's version for a pre-release
#                                         tag such as v0.2.0-beta.1, else
#                                         <version>-dev.<commit>
#   contrib/release/version.sh --number  the build version without -dev...
#
# Fails if extension/manifest.json disagrees with Cargo.toml.
set -euo pipefail
cd "$(dirname "$0")/../.."

ver=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
ext=$(sed -n 's/^ *"version": "\(.*\)",$/\1/p' extension/manifest.json)
if [ -z "$ver" ]; then
    echo "version.sh: no version in [workspace.package] of Cargo.toml" >&2
    exit 1
fi
if [ "$ver" != "$ext" ]; then
    echo "version.sh: extension/manifest.json says $ext but Cargo.toml says $ver; use contrib/release/bump.sh" >&2
    exit 1
fi

build() {
    if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
        local tag=${GITHUB_REF#refs/tags/v}
        # A pre-release (beta) of $ver: $ver-alpha.N, $ver-beta.N or $ver-rc.N.
        if [ "$tag" != "$ver" ] && ! [[ "$tag" =~ ^${ver//./\.}-(alpha|beta|rc)\.[0-9]+$ ]]; then
            echo "version.sh: tag v$tag does not match version $ver in Cargo.toml" >&2
            exit 1
        fi
        echo "$tag"
    else
        echo "$ver-dev.${VAULT_COMMIT:-$(git rev-parse --short=7 HEAD)}"
    fi
}

case "${1:-}" in
    "") echo "$ver" ;;
    --build) build ;;
    --number) echo "$ver" ;;
    *) echo "usage: version.sh [--build | --number]" >&2; exit 2 ;;
esac
