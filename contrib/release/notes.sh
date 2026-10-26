#!/usr/bin/env bash
# Print one version's section of docs/release-notes.md (for the GitHub Release).
#
#   contrib/release/notes.sh 0.2.0
set -euo pipefail
cd "$(dirname "$0")/../.."
ver=${1:?usage: notes.sh VERSION}
awk -v v="$ver" '
    /^## / { on = (index($0, "## " v " ") == 1 || $0 == "## " v) ; next }
    on { print }
' docs/release-notes.md
