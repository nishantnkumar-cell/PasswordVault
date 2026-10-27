#!/usr/bin/env bash
# Run the UI tour (mobile/ios/UITests/TourTests.swift) on an iPhone and an
# iPad simulator and export its screenshots to mobile/ios/build/screenshots.
#
#   mobile/scripts/ios-ui-test.sh
#
# Expects mobile/scripts/build-ios.sh and `xcodegen generate` to have run.
set -euo pipefail
cd "$(dirname "$0")/../ios"
out=build/screenshots
mkdir -p "$out"
# A fresh master password for this run's throwaway vaults.
phrase=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')

# The newest iOS runtime's simulator whose name starts with one of the
# given names, in order of preference.
pick() {
    xcrun simctl list devices available -j | python3 -c '
import json, re, sys
want = sys.argv[1:]
devices = json.load(sys.stdin)["devices"]
def version(runtime):
    return [int(x) for x in re.findall(r"\d+", runtime.split("iOS")[-1])] if "iOS" in runtime else []
for runtime in sorted((r for r in devices if "iOS" in r), key=version, reverse=True):
    for name in want:
        for d in devices[runtime]:
            if d["name"].startswith(name):
                print(d["udid"], d["name"], sep="\t"); sys.exit()
sys.exit("no simulator matches " + ", ".join(want))
' "$@"
}

status=0
for spec in "phone:iPhone 17 Pro:iPhone" "tablet:iPad Pro 13:iPad Pro:iPad"; do
    name=${spec%%:*}
    IFS=: read -r -a prefs <<< "${spec#*:}"
    IFS=$'\t' read -r udid model < <(pick "${prefs[@]}")
    echo "== $name: $model ($udid)"
    rm -rf "build/$name.xcresult"
    TEST_RUNNER_DEVICE=$name TEST_RUNNER_PHRASE=$phrase xcodebuild test -project SecretVault.xcodeproj -scheme SecretVault \
        -destination "id=$udid" -derivedDataPath build -resultBundlePath "build/$name.xcresult" \
        CODE_SIGNING_ALLOWED=NO VAULT_SKIP_RUST=1 | tail -40 || status=1
    tmp=build/attachments-$name
    rm -rf "$tmp"
    xcrun xcresulttool export attachments --path "build/$name.xcresult" --output-path "$tmp" || continue
    python3 - "$tmp" "$out" <<'PY'
import json, os, shutil, sys
src, dst = sys.argv[1:]
for test in json.load(open(os.path.join(src, "manifest.json"))):
    for a in test.get("attachments", []):
        name = a.get("suggestedHumanReadableName") or a["exportedFileName"]
        base = name.rsplit(".", 1)[0].split("_")[0]
        shutil.copy(os.path.join(src, a["exportedFileName"]), os.path.join(dst, base + ".png"))
PY
done
ls -1 "$out"
exit $status
