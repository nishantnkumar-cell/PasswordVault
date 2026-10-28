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
    # Boot first: a cold simulator can take longer than XCTest waits for the app to launch.
    xcrun simctl boot "$udid" 2>/dev/null || true
    xcrun simctl bootstatus "$udid" -b >/dev/null
    # A second try only when the test never started (the simulator or
    # its test runner failed to launch) or XCTest itself timed out reading
    # the screen on a busy runner; a failing check is not retried.
    for try in 1 2; do
        rm -rf "build/$name.xcresult"
        rc=0
        TEST_RUNNER_DEVICE=$name TEST_RUNNER_PHRASE=$phrase xcodebuild test -project SecretVault.xcodeproj -scheme SecretVault \
            -destination "id=$udid" -derivedDataPath build -resultBundlePath "build/$name.xcresult" \
            CODE_SIGNING_ALLOWED=NO VAULT_SKIP_RUST=1 > "build/$name.log" 2>&1 || rc=$?
        [ $rc -ne 0 ] || break
        grep -q "Test Case .*started" "build/$name.log" &&
            ! grep -qE "Timed out while fetching attributes|Failed to get matching snapshots" "build/$name.log" &&
            break
        echo "The test did not start, or XCTest timed out, on $name (try $try); the end of its log:"
        tail -40 "build/$name.log"
        xcrun simctl shutdown "$udid" 2>/dev/null || true
        xcrun simctl boot "$udid" 2>/dev/null || true
        xcrun simctl bootstatus "$udid" -b >/dev/null
    done
    # The test steps and any failure, without the build noise.
    grep -E "error:|Test Case|t = .*(Tap|Swipe|Type|Find|Wait|Assert)|TEST (FAILED|SUCCEEDED)" "build/$name.log" | tail -80 || true
    [ $rc -eq 0 ] || status=1
    tmp=build/attachments-$name
    rm -rf "$tmp"
    xcrun xcresulttool export attachments --path "build/$name.xcresult" --output-path "$tmp" >/dev/null || continue
    python3 - "$tmp" "$out" <<'PY'
import json, os, re, shutil, sys
src, dst = sys.argv[1:]
for test in json.load(open(os.path.join(src, "manifest.json"))):
    for a in test.get("attachments", []):
        name = a.get("suggestedHumanReadableName") or a["exportedFileName"]
        base = name.rsplit(".", 1)[0].split("_")[0]
        # Only the tour's own screenshots, not XCTest's recordings and debug files.
        if not re.match(r"^[a-z]+-\d\d-[a-z-]+$", base):
            continue
        shutil.copy(os.path.join(src, a["exportedFileName"]), os.path.join(dst, base + ".png"))
PY
done
ls -1 "$out"
exit $status
