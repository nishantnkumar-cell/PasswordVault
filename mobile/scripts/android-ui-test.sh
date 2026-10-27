#!/usr/bin/env bash
# Run the UI tour (app/src/androidTest/.../TourTest.kt) on the running
# emulator and copy its screenshots to mobile/android/build/screenshots.
#
#   mobile/scripts/android-ui-test.sh <device-name> [foldable]
#
# Expects the debug and test APKs to be built already
# (./gradlew assembleDebug assembleDebugAndroidTest). For a foldable it
# runs the tour unfolded, then folds the emulator and runs it again (the
# second run unlocks the vault the first one made).
set -euo pipefail
cd "$(dirname "$0")/../android"

name=$1
foldable=${2:-}
pkg=dev.passwordvault.app
out=build/screenshots
mkdir -p "$out"

adb wait-for-device
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
adb install -r -g app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0

run() {
    local status=0
    adb shell am instrument -w -r -e device "$1" \
        -e class dev.passwordvault.app.TourTest \
        $pkg.test/androidx.test.runner.AndroidJUnitRunner | tee "$out/$1.log" || status=$?
    # am instrument exits 0 even when a test fails; look at its report.
    grep -q "FAILURES!!!\|INSTRUMENTATION_FAILED\|Process crashed" "$out/$1.log" && status=1
    adb exec-out run-as $pkg sh -c 'cd files/screenshots 2>/dev/null && tar cf - .' | tar xf - -C "$out" || true
    return $status
}

status=0
if [ -n "$foldable" ]; then
    adb emu unfold >/dev/null 2>&1 || true
    sleep 3
    run "$name-open" || status=1
    adb emu fold >/dev/null 2>&1 || true
    sleep 3
    run "$name-folded" || status=1
else
    run "$name" || status=1
fi
ls -1 "$out"
exit $status
