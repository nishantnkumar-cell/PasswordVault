#!/usr/bin/env bash
# Build the app and open it on one iOS simulator or Android emulator on a
# Mac, for clicking through by hand. Starts only that one device, so it
# fits a Mac with 8 GB of memory; `stop` shuts everything down again.
#
#   mobile/scripts/run-sim.sh ios ["iPhone 18 Pro"]
#   mobile/scripts/run-sim.sh android [avd-name]
#   mobile/scripts/run-sim.sh stop
#
# iOS needs Xcode 26 or later and XcodeGen; the build is signed to run
# locally so AutoFill shows up in the simulator's Settings. Android needs
# the SDK (Android Studio's, in ~/Library/Android/sdk, by default) and an
# emulator (avd) already made in Android Studio's Device Manager.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
pkg=dev.passwordvault.app

# Use the Xcode app even when xcode-select still points at the
# Command Line Tools.
if [[ -z ${DEVELOPER_DIR:-} && -d /Applications/Xcode.app ]]; then
    export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Library/Android/sdk}
adb=$ANDROID_HOME/platform-tools/adb
emulator=$ANDROID_HOME/emulator/emulator

stop_all() {
    xcrun simctl shutdown all 2>/dev/null || true
    if [[ -x $adb ]]; then
        for s in $("$adb" devices | awk '/^emulator-/{print $1}'); do "$adb" -s "$s" emu kill || true; done
    fi
    (cd "$root/mobile/android" && ./gradlew --stop >/dev/null 2>&1) || true
}

case ${1:-} in
ios)
    device=${2:-iPhone 18 Pro}
    stop_all
    "$root/mobile/scripts/build-ios.sh"
    cd "$root/mobile/ios"
    xcodegen generate
    xcodebuild -project SecretVault.xcodeproj -scheme SecretVault \
        -destination "platform=iOS Simulator,name=$device" -derivedDataPath build \
        CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= VAULT_SKIP_RUST=1 \
        -quiet build
    xcrun simctl boot "$device" 2>/dev/null || true
    xcrun simctl bootstatus "$device" -b
    xcrun simctl install "$device" build/Build/Products/Debug-iphonesimulator/SecretVault.app
    xcrun simctl launch "$device" $pkg
    # Xcode 27 shows simulators in Device Hub; older ones in Simulator.
    dev=${DEVELOPER_DIR:-$(xcode-select -p)}
    for app in "$dev/../Applications/DeviceHub.app" "$dev/Applications/Simulator.app"; do
        if [[ -d $app ]]; then open "$app"; break; fi
    done
    ;;
android)
    avd=${2:-$("$emulator" -list-avds | head -1)}
    [[ -n $avd ]] || { echo "Make an emulator in Android Studio's Device Manager first." >&2; exit 1; }
    stop_all
    # Gradle runs on Android Studio's Java unless JAVA_HOME is set.
    jbr="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    [[ -z ${JAVA_HOME:-} && -d $jbr ]] && export JAVA_HOME=$jbr
    (cd "$root/mobile/android" && ./gradlew assembleDebug && ./gradlew --stop >/dev/null)
    "$emulator" -avd "$avd" -memory 2048 -no-snapshot-save >/dev/null 2>&1 &
    "$adb" wait-for-device
    until [[ $("$adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]]; do sleep 2; done
    "$adb" install -r "$root/mobile/android/app/build/outputs/apk/debug/app-debug.apk"
    "$adb" shell am start -n $pkg/.MainActivity
    ;;
stop)
    stop_all
    ;;
*)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
