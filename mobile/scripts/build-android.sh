#!/usr/bin/env bash
# Build vault-mobile for Android and generate its Kotlin bindings.
#
#   mobile/scripts/build-android.sh [debug|release] [ABI...]
#
# Writes <abi>/libvault_mobile.so under $VAULT_JNILIBS_OUT and the Kotlin
# bindings under $VAULT_BINDINGS_OUT (by default app/src/main/jniLibs and
# app/build/generated/uniffi under mobile/android; Gradle passes its own). Needs the Android NDK
# (ANDROID_NDK_HOME, or the newest one under the SDK) and cargo-ndk.
# The Gradle build runs this before compiling; run it by hand only to debug.
set -euo pipefail
cd "$(dirname "$0")/../.."

profile=${1:-release}
shift || true
abis=("$@")
[ ${#abis[@]} -gt 0 ] || abis=(arm64-v8a x86_64)

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}
    ndk=$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1 || true)
    [ -n "$ndk" ] || { echo "build-android.sh: no NDK; install one with sdkmanager \"ndk;<version>\"" >&2; exit 1; }
    export ANDROID_NDK_HOME=$ndk
fi
command -v cargo-ndk >/dev/null || cargo install cargo-ndk --locked

targets=()
for abi in "${abis[@]}"; do
    case $abi in
        arm64-v8a) targets+=(aarch64-linux-android) ;;
        armeabi-v7a) targets+=(armv7-linux-androideabi) ;;
        x86_64) targets+=(x86_64-linux-android) ;;
        x86) targets+=(i686-linux-android) ;;
        *) echo "build-android.sh: unknown ABI $abi" >&2; exit 2 ;;
    esac
done
rustup target add "${targets[@]}" >/dev/null 2>&1 || true

flags=()
[ "$profile" = release ] && flags+=(--release)
out=${VAULT_JNILIBS_OUT:-mobile/android/app/src/main/jniLibs}
args=()
for abi in "${abis[@]}"; do args+=(-t "$abi"); done
cargo ndk "${args[@]}" -o "$out" --platform 28 build -p vault-mobile --locked "${flags[@]}"

# Bindings come from the host build of the same crate (library mode).
cargo build -p vault-mobile --locked
lib=target/debug/libvault_mobile.so
[ -f "$lib" ] || lib=target/debug/libvault_mobile.dylib
cargo run -q -p vault-mobile --features cli --bin uniffi-bindgen --locked -- \
    generate --library "$lib" --language kotlin --no-format \
    --out-dir "${VAULT_BINDINGS_OUT:-mobile/android/app/build/generated/uniffi}"
