#!/bin/sh
# Builds libdrastic_wfc.so for arm64 and copies it into the APK tree.
# Usage: ANDROID_NDK_HOME=/path/to/ndk ./wfc/build.sh
set -e

: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an Android NDK (r21+)}"

HERE=$(cd "$(dirname "$0")" && pwd)
HOST=$(ls "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" | head -n 1)
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android21-clang"
OUT="$HERE/../universal/lib/arm64-v8a/libdrastic_wfc.so"

"$CC" -shared -fPIC -O2 -Wall -Wextra -Werror \
    -Wl,-z,max-page-size=16384 -Wl,--build-id=none -s \
    -o "$OUT" "$HERE"/src/*.c -llog -ldl

echo "built $OUT"
