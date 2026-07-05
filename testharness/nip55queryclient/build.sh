#!/usr/bin/env bash
# Builds the standalone NIP-55 cross-process query client APK used by
# Nip55CrossProcessRequestInstrumentedTest (gh#374, keep-android-166).
#
# This is a tiny pure-Java app (applicationId io.privkey.keeptest.queryclient) with
# its own UID and debug signature, so keep's getVerifiedCaller() treats it as a real
# external caller. It is built by hand (aapt2/d8/apksigner) rather than Gradle to avoid
# pulling the NDK/Rust-coupled root build for a no-native client.
#
# Usage from a clean checkout:
#   export ANDROID_SDK_ROOT=/path/to/android-sdk   # or ANDROID_HOME
#   testharness/nip55queryclient/build.sh
#   adb install -r testharness/nip55queryclient/out/queryclient.apk
# then run the gated test:
#   ./gradlew :app:connectedDebugAndroidTest \
#     -Pandroid.testInstrumentationRunnerArguments.class=io.privkey.keep.nip55.Nip55CrossProcessRequestInstrumentedTest \
#     -Pandroid.testInstrumentationRunnerArguments.crossProcessManual=1
#
# The test computes the installed client's live signing hash at runtime, so any
# machine's debug keystore works; no hash is hardcoded in the test path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
  echo "error: set ANDROID_SDK_ROOT (or ANDROID_HOME) to your Android SDK dir" >&2
  exit 1
fi

pick_latest() { ls -d $1 2>/dev/null | sort -V | tail -1; }

BT="$(pick_latest "$SDK/build-tools/*/")"
BT="${BT%/}"
[ -n "$BT" ] && [ -x "$BT/aapt2" ] || { echo "error: no usable build-tools under $SDK/build-tools" >&2; exit 1; }

# android-37.0 sorts after android-36 under -V; strip any non-numeric platform dirs
# and take the highest numeric API android.jar available.
ANDROID_JAR="$(pick_latest "$SDK/platforms/android-*/android.jar")"
[ -n "$ANDROID_JAR" ] || { echo "error: no android.jar under $SDK/platforms" >&2; exit 1; }

KEYSTORE="${ANDROID_DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"
if [ ! -f "$KEYSTORE" ]; then
  echo "== generating debug keystore at $KEYSTORE =="
  mkdir -p "$(dirname "$KEYSTORE")"
  keytool -genkeypair -v -keystore "$KEYSTORE" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=Android,C=US"
fi

OUT="$HERE/out"
rm -rf "$OUT"; mkdir -p "$OUT/classes"

echo "== build-tools: $BT =="
echo "== android.jar: $ANDROID_JAR =="

echo "== javac =="
javac --release 17 -classpath "$ANDROID_JAR" -d "$OUT/classes" \
  "$HERE/src/io/privkey/keeptest/queryclient/QueryActivity.java"

echo "== d8 =="
"$BT/d8" --min-api 33 --output "$OUT" \
  $(find "$OUT/classes" -name '*.class')

echo "== aapt2 link =="
"$BT/aapt2" link \
  --manifest "$HERE/AndroidManifest.xml" \
  -I "$ANDROID_JAR" \
  --min-sdk-version 33 --target-sdk-version 34 \
  -o "$OUT/base.apk"

echo "== add dex =="
( cd "$OUT" && jar uf "$OUT/base.apk" -C "$OUT" classes.dex )

echo "== zipalign =="
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"

echo "== apksigner =="
"$BT/apksigner" sign \
  --ks "$KEYSTORE" \
  --ks-pass pass:android \
  --ks-key-alias androiddebugkey \
  --key-pass pass:android \
  --out "$OUT/queryclient.apk" \
  "$OUT/aligned.apk"

echo "== done =="
ls -la "$OUT/queryclient.apk"
