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

shopt -s nullglob
# Highest-versioned match of a glob, or empty (no failing `ls` in a pipe, so a missing
# dir does not trip `set -o pipefail` before the friendly guards below can report it).
pick_latest() {
  # Empty IFS so a pattern whose literal portion contains spaces is not word-split;
  # pathname expansion still splits $1 into separate matches with spaces preserved.
  local IFS=
  local matches=($1)
  (( ${#matches[@]} )) || return 0
  printf '%s\n' "${matches[@]}" | sort -V | tail -1
}

# Enforce a build-tools floor: javac below emits class file v61 (--release 17), and
# 34.0.0's d8 crashes with an internal R8 NPE on this client's anonymous Runnable while
# <34 predates reliable class-61 desugaring here; 35.0.0+ (36.0.0 verified) build fine.
# Pick the NEWEST installed build-tools whose version is >= the floor, and fail fast with
# an actionable message otherwise rather than letting an incompatible d8 crash mid-build.
MIN_BUILD_TOOLS="35.0.0"
BT=""
for cand in "$SDK/build-tools/"*/; do
  cand="${cand%/}"
  ver="$(basename "$cand")"
  [ -x "$cand/aapt2" ] || continue
  [ "$(printf '%s\n%s\n' "$MIN_BUILD_TOOLS" "$ver" | sort -V | head -1)" = "$MIN_BUILD_TOOLS" ] || continue
  if [ -z "$BT" ] || [ "$(printf '%s\n%s\n' "$(basename "$BT")" "$ver" | sort -V | tail -1)" = "$ver" ]; then
    BT="$cand"
  fi
done
if [ -z "$BT" ]; then
  installed="$(pick_latest "$SDK/build-tools/*/")"; installed="${installed%/}"
  echo "error: no build-tools >= $MIN_BUILD_TOOLS under $SDK/build-tools (d8 must handle class v61 from --release 17 and avoid the 34.0.0 R8 NPE);" \
       "newest installed: ${installed:-none}. Install build-tools $MIN_BUILD_TOOLS or newer." >&2
  exit 1
fi

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
mapfile -t CLASS_FILES < <(find "$OUT/classes" -name '*.class')
"$BT/d8" --min-api 33 --output "$OUT" "${CLASS_FILES[@]}"

echo "== aapt2 link =="
"$BT/aapt2" link \
  --manifest "$HERE/AndroidManifest.xml" \
  -I "$ANDROID_JAR" \
  --min-sdk-version 33 --target-sdk-version 34 \
  -o "$OUT/base.apk"

echo "== add dex =="
( cd "$OUT" && for dex in classes*.dex; do jar uf "$OUT/base.apk" -C "$OUT" "$dex"; done )

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
