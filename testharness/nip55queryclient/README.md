# nip55queryclient

Standalone cross-process NIP-55 query client for keep-android instrumented tests
(gh#374, keep-android-166).

A tiny pure-Java app (`applicationId io.privkey.keeptest.queryclient`) with its own
UID and debug signature, so keep's `getVerifiedCaller()` treats it as a genuine
external caller. On launch its single exported `QueryActivity` runs a
`ContentResolver.query` against keep's NIP-55 provider and broadcasts the resulting
cursor (columns + row0) back to the orchestrating test.

It drives `Nip55CrossProcessRequestInstrumentedTest`, which is a **manual-only**
instrumented test (skipped by default).

## Build + run

```bash
export ANDROID_SDK_ROOT=/path/to/android-sdk   # or ANDROID_HOME
testharness/nip55queryclient/build.sh
adb install -r testharness/nip55queryclient/out/queryclient.apk

./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.privkey.keep.nip55.Nip55CrossProcessRequestInstrumentedTest \
  -Pandroid.testInstrumentationRunnerArguments.crossProcessManual=1
```

Notes:
- `build.sh` builds by hand (aapt2/d8/apksigner) instead of Gradle to avoid pulling
  the NDK/Rust-coupled root build for a client with no native code. It resolves
  build-tools and `android.jar` from `$ANDROID_SDK_ROOT`/`$ANDROID_HOME` and signs
  with the debug keystore (`~/.android/debug.keystore`, auto-generated if missing).
- The test computes the installed client's live signing hash at runtime, so any
  machine's debug keystore works; nothing depends on a hardcoded hash.
- Without `-e crossProcessManual 1` the test reports SKIPPED (assumption failure),
  keeping default `connectedAndroidTest`/CI green. It also SKIPS if the client is
  not installed.
- Build artifacts land in `out/` and are not committed.
