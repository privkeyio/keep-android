# Dependency Audit

Audit of the release dependency tree for proprietary and tracker
libraries, as a prerequisite for F-Droid / IzzyOnDroid submission.

## Status

- **Proprietary artifacts in `releaseRuntimeClasspath`:** none.
- **Trackers in release APK:** none. See [`exodus-report.md`](exodus-report.md).

## History

- **Pre-swap audit (#244):** identified 17 proprietary artifacts
  transitively pulled in by `com.google.mlkit:barcode-scanning`
  (ML Kit, Play Services, Firebase, DataTransport, ODML).
- **Swap (#248):** replaced Google ML Kit barcode scanning with
  [ZXing](https://github.com/zxing/zxing), removing all 17 proprietary
  artifacts from the release classpath.
- **Post-swap re-audit (#244):** confirmed zero flagged artifacts.
- **Exodus scan (#250):** confirmed zero trackers in the built release
  APK, documented in [`exodus-report.md`](exodus-report.md).

## Reproduce

```sh
JAVA_HOME=/path/to/jdk17 ANDROID_HOME=/path/to/android-sdk \
  ./gradlew :app:dependencies --configuration releaseRuntimeClasspath
```

Scan the tree for `com.google.*` (ZXing core `com.google.zxing:core`
is OSS and permitted). Any other `com.google.*` artifact is
disqualifying and must have a replacement issue filed.
