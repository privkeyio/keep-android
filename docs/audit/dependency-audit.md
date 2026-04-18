# Release Dependency Audit

Audit of every transitive dependency in the `releaseRuntimeClasspath` configuration for proprietary/closed-source code and known trackers. Prerequisite for F-Droid (and IzzyOnDroid) submission.

- Branch: `Audit-dependency-tree`
- Issue: #244 (blocks #245, soft-blocks #246)
- Follow-up to: #228
- Date generated: 2026-04-17
- Gradle command: `ANDROID_HOME=/usr/lib/android-sdk ./gradlew :app:dependencies --configuration releaseRuntimeClasspath`
- Raw output: [`release-dependencies.txt`](./release-dependencies.txt)

## Summary

| Metric | Count |
|---|---|
| Unique `group:artifact` coordinates in release classpath | 176 |
| Top-level `implementation(...)` declarations in `app/build.gradle.kts` | 17 |
| Flagged as proprietary / non-OSS | 13 |
| Must-replace before F-Droid | 13 (all pulled in by a single top-level dep) |
| Known trackers (exodus-privacy list) | 0 confirmed (scan deferred — see Exodus section) |

### Headline finding

The single declaration `implementation("com.google.mlkit:barcode-scanning:17.3.0")` in `app/build.gradle.kts` pulls the entire **proprietary Google stack** into the release APK:

- `com.google.mlkit:*` (4 artifacts)
- `com.google.android.gms:play-services-*` (4 artifacts, including `play-services-mlkit-barcode-scanning`)
- `com.google.firebase:firebase-*` (4 artifacts — `firebase-annotations`, `firebase-components`, `firebase-encoders`, `firebase-encoders-json`)
- `com.google.android.datatransport:*` (3 artifacts — `transport-api`, `transport-backend-cct`, `transport-runtime`)
- `com.google.android.odml:image`

These are closed-source (Play Services / Firebase), incompatible with F-Droid's inclusion policy, and `datatransport` / `firebase-components` are historically flagged by exodus-privacy as telemetry/tracker components. Every other dependency in the tree is OSS (Apache-2.0, MIT, BSD, or equivalent).

ZXing (`com.google.zxing:core:3.5.4` — Apache-2.0, note the `com.google.zxing` group is OSS and unrelated to Google Inc.) is already on the classpath and is the standard OSS replacement for ML Kit barcode scanning.

## Full dependency tree

See [`release-dependencies.txt`](./release-dependencies.txt) (1116 lines, raw `gradle :app:dependencies` output).

## Per-dependency classification

### Flagged: proprietary / must-replace

All of these are transitive dependencies of `com.google.mlkit:barcode-scanning:17.3.0`. Removing that single top-level declaration removes all of them.

| Coordinate | License | Classification | Notes |
|---|---|---|---|
| com.google.mlkit:barcode-scanning | [Google ML Kit ToS](https://developers.google.com/ml-kit/terms) | must-replace | Closed-source. Replace with ZXing (already on classpath). |
| com.google.mlkit:barcode-scanning-common | Google ML Kit ToS | must-replace | Transitive of above. |
| com.google.mlkit:common | Google ML Kit ToS | must-replace | Transitive of above. |
| com.google.mlkit:vision-common | Google ML Kit ToS | must-replace | Transitive of above. |
| com.google.mlkit:vision-interfaces | Google ML Kit ToS | must-replace | Transitive of above. |
| com.google.android.gms:play-services-mlkit-barcode-scanning | Google Play Services ToS | must-replace | Proprietary; forbidden by F-Droid inclusion policy. |
| com.google.android.gms:play-services-base | Google Play Services ToS | must-replace | Proprietary. |
| com.google.android.gms:play-services-basement | Google Play Services ToS | must-replace | Proprietary. |
| com.google.android.gms:play-services-tasks | Google Play Services ToS | must-replace | Proprietary. |
| com.google.android.odml:image | Google proprietary | must-replace | Proprietary. |
| com.google.firebase:firebase-annotations | Apache-2.0 (but Firebase SDK ecosystem) | must-replace | Pulled by ML Kit runtime. |
| com.google.firebase:firebase-components | Apache-2.0 | must-replace | Firebase DI container; not needed without ML Kit. |
| com.google.firebase:firebase-encoders | Apache-2.0 | must-replace | JSON encoders for Firebase telemetry. |
| com.google.firebase:firebase-encoders-json | Apache-2.0 | must-replace | Same. |
| com.google.android.datatransport:transport-api | Apache-2.0 | must-replace | Google telemetry transport API. Historically exodus-flagged family. |
| com.google.android.datatransport:transport-backend-cct | Apache-2.0 | must-replace | Phones home to Google CCT endpoint. |
| com.google.android.datatransport:transport-runtime | Apache-2.0 | must-replace | Telemetry runtime. |

Note: several Firebase/datatransport artifacts are technically Apache-2.0 licensed, but they exist to support the closed-source Play Services / ML Kit runtime and establish network connections to Google endpoints. IzzyOnDroid and F-Droid both treat them as non-free-network-dependencies.

### OSS — keep, no action

All `androidx.*`, Kotlin, Compose, Room, CameraX, JNA, SQLCipher, Guava, Tink, and Dagger dependencies. Full list (unique `group:artifact`):

- `androidx.*` (all artifacts) — Apache-2.0 — OSS, standard AndroidX.
- `org.jetbrains.kotlin:*`, `org.jetbrains.kotlinx:*`, `org.jetbrains:annotations` — Apache-2.0 — OSS.
- `androidx.compose.*` (all artifacts, via `androidx.compose:compose-bom:2026.03.01`) — Apache-2.0 — OSS.
- `androidx.camera:*`, `androidx.camera.featurecombinationquery:*`, `androidx.camera.viewfinder:*` — Apache-2.0 — OSS.
- `androidx.media3:media3-common`, `media3-container`, `media3-muxer` — Apache-2.0 — OSS (pulled via CameraX video).
- `androidx.navigation:*`, `androidx.navigationevent:*` — Apache-2.0 — OSS.
- `androidx.room:*`, `androidx.sqlite:*` — Apache-2.0 — OSS.
- `androidx.security:security-crypto:1.1.0` — Apache-2.0 — OSS.
- `androidx.biometric:biometric:1.1.0` — Apache-2.0 — OSS.
- `net.zetetic:sqlcipher-android:4.14.1` — BSD-3-Clause (Zetetic) — OSS.
- `net.java.dev.jna:jna:5.18.1` — Apache-2.0 / LGPL-2.1 dual — OSS.
- `com.google.zxing:core:3.5.4` — Apache-2.0 — OSS. Despite the `com.google` group coordinate, ZXing is a community OSS project, not a Google product.
- `com.google.guava:guava:33.3.1-android`, `failureaccess`, `listenablefuture` — Apache-2.0 — OSS (pulled via CameraX/media3).
- `com.google.crypto.tink:tink-android` — Apache-2.0 — OSS (pulled via `androidx.security:security-crypto`).
- `com.google.dagger:dagger` — Apache-2.0 — OSS (pulled via ML Kit; will drop with ML Kit removal).
- `com.google.code.gson:gson` — Apache-2.0 — OSS (pulled via Firebase; will drop with ML Kit removal).
- `com.google.auto.value:auto-value-annotations:1.6.3` — Apache-2.0 — OSS.
- `org.jspecify:jspecify:1.0.0` — Apache-2.0 — OSS.
- `jakarta.inject:jakarta.inject-api`, `javax.inject:javax.inject` — Apache-2.0 / EPL-2.0 — OSS.

### proprietary-but-OK-for-IzzyOnDroid

None. IzzyOnDroid tolerates some proprietary blobs that F-Droid rejects, but all of the flagged items above phone home to Google services and so are rejected by IzzyOnDroid as well. There is no middle-ground bucket in this audit.

## Exodus-privacy scan

**Status: deferred.** `exodus-standalone` is not installed in the local environment, and this audit will not install system packages.

No release APK currently exists at `app/build/outputs/apk/` (tree not built for release). Once the ML-Kit removal work is done, build a release APK (`ANDROID_HOME=/usr/lib/android-sdk ./gradlew :app:assembleRelease`) and run:

```sh
# Preferred: official CLI
pipx install exodus-standalone
exodus-standalone app/build/outputs/apk/release/app-release.apk

# Or via the hosted scanner
# Upload APK to https://reports.exodus-privacy.eu.org/en/analysis/submit/
```

Expected outcome after removing `com.google.mlkit:barcode-scanning`: **zero trackers**. The current release classpath contains the `com.google.android.datatransport.*` family, which exodus historically flags (e.g., "Google Firelog"/"Google CrashLytics" signatures are in the same family and share infrastructure); the DataTransport runtime itself is classified as telemetry transport.

## Recommended follow-up issues

1. **Replace ML Kit barcode scanning with ZXing** (blocks #245)
   - Remove `implementation("com.google.mlkit:barcode-scanning:17.3.0")` from `app/build.gradle.kts`.
   - Refactor the CameraX barcode pipeline to feed frames through `com.google.zxing:core` (already a declared dependency) via a small `ImageAnalysis.Analyzer` that runs `MultiFormatReader` or QR-only `QRCodeReader`.
   - Verify scan performance on low-end arm64 devices.
   - After merge, re-run this audit to confirm the 13 flagged artifacts are gone.

2. **Run exodus-privacy scan on the post-replacement release APK** (soft-blocks #246)
   - Gate release tagging on a clean exodus report (0 trackers).
   - Consider automating via CI once the replacement lands.

3. **(Optional) Add Gradle dependency-resolution check in CI** to fail the build if any `com.google.android.gms:*`, `com.google.firebase:*`, `com.google.android.datatransport:*`, `com.google.mlkit:*`, or `com.google.android.odml:*` coordinate reappears in `releaseRuntimeClasspath`. Prevents accidental re-introduction of proprietary Google libs.
