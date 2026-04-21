# Exodus Privacy Scan

Static tracker analysis of the release APK, performed with
[exodus-standalone](https://github.com/Exodus-Privacy/exodus-standalone).

## Result

**0 trackers detected.**

Raw JSON: [`exodus-report.json`](exodus-report.json)

## Scan metadata

| Field | Value |
| --- | --- |
| App | `io.privkey.keep` |
| Version scanned | 0.6.3 (code 11) |
| Also applies to | 1.0.0 (code 12), version-bump only since scan |
| APK SHA-256 | `c6bc53053325310efd726407c06d2c1f93721ed8b10492c3c05d227162eaf365` |
| Scanner | `exodusprivacy/exodus-standalone` (Docker) |
| Image digest | `sha256:a6531be9a6b666a8ffb6aec98b409cf6faf65536c5b9597e5b99195ca9422b88` |
| Scanner tag | v1.5.0 |
| Scan date | 2026-04-20 |

## Reproduce

From the repo root, build a release APK with the pinned toolchain (see
[`REPRODUCIBLE_BUILDS.md`](../REPRODUCIBLE_BUILDS.md)), then:

```sh
docker run --rm \
  -v "$(pwd)/app/build/outputs/apk/release:/app" \
  exodusprivacy/exodus-standalone@sha256:a6531be9a6b666a8ffb6aec98b409cf6faf65536c5b9597e5b99195ca9422b88 \
  /app/app-release.apk -j
```

Or upload the APK to the hosted scanner at
<https://reports.exodus-privacy.eu.org/en/analysis/submit/>.

## Context

This scan is the runtime confirmation of the static dependency audit
(issue #244, resolved in #248 by replacing Google ML Kit with ZXing). The
audit established that `releaseRuntimeClasspath` contains zero artifacts
from Google Play Services / ML Kit / Firebase / DataTransport. This scan
confirms that property holds against the built APK.

The v1.0.0 (code 12) release (commit 83a6735) differs from the scanned
commit (806b0ad) only in `versionCode` / `versionName` in
`app/build.gradle.kts`. Dependency graph is unchanged, so the scan
result applies unchanged.
