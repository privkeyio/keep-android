# Reproducible Builds

Two independent builders with matching toolchains and source commits must
produce byte-identical release APKs. This document lists the required
environment and the verification procedure.

## Required toolchain

Pinned and enforced by `scripts/check-toolchain-pins.sh`:

| Component     | Version           |
|---------------|-------------------|
| Rust          | 1.89.0            |
| cargo-ndk     | 4.1.2             |
| Android NDK   | 29.0.14206865     |
| Android build-tools | 36.0.0      |
| JDK           | 17 (Temurin, verified with 17.0.13+11) |
| AGP           | 9.1.0             |
| Kotlin        | 2.3.20            |

The `keep` sibling repository must be checked out at the exact commit
referenced by `.github/workflows/release.yml` (`ref:` under the
`Checkout keep repo` step).

## Required environment

| Variable              | Value                                         |
|-----------------------|-----------------------------------------------|
| `SOURCE_DATE_EPOCH`   | commit timestamp (see below)                  |
| `LC_ALL`              | `C` (set by `build-rust.sh`)                  |
| `TZ`                  | `UTC` (set by `build-rust.sh`)                |
| `umask`               | `022` (set by `build-rust.sh`)                |
| Filesystem            | case-sensitive (ext4, APFS case-sensitive)    |

`SOURCE_DATE_EPOCH` is derived by `scripts/derive-sde.sh` (called by both
`build-rust.sh` and `.github/workflows/release.yml`) as the later of the
HEAD commit times of this repository and the `keep` workspace. Override
by exporting it explicitly.

**Local `./gradlew assembleRelease` callers must export
`SOURCE_DATE_EPOCH` in the shell before invoking Gradle.** AGP's
packaging and signing steps read it from the Gradle process environment;
`build.gradle.kts` only forwards it into the `buildRust` `Exec`
subprocess, so an unset shell variable will produce a non-reproducible
APK even if the Rust build was reproducible. Easiest recipe (the
example assumes the `keep` checkout is at `./keep`; set `KEEP_REPO` if
it lives elsewhere):

```bash
export KEEP_REPO=../keep
export SOURCE_DATE_EPOCH="$(./scripts/derive-sde.sh)"
```

### JDK minor version

The JDK minor version is a known reproducibility variable. Release
builds are verified against Temurin 17.0.13+11; other 17.x builds may
produce byte-identical output but are not guaranteed to.

### `umask` scope

`umask 022` in `build-rust.sh` only affects files the script itself
writes (cargo-ndk outputs, generated bindings). Gradle's APK packager
normalizes entry modes inside the APK independently, so this setting is
belt-and-suspenders rather than load-bearing for APK reproducibility.

## Local verification

```bash
export KEEP_REPO=../keep
export SOURCE_DATE_EPOCH="$(./scripts/derive-sde.sh)"

# clean state
./gradlew clean
rm -rf app/src/main/jniLibs app/src/main/kotlin/io/privkey/keep/uniffi

# build 1
./build-rust.sh
ANDROID_HOME=/usr/lib/android-sdk ./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release*.apk /tmp/build1.apk

# clean and re-build
./gradlew clean
rm -rf app/src/main/jniLibs app/src/main/kotlin/io/privkey/keep/uniffi
./build-rust.sh
ANDROID_HOME=/usr/lib/android-sdk ./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release*.apk /tmp/build2.apk

sha256sum /tmp/build1.apk /tmp/build2.apk
diffoscope /tmp/build1.apk /tmp/build2.apk
```

## Sources of non-determinism addressed

1. **Build timestamps** — `SOURCE_DATE_EPOCH` derived from the latest
   commit of the two source repos, propagated to `cargo`, AGP, and the
   APK signing path.
2. **Absolute paths in Rust debuginfo** — `build-rust.sh` injects
   `--remap-path-prefix` for the `keep` workspace, `CARGO_HOME`, and the
   cargo registry.
3. **Play dependency metadata** — `android.dependenciesInfo
   { includeInApk = false; includeInBundle = false }` strips the
   encrypted Play Store metadata blob (contains a signing timestamp).
4. **Native lib packaging** — `jniLibs.useLegacyPackaging = false`
   ensures uncompressed, page-aligned, deterministic entries.
5. **Locale/timezone ordering** — `LC_ALL=C TZ=UTC umask 022` set
   before any file I/O or archive creation.

## Known residual differences

None currently documented. If a verifier finds a diff, attach the
`diffoscope` output to an issue.

## Automated CI enforcement

`.github/workflows/reproducibility.yml` guards against regressions by
rebuilding inside the pinned `Dockerfile.reproducible` container and
comparing the result against the published release APK. The workflow:

- Runs on `workflow_dispatch`, a weekly `schedule` (Mondays 06:00 UTC),
  on `v*` tag pushes so every release is verified, and on pull requests
  carrying the `reproducibility` label. It is deliberately excluded from
  the default PR path because a release build is expensive.
- Builds the APK exactly as `release.yml` does, inside
  `Dockerfile.reproducible`, which owns the pinned toolchain (Rust,
  cargo-ndk, NDK, build-tools, JDK) and derives `SOURCE_DATE_EPOCH`
  internally. The bare runner produces a non-standard aws-lc build, so
  the container is what makes the output match the release.
- On `schedule`/`workflow_dispatch` it resolves the latest published
  release tag, checks it out, and builds from that tag so the source
  tree and `keep.version` match the downloaded APK. On a `v*` tag push it
  builds that tag.
- Downloads the published, developer-signed release APK and compares the
  zip payload with `apksigcopier compare`, which ignores the signing
  block, the same comparison F-Droid performs. A payload difference fails
  the job so the regression is visible.
- On labeled pull requests it builds the PR head in the container to
  prove the reproducible path still builds, but skips the download and
  comparison (there is no matching published APK).

This verifies that the container build is deterministic and reproduces
the published payload on the same runner. It is not an independent
cross-environment rebuild, only F-Droid's buildserver provides that.
