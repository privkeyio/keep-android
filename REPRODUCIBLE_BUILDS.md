# Reproducible Builds

This document describes how to independently reproduce the official release APK
of keep-android bit-for-bit from source. A successful reproduction yields a
file whose SHA-256 matches the APK published on the corresponding
[GitHub release](https://github.com/privkeyio/keep-android/releases) once the
release's signature block is stripped or the same signing key is used.

The recipe is pinned, self-contained, and does not require contacting the
maintainers. If your build does not match, the automated
`.github/workflows/reproducibility.yml` job (which rebuilds twice and compares)
is the reference and your environment drift is the likely cause.

## Overview

A reproducible keep-android build requires:

1. Source at the exact commit of the release tag.
2. The `keep` Rust workspace at the SHA pinned in `keep.version`.
3. Exact toolchain versions (JDK, Android SDK build-tools, Android NDK, Rust, cargo-ndk).
4. `SOURCE_DATE_EPOCH` derived from the later of the two repos' HEAD commit times.
5. Path remapping in `rustc` (already encoded in `build-rust.sh`).

Two paths are supported:

- **Host build** (Section 3) — install the pinned toolchain on your host.
- **Container build** (Section 4) — use `Dockerfile.reproducible` at the repo root.

After building, verify via `apksigner` and compare to the release APK via
`diffoscope` (Section 5).

## 1. Pinned Toolchain (source of truth)

`scripts/check-toolchain-pins.sh` cross-validates the Rust, cargo-ndk, NDK,
JDK major, build-tools, AGP, Kotlin compose plugin, and KSP pins across all
files where they appear. Run it after any toolchain change. Do not substitute.

| Component                  | Version                                  | Source of truth                                  |
|----------------------------|------------------------------------------|--------------------------------------------------|
| Host OS (CI reference)     | Ubuntu 24.04                             | `.github/workflows/release.yml` (`runs-on`)      |
| Container base             | Debian 12 bookworm-slim (digest-pinned)  | `Dockerfile.reproducible` (`FROM debian@sha256:...`) |
| Debian APT snapshot        | snapshot.debian.org fixed timestamp      | `Dockerfile.reproducible` (`DEBIAN_SNAPSHOT`)    |
| JDK                        | Temurin 17                               | `build.gradle.kts` (`expectedJavaMajor = 17`)    |
| Android SDK build-tools    | 36.0.0                                   | `.github/workflows/release.yml` (`BUILD_TOOLS_VERSION`) |
| Android `compileSdk`       | 36                                       | `app/build.gradle.kts`                           |
| Android `minSdk`           | 33                                       | `app/build.gradle.kts`                           |
| Android NDK                | 29.0.14206865                            | `build.gradle.kts` (`expectedNdkVersion`)        |
| Rust (rustc/cargo)         | 1.89.0                                   | `build-rust.sh` (`EXPECTED_RUST`) / `keep/rust-toolchain.toml` |
| cargo-ndk                  | 4.1.2                                    | `build-rust.sh` (`CARGO_NDK_VERSION`)            |
| Android Gradle Plugin      | 9.1.0                                    | `build.gradle.kts`                               |
| Kotlin Compose plugin      | 2.3.20                                   | `build.gradle.kts`                               |
| KSP                        | 2.3.6                                    | `build.gradle.kts`                               |

The container build (Section 4) is the canonical reproducibility path — its
toolchain layers are byte-pinned (base image digest + SHA-256 of every
downloaded archive). Host builds on other distros may not produce
byte-identical APKs even with matching tool versions, since aapt2/dex tooling
can embed host libc strings and tzdata.

## 2. Pinned Source

- **keep-android**: check out the tag of the release you are reproducing
  (e.g. `v0.5.2`). The current `keep` pin lives in
  [`keep.version`](./keep.version) at that tag — read it with
  `tr -d '[:space:]' < keep.version`.
- **keep** (Rust workspace): checked out at the 40-char hex SHA in
  `keep.version`. The Gradle task `verifyKeepVersion` aborts the build if the
  checkout drifts, so you cannot silently reproduce against the wrong sources.

> **Trust model.** The recipe pins `keep` by commit SHA, which defeats
> post-hoc tampering of the `keep` repo, but does not by itself attest to who
> authored that commit. Before trusting a reproduction, verify the
> keep-android release tag's GPG/SSH signature out of band
> (`git tag --verify v<x.y.z>`).

Clone both:

```bash
# Pick the release tag you want to reproduce.
TAG=v0.5.2  # example — substitute the release you are verifying

git clone https://github.com/privkeyio/keep-android.git
git -C keep-android checkout "$TAG"

KEEP_SHA="$(tr -d '[:space:]' < keep-android/keep.version)"
git clone https://github.com/privkeyio/keep.git
git -C keep checkout "$KEEP_SHA"
```

Both directories must be siblings, or `KEEP_REPO` must point at the `keep`
checkout.

## 3. Host Build

### 3.1 Install the pinned toolchain

- **JDK 17 (Temurin)**: install from your package manager or
  [Adoptium](https://adoptium.net/). Ensure `java -version` reports 17.
- **Android SDK**: install `cmdline-tools`, then run:
  ```bash
  sdkmanager --install "platforms;android-36" \
                      "build-tools;36.0.0" \
                      "ndk;29.0.14206865"
  ```
  Export `ANDROID_HOME` to the SDK root (CI uses
  `/usr/local/lib/android/sdk`; Debian/Ubuntu packages use
  `/usr/lib/android-sdk`).
- **Rust 1.89.0 + cargo-ndk 4.1.2**:
  ```bash
  rustup toolchain install 1.89.0
  rustup override set 1.89.0   # optional; rust-toolchain.toml also pins it
  rustup target add aarch64-linux-android x86_64-linux-android
  cargo install --locked cargo-ndk --version 4.1.2
  ```

`scripts/check-toolchain-pins.sh` cross-verifies every pin and fails loudly on
drift; run it after installation:

```bash
cd keep-android
./scripts/check-toolchain-pins.sh
```

### 3.2 Build the APK

```bash
cd keep-android

export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/29.0.14206865"
export KEEP_REPO="$PWD/../keep"
export AWS_LC_SYS_CMAKE_BUILDER=1

# Deterministic timestamp (later of the two repos' HEAD commit times).
export SOURCE_DATE_EPOCH="$(./scripts/derive-sde.sh)"

# Native libs + UniFFI Kotlin bindings.
./build-rust.sh

# Android release APK. Signing behavior differs between the host and
# container paths:
#   * Host build: if no `KEYSTORE_FILE` is exported and no `storeFile` is
#     resolved by `app/build.gradle.kts`, Gradle falls back to the debug
#     signing key and still writes `app-release.apk`.
#   * Container build (Section 4): `Dockerfile.reproducible` intentionally
#     generates a throwaway keystore per build when `KEYSTORE_FILE` is unset,
#     so the APK is always release-signed. This enforces a deterministic
#     signing path for reproducibility verification; the fallback-to-debug
#     behavior of `app/build.gradle.kts` is therefore not exercised by the
#     container. Pass `KEYSTORE_FILE`/`KEYSTORE_PASSWORD`/`KEY_ALIAS`/
#     `KEY_PASSWORD` to sign with a real key inside the container.
./gradlew assembleRelease --no-daemon
```

Output: `app/build/outputs/apk/release/app-release.apk`.

If you want to reproduce the exact byte layout of the published APK, you must
sign with the same release key; otherwise the APK payload is identical but the
signing block (v2/v3) differs. For pure reproducibility verification (two
independent builds of the same sources producing identical bytes), use a
throwaway keystore and compare two of your own builds, as
`.github/workflows/reproducibility.yml` does.

## 4. Container Build

A self-contained `Dockerfile.reproducible` at the repo root encapsulates the
host build. It pins a Debian base image by digest and installs the exact
toolchain versions.

The container build requires `.git` to exist in the keep-android checkout
(it is needed by `scripts/derive-sde.sh`). The shipped `.dockerignore`
preserves `.git/`; do not exclude it.

```bash
cd keep-android

# Export the pinned keep SHA and a deterministic timestamp.
export KEEP_SHA="$(tr -d '[:space:]' < keep.version)"
export SOURCE_DATE_EPOCH="$(./scripts/derive-sde.sh)"

# BuildKit is required for the `--output` export stage.
DOCKER_BUILDKIT=1 docker build \
    --build-arg KEEP_SHA="$KEEP_SHA" \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    --output type=local,dest=out \
    -f Dockerfile.reproducible \
    .

ls out/   # app-release.apk
```

The container:

1. Starts from a digest-pinned Debian slim base.
2. Installs Temurin JDK 17, Android cmdline-tools, build-tools 36.0.0, NDK
   29.0.14206865, Rust 1.89.0, and cargo-ndk 4.1.2.
3. Copies the keep-android sources in and clones `keep` at the pinned SHA.
4. Runs `build-rust.sh` and `./gradlew assembleRelease` with
   `SOURCE_DATE_EPOCH` set.
5. Exports the signed release APK to `./out/` (signed with a per-build
   throwaway keystore unless a keystore is supplied; see § 4.1).

### 4.1 Optional build-args

- `KEEP_SHA` (default: read from `keep.version`): 40-char hex commit SHA of
  the `keep` Rust workspace to check out. Overriding this reproduces against
  a different pin than the shipped one and is for forensic use only.
- `KEEP_REMOTE` (default: `https://github.com/privkeyio/keep.git`): the
  remote to clone `keep` from. Only https URLs are accepted. Useful when
  mirroring the source behind a restricted network.
- `SOURCE_DATE_EPOCH` (default: derived by `scripts/derive-sde.sh` inside
  the container): deterministic timestamp for the build. The literal value
  `0` is accepted and honored verbatim (1970-01-01).
- `KEYSTORE_FILE` / `KEYSTORE_PASSWORD` / `KEY_ALIAS` / `KEY_PASSWORD`: pass
  a real keystore into the build to produce an APK whose signing block
  matches the released bytes. Passing secrets via `--build-arg` leaves them
  in `docker history`; prefer mounting a keystore file with
  `docker build --secret id=keystore,src=/path/to/keystore.jks` and setting
  `KEYSTORE_FILE=/run/secrets/keystore` via an entrypoint wrapper. When
  `KEYSTORE_FILE` is set, all three of `KEYSTORE_PASSWORD`, `KEY_ALIAS`,
  and `KEY_PASSWORD` must also be provided or the build fails fast. Without
  any of these, a throwaway keystore is generated and used (DO NOT SHIP).

## 5. Verify the Result

### 5.1 Inspect APK signature (official release only)

The official APK is signed with APK signature scheme v2/v3. Many system
`apksigner` packages (e.g. Debian's 0.9) are too old to verify v2/v3. Use the
build-tools 36.0.0 `apksigner` shipped with the SDK:

```bash
# Use the build-tools version pinned in the table above (Section 1).
BUILD_TOOLS_VERSION=36.0.0
"$ANDROID_HOME/build-tools/${BUILD_TOOLS_VERSION}/apksigner" verify --print-certs \
    keep-android-v0.5.2.apk
```

### 5.2 Compare against the release APK

Download the published APK and its checksum from the corresponding GitHub
release (both live under `https://github.com/privkeyio/keep-android/releases`
and a `SHA256SUMS` file is attached).

```bash
# 1. Confirm the checksum of the download.
sha256sum -c SHA256SUMS

# 2. Compare the official APK with your local build. The payload is what is
#    reproducible; the signing block is not, since it requires the release
#    signing key. diffoscope runs directly on the two APKs and highlights the
#    signing-block differences inline — no manual stripping required.
#    A plain `sha256sum` match is only expected when you rebuild with the same
#    signing key as the release.

sudo apt-get install -y diffoscope
diffoscope --html diffoscope.html --text diffoscope.txt \
    keep-android-v0.5.2.apk \
    app/build/outputs/apk/release/app-release.apk
```

A reproducible build produces a `diffoscope` report in which:

- All `classes*.dex`, `resources.arsc`, `AndroidManifest.xml`, native `.so`
  libraries, and asset files are byte-identical.
- Only the signing block (`META-INF/CERT.*`, `META-INF/MANIFEST.MF`,
  `META-INF/*.SF`, APK signature scheme v2/v3 block) differs, because the
  release was signed with a key you do not hold.

If anything else differs, your environment has drifted from the pins.

### 5.3 Independent double-build check

You do not need the published APK at all to verify reproducibility — you can
verify that two builds of the same sources in the same environment produce
identical bytes, which is exactly what `.github/workflows/reproducibility.yml`
does weekly and on every release tag:

Requires `KEEP_REPO` to be exported (see § 3.2); `"$KEEP_REPO/keep-mobile/target"`
is removed explicitly so the sibling cargo target dir is purged even when
`keep` is checked out outside this repo tree.

```bash
: "${KEEP_REPO:?set KEEP_REPO to your keep checkout, e.g. export KEEP_REPO=\"\$PWD/../keep\"}"

./gradlew clean --no-daemon
rm -rf app/src/main/jniLibs app/src/main/kotlin/io/privkey/keep/uniffi "$KEEP_REPO/keep-mobile/target"
./build-rust.sh
./gradlew assembleRelease --no-daemon
cp app/build/outputs/apk/release/app-release.apk /tmp/build1.apk

./gradlew clean --no-daemon
rm -rf app/src/main/jniLibs app/src/main/kotlin/io/privkey/keep/uniffi "$KEEP_REPO/keep-mobile/target"
./build-rust.sh
./gradlew assembleRelease --no-daemon
cp app/build/outputs/apk/release/app-release.apk /tmp/build2.apk

sha256sum /tmp/build1.apk /tmp/build2.apk
```

The two SHA-256 hashes MUST be identical.

## 6. Troubleshooting

- **`SOURCE_DATE_EPOCH is not set`**: you invoked `assembleRelease` without
  exporting it. Always run
  `export SOURCE_DATE_EPOCH="$(./scripts/derive-sde.sh)"` first.
- **`rustc version mismatch`**: rustup selected a different toolchain than
  `rust-toolchain.toml` pins. Run `rustup toolchain install 1.89.0` and ensure
  no `RUSTUP_TOOLCHAIN` override is set.
- **`keep checkout ... does not match pinned ...`**: run
  `git -C ../keep checkout "$(tr -d '[:space:]' < keep.version)"`.
- **`cargo-ndk version mismatch`**: run
  `cargo install --locked cargo-ndk --version 4.1.2 --force`.
- **NDK missing**: `sdkmanager --install "ndk;29.0.14206865"`.
- **`apksigner` verify reports v2/v3 unsupported**: your system `apksigner` is
  too old; use `$ANDROID_HOME/build-tools/36.0.0/apksigner`.

## 7. Reporting Reproducibility Failures

If you followed the recipe exactly and cannot reproduce a release, file an
issue at <https://github.com/privkeyio/keep-android/issues> with:

- The release tag you were reproducing.
- The exact commands you ran (prefer the container build for reproducibility).
- The `diffoscope --text` output.
- The output of `scripts/check-toolchain-pins.sh` and
  `rustc --version`, `cargo ndk --version`, `java -version`, `sdkmanager --list_installed`.
