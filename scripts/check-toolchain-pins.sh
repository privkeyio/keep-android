#!/bin/bash
set -euo pipefail

# Verifies that pinned toolchain versions are consistent across all files.
# Sources of truth checked:
#   build-rust.sh            (EXPECTED_RUST, CARGO_NDK_VERSION)
#   .github/workflows/ci.yml (RUST_VERSION, NDK_VERSION, CARGO_NDK_VERSION)
#   .github/workflows/release.yml (RUST_VERSION, NDK_VERSION, CARGO_NDK_VERSION)
#   keep/rust-toolchain.toml (channel, if present)
#   build.gradle.kts         (expectedNdkVersion, expectedJavaMajor)
#   .github/workflows/*.yml  (java-version in actions/setup-java steps)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

fail() {
    echo "error: $*" >&2
    exit 1
}

extract() {
    # extract <file> <regex with one capture group>
    local file="$1"
    local regex="$2"
    local val
    val=$(sed -nE "s/.*${regex}.*/\1/p" "$file" | head -1)
    [ -n "$val" ] || fail "could not extract /$regex/ from $file"
    echo "$val"
}

BUILD_RUST="$ROOT/build-rust.sh"
CI_YML="$ROOT/.github/workflows/ci.yml"
RELEASE_YML="$ROOT/.github/workflows/release.yml"
REPRO_YML="$ROOT/.github/workflows/reproducibility.yml"
GRADLE_KTS="$ROOT/build.gradle.kts"
TOOLCHAIN_TOML="$ROOT/keep/rust-toolchain.toml"
DOCKERFILE="$ROOT/Dockerfile.reproducible"

for f in "$BUILD_RUST" "$CI_YML" "$RELEASE_YML" "$REPRO_YML" "$GRADLE_KTS"; do
    [ -f "$f" ] || fail "missing file: $f"
done

yaml_env() {
    # yaml_env <file> <KEY> <value-regex>
    extract "$1" "^[[:space:]]+$2: \"($3)\""
}

BR_RUST=$(extract "$BUILD_RUST" 'EXPECTED_RUST="([0-9]+\.[0-9]+\.[0-9]+)"')
BR_CARGO_NDK=$(extract "$BUILD_RUST" 'CARGO_NDK_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"')

SEMVER='[0-9]+\.[0-9]+\.[0-9]+'
NDK_VER='[0-9]+(\.[0-9]+)*'

CI_RUST=$(yaml_env "$CI_YML" RUST_VERSION "$SEMVER")
CI_NDK=$(yaml_env "$CI_YML" NDK_VERSION "$NDK_VER")
CI_CARGO_NDK=$(yaml_env "$CI_YML" CARGO_NDK_VERSION "$SEMVER")

REL_RUST=$(yaml_env "$RELEASE_YML" RUST_VERSION "$SEMVER")
REL_NDK=$(yaml_env "$RELEASE_YML" NDK_VERSION "$NDK_VER")
REL_CARGO_NDK=$(yaml_env "$RELEASE_YML" CARGO_NDK_VERSION "$SEMVER")
REL_BUILD_TOOLS=$(yaml_env "$RELEASE_YML" BUILD_TOOLS_VERSION "$NDK_VER")

REPRO_RUST=$(yaml_env "$REPRO_YML" RUST_VERSION "$SEMVER")
REPRO_NDK=$(yaml_env "$REPRO_YML" NDK_VERSION "$NDK_VER")
REPRO_CARGO_NDK=$(yaml_env "$REPRO_YML" CARGO_NDK_VERSION "$SEMVER")
REPRO_BUILD_TOOLS=$(yaml_env "$REPRO_YML" BUILD_TOOLS_VERSION "$NDK_VER")

GRADLE_NDK=$(extract "$GRADLE_KTS" 'expectedNdkVersion = "([0-9.]+)"')
GRADLE_JDK=$(extract "$GRADLE_KTS" 'expectedJavaMajor = ([0-9]+)')
GRADLE_COMPILE_SDK=$(extract "$ROOT/app/build.gradle.kts" 'compileSdk = ([0-9]+)')

extract_unique() {
    # extract_unique <file> <regex with one capture group>: all matches must be equal
    local file="$1"
    local regex="$2"
    local vals
    vals=$(sed -nE "s/.*${regex}.*/\1/p" "$file" | sort -u)
    [ -n "$vals" ] || fail "could not extract /$regex/ from $file"
    [ "$(echo "$vals" | wc -l)" -eq 1 ] || fail "inconsistent values for /$regex/ within $file: $vals"
    echo "$vals"
}

CI_JDK=$(extract_unique "$CI_YML" "^[[:space:]]+java-version: '([0-9]+)'")
REL_JDK=$(extract_unique "$RELEASE_YML" "^[[:space:]]+java-version: '([0-9]+)'")
REPRO_JDK=$(extract_unique "$REPRO_YML" "^[[:space:]]+java-version: '([0-9]+)'")

check_equal() {
    local name="$1"
    shift
    local first="$1"
    shift
    for v in "$@"; do
        if [ "$v" != "$first" ]; then
            fail "$name mismatch: $first vs $v (values: $first $*)"
        fi
    done
    echo "ok: $name = $first"
}

check_equal "rust version"        "$BR_RUST"       "$CI_RUST"       "$REL_RUST"       "$REPRO_RUST"
check_equal "cargo-ndk version"   "$BR_CARGO_NDK"  "$CI_CARGO_NDK"  "$REL_CARGO_NDK"  "$REPRO_CARGO_NDK"
check_equal "ndk version"         "$CI_NDK"        "$REL_NDK"       "$GRADLE_NDK"     "$REPRO_NDK"
check_equal "jdk major version"   "$GRADLE_JDK"    "$CI_JDK"        "$REL_JDK"        "$REPRO_JDK"
check_equal "build-tools version" "$REL_BUILD_TOOLS" "$REPRO_BUILD_TOOLS"

# Cross-check Dockerfile.reproducible pins against the same sources of truth
# so the container recipe cannot drift silently.
if [ -f "$DOCKERFILE" ]; then
    DOCKER_RUST=$(extract "$DOCKERFILE" 'ARG RUST_VERSION=('"$SEMVER"')')
    DOCKER_CARGO_NDK=$(extract "$DOCKERFILE" 'ARG CARGO_NDK_VERSION=('"$SEMVER"')')
    DOCKER_NDK=$(extract "$DOCKERFILE" 'ARG ANDROID_NDK_VERSION=('"$NDK_VER"')')
    DOCKER_BUILD_TOOLS=$(extract "$DOCKERFILE" 'ARG ANDROID_BUILD_TOOLS_VERSION=('"$NDK_VER"')')
    DOCKER_JDK_MAJOR=$(extract "$DOCKERFILE" 'ARG JDK_VERSION=([0-9]+)\.[0-9]+\.[0-9]+\+[0-9]+')
    DOCKER_ANDROID_PLATFORM=$(extract "$DOCKERFILE" 'ARG ANDROID_PLATFORM=android-([0-9]+)')
    check_equal "Dockerfile rust version"        "$BR_RUST"        "$DOCKER_RUST"
    check_equal "Dockerfile cargo-ndk version"   "$BR_CARGO_NDK"   "$DOCKER_CARGO_NDK"
    check_equal "Dockerfile ndk version"         "$GRADLE_NDK"     "$DOCKER_NDK"
    check_equal "Dockerfile build-tools version" "$REL_BUILD_TOOLS" "$DOCKER_BUILD_TOOLS"
    check_equal "Dockerfile jdk major"           "$GRADLE_JDK"     "$DOCKER_JDK_MAJOR"
    check_equal "Dockerfile android platform"    "$GRADLE_COMPILE_SDK" "$DOCKER_ANDROID_PLATFORM"
else
    echo "note: $DOCKERFILE not present; skipping container-recipe checks."
fi

# AGP / Kotlin compose / KSP plugin pins live only in build.gradle.kts. Verify
# they are present and parseable so the doc table cannot reference something
# the build no longer pins.
AGP_VERSION=$(extract "$GRADLE_KTS" 'id\("com\.android\.application"\) version "('"$SEMVER"')"')
KOTLIN_COMPOSE_VERSION=$(extract "$GRADLE_KTS" 'id\("org\.jetbrains\.kotlin\.plugin\.compose"\) version "('"$SEMVER"')"')
KSP_VERSION=$(extract "$GRADLE_KTS" 'id\("com\.google\.devtools\.ksp"\) version "('"$SEMVER"')"')
echo "ok: AGP version = $AGP_VERSION"
echo "ok: Kotlin compose plugin = $KOTLIN_COMPOSE_VERSION"
echo "ok: KSP version = $KSP_VERSION"

if [ -f "$TOOLCHAIN_TOML" ]; then
    TOML_CHANNEL=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' "$TOOLCHAIN_TOML" | head -1)
    [ -n "$TOML_CHANNEL" ] || fail "could not parse channel from $TOOLCHAIN_TOML"
    check_equal "rust-toolchain.toml channel" "$BR_RUST" "$TOML_CHANNEL"
else
    echo "note: $TOOLCHAIN_TOML not present; skipping channel check."
fi

echo "all toolchain pins consistent."
