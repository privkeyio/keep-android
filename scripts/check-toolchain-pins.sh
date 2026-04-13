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
GRADLE_KTS="$ROOT/build.gradle.kts"
TOOLCHAIN_TOML="$ROOT/keep/rust-toolchain.toml"

for f in "$BUILD_RUST" "$CI_YML" "$RELEASE_YML" "$GRADLE_KTS"; do
    [ -f "$f" ] || fail "missing file: $f"
done

BR_RUST=$(extract "$BUILD_RUST" 'EXPECTED_RUST="([0-9]+\.[0-9]+\.[0-9]+)"')
BR_CARGO_NDK=$(extract "$BUILD_RUST" 'CARGO_NDK_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"')

CI_RUST=$(extract "$CI_YML" '^[[:space:]]+RUST_VERSION: "([0-9]+\.[0-9]+\.[0-9]+)"')
CI_NDK=$(extract "$CI_YML" '^[[:space:]]+NDK_VERSION: "([0-9.]+)"')
CI_CARGO_NDK=$(extract "$CI_YML" '^[[:space:]]+CARGO_NDK_VERSION: "([0-9]+\.[0-9]+\.[0-9]+)"')

REL_RUST=$(extract "$RELEASE_YML" '^[[:space:]]+RUST_VERSION: "([0-9]+\.[0-9]+\.[0-9]+)"')
REL_NDK=$(extract "$RELEASE_YML" '^[[:space:]]+NDK_VERSION: "([0-9.]+)"')
REL_CARGO_NDK=$(extract "$RELEASE_YML" '^[[:space:]]+CARGO_NDK_VERSION: "([0-9]+\.[0-9]+\.[0-9]+)"')

GRADLE_NDK=$(extract "$GRADLE_KTS" 'expectedNdkVersion = "([0-9.]+)"')
GRADLE_JDK=$(extract "$GRADLE_KTS" 'expectedJavaMajor = ([0-9]+)')

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

check_equal "rust version"        "$BR_RUST"       "$CI_RUST"       "$REL_RUST"
check_equal "cargo-ndk version"   "$BR_CARGO_NDK"  "$CI_CARGO_NDK"  "$REL_CARGO_NDK"
check_equal "ndk version"         "$CI_NDK"        "$REL_NDK"       "$GRADLE_NDK"
check_equal "jdk major version"   "$GRADLE_JDK"    "$CI_JDK"        "$REL_JDK"

if [ -f "$TOOLCHAIN_TOML" ]; then
    TOML_CHANNEL=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' "$TOOLCHAIN_TOML" | head -1)
    [ -n "$TOML_CHANNEL" ] || fail "could not parse channel from $TOOLCHAIN_TOML"
    check_equal "rust-toolchain.toml channel" "$BR_RUST" "$TOML_CHANNEL"
else
    echo "note: $TOOLCHAIN_TOML not present; skipping channel check."
fi

echo "all toolchain pins consistent."
