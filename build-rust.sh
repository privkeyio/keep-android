#!/bin/bash
set -euo pipefail

KEEP_REPO="${KEEP_REPO:-./keep}"
if [ ! -d "$KEEP_REPO" ]; then
    echo "error: KEEP_REPO path does not exist: $KEEP_REPO" >&2
    exit 1
fi
KEEP_REPO="$(cd "$KEEP_REPO" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_PROJECT="$KEEP_REPO/keep-mobile"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

# Reproducible-build environment. Callers may override SOURCE_DATE_EPOCH.
export LC_ALL=C
export TZ=UTC
umask 022

SOURCE_DATE_EPOCH="$(ANDROID_REPO="$SCRIPT_DIR" KEEP_REPO="$KEEP_REPO" \
    "$SCRIPT_DIR/scripts/derive-sde.sh")"
if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
    echo "error: derived SOURCE_DATE_EPOCH='$SOURCE_DATE_EPOCH' is not a non-negative integer." >&2
    exit 1
fi
export SOURCE_DATE_EPOCH
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

# Pin the NDK that cargo-ndk uses. cargo-ndk discovers the NDK from
# ANDROID_NDK_HOME / ANDROID_NDK_ROOT / ANDROID_NDK and may prefer one over
# another; on CI runners that preinstall a different NDK and set
# ANDROID_NDK_ROOT, it silently builds the native libs with the wrong toolchain
# and breaks reproducible builds. Resolve the pinned NDK (expectedNdkVersion in
# build.gradle.kts) once and force every var to it.
EXPECTED_NDK="$(sed -nE 's/^val expectedNdkVersion = "([0-9][0-9.]*)".*/\1/p' \
    "$SCRIPT_DIR/build.gradle.kts" | head -1)"
if [ -z "$EXPECTED_NDK" ]; then
    echo "error: could not read expectedNdkVersion from $SCRIPT_DIR/build.gradle.kts." >&2
    exit 1
fi
NDK_DIR=""
if [ -n "${ANDROID_NDK_HOME:-}" ] && [ "$(basename "$ANDROID_NDK_HOME")" = "$EXPECTED_NDK" ]; then
    NDK_DIR="$ANDROID_NDK_HOME"
elif [ -n "${ANDROID_NDK_ROOT:-}" ] && [ "$(basename "$ANDROID_NDK_ROOT")" = "$EXPECTED_NDK" ]; then
    NDK_DIR="$ANDROID_NDK_ROOT"
else
    SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [ -n "$SDK_DIR" ] && [ -d "$SDK_DIR/ndk/$EXPECTED_NDK" ]; then
        NDK_DIR="$SDK_DIR/ndk/$EXPECTED_NDK"
    fi
fi
if [ -z "$NDK_DIR" ] || [ ! -d "$NDK_DIR" ]; then
    echo "error: pinned NDK $EXPECTED_NDK not found (checked ANDROID_NDK_HOME, ANDROID_NDK_ROOT, and \$ANDROID_HOME/ndk/$EXPECTED_NDK)." >&2
    echo "Fix: sdkmanager --install \"ndk;$EXPECTED_NDK\" and set ANDROID_HOME." >&2
    exit 1
fi
export ANDROID_NDK_HOME="$NDK_DIR"
export ANDROID_NDK_ROOT="$NDK_DIR"
export ANDROID_NDK="$NDK_DIR"
echo "Using pinned NDK: $NDK_DIR"

# Build aws-lc-sys's bundled C with a fixed CMake generator so every builder
# (CI, F-Droid, local) produces identical native libraries. The Android NDK
# CMake toolchain only reliably supports Ninja.
if ! command -v ninja >/dev/null 2>&1; then
    echo "error: ninja not found; required to build aws-lc-sys reproducibly." >&2
    echo "Fix: install ninja (apt-get install ninja-build)." >&2
    exit 1
fi
export CMAKE_GENERATOR=Ninja

# Strip absolute paths from rustc debuginfo so two builders with different
# CARGO_HOME / workspace locations produce byte-identical .so files.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
REMAP_FLAGS=(
    "--remap-path-prefix=$RUST_PROJECT=/build/keep-mobile"
    "--remap-path-prefix=$KEEP_REPO=/build"
    "--remap-path-prefix=$CARGO_HOME_DIR/registry=/cargo/registry"
    "--remap-path-prefix=$CARGO_HOME_DIR/git=/cargo/git"
    "--remap-path-prefix=$CARGO_HOME_DIR=/cargo"
)
# Use CARGO_ENCODED_RUSTFLAGS with 0x1f (ASCII unit separator) between flags so
# whitespace in paths (e.g., $HOME containing spaces) can't split a flag mid-arg.
ALL_FLAGS=()
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    # Preserve pre-encoded flags verbatim as a single pre-joined segment.
    ALL_FLAGS+=("$CARGO_ENCODED_RUSTFLAGS")
elif [ -n "${RUSTFLAGS:-}" ]; then
    echo "error: RUSTFLAGS is set but CARGO_ENCODED_RUSTFLAGS is not." >&2
    echo "Word-splitting RUSTFLAGS would silently corrupt flags containing spaces." >&2
    echo "Fix: re-encode your flags into CARGO_ENCODED_RUSTFLAGS using 0x1f (ASCII unit" >&2
    echo "separator) between flags, then unset RUSTFLAGS before invoking this script." >&2
    exit 1
fi
ALL_FLAGS+=("${REMAP_FLAGS[@]}")
# Join with 0x1f.
printf -v CARGO_ENCODED_RUSTFLAGS '%s\x1f' "${ALL_FLAGS[@]}"
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"
export CARGO_ENCODED_RUSTFLAGS

# Pinned toolchain versions. Keep in sync with CI workflows and rust-toolchain.toml.
EXPECTED_RUST="1.89.0"
CARGO_NDK_VERSION="4.1.2"

if [[ ! "$EXPECTED_RUST" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: EXPECTED_RUST ($EXPECTED_RUST) is not a valid semver version." >&2
    exit 1
fi

if [ ! -d "$RUST_PROJECT" ]; then
    echo "error: keep-mobile not found at $RUST_PROJECT" >&2
    echo "Set KEEP_REPO to the path of your local keep checkout." >&2
    exit 1
fi

TOOLCHAIN_FILE="$KEEP_REPO/rust-toolchain.toml"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
    echo "error: $TOOLCHAIN_FILE not found; cannot determine pinned Rust version." >&2
    exit 1
fi
TOOLCHAIN_CHANNEL=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$TOOLCHAIN_FILE" | head -1)
if [ -z "$TOOLCHAIN_CHANNEL" ]; then
    echo "error: could not parse channel from $TOOLCHAIN_FILE" >&2
    exit 1
fi
if [ "$TOOLCHAIN_CHANNEL" != "$EXPECTED_RUST" ]; then
    echo "error: rust-toolchain.toml channel does not match pinned EXPECTED_RUST" >&2
    echo "  pinned (build-rust.sh): $EXPECTED_RUST" >&2
    echo "  channel ($TOOLCHAIN_FILE): $TOOLCHAIN_CHANNEL" >&2
    echo "Fix: update both to the same version after reviewing the keep repo SHA pin." >&2
    exit 1
fi

ACTUAL_RUST=$(cd "$RUST_PROJECT" && rustc --version | awk '{print $2}')
if [ -z "$ACTUAL_RUST" ]; then
    echo "error: failed to determine rustc version (empty output from 'rustc --version')." >&2
    echo "Fix: ensure rustup/rustc is installed and on PATH." >&2
    exit 1
fi
if [[ ! "$ACTUAL_RUST" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: rustc version '$ACTUAL_RUST' is not a valid semver version." >&2
    exit 1
fi
if [ "$ACTUAL_RUST" != "$EXPECTED_RUST" ]; then
    echo "error: rustc version mismatch" >&2
    echo "  expected: $EXPECTED_RUST" >&2
    echo "  actual:   $ACTUAL_RUST" >&2
    echo "Fix: run 'rustup install $EXPECTED_RUST' (rustup should auto-select via rust-toolchain.toml)." >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "error: cargo-ndk not installed." >&2
    echo "Fix: cargo install --locked cargo-ndk --version $CARGO_NDK_VERSION" >&2
    exit 1
fi
VERSION_OUTPUT="$(cargo ndk --version 2>/dev/null || true)"
ACTUAL_CARGO_NDK="$(sed -nE 's/^cargo-ndk[[:space:]]+v?([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<<"$VERSION_OUTPUT" | head -1)"
if [ "$ACTUAL_CARGO_NDK" != "$CARGO_NDK_VERSION" ]; then
    echo "error: cargo-ndk version mismatch" >&2
    echo "  expected: $CARGO_NDK_VERSION" >&2
    echo "  actual:   ${ACTUAL_CARGO_NDK:-<unparseable>}" >&2
    echo "Fix: cargo install --locked cargo-ndk --version $CARGO_NDK_VERSION --force" >&2
    exit 1
fi

echo "Building keep-mobile for Android..."

if [ -n "${TARGETS:-}" ]; then
    IFS=',' read -ra TARGETS <<< "$TARGETS"
else
    TARGETS=(
        "aarch64-linux-android"
        "x86_64-linux-android"
    )
fi

cd "$RUST_PROJECT"

for target in "${TARGETS[@]}"; do
    rustup target add "$target"
done

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo ndk -t "$target" -P 33 -o "$JNILIBS_DIR" build --release --locked
done

rm -f "$JNILIBS_DIR"/*/libredb-*.so

BINDING_LIB=$(find "$JNILIBS_DIR" -name "libkeep_mobile.so" | LC_ALL=C sort | head -1)
echo "Generating Kotlin bindings from $BINDING_LIB..."
cargo run --features cli --bin uniffi-bindgen generate \
    --library "$BINDING_LIB" \
    --language kotlin \
    --out-dir "$SCRIPT_DIR/app/src/main/kotlin"

GENERATED_KT="$SCRIPT_DIR/app/src/main/kotlin/io/privkey/keep/uniffi/keep_mobile.kt"
if [ -f "$GENERATED_KT" ]; then
    sed -i 's/@file:Suppress([^)]*)/@file:Suppress("NAME_SHADOWING", "REDUNDANT_CALL_OF_CONVERSION_METHOD", "NOTHING_TO_INLINE", "UNUSED_PARAMETER", "UNUSED_EXPRESSION")/' "$GENERATED_KT"
fi

echo "Done!"
