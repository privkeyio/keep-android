#!/bin/bash
set -e

KEEP_REPO="${KEEP_REPO:-./keep}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_PROJECT="$KEEP_REPO/keep-mobile"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

# Pinned toolchain versions. Keep in sync with CI workflows and rust-toolchain.toml.
CARGO_NDK_VERSION="4.1.2"

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
EXPECTED_RUST=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$TOOLCHAIN_FILE" | head -1)
if [ -z "$EXPECTED_RUST" ]; then
    echo "error: could not parse channel from $TOOLCHAIN_FILE" >&2
    exit 1
fi

ACTUAL_RUST=$(cd "$RUST_PROJECT" && rustc --version | awk '{print $2}')
if [ "$ACTUAL_RUST" != "$EXPECTED_RUST" ]; then
    echo "error: rustc version mismatch" >&2
    echo "  expected: $EXPECTED_RUST (from $TOOLCHAIN_FILE)" >&2
    echo "  actual:   $ACTUAL_RUST" >&2
    echo "Fix: run 'rustup install $EXPECTED_RUST' (rustup should auto-select via rust-toolchain.toml)." >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "error: cargo-ndk not installed." >&2
    echo "Fix: cargo install --locked cargo-ndk --version $CARGO_NDK_VERSION" >&2
    exit 1
fi
ACTUAL_CARGO_NDK=$(cargo ndk --version | awk '{print $2}')
if [ "$ACTUAL_CARGO_NDK" != "$CARGO_NDK_VERSION" ]; then
    echo "error: cargo-ndk version mismatch" >&2
    echo "  expected: $CARGO_NDK_VERSION" >&2
    echo "  actual:   $ACTUAL_CARGO_NDK" >&2
    echo "Fix: cargo install --locked cargo-ndk --version $CARGO_NDK_VERSION --force" >&2
    exit 1
fi

echo "Building keep-mobile for Android..."

if [ -n "$TARGETS" ]; then
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
    cargo ndk -t "$target" -P 33 -o "$JNILIBS_DIR" build --release
done

rm -f "$JNILIBS_DIR"/*/libredb-*.so

BINDING_LIB=$(find "$JNILIBS_DIR" -name "libkeep_mobile.so" | head -1)
echo "Generating Kotlin bindings from $BINDING_LIB..."
cargo run --bin uniffi-bindgen generate \
    --library "$BINDING_LIB" \
    --language kotlin \
    --out-dir "$SCRIPT_DIR/app/src/main/kotlin"

GENERATED_KT="$SCRIPT_DIR/app/src/main/kotlin/io/privkey/keep/uniffi/keep_mobile.kt"
if [ -f "$GENERATED_KT" ]; then
    sed -i 's/@file:Suppress([^)]*)/@file:Suppress("NAME_SHADOWING", "REDUNDANT_CALL_OF_CONVERSION_METHOD", "NOTHING_TO_INLINE", "UNUSED_PARAMETER")/' "$GENERATED_KT"
fi

echo "Done!"
