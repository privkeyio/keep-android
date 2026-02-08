#!/bin/bash
set -e

KEEP_REPO="${KEEP_REPO:-./keep}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_PROJECT="$KEEP_REPO/keep-mobile"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

echo "Building keep-mobile for Android..."

if [ -n "$TARGETS" ]; then
    IFS=',' read -ra TARGETS <<< "$TARGETS"
else
    TARGETS=(
        "aarch64-linux-android"
        "armv7-linux-androideabi"
        "x86_64-linux-android"
        "i686-linux-android"
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

echo "Done!"
