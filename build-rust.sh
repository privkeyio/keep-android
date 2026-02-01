#!/bin/bash
set -e

# Path to keep repo (adjust as needed)
KEEP_REPO="${KEEP_REPO:-./keep}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_PROJECT="$KEEP_REPO/keep-mobile"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

echo "Building keep-mobile for Android..."

# Build for Android targets (can override with TARGETS env var)
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
    echo "Building for $target..."
    cargo ndk -t "$target" -o "$JNILIBS_DIR" build --release
done

# Remove unnecessary redb cdylib artifacts (redb is statically linked)
rm -f "$JNILIBS_DIR"/*/libredb-*.so

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run --bin uniffi-bindgen generate \
    --library "$JNILIBS_DIR/arm64-v8a/libkeep_mobile.so" \
    --language kotlin \
    --out-dir "$SCRIPT_DIR/app/src/main/kotlin"

echo "Done!"
