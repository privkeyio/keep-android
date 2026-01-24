#!/bin/bash
set -e

# Path to keep repo (adjust as needed)
KEEP_REPO="${KEEP_REPO:-./keep}"
RUST_PROJECT="$KEEP_REPO/keep-mobile"

echo "Building keep-mobile for Android..."

# Build for all Android targets
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "x86_64-linux-android"
    "i686-linux-android"
)

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo ndk -t "$target" -o app/src/main/jniLibs build --manifest-path "$RUST_PROJECT/Cargo.toml" --release
done

# Generate Kotlin bindings
echo "Generating Kotlin bindings..."
cargo run --manifest-path "$RUST_PROJECT/Cargo.toml" --bin uniffi-bindgen generate \
    --library "app/src/main/jniLibs/arm64-v8a/libkeep_mobile.so" \
    --language kotlin \
    --out-dir "app/src/main/kotlin"

echo "Done!"
