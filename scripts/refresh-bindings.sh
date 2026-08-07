#!/bin/bash
# Regenerate the Kotlin FFI bindings without the Android toolchain.
#
# `build-rust.sh` cross-compiles keep-mobile for each Android ABI and then
# generates bindings from one of the resulting .so files. That is what a
# runnable APK needs, but it means a change to keep-mobile's FFI cannot be
# typechecked here without the NDK, cargo-ndk and the Android targets, even
# though the Kotlin it produces is platform independent.
#
# uniffi reads interface metadata from the library, not machine code, so a
# plain host build carries the same metadata as a cross-compiled one. This
# builds for the host and generates from that.
#
# This does NOT replace build-rust.sh. It writes no jniLibs, so the app will
# compile and will fail at runtime with an UnsatisfiedLinkError. Use it to
# typecheck against a changed core; use build-rust.sh to run anything.
set -euo pipefail

KEEP_REPO="${KEEP_REPO:-./keep}"
if [ ! -d "$KEEP_REPO" ]; then
    echo "error: KEEP_REPO path does not exist: $KEEP_REPO" >&2
    exit 1
fi
KEEP_REPO="$(cd "$KEEP_REPO" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUST_PROJECT="$KEEP_REPO/keep-mobile"

PROFILE="${PROFILE:-debug}"
case "$PROFILE" in
    debug) CARGO_PROFILE_ARGS=() ;;
    release) CARGO_PROFILE_ARGS=(--release) ;;
    *) echo "error: PROFILE must be debug or release, got: $PROFILE" >&2; exit 1 ;;
esac

cd "$RUST_PROJECT"

echo "Building keep-mobile for the host ($PROFILE)..."
cargo build "${CARGO_PROFILE_ARGS[@]}"

# Resolve the target dir rather than assuming ../target: a workspace may set
# CARGO_TARGET_DIR, and guessing would produce a confusing not-found on a
# library that was built successfully.
TARGET_DIR="$(cargo metadata --format-version 1 --no-deps | sed -nE 's/.*"target_directory":"([^"]*)".*/\1/p')"
if [ -z "$TARGET_DIR" ]; then
    echo "error: could not resolve cargo target directory" >&2
    exit 1
fi

case "$(uname -s)" in
    Darwin) LIB_NAME="libkeep_mobile.dylib" ;;
    *)      LIB_NAME="libkeep_mobile.so" ;;
esac
LIB="$TARGET_DIR/$PROFILE/$LIB_NAME"
if [ ! -f "$LIB" ]; then
    echo "error: expected a cdylib at $LIB but it is not there." >&2
    echo "keep-mobile must build as a cdylib for uniffi to read its metadata." >&2
    exit 1
fi

echo "Generating Kotlin bindings from $LIB..."
cargo run --features cli --bin uniffi-bindgen generate \
    --library "$LIB" \
    --language kotlin \
    --out-dir "$SCRIPT_DIR/app/src/main/kotlin"

GENERATED_KT="$SCRIPT_DIR/app/src/main/kotlin/io/privkey/keep/uniffi/keep_mobile.kt"
if [ ! -f "$GENERATED_KT" ]; then
    echo "error: bindings were not written to $GENERATED_KT" >&2
    exit 1
fi
# Same suppression list build-rust.sh applies, so the two paths produce the
# same file and switching between them does not show up as a diff.
sed -i.bak 's/@file:Suppress([^)]*)/@file:Suppress("NAME_SHADOWING", "REDUNDANT_CALL_OF_CONVERSION_METHOD", "NOTHING_TO_INLINE", "UNUSED_PARAMETER", "UNUSED_EXPRESSION")/' "$GENERATED_KT"
rm -f "$GENERATED_KT.bak"

echo "Done. Bindings refreshed; no jniLibs were built, so this typechecks but does not run."
