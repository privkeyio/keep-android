#!/bin/bash
# Prints SOURCE_DATE_EPOCH on stdout as the later of the two repo HEAD commit
# times (keep-android and the keep workspace). Respects a pre-set
# SOURCE_DATE_EPOCH by echoing it unchanged. Exits non-zero on failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_REPO="${ANDROID_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
KEEP_REPO="${KEEP_REPO:-$ANDROID_REPO/keep}"

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    if [[ ! "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]]; then
        echo "error: SOURCE_DATE_EPOCH='$SOURCE_DATE_EPOCH' is not a non-negative integer." >&2
        exit 1
    fi
    printf '%s\n' "$SOURCE_DATE_EPOCH"
    exit 0
fi

ANDROID_EPOCH=""
KEEP_EPOCH=""
if git -C "$ANDROID_REPO" rev-parse --git-dir >/dev/null 2>&1; then
    ANDROID_EPOCH=$(git -C "$ANDROID_REPO" log -1 --pretty=%ct 2>/dev/null || true)
    if [ -z "$ANDROID_EPOCH" ]; then
        echo "error: failed to read HEAD commit time from ANDROID_REPO='$ANDROID_REPO'." >&2
        exit 1
    fi
fi
if [ -d "$KEEP_REPO" ]; then
    if ! git -C "$KEEP_REPO" rev-parse --git-dir >/dev/null 2>&1; then
        echo "error: KEEP_REPO='$KEEP_REPO' exists but is not a git repository." >&2
        echo "Fix: clone keep as a git repo, or set SOURCE_DATE_EPOCH explicitly." >&2
        exit 1
    fi
    KEEP_EPOCH=$(git -C "$KEEP_REPO" log -1 --pretty=%ct 2>/dev/null || true)
    if [ -z "$KEEP_EPOCH" ]; then
        echo "error: failed to read HEAD commit time from KEEP_REPO='$KEEP_REPO'." >&2
        exit 1
    fi
fi

for name in ANDROID_EPOCH KEEP_EPOCH; do
    val="${!name}"
    if [ -n "$val" ] && [[ ! "$val" =~ ^[0-9]+$ ]]; then
        echo "error: $name='$val' is not a non-negative integer." >&2
        exit 1
    fi
done

if [ -z "$ANDROID_EPOCH" ] && [ -z "$KEEP_EPOCH" ]; then
    echo "error: SOURCE_DATE_EPOCH unset and neither repo has git history to derive it." >&2
    exit 1
fi
if [ "${ANDROID_EPOCH:-0}" -gt "${KEEP_EPOCH:-0}" ]; then
    printf '%s\n' "$ANDROID_EPOCH"
else
    printf '%s\n' "$KEEP_EPOCH"
fi
