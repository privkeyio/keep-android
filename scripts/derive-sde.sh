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
fi
if [ -d "$KEEP_REPO" ] && git -C "$KEEP_REPO" rev-parse --git-dir >/dev/null 2>&1; then
    KEEP_EPOCH=$(git -C "$KEEP_REPO" log -1 --pretty=%ct 2>/dev/null || true)
fi

for name in ANDROID_EPOCH KEEP_EPOCH; do
    val="${!name}"
    if [ -n "$val" ] && [[ ! "$val" =~ ^[0-9]+$ ]]; then
        echo "error: $name='$val' is not a non-negative integer." >&2
        exit 1
    fi
done

if [ -n "$ANDROID_EPOCH" ] && [ -n "$KEEP_EPOCH" ]; then
    if [ "$ANDROID_EPOCH" -gt "$KEEP_EPOCH" ]; then
        printf '%s\n' "$ANDROID_EPOCH"
    else
        printf '%s\n' "$KEEP_EPOCH"
    fi
elif [ -n "$ANDROID_EPOCH" ]; then
    printf '%s\n' "$ANDROID_EPOCH"
elif [ -n "$KEEP_EPOCH" ]; then
    printf '%s\n' "$KEEP_EPOCH"
else
    echo "error: SOURCE_DATE_EPOCH unset and neither repo has git history to derive it." >&2
    exit 1
fi
