#!/usr/bin/env bash
# Fails CI if the Fastlane changelog for the current release is missing.
#
# F-Droid renders "What's New" from
# fastlane/metadata/android/<locale>/changelogs/<versionCode>.txt, and reads it
# from the source tree at the *built commit*. Because the app ships per-ABI
# splits, each release has one changelog per ABI, named after the split's
# versionCode (10 * base + abiCode). Metadata added after a release is tagged
# never appears for that release, so this must be caught before tagging.
#
# Both the base versionCode and the ABI codes are parsed from
# app/build.gradle.kts so this check cannot drift from the build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GRADLE="${ROOT}/app/build.gradle.kts"
FASTLANE="${ROOT}/fastlane/metadata/android"

[ -f "$GRADLE" ] || { echo "error: $GRADLE not found" >&2; exit 1; }

BASE=$(sed -nE 's/^[[:space:]]*versionCode = ([0-9]+).*/\1/p' "$GRADLE" | head -1)
[ -n "$BASE" ] || { echo "error: could not parse 'versionCode = <n>' from $GRADLE" >&2; exit 1; }

# val abiVersionCodes = mapOf("arm64-v8a" to 2, "x86_64" to 4)
MAP_LINE=$(grep -E '^val abiVersionCodes = mapOf\(' "$GRADLE" | head -1)
[ -n "$MAP_LINE" ] || { echo "error: could not find 'val abiVersionCodes = mapOf(' in $GRADLE" >&2; exit 1; }

ABI_CODES=$(printf '%s\n' "$MAP_LINE" | grep -oE '"[^"]+" to [0-9]+' | sed -E 's/"([^"]+)" to ([0-9]+)/\1 \2/')
[ -n "$ABI_CODES" ] || { echo "error: could not parse ABI codes from: $MAP_LINE" >&2; exit 1; }

missing=0
while read -r abi code; do
    [ -n "$abi" ] || continue
    vercode=$((BASE * 10 + code))
    for dir in "$FASTLANE"/*/changelogs; do
        [ -d "$dir" ] || continue
        locale=$(basename "$(dirname "$dir")")
        f="$dir/${vercode}.txt"
        if [ ! -s "$f" ]; then
            echo "error: missing or empty changelog for $abi (versionCode $vercode): ${f#"$ROOT"/}" >&2
            missing=1
        fi
    done
done <<< "$ABI_CODES"

if [ "$missing" -ne 0 ]; then
    codes=$(while read -r _ c; do [ -n "$c" ] && printf '%s ' "$((BASE * 10 + c))"; done <<< "$ABI_CODES")
    cat >&2 <<EOF

Release metadata is incomplete for versionCode base $BASE.
F-Droid reads changelogs from the source tree at the tagged commit, so they
must be committed BEFORE tagging or that release ships with no changelog.

Fix: create these files in every locale under fastlane/metadata/android/:
  changelogs/{$(echo $codes | tr ' ' ',')}.txt
EOF
    exit 1
fi

echo "ok: changelogs present for versionCode base $BASE in all locales."
