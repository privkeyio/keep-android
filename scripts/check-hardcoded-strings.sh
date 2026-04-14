#!/usr/bin/env bash
# Fails CI if user-facing Compose strings are hardcoded instead of using
# stringResource / pluralResource / getString(R.string.*).
#
# Allowlist: files or paths that are permitted to contain inline strings
# (typically developer-only screens, debug tooling, non-localizable labels).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/app/src/main/kotlin"

# Allowlisted substrings (one per line). A match on any = the file is skipped.
ALLOWLIST=(
    # Developer log export screen - intentionally English-only debug tooling
    # (none yet - add paths here with justification)
)

violations=0

# Scan for Text("UpperCase...") literals which are almost always user-facing.
while IFS= read -r match; do
    file="${match%%:*}"
    skip=0
    for allowed in "${ALLOWLIST[@]}"; do
        if [[ "$file" == *"$allowed"* ]]; then
            skip=1
            break
        fi
    done
    if [[ $skip -eq 0 ]]; then
        echo "$match"
        violations=$((violations + 1))
    fi
done < <(grep -rEn 'Text\("[A-Z]' "$SRC" || true)

# Scan for contentDescription = "..." literal usage.
while IFS= read -r match; do
    file="${match%%:*}"
    skip=0
    for allowed in "${ALLOWLIST[@]}"; do
        if [[ "$file" == *"$allowed"* ]]; then
            skip=1
            break
        fi
    done
    if [[ $skip -eq 0 ]]; then
        echo "$match"
        violations=$((violations + 1))
    fi
done < <(grep -rEn 'contentDescription = "[^"]' "$SRC" || true)

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "ERROR: $violations hardcoded user-facing string(s) found."
    echo "Move them to app/src/main/res/values/strings.xml and use"
    echo "stringResource(R.string.x) / pluralResource / context.getString instead."
    exit 1
fi

echo "No hardcoded user-facing strings detected."
