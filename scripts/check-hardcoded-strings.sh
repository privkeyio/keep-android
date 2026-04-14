#!/usr/bin/env bash
# Fails CI if user-facing Compose strings are hardcoded instead of using
# stringResource / pluralResource / getString(R.string.*).
#
# Usage:
#   check-hardcoded-strings.sh [file1.kt file2.kt ...]
#
# With no arguments, scans a built-in list of files that have been fully
# externalized and must not regress. Other files in the tree are NOT scanned
# by default (follow-up work).
#
# Allowlist: files or paths that are permitted to contain inline strings
# (typically developer-only screens, debug tooling, non-localizable labels).
set -euo pipefail

# Require PCRE-capable grep (GNU grep -P). BSD grep on macOS does not support
# -P and would silently produce no output, masking violations.
if ! echo test | grep -P test >/dev/null 2>&1; then
    echo "Error: grep -P (PCRE) required. Install GNU grep (e.g. 'brew install grep' on macOS and use ggrep, or run in CI)." >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Default set of files that have been externalized. Add new files here as they
# are converted. Keep this list tight to avoid false positives from
# pre-existing hardcoded strings in other screens.
DEFAULT_TARGETS=(
    "app/src/main/kotlin/io/privkey/keep/BiometricUnlockScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/CreateAccountScreen.kt"
)

# Allowlisted substrings (one per line). A match on any = the file is skipped.
ALLOWLIST=(
    # (none yet - add paths here with justification)
)

if [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    TARGETS=("${DEFAULT_TARGETS[@]}")
fi

# Safe expansion for possibly-empty ALLOWLIST under `set -u` (bash < 4.4 compat).
expand_allowlist() {
    if [[ ${#ALLOWLIST[@]} -gt 0 ]]; then
        printf '%s\n' "${ALLOWLIST[@]}"
    fi
}

# Resolve to absolute paths rooted at repo root and verify they exist.
RESOLVED=()
for t in "${TARGETS[@]}"; do
    if [[ "$t" = /* ]]; then
        path="$t"
    else
        path="$ROOT/$t"
    fi
    if [[ ! -f "$path" ]]; then
        echo "ERROR: target not found: $t" >&2
        exit 2
    fi
    RESOLVED+=("$path")
done

violations=0

is_allowed() {
    local file="$1"
    local allowed
    while IFS= read -r allowed; do
        if [[ -n "$allowed" && "$file" == */"$allowed" ]]; then
            return 0
        fi
    done < <(expand_allowlist)
    return 1
}

scan() {
    local pattern="$1"
    local label="$2"
    while IFS= read -r match; do
        local file="${match%%:*}"
        if is_allowed "$file"; then
            continue
        fi
        echo "[$label] $match"
        violations=$((violations + 1))
    done < <(grep -EnH -- "$pattern" "${RESOLVED[@]}" 2>/dev/null || true)
}

scan_multiline() {
    local pattern="$1"
    local label="$2"
    while IFS= read -r match; do
        local file="${match%%:*}"
        if is_allowed "$file"; then
            continue
        fi
        echo "[$label] $match"
        violations=$((violations + 1))
    done < <(grep -PznH -- "$pattern" "${RESOLVED[@]}" 2>/dev/null | tr '\0' '\n' || true)
}

# 1. Text("...") or Text("..." positional literal — any alphabetic start.
scan 'Text\("[[:alpha:]]' 'Text-literal'

# 2. Text(text = "...") named-argument form (may span multiple lines).
scan_multiline '(?s)Text\(\s*text\s*=\s*"[A-Za-z]' 'Text-named'

# 3. contentDescription = "..." literal.
scan 'contentDescription\s*=\s*"[^"$]' 'contentDescription'

# 4. label = { Text("...") } — catch simple one-liners that start with
#    a letter inside lambda braces.
scan 'label\s*=\s*\{\s*Text\("[[:alpha:]]' 'label'

# 5. placeholder = "..." (e.g. TextField placeholder) with letter start.
scan 'placeholder\s*=\s*"[[:alpha:]]' 'placeholder'

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "ERROR: $violations hardcoded user-facing string(s) found in:"
    for f in "${RESOLVED[@]}"; do
        echo "  - ${f#"$ROOT"/}"
    done
    echo "Move them to app/src/main/res/values/strings.xml and use"
    echo "stringResource(R.string.x) / pluralResource / context.getString instead."
    exit 1
fi

echo "No hardcoded user-facing strings detected in ${#RESOLVED[@]} file(s)."
