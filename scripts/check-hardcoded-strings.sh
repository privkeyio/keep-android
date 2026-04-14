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
    "app/src/main/kotlin/io/privkey/keep/AccountActions.kt"
    "app/src/main/kotlin/io/privkey/keep/AccountSwitcherSheet.kt"
    "app/src/main/kotlin/io/privkey/keep/BackupRestoreScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/BiometricUnlockScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ConnectionCards.kt"
    "app/src/main/kotlin/io/privkey/keep/CreateAccountScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportLogsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportNcryptsecScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportShareScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ImportNsecScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ImportShareScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/MainActivity.kt"
    "app/src/main/kotlin/io/privkey/keep/MnemonicRecoveryScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/PinSetupScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/PinUnlockScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/QrCodeDisplay.kt"
    "app/src/main/kotlin/io/privkey/keep/RecoverNsecScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/SecurityCards.kt"
    "app/src/main/kotlin/io/privkey/keep/SecuritySettingsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/SeedWordsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/SettingsCards.kt"
    "app/src/main/kotlin/io/privkey/keep/ShareCards.kt"
    "app/src/main/kotlin/io/privkey/keep/ShareDetailsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/descriptor/WalletDescriptorScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/BunkerScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/Nip46ApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/NostrConnectApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/AppPermissionsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/ConnectedAppsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/Nip55ApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/PermissionsManagementScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/SigningHistoryScreen.kt"
)

# Allowlisted path suffixes; a file is skipped if it ends with any entry.
ALLOWLIST=()

if [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    TARGETS=("${DEFAULT_TARGETS[@]}")
fi

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
    local file="$1" allowed
    for allowed in ${ALLOWLIST[@]+"${ALLOWLIST[@]}"}; do
        [[ "$file" == */"$allowed" ]] && return 0
    done
    return 1
}

report() {
    local label="$1" match="$2"
    local file="${match%%:*}"
    if is_allowed "$file"; then
        return
    fi
    echo "[$label] $match"
    violations=$((violations + 1))
}

scan() {
    local pattern="$1" label="$2" match
    while IFS= read -r match; do
        report "$label" "$match"
    done < <(grep -EnH -- "$pattern" "${RESOLVED[@]}" 2>/dev/null || true)
}

scan_multiline() {
    local pattern="$1" label="$2" match
    while IFS= read -r match; do
        report "$label" "$match"
    done < <(grep -PznH -- "$pattern" "${RESOLVED[@]}" 2>/dev/null | tr '\0' '\n' || true)
}

# Text("...") positional literal starting with a letter.
scan 'Text\("[[:alpha:]]' 'Text-literal'

# Text(text = "...") named-argument form, may span multiple lines.
scan_multiline '(?s)Text\(\s*text\s*=\s*"[A-Za-z]' 'Text-named'

# contentDescription = "..." literal.
scan 'contentDescription[[:space:]]*=[[:space:]]*"[^"$]' 'contentDescription'

# label = { Text("...") } one-liner inside lambda braces.
scan 'label[[:space:]]*=[[:space:]]*\{[[:space:]]*Text\("[[:alpha:]]' 'label'

# placeholder = "..." with letter start.
scan 'placeholder[[:space:]]*=[[:space:]]*"[[:alpha:]]' 'placeholder'

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
