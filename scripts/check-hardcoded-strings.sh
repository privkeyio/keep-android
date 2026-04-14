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
    "app/src/main/kotlin/io/privkey/keep/BiometricHelper.kt"
    "app/src/main/kotlin/io/privkey/keep/BiometricUnlockScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ConnectionCards.kt"
    "app/src/main/kotlin/io/privkey/keep/CreateAccountScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportLogsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportNcryptsecScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ExportShareScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ImportNsecScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/ImportShareScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/KeepMobileApp.kt"
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
    "app/src/main/kotlin/io/privkey/keep/nip46/Nip46ApprovalActivity.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/Nip46ApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/Nip46UiComponents.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/NostrConnectActivity.kt"
    "app/src/main/kotlin/io/privkey/keep/nip46/NostrConnectApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/AppPermissionsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/ConnectedAppsScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/Nip55Activity.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/Nip55ApprovalScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/Nip55ContentProvider.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/PermissionsManagementScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/nip55/SigningHistoryScreen.kt"
    "app/src/main/kotlin/io/privkey/keep/service/SigningNotificationManager.kt"
)

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

report_matches() {
    local label="$1"
    local rc="$2"
    local pattern="$3"
    local output="$4"
    if [[ $rc -ge 2 ]]; then
        echo "ERROR: grep failed (rc=$rc) for pattern: $pattern" >&2
        exit "$rc"
    fi
    [[ -z "$output" ]] && return 0
    while IFS= read -r match; do
        echo "[$label] $match"
        violations=$((violations + 1))
    done <<< "$output"
}

scan() {
    local pattern="$1"
    local label="$2"
    local output rc
    set +e
    output="$(grep -EnH "$pattern" -- "${RESOLVED[@]}")"
    rc=$?
    set -e
    report_matches "$label" "$rc" "$pattern" "$output"
}

scan_multiline() {
    local pattern="$1"
    local label="$2"
    local output rc
    set +e
    output="$(grep -PznH "$pattern" -- "${RESOLVED[@]}" | tr '\0\n' '\n ')"
    rc=${PIPESTATUS[0]}
    set -e
    report_matches "$label" "$rc" "$pattern" "$output"
}

# Text("...") positional literal (any start except empty, interpolation, or escape).
# Whitespace-tolerant: allow optional whitespace after the opening paren.
scan 'Text\([[:space:]]*"[^"$\\]' 'Text-literal'

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
