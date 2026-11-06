#!/usr/bin/env bash
# Runs CosignSpendE2ETest on the connected device and serves the co-sign requests it
# writes to the app's files/cosign-e2e directory: each one starts a FROST peer holding the
# fixture's second share, which asks the phone to co-sign a spend. Expects the debug app
# and its test APK to be installed (./gradlew installDebug installDebugAndroidTest) and
# the device to hold the share key without a biometric (see the nip46probe README).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pkg=io.privkey.keep
log="$(mktemp)"
peer_log="$log.peer"

cargo build --release --quiet --manifest-path "$here/Cargo.toml"
peer="$here/target/release/cosignpeer"

on_device() { adb shell "run-as $pkg sh -c '$1'"; }

on_device "rm -rf files/cosign-e2e"
adb shell am instrument -w -r -e cosignSpendE2e 1 \
  -e class io.privkey.keep.service.CosignSpendE2ETest "$pkg.test/androidx.test.runner.AndroidJUnitRunner" >"$log" 2>&1 &
instrumentation=$!
trap 'kill "$instrumentation" 2>/dev/null || true; cat "$log"; echo "peer diagnostics: $peer_log"' EXIT

n=1
while kill -0 "$instrumentation" 2>/dev/null; do
  if req="$(on_device "cat files/cosign-e2e/req-$n" 2>/dev/null)" && [ -n "$req" ]; then
    # The request carries a share export, so it goes in on stdin, never on the command line.
    out="$(printf '%s\n' "$req" | "$peer" 2>>"$peer_log" | tail -n 1)" || true
    [ -n "$out" ] || out="ERR peer failed, see $peer_log"
    if printf '%s' "$out" | adb shell -T "run-as $pkg sh -c 'cat > files/cosign-e2e/res-$n.tmp && mv files/cosign-e2e/res-$n.tmp files/cosign-e2e/res-$n'"; then
      echo "request $n: ${req%% *} -> ${out:0:120}"
      n=$((n + 1))
    fi
  else
    sleep 1
  fi
done
wait "$instrumentation" || true

grep -q '^OK (1 test)' "$log" && ! grep -q 'INSTRUMENTATION_STATUS_CODE: -[34]' "$log"
