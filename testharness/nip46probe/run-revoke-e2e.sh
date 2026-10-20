#!/usr/bin/env bash
# Runs BunkerRevokeE2ETest on the connected device and serves the probe requests it
# writes to the app's files/bunker-e2e directory. Expects the debug app and its test
# APK to be installed (./gradlew installDebug installDebugAndroidTest). Set
# BUNKER_RELAY to run the bunker on a relay other than the fixture relay.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pkg=io.privkey.keep
log="$(mktemp)"
probe_log="$log.probe"

cargo build --release --quiet --manifest-path "$here/Cargo.toml"
probe="$here/target/release/nip46probe"

on_device() { adb shell "run-as $pkg sh -c '$1'"; }

on_device "rm -rf files/bunker-e2e"
adb shell am instrument -w -r -e bunkerRevokeE2e 1 ${BUNKER_RELAY:+-e bunkerRelay "$BUNKER_RELAY"} \
  -e class io.privkey.keep.nip46.BunkerRevokeE2ETest "$pkg.test/androidx.test.runner.AndroidJUnitRunner" >"$log" 2>&1 &
instrumentation=$!
trap 'kill "$instrumentation" 2>/dev/null || true; cat "$log"; echo "probe diagnostics: $probe_log"' EXIT

n=1
while kill -0 "$instrumentation" 2>/dev/null; do
  if req="$(on_device "cat files/bunker-e2e/req-$n" 2>/dev/null)" && [ -n "$req" ]; then
    # The request goes in on stdin so client secrets never appear in a process listing.
    # A probe that fails still answers, so the test reports it instead of waiting out its timeout.
    out="$(printf '%s\n' "$req" | NIP46PROBE_DEBUG=1 "$probe" 2>>"$probe_log" | tail -n 1)" || true
    [ -n "$out" ] || out="ERR probe failed, see $probe_log"
    encoded="$(printf '%s' "$out" | base64 -w0)"
    if on_device "echo $encoded | base64 -d > files/bunker-e2e/res-$n.tmp && mv files/bunker-e2e/res-$n.tmp files/bunker-e2e/res-$n"; then
      echo "request $n: ${req%% *} -> ${out:0:120}"
      n=$((n + 1))
    fi
  else
    sleep 1
  fi
done
wait "$instrumentation" || true

grep -q '^OK (1 test)' "$log" && ! grep -q 'INSTRUMENTATION_STATUS_CODE: -[34]' "$log"
