#!/usr/bin/env bash
# Self-test for check-rng-hygiene.sh.
#
# This guard keeps non-CSPRNG generators, weakened SecureRandom and
# caller-supplied GCM IVs out of production Kotlin and Java. A scanner that
# quietly stops scanning reports a clean tree exactly like a clean tree does, so
# the rules are asserted rather than trusted.
#
# Probes go under app/src/main/kotlin: the guard deliberately skips test,
# androidTest and testFixtures, so a probe placed there passes and looks like a
# bypass when it is only a misplaced probe. The positive control catches that.
#
# Each reject case requires the guard to NAME the probe file. Without that, a
# guard aborting for an unrelated reason would be credited as a detection and
# every case below would pass while detecting nothing.
#
# Probes are staged into a throwaway GIT_INDEX_FILE, so the real index is never
# touched. The file itself must exist on disk while the guard runs, because the
# scanner reads bytes; it is removed on every path including the EXIT trap.
set -uo pipefail

cd "$(dirname "$0")/.." || { echo "FAIL: cannot cd to the repo root"; exit 1; }
GUARD=scripts/check-rng-hygiene.sh
[ -x "$GUARD" ] || { echo "FAIL: $GUARD not found or not executable"; exit 1; }

TMPD=$(mktemp -d)
PROBE=""
cleanup() { rm -rf "$TMPD"; [ -n "$PROBE" ] && rm -f "$PROBE"; }
trap cleanup EXIT

fails=0

# run_probe <path> <content> <pass|fail> <description>
run_probe() {
    local name="$1" content="$2" expect="$3" desc="$4"

    if [ -e "$name" ]; then
        echo "  HARNESS BROKEN: $name exists; refusing to overwrite a real file"
        fails=$((fails + 1)); return
    fi
    PROBE="$name"
    printf '%s' "$content" > "$name"

    rm -f "$TMPD/index"
    GIT_INDEX_FILE="$TMPD/index" git read-tree HEAD 2>/dev/null
    GIT_INDEX_FILE="$TMPD/index" git add -f "$name" 2>/dev/null

    # Both that the tree is populated AND that this probe is in it. Discarding
    # the git errors above means a failed `git add` would otherwise leave the
    # guard scanning a probe-free tree, and the case would be judged on a file
    # the guard never saw.
    local staged
    staged=$(GIT_INDEX_FILE="$TMPD/index" git ls-files | wc -l)
    if [ "$staged" -lt 10 ]; then
        echo "  HARNESS BROKEN: only $staged file(s) staged; the guard would scan almost nothing"
        fails=$((fails + 1)); rm -f "$name"; PROBE=""; return
    fi
    if ! GIT_INDEX_FILE="$TMPD/index" git ls-files --error-unmatch "$name" >/dev/null 2>&1; then
        echo "  HARNESS BROKEN: $name was not staged; the guard would never see it"
        fails=$((fails + 1)); rm -f "$name"; PROBE=""; return
    fi

    local rc=0 out
    out=$(GIT_INDEX_FILE="$TMPD/index" "$GUARD" 2>&1) || rc=$?
    rm -f "$name"; PROBE=""

    if [ "$expect" = fail ]; then
        if [ "$rc" -eq 0 ]; then
            echo "  BYPASS: $desc"; fails=$((fails + 1))
        elif ! printf '%s' "$out" | grep -qF "$name"; then
            echo "  WRONG REASON: $desc (guard failed without naming $name)"; fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            echo "  FALSE POSITIVE: $desc"
            printf '%s\n' "$out" | sed 's/^/      /' | head -4
            fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    fi
}

echo "== rejects what it must reject =="

SRC=app/src/main/kotlin/io/privkey/keep

run_probe $SRC/ProbeCtl.kt 'val x = Math.random()
' fail "Math.random() (positive control: if this passes, nothing below means anything)"

run_probe $SRC/ProbeSplit.kt 'val x = Math.
random()
' fail "member access split after a trailing dot"

run_probe $SRC/ProbeSplit2.kt 'val r = java.util.
Random()
' fail "qualified name split after the package dot"

run_probe $SRC/ProbeReflect.kt 'val c = Class.forName("java.util." + "Random")
' fail "reflection with a concatenated class name"

run_probe $SRC/ProbeLoad.kt 'val c = javaClass.classLoader.loadClass("java.util.Random")
' fail "loadClass reaching a generator by name"

run_probe $SRC/ProbeSeed.kt 'val r = java.security.SecureRandom(); r.setSeed(1L)
' fail "setSeed weakening SecureRandom"

run_probe $SRC/ProbeTlr.kt 'val x = ThreadLocalRandom.current().nextInt()
' fail "ThreadLocalRandom"

run_probe $SRC/ProbeGcmIv.kt 'val c = Cipher.getInstance("AES/GCM/NoPadding")
c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
' fail "AES-GCM encrypt init with a caller-supplied IV"

run_probe $SRC/ProbeGcmHoist.kt 'val mode = Cipher.ENCRYPT_MODE
val spec = GCMParameterSpec(128, iv)
c.init(mode, key, spec)
' fail "AES-GCM encrypt init with hoisted mode and spec variables"

echo "== accepts what it must accept =="

run_probe $SRC/ProbeClean.kt 'val x = 1
' pass "ordinary code"

run_probe $SRC/ProbeOaep.kt 'val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
rsa.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec())
' pass "RSA-OAEP encrypt init passing an OAEP parameter spec"

run_probe $SRC/ProbeOaepLabel.kt 'val gcm = Cipher.getInstance("AES/GCM/NoPadding")
gcm.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, oaepLabel))
' fail "AES-GCM encrypt init is still caught when an unrelated identifier contains oaep"

run_probe $SRC/ProbeComment.kt '// Math.random() is named here in prose only
val x = 1
' pass "a banned token inside a comment is not code"

run_probe $SRC/ProbeTest.kt 'val x = 1
' pass "ordinary code in the production tree"

echo
if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails case(s) did not behave as required"
    exit 1
fi
echo "OK: check-rng-hygiene.sh rejects every known bypass and accepts sanctioned use"
