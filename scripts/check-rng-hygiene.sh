#!/usr/bin/env bash
# Fail if production code can silently fall back to predictable randomness, or
# reuse an AES-GCM IV.
#
# Motivated by the COLDCARD firmware disclosure (Block, 2026-07):
# https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware
# A guard that checked only whether a macro was *defined* -- not whether it was
# *enabled* -- silently bound wallet seed generation to a non-cryptographic
# fallback PRNG. Nothing crashed, nothing logged, and the firmware shipped that
# way for years. The lesson is not "use a CSPRNG"; every codebase already
# intends to. The lesson is that a degraded RNG path must not be able to succeed
# quietly, and that only a mechanical check keeps it that way.
#
# The shapes that bug takes in an Android app:
#
#   1. kotlin.random.Random / java.util.Random / Math.random() are seeded,
#      non-cryptographic generators. They produce plausible output forever, so
#      one standing in for SecureRandom is invisible in review and in testing.
#   2. SecureRandom weakened at the call site: an explicitly requested SHA1PRNG,
#      or a setSeed() that replaces system entropy rather than supplementing it.
#   3. An AES-GCM cipher initialised for ENCRYPT_MODE with a caller-supplied IV.
#      This is the same failure mode wearing different clothes: under GCM,
#      reusing an IV with one key destroys confidentiality AND authenticity, and
#      it does so silently -- encryption succeeds, ciphertext looks fine. Let the
#      provider draw the IV; supply one only when decrypting.
#
# Deliberate non-crypto randomness (UI jitter, sampling, shuffling a word list
# for display) is allowed with an inline opt-out on the same line or in the
# comment block directly above:
#
#     val delay = (0..100).random()   // rng-hygiene: ok - animation jitter
#
# This guard fails CLOSED. An awk error, a missing repo, or an empty file list is
# reported as a failure rather than silently passing: a guard that reports "OK"
# when it scanned nothing is worse than no guard, because it is trusted.
#
# Scope: TRACKED production Kotlin and Java only (git ls-files), so build output
# and generated UniFFI bindings can never trip a rule or hide one. Test and
# instrumentation source sets are excluded -- fixtures are deterministic on
# purpose -- as is the test harness app.
#
# What this does NOT cover: it is a grep, so it catches shapes, not intent. It
# cannot tell whether a SecureRandom draw is used correctly once generated, it
# does not see into the Rust core (keep-mobile, which has its own guard in the
# keep repo) or into dependencies, and rule 3 pins how a cipher is initialised,
# not how its output is stored.
#
# Portable to BSD awk (developers run this on macOS): no gawk extensions.
#
# Run from anywhere. Exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf '\n\033[31mFAIL\033[0m not inside a git work tree; this guard scans tracked files only\n'
  exit 1
}

# Production sources only. testharness/ is a separate debug-only app used to
# drive NIP-55 flows; it is not shipped.
list_sources() {
  git ls-files '*.kt' '*.java' \
    | grep -vE '(^|/)(test|androidTest|testFixtures|debug)/' \
    | grep -vE '^testharness/'
}

SOURCES=$(list_sources)
if [ -z "$SOURCES" ]; then
  printf '\n\033[31mFAIL\033[0m no Kotlin/Java sources found to scan; the file list is broken\n'
  exit 1
fi

# Emit "file:line:code" for every live code line, with // and /* */ comments
# stripped using real state tracking and string literals blanked. Without that,
# prose mentioning a banned name trips its own rule, and a log message
# containing "Random" reads as a violation.
#
# Statements are joined onto one line when a call's parentheses are still open,
# so a wrapped `cipher.init(\n  ENCRYPT_MODE,\n  key,\n  spec\n)` is judged whole
# rather than as four lines none of which look wrong on their own.
preprocess() {
  local f rc out
  rc=0
  for f in $SOURCES; do
    out=$(awk -v fname="$f" -v optout="$OPT_OUT" -v keepstrings="${1:-0}" '
      function strip(s,   out, i, c, d, n) {
        out = ""; cmt = ""; n = length(s)
        for (i = 1; i <= n; i++) {
          c = substr(s, i, 1); d = substr(s, i, 2)
          if (inblock) { if (d == "*/") { inblock = 0; i++ } else cmt = cmt c; continue }
          if (instr)   { if (c == "\\") { i++; continue }
                         if (c == quote) { instr = 0; out = out "\"\"" }
                         continue }
          if (d == "/*") { inblock = 1; i++; continue }
          if (d == "//") { cmt = cmt substr(s, i + 2); break }
          if (c == "\"" || c == "'"'"'") {
            if (keepstrings) { out = out c; continue }
            instr = 1; quote = c; continue
          }
          out = out c
        }
        return out
      }
      function trim(s) { sub(/^[ \t]*/, "", s); sub(/[ \t]*$/, "", s); return s }
      function count(s, ch,   i, n) {
        # Literal character count: gsub()/split() would treat ch as a regex,
        # and "(" alone is not a valid one -- BSD awk aborts on it.
        n = 0
        for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ch) n++
        return n
      }
      function emit() {
        if (buf != "" && !bufopt) printf "%s:%d:%s\n", fname, bufline, buf
        buf = ""; bufopt = 0; open = 0
      }

      BEGIN { inblock = 0; instr = 0; blockopt = 0; buf = ""; open = 0; bufopt = 0 }
      {
        code = trim(strip($0))
        marked = index(cmt, optout); cmt = ""

        if (code == "") { if (marked) blockopt = 1; next }

        if (open > 0) {
          buf = buf " " code
          if (marked) bufopt = 1
          open += count(code, "(") - count(code, ")")
          if (open <= 0) emit()
          next
        }

        if (marked || blockopt) { blockopt = 0; next }
        blockopt = 0

        buf = code; bufline = FNR; bufopt = 0
        open = count(code, "(") - count(code, ")")
        if (open <= 0) emit()
      }
      END { if (open > 0) emit() }
    ' "$f") || rc=2
    [ -n "$out" ] && printf '%s\n' "$out"
  done
  return "$rc"
}

# Two passes. Rules that reason about code shape match against CODE, where
# string literals are blanked so a log message mentioning "Random" is not a
# finding. Rules about a *value* -- an algorithm name passed to getInstance --
# need CODE_STR, where literals survive.
CODE=$(preprocess) || {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n'
  exit 1
}
CODE_STR=$(preprocess 1) || {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n'
  exit 1
}
if [ -z "$CODE" ] || [ -z "$CODE_STR" ]; then
  printf '\n\033[31mFAIL\033[0m preprocessor produced no code lines; the guard scanned nothing\n'
  exit 1
fi

scan() { # $1 = ERE, matched against code with string literals blanked
  printf '%s\n' "$CODE" | awk -v pat="$1" '{
    line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
    if (line ~ pat) print $0
  }'
}

scan_with_strings() { # $1 = ERE, matched against code with literals intact
  printf '%s\n' "$CODE_STR" | awk -v pat="$1" '{
    line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
    if (line ~ pat) print $0
  }'
}

report() { # $1 = findings, $2 = headline, $3.. = hints
  [ -z "$1" ] && return 0
  fail "$2"
  printf '%s\n' "$1" | sed 's/^/  /'
  shift 2
  for hint in "$@"; do echo "  → $hint"; done
}

# ------------------------------------------------ 1. non-CSPRNG generators ----
# Match the RNG token, not a receiver shape: pinning `"0123..".random()` is
# bypassed by hoisting the alphabet into a val, which is the same code one
# refactor away.
weak_rng=$(scan '(^|[^a-zA-Z0-9_.])(kotlin[.]random|java[.]util[.]Random|Math[.]random|Random[(]|Random[.]next|ThreadLocalRandom)|[.]random[(][)]')
report "$weak_rng" "non-cryptographic randomness in production code:" \
  'use java.security.SecureRandom, or UUID.randomUUID() for correlation ids' \
  "or mark a deliberate non-crypto use: // $OPT_OUT - <reason>"

# --------------------------------------------- 2. SecureRandom not weakened --
# SHA1PRNG is an argument value, so it only survives the strings-intact pass.
weak_sr=$(printf '%s\n%s\n' \
  "$(scan_with_strings 'SHA1PRNG')" \
  "$(scan 'setSeed[ \t]*[(]')" | grep -v '^$' || true)
report "$weak_sr" "SecureRandom weakened at the call site:" \
  'drop the explicit provider and the seed; the platform default is seeded from the OS' \
  'and SHA1PRNG is a legacy algorithm with a history of weak seeding on Android'

# ------------------------------------- 3. AES-GCM never encrypts with an IV --
# The load-bearing rule. A GCM IV reused under one key is catastrophic and
# silent, and the only structural defence is that the encrypt path never accepts
# one. Statement-scoped, so a wrapped init() call is judged whole.
gcm_bad=$(scan 'ENCRYPT_MODE[^;]*(GCMParameterSpec|IvParameterSpec|AlgorithmParameterSpec)')
report "$gcm_bad" "AES-GCM cipher initialised for encryption with a caller-supplied IV:" \
  'reusing a GCM IV under one key destroys confidentiality and authenticity, silently.' \
  'Init encryption as cipher.init(ENCRYPT_MODE, key) and let the provider draw the IV;' \
  'read it back from cipher.iv afterwards. Supply a spec only when decrypting.'

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (no non-CSPRNG generators, SecureRandom unweakened, no GCM encryption with a supplied IV)"
fi
exit "$status"
