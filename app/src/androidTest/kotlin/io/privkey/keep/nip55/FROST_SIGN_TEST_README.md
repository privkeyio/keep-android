# FROST handler-level sign + verify (manual, two-device)

Issue #353. A `sign_event` request is driven through `Nip55Handler` using a REAL
2-of-2 FROST signature coordinated over the relay in `FrostSignFixture.RELAY`, and
the resulting Schnorr signature is verified with secp256k1 (BIP-340).

The relay MUST forward ephemeral kind-24242 events to subscribers and must not
idle-disconnect aggressively, or peer discovery and signing never complete.
`wss://bucket.coracle.social` works; `wss://relay1.privkey.io` does not (it drops
ephemeral events and closes idle connections after ~10s).

This is **local/manual only** and runs **across two physical devices**. CI never
passes the `frostSignManual` instrumentation arg, so every test here is skipped
via `Assume.assumeTrue(...)` on CI.

## One-time setup: generate the share pair

Both shares must come from a single `frostGenerate(2, 2)` call. Run the generator
once on any device (gated behind `frostSignManual=1`, like the other tests):

```
adb -s <serial> shell am instrument -w \
  -e frostSignManual 1 \
  -e class io.privkey.keep.nip55.FrostSignFixtureGenerator#generateSharePair \
  io.privkey.keep.test/androidx.test.runner.AndroidJUnitRunner
```

Read the output from logcat:

```
adb -s <serial> logcat -s FrostSignFixtureGen
```

Copy `GROUP_PUBKEY`, the `EXPORT_DATA` for share index 1, and the `EXPORT_DATA`
for share index 2 into `FrostSignFixture.kt`
(`SHARE1_EXPORT_DATA`, `SHARE2_EXPORT_DATA`, `EXPECTED_GROUP_PUBKEY`).

## Run the test (two devices)

List serials with `adb devices`. Start the co-signer (device B) FIRST so it is
polling before device A requests a signature:

```
# Device B (co-signer)
adb -s <serialB> shell am instrument -w \
  -e frostSignManual 1 \
  -e class io.privkey.keep.nip55.FrostSignCosignerTest \
  io.privkey.keep.test/androidx.test.runner.AndroidJUnitRunner
```

Then, within ~90s, run the signer/verify test on device A:

```
# Device A (signer + verifier)
adb -s <serialA> shell am instrument -w \
  -e frostSignManual 1 \
  -e class io.privkey.keep.nip55.FrostSignHandlerVerifyTest \
  io.privkey.keep.test/androidx.test.runner.AndroidJUnitRunner
```

Gradle equivalent (single connected device, e.g. device A):

```
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.frostSignManual=1 \
  -Pandroid.testInstrumentationRunnerArguments.class=io.privkey.keep.nip55.FrostSignHandlerVerifyTest
```

Device B (co-signer) polls `getPendingRequests()` and calls `approveRequest(id)`
for 90s. Device A builds a kind-1 event whose `pubkey` is the group pubkey, calls
`Nip55Handler.handleRequest(...)` with `SignEvent`, then verifies the returned
64-byte Schnorr signature against the signed event id and the x-only group pubkey.

No SIGN_EVENT caller-permission pre-grant is needed: `handle_sign_event` in
nip55.rs performs no caller-permission check. Two approvals do matter, though:
- Device A (coordinator) calls `preApproveNostrEvent(event)` before the handler so
  its own `pre_sign` auto-approves instead of blocking (mirrors Nip55Activity /
  Nip55ContentProvider). Without it the round times out with "Session error: Timeout".
- Device B (co-signer) approves via the `getPendingRequests()` / `approveRequest()`
  polling loop.

`initialize()` is wrapped in a decryption-cipher context (`getCipherForDecryption`)
on both devices, since it decrypts the stored share to start the FROST node.
