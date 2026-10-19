# nip46probe

Host-side NIP-46 client for the bunker revoke end-to-end test, `BunkerRevokeE2ETest`, which is a **manual-only** instrumented test (skipped by default).

The test runs the real `BunkerService` against a public relay and drives each revoke path through its real screen: Revoke on the Bunker screen with the bunker stopped and running, and Disconnect in App Permissions. After each one it asks this probe, a real NIP-46 client on the host, to connect or sign over the relay and checks the answer:

- a client signs with a remembered grant after a plain restart (control), and is refused after a revoke made while the bunker was stopped;
- the old bunker URL no longer connects after a revoke, and the new one does over the same relay;
- a prompt approved after its client was revoked does not sign.

The probe and the test exchange requests through the app's `files/bunker-e2e` directory over `adb shell run-as`. Each request reaches the probe on stdin, so client secrets and bunker URLs never appear in a process listing. The probe prints one line per request: `OK`, `ERR`, `TIMEOUT`, or `UNSENT` when no relay took the request, so a request that never left cannot pass for a dead URL.

## Run

```bash
./gradlew installDebug installDebugAndroidTest
testharness/nip46probe/run-revoke-e2e.sh
```

Notes:
- Needs `cargo`, `adb` with one device attached, and network access to the relay in `FrostSignFixture.RELAY`. Set `BUNKER_RELAY` to use another relay.
- Turn the bunker off in the app first. With it on, the app starts the bunker as soon as the test launches it, and the test skips rather than take over a running bunker.
- The test imports a temporary account from a public test-vector key (the fixture share is 2-of-3 and cannot sign alone). It saves the device's accounts, relay and bunker settings, denylist and rotation marker to a file before changing anything, and restores them afterwards, or at the start of the next run if this one was killed.
- Every run ends with a fresh bunker URL, and the test clients it approved (two per run) stay on the device's denylist, so no test client keeps a way in. Clients paired with the device's bunker before the run need to pair again.
- If a killed run's state can no longer be restored (for example, the account that was active has since been deleted), every later run fails at the start and says so. Set the device up by hand, then remove the saved state with `adb shell run-as io.privkey.keep rm files/bunker-e2e-saved.json files/bunker-e2e-clients.txt`.
- The prompt's Approve button requires a biometric, so the test answers the prompt the way that button does once the biometric succeeds.
- `Cargo.lock` is committed so the probe builds against the same `nostr` versions as the core. Build output lands in `target/` and is not committed.
