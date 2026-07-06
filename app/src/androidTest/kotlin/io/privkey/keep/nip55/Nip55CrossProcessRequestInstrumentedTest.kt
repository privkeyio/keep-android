package io.privkey.keep.nip55

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Cross-process coverage of the NIP-55 provider's post-caller-gate branches (gh #374).
 *
 * The in-process suite ([Nip55RequestMappingInstrumentedTest]) can only reach the
 * same-UID fail-closed denial: getVerifiedCaller() rejects Process.myUid(). To reach the
 * real request-handling branches (malformed request, per-app DENY reject, rate-limit)
 * the query must come from a DISTINCTLY-SIGNED, dedicated-UID caller that keep has
 * pinned via TOFU. A tiny standalone client APK (io.privkey.keeptest.queryclient,
 * testharness/nip55queryclient) supplies that caller: on launch it runs
 * ContentResolver.query against keep's provider and broadcasts the resulting cursor's
 * columns + row0 back to this test.
 *
 * Trust is bootstrapped in-process: the test pins the client's signing-certificate hash
 * into CallerVerificationStore (the same TOFU seam a first-use UI approval would write),
 * so the client's query passes getVerifiedCaller() (cross-process UID, single package,
 * matching signature) and lands on the branch under test. The pin is REVOKED in @After
 * (untrustPackage restores the client to untrusted), so it does not persist after the run
 * and does not widen the device's caller-trust set; re-running is safe.
 *
 * Out of scope (documented, not faked):
 *  - The AUTO_APPROVE / ALLOW success cursors require a provisioned signing key + a
 *    BIOMETRIC_STRONG prompt; the FirstUseRequiresApproval path requires the interactive
 *    TOFU approval UI. Those are not the malformed/rejected branches this issue targets.
 *  - The "timed-out" acceptance branch (provider runWithTimeout -> rejectedCursor with
 *    deny_timeout / deny_velocity_timeout) is deferred: it is not deterministically
 *    reachable from a cross-process caller without injecting artificial delay into the
 *    provider, which would add flakiness for no additional contract coverage (tracked in #389).
 *  - The front-door rate-limit errorCursor ("Too many requests...") is not
 *    deterministically reachable from a single cross-process caller: the per-request
 *    caller verification that runs BEFORE the 30 req/s check (getPackageSignatureHash ->
 *    PackageManager.getPackageInfo with signing certs, serialized in system_server)
 *    caps a single caller's effective arrival rate at ~18 req/s on these devices, below
 *    the limiter threshold. Measured, not assumed (a 16-thread x N burst on the fast
 *    invalid-pubkey path never produced the limiter cursor). The limiter itself is
 *    covered by the Rust unit tests for Nip55RequestRateLimiter.
 */
@RunWith(AndroidJUnit4::class)
class Nip55CrossProcessRequestInstrumentedTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun app(): KeepMobileApp = context.applicationContext as KeepMobileApp

    private val clientPkg = "io.privkey.keeptest.queryclient"
    private val clientActivity = "$clientPkg.QueryActivity"
    private val resultAction = "io.privkey.keeptest.QUERY_RESULT"

    // The result broadcast receiver must be exported to receive the cross-UID reply, so a
    // predictable, source-visible reqid would let any co-installed app forge a QUERY_RESULT
    // and make the test assert a false PASS without keep's provider ever being hit. Each run
    // uses an unguessable nonce so a spoofer cannot pre-know the reqid to match. The client
    // echoes back whatever reqid it was launched with.
    private val runNonce = java.util.UUID.randomUUID().toString()
    private fun rid(label: String) = "$runNonce-$label"

    // Reference SHA-256 of the client APK's DER-encoded signing certificate for the
    // debug keystore that produced the originally-proven APK. Documented as a sanity
    // reference only: the test never depends on it -- it reads the installed client's
    // live hash at runtime (see @Before), so any machine's debug keystore works.
    private val referenceSignatureHash =
        "08552f38836b2bbaf8e2fa5199056ce484dcb5caf42ce58bf4e54d2a2ca1b8c5"

    @Before
    fun pinClientTrust() {
        val manual = InstrumentationRegistry.getArguments().getString(MANUAL_ARG)
        assumeTrue(
            "manual-only cross-process test; pass -e $MANUAL_ARG 1 " +
                "(build+install the client from testharness/nip55queryclient first)",
            manual == "1"
        )

        val store = app().getCallerVerificationStore()
        assertNotNull("CallerVerificationStore must be initialized", store)

        // keep can only read the client's signing hash AFTER the client has interacted
        // with keep's provider (package visibility). Drive one throwaway query to
        // establish that visibility; an untrusted caller just gets an error cursor here.
        // ActivityNotFoundException => the client APK is not installed -> skip, don't fail.
        try {
            runClientQuery(
                rid("prime"), "io.privkey.keep.SIGN_EVENT",
                arrayOf("""{"kind":1,"content":"gm","tags":[]}""", "", "")
            )
        } catch (e: android.content.ActivityNotFoundException) {
            assumeTrue(
                "cross-process client $clientPkg not installed; build it with " +
                    "testharness/nip55queryclient/build.sh and `adb install -r " +
                    "testharness/nip55queryclient/out/queryclient.apk`, then rerun",
                false
            )
        }

        // Now read the live hash via the exact production path keep uses at query time.
        val live = store!!.getPackageSignatureHash(clientPkg)
        assumeTrue(
            "live signing hash for $clientPkg unavailable (client not installed/visible); " +
                "reinstall testharness/nip55queryclient/out/queryclient.apk and rerun",
            live != null
        )
        android.util.Log.i(
            "KEEPQC-TEST",
            "live client sig hash = $live (reference = $referenceSignatureHash)"
        )
        // Pin the client's ACTUAL live hash as the TOFU-trusted signature; keep recomputes
        // the same value from its own PackageManager when the real test query arrives.
        store.trustPackage(clientPkg, live!!)
    }

    @After
    fun revokeClientTrust() {
        // Revoke the harness client's TOFU pin so it does not persist past the run and
        // does not widen the device's caller-trust set. Safe even if @Before was skipped.
        app().getCallerVerificationStore()?.untrustPackage(clientPkg)
    }

    private data class Report(val cols: List<String>, val row0: String, val raw: String)

    private fun parse(raw: String): Report {
        val m = Regex("cols=\\[(.*?)\\] row0=\\[(.*)\\]$").find(raw)
            ?: throw AssertionError("Client did not return a cursor row (past-gate failure?): $raw")
        val cols = m.groupValues[1].split(",").filter { it.isNotEmpty() }
        return Report(cols, m.groupValues[2], raw)
    }

    private fun runClientQuery(
        reqid: String,
        authority: String,
        projection: Array<String>?,
        repeat: Int = 1,
        threads: Int = 1,
        collect: Boolean = false
    ): String {
        val latch = CountDownLatch(1)
        val captured = arrayOfNulls<String>(1)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                if (i?.getStringExtra("reqid") == reqid) {
                    captured[0] = i.getStringExtra("result")
                    latch.countDown()
                }
            }
        }
        ContextCompat.registerReceiver(
            context, receiver, IntentFilter(resultAction), ContextCompat.RECEIVER_EXPORTED
        )
        try {
            val intent = Intent().apply {
                setClassName(clientPkg, clientActivity)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                putExtra("reqid", reqid)
                putExtra("authority", authority)
                putExtra("repeat", repeat)
                putExtra("threads", threads)
                putExtra("collect", collect)
                if (projection != null) putExtra("projection", projection)
            }
            context.startActivity(intent)
            assertTrue(
                "Timed out waiting for client result reqid=$reqid",
                latch.await(30, TimeUnit.SECONDS)
            )
            return captured[0] ?: throw AssertionError("Null result payload for reqid=$reqid")
        } finally {
            context.unregisterReceiver(receiver)
        }
    }

    // --- Checkpoint + malformed: trusted caller past the gate hits request validation ---

    @Test
    fun crossProcess_invalidPubkey_mapsToErrorCursor() {
        val projection = arrayOf(
            """{"kind":1,"content":"gm","tags":[]}""",
            "a".repeat(129), // > MAX_PUBKEY_LENGTH (128)
            ""
        )
        val r = parse(runClientQuery(rid("badpubkey"), "io.privkey.keep.SIGN_EVENT", projection))
        // Proves we are PAST the caller gate: a same-UID/untrusted caller would get the
        // "error"/"Request denied" cursor before any pubkey validation.
        assertEquals("Malformed request must map to the error-cursor contract", listOf("error"), r.cols)
        assertEquals("Invalid public key", r.row0)
    }

    // --- Rejected: a per-app DENY decision maps to the rejected-cursor contract ---

    @Test
    fun crossProcess_perAppDeny_mapsToRejectedCursor() {
        val store = app().getPermissionStore()!!
        try {
            runBlocking {
                // Force the manual-review path (not auto-sign) then a persistent DENY.
                // Inside the try so a throw mid-setup still hits the finally and leaves
                // no persistent app settings behind.
                store.setAppSignPolicyOverride(clientPkg, SignPolicy.MANUAL.ordinal)
                store.denyPermission(clientPkg, Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
            }
            val projection = arrayOf("""{"kind":1,"content":"gm","tags":[]}""", "", "")
            val r = parse(runClientQuery(rid("deny"), "io.privkey.keep.SIGN_EVENT", projection))
            // The "rejected" cursor is emitted by several branches (DENY, velocity, timeout,
            // expiry); the shape is identical, so this asserts the rejected-cursor contract
            // rather than proving the DENY branch specifically. It is deterministic here: this
            // is the first query after clearAppSettings, with an explicit persistent DENY set.
            assertEquals("DENY must map to the rejected-cursor contract", listOf("rejected"), r.cols)
            assertEquals("true", r.row0)
        } finally {
            runBlocking {
                store.revokePermission(clientPkg)
                store.clearAppSettings(clientPkg)
            }
        }
    }

    companion object {
        // Manual gate (mirrors FrostSignFixture.MANUAL_ARG): every test method reports
        // SKIPPED unless invoked with -e crossProcessManual 1, so default
        // connectedAndroidTest / CI stays green without the harness client installed.
        const val MANUAL_ARG = "crossProcessManual"
    }
}
