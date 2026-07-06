package io.privkey.keep.nip55

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * In-process caller-gate coverage for the NIP-55 signer boundary (gh #374, split of
 * #323). Drives the real [Nip55ContentProvider.query] entrypoint and [Nip55Activity]'s
 * result mapping, asserting the fail-closed contract a same-UID caller hits.
 *
 * An instrumented test runs *inside* the target app process, so every in-process
 * ContentResolver query is a same-UID call: getVerifiedCaller() returns null (uid ==
 * Process.myUid()) and query() deterministically maps to errorCursor("Request denied")
 * BEFORE any authority parse, rate/velocity check, or permission lookup. That is the
 * property asserted here.
 *
 * The provider's post-caller-gate branches (authority "Invalid request", malformed
 * request errorCursor, velocity/DENY rejectedCursor, rate-limit errorCursor) require a
 * distinctly-signed cross-process caller and are covered cross-process in
 * [Nip55CrossProcessRequestInstrumentedTest]. The Activity approve/reject RESULT_OK
 * mappings require a BIOMETRIC_STRONG prompt (no PIN fallback) that cannot be
 * software-injected; the unverified-caller error mapping is asserted here.
 */
@RunWith(AndroidJUnit4::class)
class Nip55RequestMappingInstrumentedTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val allAuthorities = listOf(
        "io.privkey.keep.GET_PUBLIC_KEY",
        "io.privkey.keep.SIGN_EVENT",
        "io.privkey.keep.NIP04_ENCRYPT",
        "io.privkey.keep.NIP04_DECRYPT",
        "io.privkey.keep.NIP44_ENCRYPT",
        "io.privkey.keep.NIP44_DECRYPT",
        "io.privkey.keep.DECRYPT_ZAP_EVENT"
    )

    // Asserts the deterministic fail-closed error-cursor contract a NIP-55 client
    // relies on: a single "error" column, one row, and the exact message.
    private fun assertDeniedErrorCursor(uri: Uri, projection: Array<String>?) {
        context.contentResolver.query(uri, projection, null, null, null).use { cursor ->
            assertNotNull("Registered provider must return a cursor for $uri", cursor)
            cursor!!
            assertArrayEquals(
                "Denied request must map to the error-cursor column contract",
                arrayOf("error"),
                cursor.columnNames
            )
            assertEquals("Error cursor carries exactly one row", 1, cursor.count)
            assertTrue(cursor.moveToFirst())
            assertEquals("Request denied", cursor.getString(0))
            // The error cursor never exposes signer output or a rejected flag.
            assertEquals(-1, cursor.getColumnIndex("signature"))
            assertEquals(-1, cursor.getColumnIndex("rejected"))
        }
    }

    // --- ContentProvider: same-uid caller fails closed to the error cursor ---

    @Test
    fun query_everyAuthority_sameUidCaller_returnsDeniedErrorCursor() {
        for (authority in allAuthorities) {
            assertDeniedErrorCursor(Uri.parse("content://$authority"), null)
        }
    }

    @Test
    fun query_signEvent_withWellFormedProjection_stillDeniedBeforeAuthorityParse() {
        // A fully valid sign_event projection (content, pubkey, current_user) must
        // still be denied: the caller gate precedes request-type/authority handling,
        // so a populated projection does not change the outcome.
        val projection = arrayOf(
            """{"kind":1,"content":"gm","tags":[]}""",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        assertDeniedErrorCursor(Uri.parse("content://io.privkey.keep.SIGN_EVENT"), projection)
    }

    // --- Activity: unverified caller maps to RESULT_CANCELED + error extra ---

    private fun launchAndGetResult(intent: Intent): android.app.Instrumentation.ActivityResult {
        ActivityScenario.launchActivityForResult<Nip55Activity>(intent).use { scenario ->
            return scenario.result
        }
    }

    @Test
    fun activity_unverifiedCaller_signEventIntent_mapsToCanceledError() {
        // Force a deterministically-unverified caller. Under ActivityScenario the
        // launching package (getCallingActivity) resolves to the on-device test
        // package, which the Activity would otherwise treat as a legitimate first-use
        // caller and route to the approval UI (no auto-result). Issuing a nonce bound
        // to a DIFFERENT package trips identifyCaller's direct-caller mismatch guard,
        // which clears the caller to unverified. That is the very fail-closed contract
        // under test: a well-formed sign_event request whose bearer nonce was issued to
        // another package maps to RESULT_CANCELED (an error), never to a signature.
        val app = context.applicationContext as io.privkey.keep.KeepMobileApp
        val verificationStore = app.getCallerVerificationStore()
            ?: error("CallerVerificationStore not initialized")
        val nonce = verificationStore.generateNonce("com.example.unknown.caller")
        val intent = Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
            data = Uri.parse("nostrsigner:${Uri.encode("""{"kind":1,"content":"gm","tags":[]}""")}")
            putExtra("type", "sign_event")
            putExtra("id", "req-unhappy-1")
            putExtra("nip55_nonce", nonce)
        }
        val result = launchAndGetResult(intent)

        assertEquals(
            "Unverified caller must map to RESULT_CANCELED (error), not RESULT_OK",
            Activity.RESULT_CANCELED,
            result.resultCode
        )
        val data = result.resultData
        assertNotNull("Error result must carry a result intent", data)
        // Pin the exact unknown_caller message so the assertion binds to the caller-
        // mismatch path specifically. A killed/locked device short-circuits handleIntent
        // to "signing_disabled"/"locked" BEFORE identifyCaller runs; asserting the exact
        // message catches that state-dependent false-green rather than accepting any error.
        assertEquals(
            "Unverified caller must map to the unknown_caller user message",
            "Request from unverified app",
            data!!.getStringExtra("error")
        )
        // The error mapping is distinct from the reject mapping (RESULT_OK + rejected)
        // and the success mapping (RESULT_OK + signature): neither extra is present.
        assertNull("Error result must not masquerade as a signature", data.getStringExtra("signature"))
        assertFalse("Error result must not carry the rejected flag", data.getBooleanExtra("rejected", false))
    }

    @Test
    fun activity_emptyIntent_missingUri_mapsToCanceledError() {
        // No data URI: the caller resolves (first-use test package) and passes the caller
        // gate, so parseRequest returning null on the missing URI is what cancels the
        // request -> finishWithError("Invalid request") -> the generic "Request failed"
        // user message. This covers the unparseable-request fail-closed mapping (canceled,
        // no signature/rejected), distinct from the unverified-caller path above; it is
        // NOT an unverified-caller test. On a killed/locked device it asserts the wrong
        // message and fails loudly rather than false-greening.
        val intent = Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
        }
        val result = launchAndGetResult(intent)

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        val data = result.resultData
        assertNotNull("Error result must carry a result intent", data)
        assertEquals(
            "Missing-URI request must map to the invalid-request user message",
            "Request failed",
            data!!.getStringExtra("error")
        )
        assertNull("Error result must not masquerade as a signature", data.getStringExtra("signature"))
        assertFalse("Error result must not carry the rejected flag", data.getBooleanExtra("rejected", false))
    }
}
