package io.privkey.keep.nip55

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.KeepMobileApp
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The permission-store gate at the NIP-55 foreground entrypoint: a request that
 * cannot be recorded is refused, never approved. [Nip55Activity] uses the store
 * null-safely everywhere else, so absent the gate a dead store would prompt, decide
 * with no stored DENY row consulted, hand back a signature, and skip the audit
 * append, with get_public_key also losing the risk-based escalation to PIN (the risk
 * assessment needs the store). The background path already answers this state with
 * "Permission store is not available" (Nip55ContentProvider); these tests pin the
 * foreground path to the same refusal and the same message.
 *
 * The real degraded state is set once per process: Nip55Database.getInstance fails,
 * KeepMobileApp.initializePermissionStore catches it, and the field stays null for
 * the life of the process. An instrumented test shares that process and only runs
 * after Application.onCreate has already succeeded, so the state cannot be staged
 * the way DatabaseKeyMintTest stages a key fault. These tests therefore clear the
 * activity's own resolved store between the launch and a second intent, and deliver
 * that intent through the real onNewIntent path, so the production gate is what
 * refuses. Both tests pair that with a negative control proving the gate is what
 * made the difference, not some other short-circuit.
 */
@RunWith(AndroidJUnit4::class)
class Nip55StoreGateInstrumentedTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun app(): KeepMobileApp = context.applicationContext as KeepMobileApp

    private val storeField = Nip55Activity::class.java
        .getDeclaredField("permissionStore")
        .apply { isAccessible = true }

    private val onNewIntentMethod = Nip55Activity::class.java
        .getDeclaredMethod("onNewIntent", Intent::class.java)
        .apply { isAccessible = true }

    // A request whose bearer nonce is bound to the package the activity sees as the
    // caller (the instrumentation APK, not the app under test), so identifyCaller
    // resolves a caller and the activity stays up on the approval UI rather than
    // finishing before a second intent can be delivered to it.
    private fun requestFromTheCallingPackage(id: String): Intent {
        val verificationStore = app().getCallerVerificationStore()
            ?: error("CallerVerificationStore not initialized")
        val caller = InstrumentationRegistry.getInstrumentation().context.packageName
        return signEventIntent(id, verificationStore.generateNonce(caller))
    }

    private fun signEventIntent(id: String, nonce: String): Intent =
        Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
            data = Uri.parse("nostrsigner:${Uri.encode("""{"kind":1,"content":"gm","tags":[]}""")}")
            putExtra("type", "sign_event")
            putExtra("id", id)
            putExtra("nip55_nonce", nonce)
        }

    private fun deliver(activity: Nip55Activity, intent: Intent) =
        onNewIntentMethod.invoke(activity, intent)

    private fun errorOf(result: android.app.Instrumentation.ActivityResult): String? {
        assertEquals(
            "A refused request must map to RESULT_CANCELED, not RESULT_OK",
            Activity.RESULT_CANCELED,
            result.resultCode
        )
        val data = result.resultData
        assertNotNull("A refused request must carry a result intent", data)
        assertNull("A refused request must not masquerade as a signature", data!!.getStringExtra("signature"))
        assertFalse("A refused request must not carry the rejected flag", data.getBooleanExtra("rejected", false))
        return data.getStringExtra("error")
    }

    // With the store gone, a well-formed request from a resolved caller is refused
    // with the storage message. The negative control delivers the same second intent
    // with the store in place and the activity stays up, so the refusal came from the
    // gate and not from the request or the second delivery.
    @Test
    fun aDeadPermissionStore_refusesAWellFormedRequest() {
        ActivityScenario.launchActivityForResult<Nip55Activity>(requestFromTheCallingPackage("gate-dead-1")).use { scenario ->
            val second = requestFromTheCallingPackage("gate-dead-2")
            scenario.onActivity { activity ->
                storeField.set(activity, null)
                deliver(activity, second)
            }
            assertEquals(
                "A request that cannot be recorded must be refused with the storage message",
                STORE_UNAVAILABLE_MESSAGE,
                errorOf(scenario.result)
            )
        }

        ActivityScenario.launchActivityForResult<Nip55Activity>(requestFromTheCallingPackage("gate-live-1")).use { scenario ->
            val second = requestFromTheCallingPackage("gate-live-2")
            scenario.onActivity { activity ->
                deliver(activity, second)
                // Read in the same block that delivered the intent: finish() sets this
                // synchronously, where the destroy a lifecycle-state read waits for
                // arrives from the system later and could still read RESUMED.
                assertFalse(
                    "With the store in place the same second intent must not be refused",
                    activity.isFinishing
                )
            }
        }
    }

    // The gate sits ahead of caller identification: an intent that would otherwise
    // fail closed at the caller check (a nonce issued to a DIFFERENT package, which
    // trips identifyCaller's direct-caller mismatch guard) is refused with the
    // storage message while the store is gone, and with the caller message once it is
    // back. So the gate is load-bearing AND strictly precedes identifyCaller, which
    // is what keeps a signer storage fault from being reported as a caller fault.
    @Test
    fun theStoreGate_precedesCallerIdentification() {
        val verificationStore = app().getCallerVerificationStore()
            ?: error("CallerVerificationStore not initialized")

        ActivityScenario.launchActivityForResult<Nip55Activity>(requestFromTheCallingPackage("gate-order-1")).use { scenario ->
            val mismatched = signEventIntent(
                "gate-order-2",
                verificationStore.generateNonce("com.example.unknown.caller")
            )
            scenario.onActivity { activity ->
                storeField.set(activity, null)
                deliver(activity, mismatched)
            }
            assertEquals(
                "The store gate must refuse before the caller-verification branch",
                STORE_UNAVAILABLE_MESSAGE,
                errorOf(scenario.result)
            )
        }

        ActivityScenario.launchActivityForResult<Nip55Activity>(requestFromTheCallingPackage("gate-order-3")).use { scenario ->
            val mismatched = signEventIntent(
                "gate-order-4",
                verificationStore.generateNonce("com.example.unknown.caller")
            )
            scenario.onActivity { activity -> deliver(activity, mismatched) }
            assertEquals(
                "With the store in place the same intent must reach the caller-rejection branch",
                "Request from unverified app",
                errorOf(scenario.result)
            )
        }
    }

    @After
    fun sweepCallerVerificationStore() {
        // These tests issue nonces on the shared production CallerVerificationStore
        // singleton. A gated intent is refused before identifyCaller consumes its
        // nonce, so this drops the expired ones and leaves the rest to age out of
        // their own 5-minute window: in-memory, single-use and package-bound, and
        // every sibling test mints its own.
        app().getCallerVerificationStore()?.cleanupExpiredNonces()
    }
}
