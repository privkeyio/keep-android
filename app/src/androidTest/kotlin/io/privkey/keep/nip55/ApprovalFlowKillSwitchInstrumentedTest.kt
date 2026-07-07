package io.privkey.keep.nip55

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.KeepMobileApp
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Approval-flow unhappy-branch coverage for the NIP-55 signer boundary (gh #376, split of
 * #323). Asserts that the Rust-owned kill switch gates key use at the signer entrypoint:
 * when the core kill switch is engaged, [Nip55Activity.handleIntent] maps every request to
 * RESULT_CANCELED with the "signing is disabled" message, never to a signature.
 *
 * Kill-switch policy is owned by the Rust core (mobile.setKillSwitch / getKillSwitch),
 * surfaced through [KeepMobileApp.isSigningKilled] (fail-closed on read error) and enforced
 * as the FIRST check in handleIntent -- before caller identification, handler wiring, or
 * request parsing. That ordering is the property under test: with the switch engaged no
 * branch downstream (and therefore no key material) is ever reachable. The prior core
 * switch value is captured in @Before and restored in @After so the run never leaves the
 * installed app in a kill-switched state.
 *
 * Out of scope (documented, not faked), per the #388/#389 precedent:
 *  - Biometric-authentication FAILURE and user CANCELLATION of the prompt. On these
 *    physical devices biometric is BIOMETRIC_STRONG with no PIN fallback and cannot be
 *    software-injected (no emulator biometric injection is available either). The failure/
 *    cancellation decision logic lives inside the [androidx.biometric.BiometricPrompt]
 *    .AuthenticationCallback in BiometricHelper (onAuthenticationError ->
 *    AuthResult.FAILED/LOCKOUT; onAuthenticationError ERROR_USER_CANCELED /
 *    ERROR_NEGATIVE_BUTTON -> resume(null)); those callbacks are invoked only by the real
 *    hardware prompt, so there is no non-UI seam to drive them directly. Both branches are
 *    manual/out-of-scope here rather than stubbed into a hollow pass.
 */
@RunWith(AndroidJUnit4::class)
class ApprovalFlowKillSwitchInstrumentedTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun app(): KeepMobileApp = context.applicationContext as KeepMobileApp

    private var priorKillSwitch: Boolean? = null

    @Before
    fun engageKillSwitch() {
        val mobile = app().getKeepMobile()
        assertNotNull("KeepMobile core must be initialized to drive the kill switch", mobile)
        priorKillSwitch = mobile!!.getKillSwitch()
        mobile.setKillSwitch(true)
    }

    @After
    fun restoreKillSwitch() {
        // Restore the exact pre-test core state so the switch flip does not persist on the
        // device or poison sibling tests. Safe if @Before was skipped (prior stays null).
        val mobile = app().getKeepMobile() ?: return
        priorKillSwitch?.let { mobile.setKillSwitch(it) }
    }

    private fun launchAndGetResult(intent: Intent): Instrumentation.ActivityResult {
        ActivityScenario.launchActivityForResult<Nip55Activity>(intent).use { scenario ->
            return scenario.result
        }
    }

    // A well-formed sign_event request under an engaged kill switch must be gated: the
    // signer entrypoint maps it to RESULT_CANCELED carrying the kill-switch message, and
    // never emits a signature or a reject flag (no key use occurred).
    @Test
    fun killSwitchEngaged_wellFormedSignEvent_mapsToSigningDisabled() {
        val intent = Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
            data = Uri.parse("nostrsigner:${Uri.encode("""{"kind":1,"content":"gm","tags":[]}""")}")
            putExtra("type", "sign_event")
            putExtra("id", "req-killswitch-1")
        }
        val result = launchAndGetResult(intent)

        assertEquals(
            "Engaged kill switch must map a sign request to RESULT_CANCELED, not RESULT_OK",
            Activity.RESULT_CANCELED,
            result.resultCode
        )
        val data = result.resultData
        assertNotNull("Gated result must carry a result intent", data)
        assertEquals(
            "Kill-switch gate must surface the signing-disabled user message",
            "Signing is disabled (kill switch is active)",
            data!!.getStringExtra("error")
        )
        assertNull("Gated result must not masquerade as a signature", data.getStringExtra("signature"))
        assertFalse("Gated result must not carry the rejected flag", data.getBooleanExtra("rejected", false))
    }

    // The kill-switch check precedes caller identification and request parsing: a bare intent
    // that would otherwise fail-closed with a DIFFERENT message (the caller-verification or
    // parse branch, when signing is enabled) instead maps to the signing-disabled message.
    // This pins the gate ordering, proving the engaged switch short-circuits the entrypoint
    // before any path that could reach key material.
    @Test
    fun killSwitchEngaged_precedesCallerAndParseChecks() {
        val intent = Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
        }
        val result = launchAndGetResult(intent)

        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        val data = result.resultData
        assertNotNull("Gated result must carry a result intent", data)
        assertEquals(
            "Kill switch must gate BEFORE the caller-verification and parse branches",
            "Signing is disabled (kill switch is active)",
            data!!.getStringExtra("error")
        )
        assertNull("Gated result must not masquerade as a signature", data.getStringExtra("signature"))
        assertFalse("Gated result must not carry the rejected flag", data.getBooleanExtra("rejected", false))
    }
}
