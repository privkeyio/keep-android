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
 * branch downstream (and therefore no key material) is ever reachable. The caller-precedence
 * claim is validated concretely by a negative control: an intent whose bearer nonce is bound
 * to a DIFFERENT package (which would fail-closed at the caller-verification branch with a
 * distinct message when signing is enabled) maps to the signing-disabled message while the
 * switch is engaged, and to "Request from unverified app" once it is disengaged -- so the
 * switch is load-bearing AND strictly precedes caller identification, not merely parsing.
 * @Before disengages the core switch to a known baseline before engaging it for the test, and
 * @After forces it back to disengaged unconditionally -- so this class both self-heals a switch
 * left engaged by a prior aborted run and never leaves the installed app kill-switched. The
 * single residual gap is process death strictly between setKillSwitch(true) and @After, which is
 * uncatchable in-process; a suite that must be hardened against that would need per-test
 * process isolation (Android Test Orchestrator), a module-wide execution change out of scope
 * here. Since the switch fails CLOSED (only ever disables signing), that residual cannot
 * yield a rogue signature.
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

    @Before
    fun engageKillSwitch() {
        val mobile = app().getKeepMobile()
        assertNotNull("KeepMobile core must be initialized to drive the kill switch", mobile)
        mobile!!.setKillSwitch(false)
        mobile.setKillSwitch(true)
    }

    @After
    fun restoreKillSwitch() {
        // Force the core switch back to the suite's disengaged baseline (signing enabled).
        // Unconditional so this class cannot leave -- or inherit -- a poisoned engaged state
        // across any in-process-catchable failure mode. Safe if @Before was skipped.
        val mobile = app().getKeepMobile() ?: return
        mobile.setKillSwitch(false)
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

    // The kill-switch check precedes caller identification: a request that WOULD fail-closed at
    // the caller-verification branch (a well-formed sign_event whose bearer nonce was issued to a
    // DIFFERENT package -- tripping identifyCaller's direct-caller mismatch guard) instead maps to
    // the signing-disabled message while the switch is engaged. A negative control in the same test
    // then disengages the switch and relaunches the SAME intent, proving it genuinely reaches the
    // caller-rejection branch ("Request from unverified app") absent the switch -- so the kill
    // switch is load-bearing AND strictly precedes caller identification.
    @Test
    fun killSwitchEngaged_precedesCallerAndParseChecks() {
        val verificationStore = app().getCallerVerificationStore()
            ?: error("CallerVerificationStore not initialized")
        val nonce = verificationStore.generateNonce("com.example.unknown.caller")
        val intent = Intent(context, Nip55Activity::class.java).apply {
            action = Intent.ACTION_VIEW
            data = Uri.parse("nostrsigner:${Uri.encode("""{"kind":1,"content":"gm","tags":[]}""")}")
            putExtra("type", "sign_event")
            putExtra("id", "req-killswitch-precedence")
            putExtra("nip55_nonce", nonce)
        }

        // Switch ENGAGED (the @Before baseline): the kill-switch gate must win over the caller
        // check, surfacing the signing-disabled message rather than "Request from unverified app".
        val engaged = launchAndGetResult(intent)
        assertEquals(Activity.RESULT_CANCELED, engaged.resultCode)
        val engagedData = engaged.resultData
        assertNotNull("Gated result must carry a result intent", engagedData)
        assertEquals(
            "Kill switch must gate BEFORE the caller-verification branch",
            "Signing is disabled (kill switch is active)",
            engagedData!!.getStringExtra("error")
        )
        assertNull("Gated result must not masquerade as a signature", engagedData.getStringExtra("signature"))
        assertFalse("Gated result must not carry the rejected flag", engagedData.getBooleanExtra("rejected", false))

        // Negative control: DISENGAGE the switch and relaunch the SAME intent. Now the request
        // reaches identifyCaller and fails the mismatch guard -> unknown_caller. This proves the
        // kill switch was load-bearing above (not some other short-circuit) and that it strictly
        // precedes caller identification. @After restores the disengaged baseline regardless.
        app().getKeepMobile()!!.setKillSwitch(false)
        val disengaged = launchAndGetResult(intent)
        assertEquals(Activity.RESULT_CANCELED, disengaged.resultCode)
        val disengagedData = disengaged.resultData
        assertNotNull("Caller-rejection result must carry a result intent", disengagedData)
        assertEquals(
            "Absent the kill switch the same intent must reach the caller-rejection branch",
            "Request from unverified app",
            disengagedData!!.getStringExtra("error")
        )
        assertNull("Caller-rejection result must not masquerade as a signature", disengagedData.getStringExtra("signature"))
        assertFalse("Caller-rejection result must not carry the rejected flag", disengagedData.getBooleanExtra("rejected", false))
    }

    @After
    fun sweepCallerVerificationStore() {
        // This test issues a nonce on the shared production CallerVerificationStore singleton;
        // sweep it so no residual nonce leaks into sibling tests (mirrors the sibling mapping test).
        app().getCallerVerificationStore()?.cleanupExpiredNonces()
    }
}
