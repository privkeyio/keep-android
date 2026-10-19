package io.privkey.keep.nip55

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.uniffi.Nip55DecisionInputs
import io.privkey.keep.uniffi.Nip55Outcome
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55StoredPermission
import io.privkey.keep.uniffi.Nip55VelocityCheck
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.evaluateNip55Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What the background path decides for a relay auth, through the pinned core and the
 * same whitelist fold the ContentProvider uses.
 *
 * The gate tests stop at the gate value. Whether a listed relay is then signed is
 * decided below it, in the core, and that is where membership used to authorize an
 * app that had never been granted anything. These pin the core this app ships with,
 * so a pin that moved back to a core without the fix fails here.
 */
@RunWith(AndroidJUnit4::class)
class RelayAuthDecisionTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private lateinit var store: RelayAuthWhitelistStore

    @Before
    fun setup() {
        context.deleteSharedPreferences(RelayAuthWhitelistStore.PREFS_NAME)
        store = RelayAuthWhitelistStore(context)
    }

    @After
    fun teardown() {
        context.deleteSharedPreferences(RelayAuthWhitelistStore.PREFS_NAME)
    }

    @Test
    fun aListedRelayWithNoStandingPermissionPromptsRatherThanSigning() {
        store.add("relay.example.com")
        val outcome = decide(exact = null)
        assertTrue(
            "membership must not authorize signing on its own, got $outcome",
            outcome is Nip55Outcome.RequireUi
        )
    }

    // The control: the same listed relay is signed once the app holds a grant for it,
    // so the case above cannot pass on inputs that would prompt for anything.
    @Test
    fun aListedRelayWithAStandingPermissionIsSigned() {
        store.add("relay.example.com")
        assertEquals(Nip55Outcome.AutoApprove, decide(exact = allow()))
    }

    @Test
    fun anUnlistedRelayIsRejectedEvenWithAStandingPermission() {
        store.add("other.example.com")
        assertEquals(Nip55Outcome.Reject("deny_relay_whitelist"), decide(exact = allow()))
    }

    private fun allow() = Nip55StoredPermission(
        decision = "allow",
        expiresAt = null,
        createdAt = System.currentTimeMillis(),
        createdAtElapsed = SystemClock.elapsedRealtime(),
        durationMs = null
    )

    private fun decide(exact: Nip55StoredPermission?): Nip55Outcome {
        val (hosts, readFailed) = relayWhitelistInputs(store)
        return evaluateNip55Request(
            Nip55DecisionInputs(
                packageName = "com.test.app",
                callerVerified = true,
                signingKilled = false,
                isLocked = false,
                requestType = Nip55RequestType.SIGN_EVENT,
                eventJson = EVENT_22242,
                frontDoorWithinLimit = true,
                velocityCheck = Nip55VelocityCheck.ALLOWED,
                relayWhitelist = hosts,
                relayWhitelistReadFailed = readFailed,
                policySelection = SignPolicySelection.MANUAL,
                isOptedIn = false,
                optInRateCheck = null,
                hasSignedKindBefore = true,
                appAgeMs = null,
                currentHour = 12u,
                appExpired = false,
                permissionLookupOk = true,
                storedExactPermission = exact,
                storedGenericPermission = null,
                nowElapsedMs = SystemClock.elapsedRealtime(),
                nowWallMs = System.currentTimeMillis()
            )
        )
    }

    private companion object {
        const val EVENT_22242 =
            """{"kind":22242,"content":"","tags":[["relay","wss://relay.example.com/"],["challenge","abc"]]}"""
    }
}
