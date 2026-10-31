package io.privkey.keep.nip55

import android.content.Context
import android.content.SharedPreferences
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.SignPolicySelectionStorage
import io.privkey.keep.uniffi.SignPolicyStore
import io.privkey.keep.uniffi.StorageRead
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Per-app sign-policy overrides during the move from Room into the core-owned store.
 *
 * An override is normally STRICTER than the global policy, so the invariant under
 * test is one-directional: an app must never come out of any of these paths on a
 * looser policy than it went in on. Losing the global is survivable (it defaults to
 * Manual); losing an override is not.
 *
 * These need the real core store, so they are instrumented: the uniffi types are
 * never stubbed.
 */
@RunWith(AndroidJUnit4::class)
class AppSignPolicyOverridesInstrumentedTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore
    private lateinit var core: SignPolicyStore
    private lateinit var markers: SharedPreferences

    @Before
    fun setup() {
        clearPrefs()
        markers = context.getSharedPreferences(MARKER_PREFS, Context.MODE_PRIVATE)
        database = Room.inMemoryDatabaseBuilder(
            context,
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
        core = newCore()
        AppSignPolicyOverrides.activeAccount = { ACCOUNT }
    }

    @After
    fun teardown() {
        AppSignPolicyOverrides.activeAccount = { null }
        database.close()
        clearPrefs()
    }

    private fun clearPrefs() {
        context.deleteSharedPreferences(SELECTION_PREFS)
        // The migration markers get a file of their own here, so a test can delete it
        // wholesale without touching the shared one the app ships.
        context.deleteSharedPreferences(MARKER_PREFS)
        context.deleteSharedPreferences(LEGACY_PREFS)
        context.deleteSharedPreferences(AUTO_SIGNING_PREFS)
        // Only our own one-shot marker; the marker file is shared with other
        // migrations, so it must not be deleted wholesale.
        context.getSharedPreferences(
            SignPolicySelectionPrefs.MARKER_PREFS_NAME,
            Context.MODE_PRIVATE
        ).edit().remove(SignPolicySelectionPrefs.MIGRATION_MARKER).commit()
    }

    private fun newCore() = SignPolicyStore(SignPolicySelectionPrefs(context))

    @Test
    fun theStricterOfTheTwoStoresResolves() = runBlocking {
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        // The row is a floor: a write that reached one store and not the other must not
        // widen the app, whichever side holds the looser tier.
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))

        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.MANUAL)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))

        // Across the middle tier too, since stricter() leans on the declaration order.
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.BASIC.ordinal)
        assertEquals(SignPolicySelection.BASIC, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun agreeingStoresReturnThatValue() = runBlocking {
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun aPinnedAppWhoseTierIsNotInTheCoreResolvesToManual() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.BASIC.ordinal)

        // Not migrated yet, so the tier is unknown rather than Basic. Resolving to the
        // global instead would loosen an app pinned stricter than it.
        assertNull(core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun noOverrideOnlyWhenNeitherSideKnowsOfOne() = runBlocking {
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))

        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        // A tier with no row to index it still means a tier exists, so it is unknown
        // rather than absent and resolves strict. Falling to the global here would loosen
        // an app whose only surviving record is stricter than the global.
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun outOfRangeRowOrdinalResolvesToManual() = runBlocking {
        store.setAppSignPolicyOverride(PKG, 99)

        // Pinned, with nothing the core can serve for it.
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun effectivePolicyFallsBackToGlobalThenManual() = runBlocking {
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )

        core.setGlobalPolicy(SignPolicySelection.AUTO)
        assertEquals(
            SignPolicySelection.AUTO,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )

        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
    }

    @Test
    fun writePutsTheTierInTheCoreAndIndexesItOnTheRow() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.BASIC)

        assertEquals(SignPolicySelection.BASIC, core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicy.BASIC.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(SignPolicySelection.BASIC, AppSignPolicyOverrides.override(core, store, PKG))
    }

    /**
     * A clear has to drop the row as well as the tier. The row is the index, so one left
     * behind would keep the app pinned-but-unknown, which resolves to Manual rather than
     * to the global the user asked to follow.
     */
    @Test
    fun clearedOverrideLeavesTheAppFollowingTheGlobal() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)
        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        AppSignPolicyOverrides.setOverride(core, store, PKG, null)

        assertNull(core.appOverride(ACCOUNT, PKG))
        assertNull(store.getAppSignPolicyOverride(PKG))
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
        assertEquals(
            SignPolicySelection.AUTO,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
        // Also across a fresh core instance, which re-reads from disk.
        assertNull(AppSignPolicyOverrides.override(newCore(), store, PKG))
    }

    @Test
    fun writeKeepsTheAppExpiryOnTheRow() = runBlocking {
        store.setAppExpiry(PKG, AppExpiryDuration.ONE_HOUR)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.BASIC)

        val settings = store.getAppSettings(PKG)
        assertNotNull(settings)
        assertNotNull(settings!!.expiresAt)
        assertEquals(SignPolicy.BASIC.ordinal, settings.signPolicyOverride)
    }

    /**
     * The Room mirror is what makes the override visible to the expiry sweep. Losing
     * that link is how an override outlives its window, so the row and the core value
     * must go together.
     */
    @Test
    fun expirySweepClearsTheCoreOverride() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        val now = System.currentTimeMillis()
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = SignPolicy.BASIC.ordinal,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.BASIC)

        store.cleanupExpired(core, AutoSigningSafeguards(context))

        assertNull(core.appOverride(ACCOUNT, PKG))
        assertNull(newCore().appOverride(ACCOUNT, PKG))
        assertNull(store.getAppSignPolicyOverride(PKG))
        // Back to the global, exactly where an expired row left the app before the
        // override moved into the core.
        assertEquals(
            SignPolicySelection.AUTO,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
    }

    /**
     * With no core store there is nothing to clear and nothing to confirm, so a row
     * carrying an override is deferred to a sweep that can confirm it rather than
     * deleted into an override nothing can reach.
     */
    @Test
    fun expirySweepWithoutACoreStoreDefersARowCarryingAnOverride() = runBlocking {
        val now = System.currentTimeMillis()
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = SignPolicy.MANUAL.ordinal,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = OTHER_PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = null,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )

        store.cleanupExpired(null, AutoSigningSafeguards(context))

        assertNotNull(store.getAppSettings(PKG))
        // A row with no override has no core counterpart, so it expires as it always did.
        assertNull(store.getAppSettings(OTHER_PKG))
    }

    /**
     * With no safeguards store this session, "not opted in" cannot be told apart from
     * "opted in and unclearable", so the sweep keeps the row rather than dropping the one
     * record that keeps the app expired. Fail-closed: the app stays refused until a sweep
     * that can establish it runs, instead of silently regaining the global policy.
     */
    @Test
    fun expirySweepWithoutSafeguardsKeepsTheRow() = runBlocking {
        val now = System.currentTimeMillis()
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = null,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )

        store.cleanupExpired(core, null)

        assertNotNull(store.getAppSettings(PKG))
    }

    @Test
    fun expirySweepLeavesAnUnexpiredOverrideAlone() = runBlocking {
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)

        store.cleanupExpired(core)

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
    }

    /**
     * The wipe drops the rows and leaves each tier to the account that set it. Another
     * account cannot read it, and back on its own account a tier with no row resolves
     * to Manual rather than to the old choice.
     */
    @Test
    fun accountSwitchDropsTheRowsAndLeavesTheTierToItsAccount() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.MANUAL)
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.AUTO)
        store.setAppExpiry(OTHER_PKG, AppExpiryDuration.ONE_HOUR)

        store.clearAllAppSettings()

        assertNull(store.getAppSettings(PKG))
        assertNull(store.getAppSettings(OTHER_PKG))
        assertEquals(SignPolicySelection.AUTO, core.appOverride(ACCOUNT, PKG))

        AppSignPolicyOverrides.activeAccount = { OTHER_ACCOUNT }
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))

        AppSignPolicyOverrides.activeAccount = { ACCOUNT }
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))
    }

    /** With no active account every app is Manual, and a tier cannot be written anywhere. */
    @Test
    fun withNoActiveAccountEveryAppIsManual() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        AppSignPolicyOverrides.activeAccount = { null }

        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))

        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.AUTO)
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))
        assertNull(core.appOverride(ACCOUNT, PKG))
    }

    /**
     * A tier set before overrides were per account is only a floor until it is adopted,
     * so an app pinned looser than the global resolves to the global. Adoption makes it
     * the active account's again. It is then no floor for any other account, which
     * follows its own policy for the app.
     */
    @Test
    fun adoptionRestoresALooseningLegacyTierForTheActiveAccountOnly() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.MANUAL)
        writeLegacyOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))

        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)

        assertTrue(markers.getBoolean(SignPolicySelectionPrefs.LEGACY_OVERRIDE_ADOPTION_MARKER, false))
        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.effectivePolicy(core, store, PKG))
        assertNull(core.appOverride(OTHER_ACCOUNT, PKG))
        assertEquals(SignPolicySelection.MANUAL, core.effectivePolicy(OTHER_ACCOUNT, PKG))
    }

    /** A tier the user chose after the pin is kept, not replaced by the legacy one. */
    @Test
    fun adoptionKeepsATierAlreadyScopedToTheAccount() = runBlocking {
        writeLegacyOverride(PKG, SignPolicySelection.AUTO)
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.BASIC)

        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)

        assertEquals(SignPolicySelection.BASIC, core.appOverride(ACCOUNT, PKG))
    }

    /**
     * No active account with a pinned row is a read fault, not an empty device, so the
     * adoption waits for a start that can read the account instead of giving up.
     */
    @Test
    fun adoptionWithNoActiveAccountRetriesWhileARowCarriesATier() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.MANUAL)
        writeLegacyOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        AppSignPolicyOverrides.activeAccount = { null }

        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)
        assertFalse(markers.getBoolean(SignPolicySelectionPrefs.LEGACY_OVERRIDE_ADOPTION_MARKER, false))

        AppSignPolicyOverrides.activeAccount = { ACCOUNT }
        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)
        assertEquals(SignPolicySelection.AUTO, core.appOverride(ACCOUNT, PKG))
    }

    /** With no account and no pinned row there is nothing to adopt, so it is done. */
    @Test
    fun adoptionWithNoActiveAccountAndNoPinnedRowIsDone() = runBlocking {
        writeLegacyOverride(PKG, SignPolicySelection.AUTO)
        AppSignPolicyOverrides.activeAccount = { null }

        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)

        assertTrue(markers.getBoolean(SignPolicySelectionPrefs.LEGACY_OVERRIDE_ADOPTION_MARKER, false))
    }

    /** A set marker, which an account switch also sets, stops the adoption. */
    @Test
    fun theAdoptionMarkerStopsTheAdoption() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.MANUAL)
        writeLegacyOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        markers.edit().putBoolean(SignPolicySelectionPrefs.LEGACY_OVERRIDE_ADOPTION_MARKER, true).commit()

        AppSignPolicyOverrides.adoptLegacyOverrides(core, store, markers)

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(ACCOUNT, PKG))
    }

    /** A legacy tier that will not read is not adopted, and the marker waits for a retry. */
    @Test
    fun anUnreadableLegacyTierLeavesTheMarkerUnsetForARetry() = runBlocking {
        val faulty = SignPolicyStore(UnreadableKeyStorage("sign_policy_override:$PKG"))
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        AppSignPolicyOverrides.adoptLegacyOverrides(faulty, store, markers)

        assertFalse(markers.getBoolean(SignPolicySelectionPrefs.LEGACY_OVERRIDE_ADOPTION_MARKER, false))
    }

    /** The row copy waits for an account rather than claiming packages it cannot copy. */
    @Test
    fun theRowCopyWaitsForAnActiveAccount() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        AppSignPolicyOverrides.activeAccount = { null }

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)
        assertFalse(markers.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false))

        AppSignPolicyOverrides.activeAccount = { ACCOUNT }
        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)
        assertEquals(SignPolicySelection.AUTO, core.appOverride(ACCOUNT, PKG))
    }

    // The core's own encoding of a selection: Manual 0, Basic 1, Auto 2.
    private fun writeLegacyOverride(pkg: String, selection: SignPolicySelection) {
        val ordinal = when (selection) {
            SignPolicySelection.MANUAL -> 0
            SignPolicySelection.BASIC -> 1
            SignPolicySelection.AUTO -> 2
        }
        assertTrue(SignPolicySelectionPrefs(context).save("sign_policy_override:$pkg", ordinal.toString()))
    }

    /**
     * A session whose core store failed to construct has nowhere to put a tier, so it
     * records the strictest one rather than a choice nothing can honor. The floor then
     * holds that line even once a live core turns up with a staler, looser tier.
     */
    @Test
    fun withoutACoreStoreAnOverrideIsRecordedAtManual() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)

        // Nothing can honor a tier while the store is missing, so a loosening is refused
        // rather than recorded, and the app stays at the strictest tier.
        AppSignPolicyOverrides.setOverride(null, store, PKG, SignPolicySelection.AUTO)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(null, store, PKG)
        )
    }

    /**
     * An expired window must not take the user's standing refusal with it, and must not
     * leave the app able to auto-sign under the global policy.
     *
     * A DENY carries its own expiry, so it is not part of the time-boxed grant: the sweep
     * leaving it in place is what stops expiry from loosening. Clearing the opt-in is what
     * makes the app re-approvable rather than silently back on the global.
     */
    @Test
    fun theExpirySweepKeepsAStandingDenyAndClearsTheOptIn() = runBlocking {
        val safeguards = AutoSigningSafeguards(context)
        safeguards.setOptedIn(PKG, true)
        val now = System.currentTimeMillis()
        // A refusal with no expiry of its own: the user denied this app, full stop.
        database.permissionDao().insertPermission(
            Nip55Permission(
                callerPackage = PKG,
                requestType = Nip55RequestType.SIGN_EVENT.name,
                eventKind = 1,
                decision = "deny",
                expiresAt = null,
                createdAt = now - 2_000L
            )
        )
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = null,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )

        store.setPermissionToAsk(PKG, Nip55RequestType.SIGN_EVENT, 3)
        // An ALLOW with no expiry of its own, which per-row expiry would never retire.
        database.permissionDao().insertPermission(
            Nip55Permission(
                callerPackage = PKG,
                requestType = Nip55RequestType.SIGN_EVENT.name,
                eventKind = 2,
                decision = "allow",
                expiresAt = null,
                createdAt = now - 2_000L
            )
        )

        store.cleanupExpired(core, safeguards)

        assertEquals(
            PermissionDecision.DENY,
            store.getPermissionDecision(PKG, Nip55RequestType.SIGN_EVENT, 1)
        )
        // The grant goes with the window. Keeping it would auto-approve at the stored
        // permission gate as soon as this sweep drops the settings row and the app stops
        // counting as expired.
        assertNull(store.getPermissionDecision(PKG, Nip55RequestType.SIGN_EVENT, 2))
        // An explicit "always ask" is a standing instruction too, and at keep v0.11.0 it
        // blocks the policy auto-approve, so deleting it would hand that back.
        assertEquals(
            PermissionDecision.ASK,
            store.getPermissionDecision(PKG, Nip55RequestType.SIGN_EVENT, 3)
        )
        assertFalse(safeguards.isOptedIn(PKG))
        // The row only goes once the opt-in clear is durable, since the package cannot be
        // enumerated as expired again afterwards.
        assertNull(store.getAppSettings(PKG))
    }

    @Test
    fun expirySweepKeepsARowWhoseClearDoesNotVerify() = runBlocking {
        val flaky = SignPolicyStore(UnremovableStorage(PKG))
        val now = System.currentTimeMillis()
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = SignPolicy.MANUAL.ordinal,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )
        flaky.setAppOverride(ACCOUNT, PKG, SignPolicySelection.MANUAL)

        store.cleanupExpired(flaky)

        assertNotNull(store.getAppSettings(PKG))
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSettings(PKG)?.signPolicyOverride)
        // The row is kept so a later sweep can retry the clear, but a lapsed row must
        // retire the override in BOTH stores in the meantime: the core keeps no expiry
        // of its own, and the signing path applies the policy before it evaluates app
        // expiry, so a surviving AUTO would auto-approve on the way past.
        assertNull(AppSignPolicyOverrides.override(flaky, store, PKG))
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(ACCOUNT, PKG))
    }

    /**
     * An unconfirmed write does not say which value is stored, so a tightening must not
     * be dropped. The core can serve the new tier from memory while its disk still holds
     * the old one, and a process that starts after that would otherwise auto-approve
     * against the tier the user had moved away from.
     */
    @Test
    fun aTighteningWhoseWriteIsNotConfirmedPinsManual() = runBlocking {
        val unreliable = SignPolicyStore(UncommittableStorage())
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        AppSignPolicyOverrides.setOverride(unreliable, store, PKG, SignPolicySelection.MANUAL)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))

        // The case that matters is a next process whose core file still holds the OLD,
        // looser tier, not one that holds nothing: an empty store resolves Manual through
        // the unknown arm and would pass without any floor at all.
        val nextProcess = SignPolicyStore(UncommittableStorage())
        nextProcess.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(nextProcess, store, PKG)
        )
    }

    /**
     * A clear whose row write throws leaves both stores untouched, so the override stays
     * in force and the failure is reported.
     *
     * Deliberately unlike the set path, which attempts the tier write anyway: there, the
     * tier write can only tighten, so attempting it preserves a tightening that would
     * otherwise be lost. A clear has no tightening to preserve, so leaving both stores as
     * they were is the cleaner failure and matches what the screen tells the user.
     */
    @Test
    fun aClearWhoseRowWriteThrowsLeavesTheOverrideInForce() = runBlocking {
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.BASIC)
        database.close()

        val result = runCatching { AppSignPolicyOverrides.setOverride(core, store, PKG, null) }

        assertTrue(result.isFailure)
        assertEquals(SignPolicySelection.BASIC, core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicySelection.BASIC, newCore().appOverride(ACCOUNT, PKG))
    }

    /**
     * A clear has to clear even with no core store this session. Recording a Manual
     * ordinal instead would index the app as pinned, turning the clear into a pin that
     * the next session resolves from whatever the core still holds.
     */
    @Test
    fun aClearWithoutACoreStoreDropsTheRow() = runBlocking {
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        AppSignPolicyOverrides.setOverride(null, store, PKG, null)

        assertNull(store.getAppSettings(PKG))
        // The core still holds the old tier, known to one side only, so it resolves strict
        // rather than handing the app the global.
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    /**
     * A clear whose core write does not durably land still takes the chosen tier out of
     * force: dropping the row leaves the leftover known to one side only, which resolves
     * to Manual rather than to the tier the user cleared.
     *
     * Dropping the row first is what keeps it that way across a startup. The migration
     * copies from the row's tier, so a row left behind would be written back into the
     * empty slot and revert the clear outright.
     */
    @Test
    fun aClearWhoseCoreWriteDoesNotPersistStillTakesEffect() = runBlocking {
        val flaky = SignPolicyStore(UnremovableStorage(PKG))
        AppSignPolicyOverrides.setOverride(flaky, store, PKG, SignPolicySelection.MANUAL)

        AppSignPolicyOverrides.setOverride(flaky, store, PKG, null)

        assertNull(store.getAppSettings(PKG))
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(ACCOUNT, PKG))
        // The clear took effect in that the chosen tier is gone, but the leftover is known
        // to one side only, so it resolves strict instead of following the global.
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(flaky, store, PKG)
        )

        // The row is gone, so the migration has nothing to copy back. Asserted on the
        // resolved policy rather than on the row, which was already absent and would hold
        // whatever the migration did.
        AppSignPolicyOverrides.migrateLegacyOverrides(flaky, store, markers)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(flaky, store, PKG)
        )
    }

    /**
     * A row write that throws must not skip the tier write. The floor means the core
     * holding the new tier against a row still holding the old one resolves to the
     * stricter of the two, so attempting it can only tighten, and returning early would
     * leave both stores on the old tier and lose the tightening.
     *
     * Asserted on the core rather than through the resolver on purpose: with the database
     * closed the row read throws, and that alone yields Manual whatever the ordering was,
     * which is what made the previous version of this test vacuous.
     */
    @Test
    fun aRowWriteThatThrowsStillWritesTheTier() = runBlocking {
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.AUTO)
        database.close()

        val result = runCatching {
            AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)
        }

        assertTrue(result.isFailure)
        assertEquals(SignPolicySelection.MANUAL, core.appOverride(ACCOUNT, PKG))
        // And durably, not just in the store's in-memory map.
        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(ACCOUNT, PKG))
    }

    @Test
    fun migrationCopiesRoomOverridesIntoTheCore() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)
        store.setAppSignPolicyOverride(OTHER_PKG, SignPolicy.BASIC.ordinal)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicySelection.BASIC, core.appOverride(ACCOUNT, OTHER_PKG))
        // A fresh instance proves the copy was persisted, not just cached.
        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(ACCOUNT, PKG))
    }

    @Test
    fun migrationLeavesTheRowValuesInPlaceAsItsOwnSource() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
    }

    @Test
    fun migrationIsIdempotentAndNeverOverwritesTheCore() = runBlocking {
        // Room still holds the old, looser value the user has since tightened.
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        core.setAppOverride(ACCOUNT, PKG, SignPolicySelection.MANUAL)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)
        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)
        AppSignPolicyOverrides.migrateLegacyOverrides(newCore(), store, markers)

        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(ACCOUNT, PKG))
    }

    @Test
    fun migrationSkipsAnExpiredRow() = runBlocking {
        val now = System.currentTimeMillis()
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = SignPolicy.AUTO.ordinal,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        // Copying it would freeze a time-boxed override into the core, which has no
        // expiry. Nor does the Room fallback serve it while it waits for the sweep: the
        // core applies the policy at its sign-policy gate, before the one that denies an
        // expired app, so a retained AUTO would auto-approve on the way past.
        assertNull(core.appOverride(ACCOUNT, PKG))
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun aFullRunSetsTheRunWideMarkerAndDropsThePerPackageOnes() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertTrue(markers.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false))
        // The per-package markers are only read before the run-wide one is set, so keeping
        // them would leave a standing list of which apps the user pinned. That they are
        // written at all is covered by aPartialRunKeepsThePerPackageMarkersItRecorded.
        assertTrue(
            "per-package markers should be gone: ${markers.all.keys}",
            markers.all.keys.none {
                it.startsWith(SignPolicySelectionPrefs.APP_OVERRIDE_MARKER_PREFIX)
            }
        )
    }

    @Test
    fun aPartialRunKeepsThePerPackageMarkersItRecorded() = runBlocking {
        val now = System.currentTimeMillis()
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)
        // An expired row is never attempted, so this run is not complete and the run-wide
        // marker has to stay unset: the sweep can keep such a row and its window can be
        // refreshed later, and claiming the marker would strand that tier for good.
        database.appSettingsDao().insertOrUpdate(
            Nip55AppSettings(
                callerPackage = OTHER_PKG,
                expiresAt = now - 1_000L,
                signPolicyOverride = SignPolicy.AUTO.ordinal,
                createdAt = now - 2_000L,
                createdAtElapsed = 0L,
                durationMs = null
            )
        )

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertFalse(markers.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false))
        assertTrue(markers.getBoolean(SignPolicySelectionPrefs.appOverrideMarkerKey(PKG), false))
        // The point of withholding the run-wide marker: the expired row must not come out
        // of this recorded as attempted, or its tier becomes uncopyable once the window is
        // refreshed. Covered end to end by aRefreshedWindowIsCopiedByALaterRun.
        assertFalse(
            markers.getBoolean(SignPolicySelectionPrefs.appOverrideMarkerKey(OTHER_PKG), false)
        )
    }

    /**
     * The positive control for withholding the run-wide marker on an expired row. The sweep
     * can retain such a row, `setAppExpiry` can refresh its window while preserving the
     * tier, and a later run then has to be able to copy it.
     */
    @Test
    fun aRefreshedWindowIsCopiedByALaterRun() = runBlocking {
        val now = System.currentTimeMillis()
        val expired = Nip55AppSettings(
            callerPackage = PKG,
            expiresAt = now - 1_000L,
            signPolicyOverride = SignPolicy.AUTO.ordinal,
            createdAt = now - 2_000L,
            createdAtElapsed = 0L,
            durationMs = null
        )
        database.appSettingsDao().insertOrUpdate(expired)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertNull("an expired row must not be copied", core.appOverride(ACCOUNT, PKG))
        assertFalse(markers.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false))

        database.appSettingsDao().insertOrUpdate(expired.copy(expiresAt = now + 600_000L))

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertEquals(SignPolicySelection.AUTO, core.appOverride(ACCOUNT, PKG))
    }

    /**
     * Installs that finished this copy before the markers became per-package carry only
     * the run-wide one, so it has to keep standing on its own.
     */
    @Test
    fun aRunWideMarkerAloneStopsTheCopy() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        markers.edit()
            .putBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, true)
            .commit()

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertNull(core.appOverride(ACCOUNT, PKG))
    }

    @Test
    fun aLaterRunCopiesOnlyThePackagesNoRunReached() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        store.setAppSignPolicyOverride(OTHER_PKG, SignPolicy.BASIC.ordinal)
        // PKG was attempted by an earlier run that never reached OTHER_PKG.
        markers.edit()
            .putBoolean(SignPolicySelectionPrefs.appOverrideMarkerKey(PKG), true)
            .commit()

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)

        assertNull(core.appOverride(ACCOUNT, PKG))
        assertEquals(SignPolicySelection.BASIC, core.appOverride(ACCOUNT, OTHER_PKG))
    }

    /**
     * Why the marker rather than the absence check carries this. By the time a second run
     * happens the core may durably hold the stricter Manual an unconfirmed write pinned
     * while the row still holds the looser tier the user asked for. Copying the row again
     * would then widen the app, so an attempted package is never copied twice, even when
     * the core answers that nothing is stored.
     */
    @Test
    fun anAttemptedPackageIsNotCopiedWhenTheCoreReadsAsEmpty() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        markers.edit()
            .putBoolean(SignPolicySelectionPrefs.appOverrideMarkerKey(PKG), true)
            .commit()
        val unreadable = UnreadableStorage()
        val faulting = SignPolicyStore(unreadable)
        // What an unconfirmed setOverride write leaves behind: the core durably holds the
        // stricter tier while reads of it come back empty.
        faulting.setAppOverride(ACCOUNT, PKG, SignPolicySelection.MANUAL)
        val before = unreadable.saved.toList()

        AppSignPolicyOverrides.migrateLegacyOverrides(faulting, store, markers)

        assertEquals(before, unreadable.saved)
    }

    /**
     * A copy that does not confirm pins Manual rather than leaving the tier it could not
     * durably write. Retrying it on a later start would be a copy whose outcome is already
     * unknown, which is the one shape that can widen.
     */
    @Test
    fun aCopyThatDoesNotConfirmPinsManual() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        val uncommittable = UncommittableStorage()

        AppSignPolicyOverrides.migrateLegacyOverrides(
            SignPolicyStore(uncommittable),
            store,
            markers
        )

        // Read through a fresh store over the same backing map, the way the next process
        // would: the repair is what is there to be read, not the row's AUTO.
        assertEquals(
            SignPolicySelection.MANUAL,
            SignPolicyStore(uncommittable).appOverride(ACCOUNT, PKG)
        )
    }

    /**
     * A marker whose write never reaches the disk must not leave the package marked. The
     * platform applies an edit to its in-memory map before it reports the disk result, and
     * a write serializes the whole map, so a marker left behind would be persisted by the
     * next successful write in the same run, for a package nothing was copied for.
     */
    @Test
    fun aMarkerThatDoesNotPersistLeavesThePackageUnmarked() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        val unwritable = UncommittablePrefs()

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, unwritable)

        assertFalse(
            unwritable.getBoolean(SignPolicySelectionPrefs.appOverrideMarkerKey(PKG), false)
        )
        assertFalse(
            unwritable.getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false)
        )
        // And nothing was copied, since the attempt could not be recorded.
        assertNull(core.appOverride(ACCOUNT, PKG))
    }

    /**
     * The safety invariant end to end: an app pinned stricter than a loose global
     * stays pinned across the migration, and stays pinned if the Room mirror is lost
     * on its own, read back through a fresh core instance.
     */
    @Test
    fun strictOverrideSurvivesTheMigrationEndToEnd() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store, markers)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )

        // Dropping the row leaves the tier known to only one side, which resolves strict
        // rather than falling to the looser global.
        store.clearAppSettings(PKG)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(newCore(), store, PKG)
        )
    }

    /**
     * A migration that never ran (or failed outright) must not loosen anything: the
     * Room fallback still pins the app.
     */
    @Test
    fun strictOverrideHoldsWhenTheMigrationNeverRan() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        assertNull(core.appOverride(ACCOUNT, PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
    }

    private companion object {
        const val ACCOUNT = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        const val OTHER_ACCOUNT = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
        const val PKG = "com.test.app"
        const val OTHER_PKG = "com.test.other"
        const val SELECTION_PREFS = "keep_sign_policy_selection"
        const val AUTO_SIGNING_PREFS = "nip55_auto_signing"
        const val LEGACY_PREFS = "keep_sign_policy"
        const val MARKER_PREFS = "test_migration_markers"
    }
}

/**
 * A backend whose writes never persist: the `commit()` returning false that the core's
 * trait warns about. The value is served from memory for the rest of the session while
 * the durable write is reported as failed, which is the case a caller cannot detect by
 * reading back.
 */
private class UncommittableStorage : SignPolicySelectionStorage {

    private val values = HashMap<String, String>()

    override fun load(key: String): StorageRead =
        values[key]?.let { StorageRead.Found(it) } ?: StorageRead.Absent

    override fun save(key: String, value: String): Boolean {
        values[key] = value
        return false
    }

    override fun remove(key: String): Boolean {
        values.remove(key)
        return false
    }
}

/**
 * A real backend for the real core store, not a stubbed uniffi type: it implements the
 * same [SignPolicySelectionStorage] trait the production encrypted-prefs class does,
 * and reproduces the failure the write paths have to survive. Clears and removals for
 * [unremovablePackage] are dropped and reported as the failed durable write they are,
 * which is what the production backend returns when `commit()` fails.
 */
private class UnremovableStorage(private val unremovablePackage: String) : SignPolicySelectionStorage {

    private val values = HashMap<String, String>()

    override fun load(key: String): StorageRead =
        values[key]?.let { StorageRead.Found(it) } ?: StorageRead.Absent

    // A clear is stored as the core's "follows global" value, so that is the write
    // that does not persist.
    override fun save(key: String, value: String): Boolean {
        if (key.endsWith(unremovablePackage) && value == "global") return false
        values[key] = value
        return true
    }

    override fun remove(key: String): Boolean {
        if (key.endsWith(unremovablePackage)) return false
        values.remove(key)
        return true
    }
}

/** A backend that cannot read one key, as a value that will not decrypt reads. */
private class UnreadableKeyStorage(private val unreadableKey: String) : SignPolicySelectionStorage {

    private val values = HashMap<String, String>()

    override fun load(key: String): StorageRead =
        if (key == unreadableKey) StorageRead.Unavailable
        else values[key]?.let { StorageRead.Found(it) } ?: StorageRead.Absent

    override fun save(key: String, value: String): Boolean {
        values[key] = value
        return true
    }

    override fun remove(key: String): Boolean {
        values.remove(key)
        return true
    }
}

/**
 * A backend whose reads all come back absent while its writes persist, so a test can
 * see what the migration does when the core answers that nothing is stored whatever it
 * holds. Records what it was asked to store so a test can tell a copy that was skipped
 * from one that landed.
 */
private class UnreadableStorage : SignPolicySelectionStorage {

    val saved = mutableListOf<Pair<String, String>>()

    override fun load(key: String): StorageRead = StorageRead.Absent

    override fun save(key: String, value: String): Boolean {
        saved += key to value
        return true
    }

    override fun remove(key: String): Boolean = true
}

/**
 * Prefs whose edits reach the in-memory map but never the disk, which is what the platform
 * does when a `commit()` fails: it applies to memory first and its result reports only the
 * durable write. Only booleans are exercised; the rest satisfies the interface.
 */
private class UncommittablePrefs : SharedPreferences {

    private val values = HashMap<String, Any?>()

    override fun getAll(): MutableMap<String, *> = HashMap(values)

    override fun getString(key: String, defValue: String?): String? =
        values[key] as? String ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        values[key] as? MutableSet<String> ?: defValues

    override fun getInt(key: String, defValue: Int): Int = values[key] as? Int ?: defValue

    override fun getLong(key: String, defValue: Long): Long = values[key] as? Long ?: defValue

    override fun getFloat(key: String, defValue: Float): Float = values[key] as? Float ?: defValue

    override fun getBoolean(key: String, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    override fun contains(key: String): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = FailingEditor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?
    ) = Unit

    private inner class FailingEditor : SharedPreferences.Editor {

        private val pending = HashMap<String, Any?>()
        private val removals = HashSet<String>()
        private var clearRequested = false

        private fun put(key: String, value: Any?): SharedPreferences.Editor {
            pending[key] = value
            return this
        }

        override fun putString(key: String, value: String?): SharedPreferences.Editor =
            put(key, value)

        override fun putStringSet(
            key: String,
            values: MutableSet<String>?
        ): SharedPreferences.Editor = put(key, values)

        override fun putInt(key: String, value: Int): SharedPreferences.Editor = put(key, value)

        override fun putLong(key: String, value: Long): SharedPreferences.Editor = put(key, value)

        override fun putFloat(key: String, value: Float): SharedPreferences.Editor = put(key, value)

        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor =
            put(key, value)

        override fun remove(key: String): SharedPreferences.Editor {
            removals += key
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clearRequested = true
            return this
        }

        override fun commit(): Boolean {
            applyToMemory()
            return false
        }

        override fun apply() {
            applyToMemory()
        }

        private fun applyToMemory() {
            if (clearRequested) values.clear()
            removals.forEach { values.remove(it) }
            values.putAll(pending)
            pending.clear()
            removals.clear()
            clearRequested = false
        }
    }
}
