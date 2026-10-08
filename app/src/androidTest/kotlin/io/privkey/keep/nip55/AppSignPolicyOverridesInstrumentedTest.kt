package io.privkey.keep.nip55

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.SignPolicySelectionStorage
import io.privkey.keep.uniffi.SignPolicyStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    @Before
    fun setup() {
        clearPrefs()
        database = Room.inMemoryDatabaseBuilder(
            context,
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
        core = newCore()
    }

    @After
    fun teardown() {
        database.close()
        clearPrefs()
    }

    private fun clearPrefs() {
        context.deleteSharedPreferences(SELECTION_PREFS)
        context.deleteSharedPreferences(LEGACY_PREFS)
        // Only our own one-shot marker; the marker file is shared with other
        // migrations, so it must not be deleted wholesale.
        context.getSharedPreferences(
            SignPolicySelectionPrefs.MARKER_PREFS_NAME,
            Context.MODE_PRIVATE
        ).edit().remove(SignPolicySelectionPrefs.MIGRATION_MARKER).commit()
    }

    private fun newCore() = SignPolicyStore(SignPolicySelectionPrefs(context))

    @Test
    fun theCoreTierResolvesWhateverTheRowCopyHolds() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        // The row marks the app as pinned and seeds the migration. It is not the policy,
        // so there is no disagreement between the two to reconcile.
        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun agreeingStoresReturnThatValue() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun aPinnedAppWhoseTierIsNotInTheCoreResolvesToManual() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.BASIC.ordinal)

        // Not migrated yet, so the tier is unknown rather than Basic. Resolving to the
        // global instead would loosen an app pinned stricter than it.
        assertNull(core.appOverride(PKG))
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun noOverrideWhenNoRowCarriesOne() = runBlocking {
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))

        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        // A tier with no row to index it is inert: the app is simply not pinned, and the
        // lifecycle sweeps are what clear the leftover. Honoring it would put policy back
        // in two places, which is the ambiguity this design removes.
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
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

        assertEquals(SignPolicySelection.BASIC, core.appOverride(PKG))
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
        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)

        AppSignPolicyOverrides.setOverride(core, store, PKG, null)

        assertNull(core.appOverride(PKG))
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
        core.setAppOverride(PKG, SignPolicySelection.BASIC)

        store.cleanupExpired(core)

        assertNull(core.appOverride(PKG))
        assertNull(newCore().appOverride(PKG))
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

        store.cleanupExpired()

        assertNotNull(store.getAppSettings(PKG))
        // A row with no override has no core counterpart, so it expires as it always did.
        assertNull(store.getAppSettings(OTHER_PKG))
    }

    @Test
    fun expirySweepLeavesAnUnexpiredOverrideAlone() = runBlocking {
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)

        store.cleanupExpired(core)

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(PKG))
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
    }

    @Test
    fun accountSwitchLeavesNoCoreOverrideBehind() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)
        AppSignPolicyOverrides.setOverride(core, store, OTHER_PKG, SignPolicySelection.BASIC)

        store.clearAllAppSettings(core)

        assertNull(core.appOverride(PKG))
        assertNull(core.appOverride(OTHER_PKG))
        assertNull(newCore().appOverride(PKG))
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
        assertEquals(
            SignPolicySelection.AUTO,
            AppSignPolicyOverrides.effectivePolicy(core, store, OTHER_PKG)
        )
    }

    /**
     * A session whose core store failed to construct writes to Room alone. The next
     * session has a live core holding the STALE, looser value, and the migration skips
     * the package because the core already knows it. Only stricter-wins keeps the
     * tightening the user actually made.
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
     * An override whose mirror row is gone is invisible to the app-settings table, so
     * the wipe has to reach it through another record of the package.
     */
    @Test
    fun accountSwitchClearsACoreOverrideWithNoRoomRow() = runBlocking {
        store.grantPermission(
            callerPackage = PKG,
            requestType = Nip55RequestType.SIGN_EVENT,
            eventKind = 1,
            duration = PermissionDuration.FOREVER
        )
        core.setAppOverride(PKG, SignPolicySelection.MANUAL)
        assertNull(store.getAppSettings(PKG))

        store.clearAllAppSettings(core)

        assertNull(core.appOverride(PKG))
        assertNull(newCore().appOverride(PKG))
    }

    /**
     * The storage backend swallows failures, so a clear that does not stick returns
     * normally. The read-back has to catch it and the row has to stay, or the override
     * is stranded where nothing can find it again.
     */
    @Test
    fun accountSwitchKeepsRowsWhoseClearDoesNotVerify() = runBlocking {
        val flaky = SignPolicyStore(UnremovableStorage(PKG))
        AppSignPolicyOverrides.setOverride(flaky, store, PKG, SignPolicySelection.MANUAL)
        AppSignPolicyOverrides.setOverride(flaky, store, OTHER_PKG, SignPolicySelection.BASIC)

        store.clearAllAppSettings(flaky)

        // Unprocessed package: override intact and still indexed by its row.
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(PKG))
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(flaky, store, PKG)
        )
        // The verified package is gone from both stores.
        assertNull(flaky.appOverride(OTHER_PKG))
        assertNull(store.getAppSettings(OTHER_PKG))
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
        flaky.setAppOverride(PKG, SignPolicySelection.MANUAL)

        store.cleanupExpired(flaky)

        assertNotNull(store.getAppSettings(PKG))
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSettings(PKG)?.signPolicyOverride)
        // The row is kept so a later sweep can retry the clear, but a lapsed row must
        // retire the override in BOTH stores in the meantime: the core keeps no expiry
        // of its own, and the signing path applies the policy before it evaluates app
        // expiry, so a surviving AUTO would auto-approve on the way past.
        assertNull(AppSignPolicyOverrides.override(flaky, store, PKG))
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(PKG))
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
        // A fresh process, whose core never persisted anything, still sees the tightening.
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(SignPolicyStore(UncommittableStorage()), store, PKG)
        )
    }

    /**
     * A clear whose core write does not durably land must leave the override indexed.
     * The row is the only record Kotlin has of a core override, so dropping it would
     * put the live value out of reach of the UI and of both sweeps.
     */
    @Test
    fun aClearWhoseCoreWriteDoesNotPersistPinsManualAndKeepsTheRow() = runBlocking {
        val flaky = SignPolicyStore(UnremovableStorage(PKG))
        AppSignPolicyOverrides.setOverride(flaky, store, PKG, SignPolicySelection.MANUAL)

        AppSignPolicyOverrides.setOverride(flaky, store, PKG, null)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSettings(PKG)?.signPolicyOverride)
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(flaky, store, PKG)
        )
    }

    /**
     * A clear confirms the core write before dropping the row, so a row write that then
     * fails leaves the app pinned-but-unknown rather than unpinned. An unreadable row
     * makes the signing path fall to Manual, never to a global that may be looser than
     * the tier the user had chosen.
     */
    @Test
    fun aClearWhoseRowWriteThrowsStillFailsClosed() = runBlocking {
        core.setGlobalPolicy(SignPolicySelection.AUTO)
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)
        database.close()

        runCatching { AppSignPolicyOverrides.setOverride(core, store, PKG, null) }

        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
    }

    @Test
    fun migrationCopiesRoomOverridesIntoTheCore() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)
        store.setAppSignPolicyOverride(OTHER_PKG, SignPolicy.BASIC.ordinal)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(PKG))
        assertEquals(SignPolicySelection.BASIC, core.appOverride(OTHER_PKG))
        // A fresh instance proves the copy was persisted, not just cached.
        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(PKG))
    }

    @Test
    fun migrationLeavesTheRowValuesInPlaceAsItsOwnSource() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
    }

    @Test
    fun migrationIsIdempotentAndNeverOverwritesTheCore() = runBlocking {
        // Room still holds the old, looser value the user has since tightened.
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)
        core.setAppOverride(PKG, SignPolicySelection.MANUAL)

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)
        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)
        AppSignPolicyOverrides.migrateLegacyOverrides(newCore(), store)

        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(PKG))
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

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)

        // Copying it would freeze a time-boxed override into the core, which has no
        // expiry. Nor does the Room fallback serve it while it waits for the sweep: the
        // core applies the policy at its sign-policy gate, before the one that denies an
        // expired app, so a retained AUTO would auto-approve on the way past.
        assertNull(core.appOverride(PKG))
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
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

        AppSignPolicyOverrides.migrateLegacyOverrides(core, store)
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )

        // Dropping the row un-indexes the tier, so the app follows the global again. The
        // old design honored the orphaned tier instead, which is how an override could
        // outlive every record of itself.
        store.clearAppSettings(PKG)
        assertEquals(
            SignPolicySelection.AUTO,
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

        assertNull(core.appOverride(PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(core, store, PKG)
        )
    }

    private companion object {
        const val PKG = "com.test.app"
        const val OTHER_PKG = "com.test.other"
        const val SELECTION_PREFS = "keep_sign_policy_selection"
        const val LEGACY_PREFS = "keep_sign_policy"
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

    override fun load(key: String): String? = values[key]

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
 * and reproduces the failure the write paths have to survive. Removals for
 * [unremovablePackage] are dropped and reported as the failed durable write they are,
 * which is what the production backend returns when `commit()` fails.
 */
private class UnremovableStorage(private val unremovablePackage: String) : SignPolicySelectionStorage {

    private val values = HashMap<String, String>()

    override fun load(key: String): String? = values[key]

    override fun save(key: String, value: String): Boolean {
        values[key] = value
        return true
    }

    override fun remove(key: String): Boolean {
        if (key.endsWith(unremovablePackage)) return false
        values.remove(key)
        return true
    }
}
