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
    fun stricterWinsWhenTheCoreIsLooserThanRoom() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun stricterWinsWhenRoomIsLooserThanTheCore() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.MANUAL)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun stricterWinsAcrossTheMiddleTier() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.BASIC.ordinal)

        assertEquals(SignPolicySelection.BASIC, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun agreeingStoresReturnThatValue() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun roomOverrideIsUsedWhenTheCoreHasNone() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.BASIC.ordinal)

        assertNull(core.appOverride(PKG))
        assertEquals(SignPolicySelection.BASIC, AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun noOverrideOnlyWhenBothStoresAreEmpty() = runBlocking {
        assertNull(AppSignPolicyOverrides.override(core, store, PKG))
    }

    @Test
    fun outOfRangeRoomOrdinalResolvesToManual() = runBlocking {
        store.setAppSignPolicyOverride(PKG, 99)

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
    fun writeMirrorsTheSameValueIntoBothStores() = runBlocking {
        store.setAppSignPolicyOverride(PKG, SignPolicy.MANUAL.ordinal)

        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.BASIC)

        assertEquals(SignPolicySelection.BASIC, core.appOverride(PKG))
        assertEquals(SignPolicy.BASIC.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(SignPolicySelection.BASIC, AppSignPolicyOverrides.override(core, store, PKG))
    }

    /**
     * The resurrection case: a clear has to null BOTH stores, or the dual read would
     * hand the stale Room mirror straight back after the user cleared it.
     */
    @Test
    fun clearedOverrideDoesNotResurrectFromRoom() = runBlocking {
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
    fun aTighteningMadeWithoutACoreStoreOutranksTheStaleCoreValue() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.AUTO)

        AppSignPolicyOverrides.setOverride(null, store, PKG, SignPolicySelection.MANUAL)
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))

        val liveCore = newCore()
        AppSignPolicyOverrides.migrateLegacyOverrides(liveCore, store)
        assertEquals(SignPolicySelection.AUTO, liveCore.appOverride(PKG))

        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.override(liveCore, store, PKG)
        )
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(liveCore, store, PKG)
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
        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(SignPolicySelection.MANUAL, flaky.appOverride(PKG))
    }

    /**
     * A clear writes the mirror first, so a mirror failure aborts before the core is
     * touched: both stores still hold the override and there is nothing to resurrect.
     * The reverse order would leave the stale mirror as the only copy, and the next
     * migration would copy it back into the core for good.
     */
    @Test
    fun aClearWhoseMirrorWriteThrowsDoesNotResurrect() = runBlocking {
        AppSignPolicyOverrides.setOverride(core, store, PKG, SignPolicySelection.MANUAL)
        database.close()

        runCatching { AppSignPolicyOverrides.setOverride(core, store, PKG, null) }

        assertEquals(SignPolicySelection.MANUAL, core.appOverride(PKG))
        assertEquals(SignPolicySelection.MANUAL, newCore().appOverride(PKG))
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
    fun migrationLeavesTheRoomValuesInPlaceForTheFallback() = runBlocking {
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
        // expiry. The Room fallback still serves it until the expiry sweep runs.
        assertNull(core.appOverride(PKG))
        assertEquals(SignPolicySelection.AUTO, AppSignPolicyOverrides.override(core, store, PKG))
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
 * A real backend for the real core store, not a stubbed uniffi type: it implements the
 * same [SignPolicySelectionStorage] trait the production encrypted-prefs class does,
 * and reproduces the failure mode that motivates the read-back checks. Removals for
 * [unremovablePackage] are dropped and reported as success, exactly as the production
 * backend does when it swallows an exception or `commit()` returns false.
 */
private class UnremovableStorage(private val unremovablePackage: String) : SignPolicySelectionStorage {

    private val values = HashMap<String, String>()

    override fun load(key: String): String? = values[key]

    override fun save(key: String, value: String) {
        values[key] = value
    }

    override fun remove(key: String) {
        if (key.endsWith(unremovablePackage)) return
        values.remove(key)
    }
}
