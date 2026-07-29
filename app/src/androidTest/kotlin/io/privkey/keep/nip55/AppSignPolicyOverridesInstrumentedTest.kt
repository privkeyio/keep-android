package io.privkey.keep.nip55

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.uniffi.SignPolicySelection
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
    fun coreOverrideWinsWhenBothStoresHoldOne() = runBlocking {
        core.setAppOverride(PKG, SignPolicySelection.MANUAL)
        store.setAppSignPolicyOverride(PKG, SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(core, store, PKG))
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

    @Test
    fun withoutACoreStoreTheOverrideStaysInRoom() = runBlocking {
        AppSignPolicyOverrides.setOverride(null, store, PKG, SignPolicySelection.MANUAL)

        assertEquals(SignPolicy.MANUAL.ordinal, store.getAppSignPolicyOverride(PKG))
        assertEquals(SignPolicySelection.MANUAL, AppSignPolicyOverrides.override(null, store, PKG))
        assertEquals(
            SignPolicySelection.MANUAL,
            AppSignPolicyOverrides.effectivePolicy(null, store, PKG)
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
