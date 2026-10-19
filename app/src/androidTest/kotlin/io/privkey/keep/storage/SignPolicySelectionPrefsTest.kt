package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.SignPolicyStore
import io.privkey.keep.uniffi.StorageRead
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The global sign-policy selection now lives in the core store; Android only backs it
 * with encrypted prefs. These cover the one-time hand-off from the deleted Kotlin
 * store (which wrote the same key as an Int in a different prefs file) and the
 * fail-safe default: anything unreadable resolves to MANUAL, the strictest tier.
 */
@RunWith(AndroidJUnit4::class)
class SignPolicySelectionPrefsTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clearPrefs()

    @After
    fun teardown() = clearPrefs()

    private fun clearPrefs() {
        context.deleteSharedPreferences(SELECTION_PREFS)
        context.deleteSharedPreferences(LEGACY_PREFS)
        // Only our own one-shot marker; the marker file is shared with other
        // migrations, so it must not be deleted wholesale.
        context.getSharedPreferences(
            SignPolicySelectionPrefs.MARKER_PREFS_NAME,
            android.content.Context.MODE_PRIVATE
        ).edit().remove(SignPolicySelectionPrefs.MIGRATION_MARKER).commit()
    }

    private fun writeLegacyOrdinal(ordinal: Int) {
        KeystoreEncryptedPrefs.create(context, LEGACY_PREFS)
            .edit()
            .putInt(GLOBAL_KEY, ordinal)
            .commit()
    }

    private fun newStore() = SignPolicyStore(SignPolicySelectionPrefs(context))

    @Test
    fun legacyIntOrdinalMigratesIntoTheCoreStore() {
        writeLegacyOrdinal(SignPolicy.BASIC.ordinal)

        assertEquals(SignPolicySelection.BASIC, newStore().globalPolicy())
    }

    @Test
    fun migrationIsIdempotentAndNeverClobbersTheNewValue() {
        writeLegacyOrdinal(SignPolicy.BASIC.ordinal)

        newStore().setGlobalPolicy(SignPolicySelection.AUTO)

        // A second construction re-runs the migration against a populated store.
        assertEquals(SignPolicySelection.AUTO, newStore().globalPolicy())
        assertEquals(SignPolicySelection.AUTO, newStore().globalPolicy())
    }

    @Test
    fun migrationNeverResurrectsTheLegacySelectionAfterTheStoreIsLost() {
        // The legacy value is kept on disk, and a lost store reads as absent, so gating
        // the migration on "new value is absent" alone would re-run it and restore the
        // old, possibly looser, selection.
        // The one-shot marker must prevent that: losing the store falls back to
        // MANUAL (strictest), never back to the legacy AUTO.
        writeLegacyOrdinal(SignPolicy.AUTO.ordinal)
        assertEquals(SignPolicySelection.AUTO, newStore().globalPolicy())

        newStore().setGlobalPolicy(SignPolicySelection.MANUAL)
        assertEquals(SignPolicySelection.MANUAL, newStore().globalPolicy())

        // Simulate the stored selection becoming unreadable/lost.
        context.deleteSharedPreferences(SELECTION_PREFS)

        assertEquals(SignPolicySelection.MANUAL, newStore().globalPolicy())
    }

    /**
     * The migration copies only over a value that is not there. One that is stored but
     * will not decrypt resolves to MANUAL, and reading it as absent would put the legacy
     * selection, here a looser one, in its place.
     */
    @Test
    fun migrationNeverCopiesOverAValueThatCannotBeRead() {
        val storedName = writeAndFindStoredName(context, SELECTION_PREFS) {
            SignPolicySelectionPrefs(context).save(GLOBAL_KEY, SignPolicySelection.BASIC.ordinal.toString())
        }
        corruptStoredValue(context, SELECTION_PREFS, storedName)
        // As on an install that has not run the migration yet.
        context.getSharedPreferences(SignPolicySelectionPrefs.MARKER_PREFS_NAME, Context.MODE_PRIVATE)
            .edit().remove(SignPolicySelectionPrefs.MIGRATION_MARKER).commit()
        writeLegacyOrdinal(SignPolicy.AUTO.ordinal)

        assertEquals(SignPolicySelection.MANUAL, newStore().globalPolicy())
        forgetWriteProbe(context, SELECTION_PREFS)
    }

    @Test
    fun migrationLeavesTheLegacyValueInPlace() {
        writeLegacyOrdinal(SignPolicy.AUTO.ordinal)

        newStore()

        assertEquals(
            SignPolicy.AUTO.ordinal,
            KeystoreEncryptedPrefs.create(context, LEGACY_PREFS).getInt(GLOBAL_KEY, -1)
        )
    }

    @Test
    fun noLegacyValueLeavesTheStoreUnsetAndDefaultsToManual() {
        val prefs = SignPolicySelectionPrefs(context)

        assertEquals(StorageRead.Absent, prefs.load(GLOBAL_KEY))
        assertEquals(SignPolicySelection.MANUAL, SignPolicyStore(prefs).globalPolicy())
    }

    @Test
    fun outOfRangeLegacyOrdinalIsNotMigratedAndDefaultsToManual() {
        writeLegacyOrdinal(99)

        assertEquals(SignPolicySelection.MANUAL, newStore().globalPolicy())
    }

    @Test
    fun unreadableStoredValueFallsBackToManual() {
        // A value of the wrong type is what the pre-migration prefs file held; reading
        // it must report a fault rather than throwing into the signing path.
        KeystoreEncryptedPrefs.create(context, SELECTION_PREFS)
            .edit()
            .putInt(GLOBAL_KEY, SignPolicy.AUTO.ordinal)
            .commit()

        val prefs = SignPolicySelectionPrefs(context)

        assertEquals(StorageRead.Unavailable, prefs.load(GLOBAL_KEY))
        assertEquals(SignPolicySelection.MANUAL, SignPolicyStore(prefs).globalPolicy())
    }

    @Test
    fun unparseableStoredValueFallsBackToManual() {
        val prefs = SignPolicySelectionPrefs(context)
        prefs.save(GLOBAL_KEY, "not-an-ordinal")

        assertEquals(SignPolicySelection.MANUAL, SignPolicyStore(prefs).globalPolicy())
    }

    @Test
    fun everySelectionRoundTripsThroughTheStore() {
        for (selection in SignPolicySelection.entries) {
            val store = newStore()
            store.setGlobalPolicy(selection)
            assertEquals(selection, newStore().globalPolicy())
        }
    }

    @Test
    fun removeClearsThePersistedSelection() {
        val prefs = SignPolicySelectionPrefs(context)
        prefs.save(GLOBAL_KEY, SignPolicy.AUTO.ordinal.toString())

        prefs.remove(GLOBAL_KEY)

        assertEquals(StorageRead.Absent, prefs.load(GLOBAL_KEY))
        assertEquals(SignPolicySelection.MANUAL, SignPolicyStore(prefs).globalPolicy())
    }

    /**
     * An override that is stored but will not decrypt must not fall back to the global
     * selection, which can be looser than the override the owner set. Reported as
     * absent, it would: the core reads absent as "no override". Reported as
     * unavailable, the core resolves it to MANUAL.
     *
     * Staged on disk, so this is the production backend's answer for a real
     * undecryptable entry rather than a fake's.
     */
    @Test
    fun anUndecryptableOverrideResolvesToManualRatherThanTheGlobal() {
        newStore().setGlobalPolicy(SignPolicySelection.AUTO)
        val storedName = writeAndFindStoredName(context, SELECTION_PREFS) {
            newStore().setAppOverride(PKG, SignPolicySelection.BASIC)
        }
        corruptStoredValue(context, SELECTION_PREFS, storedName)

        val store = newStore()
        assertEquals(SignPolicySelection.MANUAL, store.appOverride(PKG))
        assertEquals(SignPolicySelection.MANUAL, store.effectivePolicy(PKG))
        forgetWriteProbe(context, SELECTION_PREFS)
    }

    // The controls: a readable override wins over the global, and a package with no
    // override gets the global, so the case above cannot pass on a store that answers
    // MANUAL for everything.
    @Test
    fun aReadableOverrideWinsOverTheGlobal() {
        newStore().setGlobalPolicy(SignPolicySelection.AUTO)
        newStore().setAppOverride(PKG, SignPolicySelection.BASIC)

        assertEquals(SignPolicySelection.BASIC, newStore().effectivePolicy(PKG))
    }

    @Test
    fun aPackageWithNoOverrideGetsTheGlobal() {
        newStore().setGlobalPolicy(SignPolicySelection.AUTO)

        assertEquals(SignPolicySelection.AUTO, newStore().effectivePolicy(PKG))
    }

    private companion object {
        const val PKG = "com.test.app"
        const val SELECTION_PREFS = "keep_sign_policy_selection"
        const val LEGACY_PREFS = "keep_sign_policy"
        const val GLOBAL_KEY = SignPolicySelectionPrefs.GLOBAL_POLICY_KEY
    }
}
