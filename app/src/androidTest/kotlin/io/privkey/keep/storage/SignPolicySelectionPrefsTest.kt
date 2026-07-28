package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.SignPolicyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
        // The legacy value is kept on disk, and the encrypted-prefs layer reports an
        // undecryptable value as absent, so gating the migration on "new value is
        // absent" would re-run it and restore the old, possibly looser, selection.
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

        assertNull(prefs.load(GLOBAL_KEY))
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
        // it must yield "unset" rather than throwing into the signing path.
        KeystoreEncryptedPrefs.create(context, SELECTION_PREFS)
            .edit()
            .putInt(GLOBAL_KEY, SignPolicy.AUTO.ordinal)
            .commit()

        val prefs = SignPolicySelectionPrefs(context)

        assertNull(prefs.load(GLOBAL_KEY))
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

        assertNull(prefs.load(GLOBAL_KEY))
        assertEquals(SignPolicySelection.MANUAL, SignPolicyStore(prefs).globalPolicy())
    }

    private companion object {
        const val SELECTION_PREFS = "keep_sign_policy_selection"
        const val LEGACY_PREFS = "keep_sign_policy"
        const val GLOBAL_KEY = SignPolicySelectionPrefs.GLOBAL_POLICY_KEY
    }
}
