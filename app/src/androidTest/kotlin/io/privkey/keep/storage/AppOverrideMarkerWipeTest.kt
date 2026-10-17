package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.room.Room
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The account-switch wipe exists so nothing of the previous identity survives
 * it. The per-package override markers did: one key per package that identity
 * had pinned a sign policy for, in a plaintext file, which is a record of which
 * apps it used and how many. The digest over the package name is obfuscation
 * and not confidentiality, so it is no answer to that.
 *
 * The migration sweeps those markers itself once a run completes, so ordinarily
 * the file holds none. What the wipe has to deal with is the install whose run
 * never completes, because it still holds a row the sweep could not clear, and
 * so keeps its markers indefinitely.
 *
 * The run-wide markers must survive the wipe, which is the other half of this:
 * clearing them would let the legacy copies run again on the next launch and
 * bring the previous account's choices back with them.
 */
@RunWith(AndroidJUnit4::class)
class AppOverrideMarkerWipeTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun markers() = context.getSharedPreferences(
        SignPolicySelectionPrefs.MARKER_PREFS_NAME,
        Context.MODE_PRIVATE
    )

    @After
    fun removeWhatThisStaged() {
        // The marker file is shared with the other migrations, so only the keys
        // this test wrote go, never the file.
        markers().edit()
            .remove(SignPolicySelectionPrefs.appOverrideMarkerKey(PINNED))
            .remove(SignPolicySelectionPrefs.appOverrideMarkerKey(ALSO_PINNED))
            .remove(UNRELATED_MARKER)
            .commit()
    }

    @Test
    fun theWipeDropsEveryPerPackageMarkerAndKeepsTheRunWideOnes() {
        val pinned = SignPolicySelectionPrefs.appOverrideMarkerKey(PINNED)
        val alsoPinned = SignPolicySelectionPrefs.appOverrideMarkerKey(ALSO_PINNED)
        val runWide = SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER
        markers().edit()
            .putBoolean(pinned, true)
            .putBoolean(alsoPinned, true)
            .putBoolean(runWide, true)
            .putBoolean(UNRELATED_MARKER, true)
            .commit()

        // Through the wipe itself, with its own database, so what is exercised is
        // the step in the account switch rather than a helper beside it.
        val database = Room.inMemoryDatabaseBuilder(context, Nip55Database::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            runBlocking { PermissionStore(database).clearAllAppSettings(null, markers()) }
        } finally {
            database.close()
        }

        assertFalse("a pinned package must not be recoverable from the file", markers().contains(pinned))
        assertFalse("nor any other", markers().contains(alsoPinned))
        assertTrue(
            "the run-wide marker must stay, or the legacy copies run again for the new account",
            markers().getBoolean(runWide, false)
        )
        assertTrue(
            "and the file's other migrations must be left alone",
            markers().getBoolean(UNRELATED_MARKER, false)
        )
    }

    private companion object {
        const val PINNED = "com.example.pinned.app"
        const val ALSO_PINNED = "com.example.other.pinned.app"
        // Stands in for the other migrations that share this file, whose keys are
        // built from a prefs file name rather than from the override prefix.
        const val UNRELATED_MARKER = "keep_migrated_some_other_prefs"
    }
}
