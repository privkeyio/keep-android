package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.KeepMobileApp
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The account-switch wipe exists so nothing of the previous identity survives
 * it. The per-package override markers did: one key per package that identity
 * had pinned a sign policy for, in a plaintext file, which is a record of which
 * applications it used and how many. The digest over the package name is
 * obfuscation and not confidentiality, so it is no answer to that.
 *
 * The migration sweeps those markers itself once a run completes, so ordinarily
 * the file holds none. What the wipe has to deal with is the install whose run
 * never completes, because it still holds a row the sweep could not clear, and
 * which therefore keeps its markers indefinitely.
 *
 * Clearing them alone would not be safe, which is the other half of this. A
 * per-package marker is also what stops the migration copying that row's tier
 * into the core, so a row whose clear failed earlier in the wipe would be copied
 * on the next launch and the new account would inherit the previous account's
 * tier. So the wipe sets the run-wide marker in the same commit, retiring the
 * migration, and never clears a run-wide marker, since a cleared one reopens a
 * legacy copy for the next account.
 *
 * Driven against a file of this test's own rather than the shared one the app
 * uses. That is not only hygiene: this app runs the override migration at
 * startup, and on a fresh install that migration commits the very same sweep
 * against the real file, so a test pointed there could pass with the production
 * sweep deleted. The one thing a private file cannot cover is that the call
 * site passes the real file name, which is a single literal read at the call
 * site, as the other steps of that wipe are.
 */
@RunWith(AndroidJUnit4::class)
class AppOverrideMarkerWipeTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private fun app(): KeepMobileApp = context.applicationContext as KeepMobileApp

    private fun markers() = context.getSharedPreferences(TEST_MARKER_PREFS, Context.MODE_PRIVATE)

    @Before
    fun startClean() = context.deleteSharedPreferences(TEST_MARKER_PREFS).let { }

    @After
    fun removeTheTestFile() = context.deleteSharedPreferences(TEST_MARKER_PREFS).let { }

    @Test
    fun theWipeDropsEveryPerPackageMarkerAndKeepsTheRunWideOnes() {
        val pinned = SignPolicySelectionPrefs.appOverrideMarkerKey(PINNED)
        val alsoPinned = SignPolicySelectionPrefs.appOverrideMarkerKey(ALSO_PINNED)
        val runWide = SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER
        // Staged without the run-wide marker, which is the state this exists for:
        // a run that never completed, so the migration is still live.
        assertTrue(
            "the staging write has to land, or the assertions below pass on an empty file",
            markers().edit()
                .putBoolean(pinned, true)
                .putBoolean(alsoPinned, true)
                .putBoolean(UNRELATED_MARKER, true)
                .commit()
        )
        assertFalse("precondition: the migration is still live", markers().getBoolean(runWide, false))
        assertTrue("precondition: the pinned package is recoverable before the wipe", markers().contains(pinned))

        app().clearAppOverrideMarkers(markers())

        assertFalse("a pinned package must not be recoverable from the file", markers().contains(pinned))
        assertFalse("nor any other", markers().contains(alsoPinned))
        assertTrue(
            "the migration must be retired, or a row whose clear failed is copied forward",
            markers().getBoolean(runWide, false)
        )
        assertTrue(
            "and the file's other migrations must be left alone",
            markers().getBoolean(UNRELATED_MARKER, false)
        )
    }

    // The reason the retirement is in the same commit: a row whose clear failed
    // keeps the previous account's tier, and its marker is the only thing that
    // stops the next launch copying that tier into the core, where the row and
    // the core would then agree on it. Dropping the marker without retiring the
    // migration is what opens that, so the two must not be separable.
    @Test
    fun theMigrationIsRetiredInTheSameCommitThatDropsTheMarkers() {
        val pinned = SignPolicySelectionPrefs.appOverrideMarkerKey(PINNED)
        assertTrue(markers().edit().putBoolean(pinned, true).commit())

        app().clearAppOverrideMarkers(markers())

        val runWide = markers().getBoolean(SignPolicySelectionPrefs.APP_OVERRIDE_MIGRATION_MARKER, false)
        val markerGone = !markers().contains(pinned)
        assertTrue(
            "the marker went without the migration being retired, which is the unsafe half alone",
            !markerGone || runWide
        )
        assertTrue("and both halves must actually have happened", markerGone && runWide)
    }

    private companion object {
        const val TEST_MARKER_PREFS = "test_override_marker_wipe"
        const val PINNED = "com.example.pinned.app"
        const val ALSO_PINNED = "com.example.other.pinned.app"
        // Shaped like the keys LegacyPrefsMigration puts in this file, which are
        // built from a prefs file name rather than from the override prefix.
        const val UNRELATED_MARKER = "some_other_prefs_some_key_migrated"
    }
}
