package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The delete contract the core states for these stores: a key genuinely absent
 * from the durable store is a successful delete, a lookup that could not
 * determine absence is not. An implementation that reports "I cannot see it" as
 * "it is gone" leaves a live entry on disk that becomes enforceable again the
 * moment lookup recovers, which for the rate limiter is a cooling-off the user
 * was told had been cleared.
 *
 * Names here are resolved through a registry this store keeps encrypted beside
 * the values, so the case the editor cannot answer on its own is a registry it
 * could not read. These tests stage exactly that, by flipping a byte of the
 * registry's ciphertext so it fails its GCM tag check the way a lost Keystore
 * alias would, and pin all three outcomes: uncertified absence reports false,
 * an entry that was found is still deleted and reports true, and a readable
 * registry still certifies absence.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsDeleteContractTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    // Block body on purpose: an expression body returns the delete's Boolean,
    // which makes the @Before/@After methods non-void and JUnit refuses to
    // instantiate the class at all.
    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun reopen() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    /**
     * Seeds two keys and returns the registry's stored name.
     *
     * A test cannot name the registry: it is stored under a hash of a per-file
     * derivation key it has no access to. What identifies it is being the one
     * entry a commit rewrites rather than adds, since every commit writes the
     * updated key list back.
     */
    private fun seedAndFindRegistryName(): String {
        val prefs = reopen()
        prefs.edit().putString(KEPT_KEY, "1").commit()
        val before = rawPrefs(context, PREFS_NAME).all.toMap()
        prefs.edit().putString("beta", "2").commit()
        val after = rawPrefs(context, PREFS_NAME).all.toMap()

        val rewritten = before.keys.filter { after[it] != before[it] }
        assertEquals("expected exactly one rewritten entry, the registry: $rewritten", 1, rewritten.size)
        return rewritten.first()
    }

    // The case the contract is about: nothing answered the lookup, and the index
    // that says what this file holds could not be read, so absence was never
    // established and the delete must not claim it.
    @Test
    fun aRemovalThatFoundNothingIsRefusedWhileTheRegistryIsUnreadable() {
        corruptStoredValue(context, PREFS_NAME, seedAndFindRegistryName())

        assertFalse(
            "a removal that could not determine absence must not report success",
            reopen().edit().remove("never_written").commit()
        )
    }

    // The same unreadable registry must not fail a delete that did resolve: the
    // entry was found and dropped, so the deletion reached the durable store and
    // the index was not needed to establish it.
    @Test
    fun aRemovalThatFoundTheEntryStillSucceedsWhileTheRegistryIsUnreadable() {
        corruptStoredValue(context, PREFS_NAME, seedAndFindRegistryName())

        val prefs = reopen()
        assertTrue(
            "a removal that found its entry must still report success",
            prefs.edit().remove(KEPT_KEY).commit()
        )
        assertNull("the entry must be gone", reopen().getString(KEPT_KEY, null))
    }

    // The baseline the refusal must not swallow: with the registry readable, a
    // key that was never written is genuinely absent and deleting it succeeds.
    @Test
    fun aRemovalOfAKeyThatWasNeverWrittenSucceedsWhileTheRegistryIsReadable() {
        seedAndFindRegistryName()

        assertTrue(
            "absence established against a readable registry is a successful delete",
            reopen().edit().remove("never_written").commit()
        )
    }

    // A clear is the recovery path: it removes the unreadable registry with
    // everything else, so it reports success and leaves the store certifying
    // again rather than refusing every later delete.
    @Test
    fun aClearRecoversTheStoreFromAnUnreadableRegistry() {
        corruptStoredValue(context, PREFS_NAME, seedAndFindRegistryName())

        assertTrue("a clear must not be held back by the registry it wipes", reopen().edit().clear().commit())
        assertTrue(
            "deletes must certify again once the unreadable registry is gone",
            reopen().edit().remove("never_written").commit()
        )
    }

    private companion object {
        const val PREFS_NAME = "delete_contract_test_prefs"
        const val KEPT_KEY = "alpha"
    }
}
