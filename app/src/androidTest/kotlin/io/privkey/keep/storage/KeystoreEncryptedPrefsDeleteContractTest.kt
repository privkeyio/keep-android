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
 * A lookup here resolves forward from the plaintext key, hashing it under the
 * current derivation key and under the deterministic fallback epoch, so a miss
 * is conclusive while this store holds the key the names on disk were derived
 * with. The state where it is not is a file that already held entries when the
 * key in use was minted: their names were derived with a key that is gone, so
 * nothing can compute where they live, and a rollback of this file is what
 * produces it, the same rollback that can later bring the old key back.
 *
 * These tests stage that by removing the stored derivation key out from under
 * entries written with it, and pin the three outcomes: a miss in that state is
 * refused, a miss in a store whose key accounts for its entries is a successful
 * delete, and an entry that is found is deleted and reported either way.
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

    private fun raw() = rawPrefs(context, PREFS_NAME)

    /**
     * Writes an entry, then takes the store's derivation key away from it.
     *
     * The entry stays exactly where it was, at a name hashed with the key that
     * is now gone. The next instance finds no key to load, mints a fresh one,
     * and can no longer compute that name, which is the state a rollback of this
     * file leaves behind: the values from before it, none of the key material
     * written since.
     */
    private fun strandEntriesUnderALostKey() {
        reopen().edit().putString(KEPT_KEY, "1").commit()
        assertTrue("the store must have persisted a derivation key", raw().contains(HMAC_KEY_PREF))
        raw().edit().remove(HMAC_KEY_PREF).commit()
    }

    // The case the contract is about: nothing answered the lookup, and this file
    // holds entries whose names were derived with a key it no longer has, so a
    // miss does not establish absence and the delete must not claim it.
    @Test
    fun aRemovalThatFoundNothingIsRefusedWhileEntriesPredateTheKey() {
        strandEntriesUnderALostKey()

        assertFalse(
            "a removal that could not determine absence must not report success",
            reopen().edit().remove("never_written").commit()
        )
    }

    // The stranded entry itself is the one the contract is protecting: its name
    // cannot be computed any more, so the delete that would have removed it
    // reports failure rather than reporting it gone while it waits on disk for
    // the key to come back.
    @Test
    fun aRemovalOfAStrandedEntryIsRefusedRatherThanReportedGone() {
        strandEntriesUnderALostKey()

        assertFalse(
            "an entry at an uncomputable name must not be reported deleted",
            reopen().edit().remove(KEPT_KEY).commit()
        )
        assertTrue("and it is still on disk", raw().all.keys.any { it != HMAC_KEY_PREF })
    }

    // The baseline the refusal must not swallow: a store whose key accounts for
    // what it holds resolves names conclusively, so a key that was never written
    // is genuinely absent and deleting it succeeds.
    @Test
    fun aRemovalOfAKeyThatWasNeverWrittenSucceedsWhileTheKeyAccountsForTheEntries() {
        reopen().edit().putString(KEPT_KEY, "1").commit()

        assertTrue(
            "absence established under the store's own key is a successful delete",
            reopen().edit().remove("never_written").commit()
        )
    }

    // A found entry is deleted and reported deleted, which is what keeps the
    // refusal from being a blanket failure on a faulted store.
    @Test
    fun aRemovalThatFoundTheEntryStillSucceeds() {
        reopen().edit().putString(KEPT_KEY, "1").commit()

        assertTrue("a removal that found its entry must report success", reopen().edit().remove(KEPT_KEY).commit())
        assertNull("the entry must be gone", reopen().getString(KEPT_KEY, null))
    }

    // The refusal has to outlive the instance that noticed: the open that mints
    // a key over stranded entries is rarely the one a later delete runs on, and
    // a restart that forgot would certify absence over the same entries.
    @Test
    fun theRefusalSurvivesTheInstanceThatNoticed() {
        strandEntriesUnderALostKey()
        // The mint happens here, in an instance that is then discarded.
        assertFalse(reopen().edit().remove("never_written").commit())

        assertFalse(
            "a later instance, reading a key that is now its own, must still refuse",
            reopen().edit().remove("never_written").commit()
        )
        assertFalse(
            "and must still refuse for the stranded entry itself",
            reopen().edit().remove(KEPT_KEY).commit()
        )
    }

    // Recovery: a clear takes the stranded entries with everything else, so the
    // store certifies again rather than refusing every later delete.
    @Test
    fun aClearRecoversTheStoreFromStrandedEntries() {
        strandEntriesUnderALostKey()

        assertTrue("a clear must not be held back by what it wipes", reopen().edit().clear().commit())
        assertTrue(
            "deletes must certify again once the stranded entries are gone",
            reopen().edit().remove("never_written").commit()
        )
    }

    // An unreadable registry is not this condition and must not be read as it.
    // The registry lists plain key names, which is less than a caller passes to
    // remove(), and a lookup never consults it; refusing on it would fail deletes
    // that did establish absence. It is also the copy an attacker can write: the
    // fallback registry's name is derivable from the APK and nothing drops a copy
    // it cannot decode, so a guard there would latch on one planted value.
    @Test
    fun anUnreadableRegistryDoesNotRefuseARemoval() {
        val prefs = reopen()
        prefs.edit().putString(KEPT_KEY, "1").commit()
        val before = raw().all.toMap()
        prefs.edit().putString("beta", "2").commit()
        // The registry cannot be named from here: it is stored under a hash of
        // the per-file derivation key. What identifies it is being the one entry
        // a commit rewrites rather than adds.
        val rewritten = raw().all.toMap().let { after -> before.keys.filter { after[it] != before[it] } }
        assertEquals("expected exactly one rewritten entry, the registry: $rewritten", 1, rewritten.size)
        corruptStoredValue(context, PREFS_NAME, rewritten.first())

        assertTrue(
            "an unreadable index must not fail a delete the lookup could settle",
            reopen().edit().remove("never_written").commit()
        )
    }

    private companion object {
        const val PREFS_NAME = "delete_contract_test_prefs"
        const val KEPT_KEY = "alpha"

        /** The one entry this store keeps under its literal name. */
        const val HMAC_KEY_PREF = "__hmac_key__"
    }
}
