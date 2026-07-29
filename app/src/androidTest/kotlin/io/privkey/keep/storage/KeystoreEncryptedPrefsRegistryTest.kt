package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The key registry lists every plaintext key the store holds. It is rewritten
 * from an in-memory cache on each commit, and that cache only contains keys the
 * current instance has touched, so a write performed after a restart must not be
 * allowed to drop the rest.
 *
 * This matters beyond tidiness: entries missing from the registry stay on disk
 * but become invisible to [android.content.SharedPreferences.getAll] and to the
 * migration that re-hashes keys after a derivation-key change, which only visits
 * registry-listed keys. For the signer's rate-limiter store that turns a
 * package's recorded usage into "no usage yet".
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsRegistryTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    /** A fresh wrapper over the same file, standing in for a process restart. */
    private fun reopen() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    @Test
    fun aWriteFromAFreshInstanceKeepsEntriesItNeverTouched() {
        val first = reopen()
        first.edit().putString("alpha", "1").commit()
        first.edit().putString("beta", "2").commit()

        // A new instance writes a third key without ever reading the first two,
        // so its cache holds only "gamma" when the registry is rewritten.
        val second = reopen()
        second.edit().putString("gamma", "3").commit()

        val visible = reopen().all.keys
        assertTrue("alpha must survive a write that never touched it", visible.contains("alpha"))
        assertTrue("beta must survive a write that never touched it", visible.contains("beta"))
        assertTrue(visible.contains("gamma"))
    }

    @Test
    fun untouchedEntriesRemainReadableAfterAnUnrelatedWrite() {
        reopen().edit().putString("alpha", "1").commit()

        val second = reopen()
        second.edit().putString("beta", "2").commit()

        val reopened = reopen()
        assertEquals("1", reopened.getString("alpha", null))
        assertEquals("2", reopened.getString("beta", null))
    }

    @Test
    fun clearStillEmptiesTheRegistry() {
        val prefs = reopen()
        prefs.edit().putString("alpha", "1").commit()
        prefs.edit().putString("beta", "2").commit()

        // Seeding must not resurrect keys a clear removed.
        reopen().edit().clear().commit()

        assertTrue(reopen().all.keys.isEmpty())
    }

    @Test
    fun aRemovedKeyIsNotResurrectedBySeeding() {
        reopen().edit().putString("alpha", "1").commit()
        reopen().edit().putString("beta", "2").commit()

        // Fresh instance: the removal is applied against a cache seeded from the
        // registry, so the key must not reappear when the registry is rewritten.
        reopen().edit().remove("alpha").commit()

        val visible = reopen().all.keys
        assertTrue("removed key must stay removed", !visible.contains("alpha"))
        assertTrue(visible.contains("beta"))
    }

    @Test
    fun concurrentWritersDoNotDropEachOthersKeys() {
        // Two writers racing on one instance. Each snapshots the shared cache to
        // rewrite the registry, so without serialising the commit the later one
        // can persist a registry that predates the other's key, stranding it.
        val prefs = reopen()
        val threads = (0 until 8).map { i ->
            Thread { prefs.edit().putString("key$i", "v$i").commit() }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val visible = reopen().all.keys
        for (i in 0 until 8) {
            assertTrue("key$i must survive concurrent writers", visible.contains("key$i"))
        }
    }

    @Test
    fun aSecondInstanceWritingConcurrentlyDoesNotTruncateTheRegistry() {
        // Separate wrappers over the same file, each seeding independently.
        reopen().edit().putString("existing", "1").commit()

        val a = reopen()
        val b = reopen()
        val t1 = Thread { a.edit().putString("fromA", "2").commit() }
        val t2 = Thread { b.edit().putString("fromB", "3").commit() }
        t1.start(); t2.start(); t1.join(); t2.join()

        val visible = reopen().all.keys
        assertTrue("pre-existing key must survive", visible.contains("existing"))
        assertTrue(visible.contains("fromA"))
        assertTrue(visible.contains("fromB"))
    }

    companion object {
        private const val PREFS_NAME = "keystore_prefs_registry_test"
    }
}
