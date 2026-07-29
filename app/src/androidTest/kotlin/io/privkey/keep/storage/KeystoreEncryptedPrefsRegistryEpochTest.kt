package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The key registry can itself be left under the previous derivation epoch, and
 * that is worse than an ordinary entry being stranded.
 *
 * The migration away from that epoch runs only while no derivation key is
 * persisted, so a registry written during a later fallback window keeps the old
 * name for good. A fold that resolves only the current name then reads nothing,
 * so every key disappears from enumeration, and the next write rewrites the
 * registry from a cache holding just the keys that write touched. The rest are
 * dropped from it permanently, which is silent: direct lookups still work, so
 * nothing surfaces until something enumerates or the re-hash migration runs.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsRegistryEpochTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun raw() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun open() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    /** Mirrors the store's fallback derivation so a test can name the registry the way that epoch would. */
    private fun fallbackRegistryName(): String {
        val key = MessageDigest.getInstance("SHA-256")
            .digest("$DETERMINISTIC_SEED:$PREFS_NAME".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return Base64.encodeToString(
            mac.doFinal(KEY_REGISTRY.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP or Base64.URL_SAFE
        )
    }

    /**
     * Writes two keys, then moves the registry entry to the name the fallback
     * epoch would have used.
     *
     * The registry cannot be identified by name from a test, because the
     * derivation key is per-file and secret. It is identified by behaviour
     * instead: it is the one pre-existing entry whose stored value changes when
     * an unrelated key is added, since every commit rewrites the key list while
     * the other values stay byte-identical.
     */
    private fun strandTheRegistry() {
        open().edit().putString("alpha", "1").commit()
        val before = raw().all.mapValues { it.value as String }

        open().edit().putString("beta", "2").commit()
        val after = raw().all.mapValues { it.value as String }

        val changed = before.keys.filter { after[it] != null && after[it] != before[it] }
        assertEquals("expected exactly one rewritten entry, the registry", 1, changed.size)

        val registryName = changed.first()
        val registryValue = after.getValue(registryName)
        raw().edit().remove(registryName).putString(fallbackRegistryName(), registryValue).commit()
    }

    @Test
    fun aRegistryLeftUnderTheFallbackEpochStillEnumeratesEveryKey() {
        strandTheRegistry()

        val visible = open().all.keys
        assertTrue("alpha must still be enumerable", visible.contains("alpha"))
        assertTrue("beta must still be enumerable", visible.contains("beta"))
    }

    @Test
    fun aWriteAgainstAStrandedRegistryDoesNotDropUntouchedKeys() {
        // The damaging path: the fold reads nothing, so a write rewrites the key
        // list from a cache that only knows the key it just wrote.
        strandTheRegistry()

        open().edit().putString("gamma", "3").commit()

        val visible = open().all.keys
        assertTrue("alpha must survive a write made against a stranded registry", visible.contains("alpha"))
        assertTrue("beta must survive a write made against a stranded registry", visible.contains("beta"))
        assertTrue(visible.contains("gamma"))
    }

    @Test
    fun valuesRemainReadableAfterTheRegistryIsRecovered() {
        strandTheRegistry()

        val reopened = open()
        assertEquals("1", reopened.getString("alpha", null))
        assertEquals("2", reopened.getString("beta", null))
    }

    @Test
    fun theStrandedRegistryCopyIsDroppedOnceTheCurrentOneIsWritten() {
        strandTheRegistry()
        assertTrue("precondition: the stranded copy exists", raw().contains(fallbackRegistryName()))

        open().edit().putString("gamma", "3").commit()

        assertTrue(
            "a stale key list must not linger for the read path to fall back to",
            !raw().contains(fallbackRegistryName())
        )
        val visible = open().all.keys
        assertTrue(visible.contains("alpha"))
        assertTrue(visible.contains("gamma"))
    }

    companion object {
        private const val PREFS_NAME = "keystore_prefs_registry_epoch_test"
        private const val DETERMINISTIC_SEED = "keystore_prefs_hmac_key"
        private const val KEY_REGISTRY = "__keys__"
    }
}
