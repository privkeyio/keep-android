package io.privkey.keep.nip55

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.rawPrefs
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.uniffi.KeepMobileException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The database passphrase and the audit HMAC secret are each read once and minted when
 * the read finds nothing, so a read that reports an undecryptable key as nothing mints
 * over it. That is not a recovery. Room opens the existing encrypted file with the new
 * passphrase and cannot, since nothing deletes or rebuilds it, and the audit chain would
 * restart with nothing recording that it had. An unreadable key has to fail the open.
 *
 * Staged in prefs of their own: the fault has to be written to disk, and the file the
 * production path uses is the one much of this suite depends on.
 */
@RunWith(AndroidJUnit4::class)
class DatabaseKeyMintTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = clear()
    @After fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS)
        // The legacy lookup leaves a marker keyed by the prefs name, and a marker left
        // behind would skip the migration branch the mint sits behind.
        context.deleteSharedPreferences("keep_migration_markers")
    }

    private fun open() = KeystoreEncryptedPrefs.create(context, PREFS)

    private fun keyFor(prefs: io.privkey.keep.storage.ReadablePrefs) =
        Nip55Database.getOrCreateKey(context, KEY, commit = true, prefsName = PREFS, prefs = prefs)

    private fun storeUnreadableKey(): String {
        val storedName = writeAndFindStoredName(context, PREFS) {
            open().edit().putString(KEY, Base64.encodeToString(ByteArray(32), Base64.NO_WRAP)).commit()
        }
        corruptStoredValue(context, PREFS, storedName)
        return storedName
    }

    @Test
    fun a_first_run_mints_a_key_and_reads_the_same_one_back() {
        val minted = keyFor(open())

        assertEquals(32, minted.size)
        assertArrayEquals(minted, keyFor(open()))
    }

    @Test
    fun a_stored_key_is_returned_rather_than_replaced() {
        val key = ByteArray(32) { it.toByte() }
        open().edit().putString(KEY, Base64.encodeToString(key, Base64.NO_WRAP)).commit()

        assertArrayEquals(key, keyFor(open()))
    }

    @Test
    fun an_unreadable_key_is_reported_rather_than_minted_over() {
        storeUnreadableKey()

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { keyFor(open()) }
        assertEquals("Stored $KEY could not be read", thrown.msg)
    }

    @Test
    fun a_refused_read_leaves_the_stored_key_in_place() {
        // What the refusal buys: the ciphertext survives, so a restore that brings the
        // Keystore alias back brings the database and the audit chain back with it.
        val storedName = storeUnreadableKey()
        val corrupted = rawPrefs(context, PREFS).getString(storedName, null)

        runCatching { keyFor(open()) }

        assertEquals(corrupted, rawPrefs(context, PREFS).getString(storedName, null))
    }

    private companion object {
        const val PREFS = "database_key_mint_test"
        const val KEY = "db_passphrase"
    }
}
