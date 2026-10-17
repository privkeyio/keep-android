package io.privkey.keep.nip55

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.storage.KeystoreEncryptedPrefs
import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.ReadablePrefs
import io.privkey.keep.storage.SignPolicySelectionPrefs
import io.privkey.keep.storage.corruptStoredValue
import io.privkey.keep.storage.fallbackNameIn
import io.privkey.keep.storage.rawPrefs
import io.privkey.keep.storage.writeAndFindStoredName
import io.privkey.keep.uniffi.KeepMobileException
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The database passphrase and the audit HMAC secret are each read once and minted when
 * the read finds nothing, so a read that reports an undecryptable key as nothing mints
 * over it. That is not a recovery. Room opens the existing encrypted file with the new
 * passphrase and cannot, since nothing deletes or rebuilds it, and the audit chain would
 * restart with nothing recording that it had. An unreadable key has to fail the open, and
 * so does an absent one over state the key it replaces already protects: the database file
 * for the passphrase, the audit anchor for the secret.
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
        context.deleteDatabase(DB)
        // The legacy lookup the mint sits behind is one-shot, gated by a marker in a file
        // the whole app shares. Only the two this test sets are removed, since clearing
        // the file would re-open migrations other tests have already run.
        context.getSharedPreferences(
            SignPolicySelectionPrefs.MARKER_PREFS_NAME,
            Context.MODE_PRIVATE
        ).edit()
            .remove("${PREFS}_${KEY}_migrated")
            .remove("${PREFS}_${HMAC_KEY}_migrated")
            .commit()
    }

    private fun open() = KeystoreEncryptedPrefs.create(context, PREFS)

    private fun keyFor(prefKey: String = KEY) =
        Nip55Database.getOrCreateKey(context, prefKey, prefsName = PREFS)

    private fun dbKey() = Nip55Database.getOrCreateDbKey(context, prefsName = PREFS, dbName = DB)

    private fun auditSecret() = Nip55Database.getOrCreateAuditSecret(context, prefsName = PREFS)

    private fun stagedDatabase(content: String?): File =
        context.getDatabasePath(DB).apply {
            parentFile?.mkdirs()
            delete()
            if (content != null) writeText(content)
        }

    private fun stageAnchor(count: Long, hash: String) {
        open().edit().putLong(ANCHOR_COUNT, count).putString(ANCHOR_HASH, hash).commit()
    }

    private fun stageUnreadableAnchorCount() {
        open().edit().putString(ANCHOR_HASH, "hashB").commit()
        val storedName = writeAndFindStoredName(context, PREFS) {
            open().edit().putLong(ANCHOR_COUNT, 3L).commit()
        }
        corruptStoredValue(context, PREFS, storedName)
    }

    private fun storeUnreadableKey(prefKey: String = KEY): String {
        val storedName = writeAndFindStoredName(context, PREFS) {
            open().edit().putString(prefKey, Base64.encodeToString(ByteArray(32), Base64.NO_WRAP)).commit()
        }
        corruptStoredValue(context, PREFS, storedName)
        return storedName
    }

    private fun storedValue(storedName: String) = rawPrefs(context, PREFS).getString(storedName, null)

    @Test
    fun a_first_run_mints_a_key_and_reads_the_same_one_back() {
        val minted = keyFor()

        assertEquals(32, minted.size)
        assertArrayEquals(minted, keyFor())
    }

    @Test
    fun a_stored_key_is_returned_rather_than_replaced() {
        val key = ByteArray(32) { it.toByte() }
        val storedName = writeAndFindStoredName(context, PREFS) {
            open().edit().putString(KEY, Base64.encodeToString(key, Base64.NO_WRAP)).commit()
        }
        val stored = storedValue(storedName)

        assertArrayEquals(key, keyFor())

        assertEquals(stored, storedValue(storedName))
    }

    @Test
    fun an_unreadable_key_is_reported_rather_than_minted_over() {
        storeUnreadableKey()

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { keyFor() }
        assertEquals("Stored $KEY could not be read", thrown.msg)
    }

    @Test
    fun an_unreadable_audit_secret_is_reported_rather_than_minted_over() {
        // The same refusal on the other key this mints. Restarting the chain under a new
        // secret leaves every entry written under the old one unverifiable, and nothing
        // in the log saying why.
        storeUnreadableKey(HMAC_KEY)

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { auditSecret() }
        assertEquals("Stored $HMAC_KEY could not be read", thrown.msg)
    }

    @Test
    fun an_absent_audit_secret_over_an_anchored_chain_is_refused() {
        // Minting here restarts the chain under a new secret, which leaves every row
        // written under the old one unverifiable and nothing recording that it changed.
        // The anchor is the evidence that there are such rows: it is advanced after every
        // append, out of reach of whoever deleted the secret.
        stageAnchor(count = 3L, hash = "hashB")

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { auditSecret() }
        assertEquals("No stored $HMAC_KEY for an audit chain that exists", thrown.msg)
        assertEquals(
            "the refusal must not have minted one on its way out",
            PrefRead.Absent,
            open().readString(HMAC_KEY)
        )
    }

    @Test
    fun a_stored_audit_secret_is_returned_over_an_anchored_chain() {
        // The refusal is on the absent branch and must stay there: a count above zero
        // beside a stored secret is the steady state of every install past its first
        // audit row, so a refusal reaching it would throw out of getInstance on every
        // launch. Nothing else pins which branch the refusal sits on.
        val key = ByteArray(32) { (it + 7).toByte() }
        open().edit().putString(HMAC_KEY, Base64.encodeToString(key, Base64.NO_WRAP)).commit()
        stageAnchor(count = 3L, hash = "hashB")

        assertArrayEquals(key, auditSecret())
    }

    @Test
    fun a_stored_passphrase_is_returned_over_a_database_that_exists() {
        // The same branch, on the key whose refusal predates it.
        val key = ByteArray(32) { it.toByte() }
        open().edit().putString(KEY, Base64.encodeToString(key, Base64.NO_WRAP)).commit()
        stagedDatabase("not empty")

        assertArrayEquals(key, dbKey())
    }

    @Test
    fun an_unreadable_anchor_count_refuses_the_audit_secret_mint() {
        // The read has to be three-way for the refusal to hold: a count that will not
        // decrypt reads as zero through the ordinary getter, which is the one anchor
        // state that mints.
        stageUnreadableAnchorCount()

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { auditSecret() }
        assertEquals("No stored $HMAC_KEY for an audit chain that exists", thrown.msg)
    }

    @Test
    fun an_absent_audit_secret_beside_half_an_anchor_is_refused() {
        // Both halves are written in one commit, so deleting only the count is the way
        // past the check above. It is closed by reading both halves, which is what this
        // pins: the count alone reads as an absence here.
        open().edit().putString(ANCHOR_HASH, "hashB").commit()

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { auditSecret() }
        assertEquals("No stored $HMAC_KEY for an audit chain that exists", thrown.msg)
    }

    @Test
    fun an_absent_audit_secret_with_no_anchor_still_mints() {
        // A first run, and an install from before the anchor shipped. Refusing here would
        // close the app on both.
        assertEquals(32, auditSecret().size)
    }

    @Test
    fun an_absent_audit_secret_with_a_zero_anchor_still_mints() {
        // What a sanctioned clear leaves: the table is empty, so a new secret restarts a
        // chain with nothing in it.
        stageAnchor(count = 0L, hash = "")

        assertEquals(32, auditSecret().size)
    }

    @Test
    fun a_key_that_decrypts_but_will_not_decode_is_reported_the_same_way() {
        // Reported as unreadable rather than raising out of the decoder: it is a stored
        // value that cannot be used, which is the case this function refuses on.
        open().edit().putString(KEY, "not base64").commit()

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { keyFor() }
        assertEquals("Stored $KEY could not be read", thrown.msg)
    }

    @Test
    fun a_refused_read_leaves_the_stored_key_in_place() {
        // What the refusal buys: the ciphertext survives, so a restore that brings the
        // Keystore alias back brings the database and the audit chain back with it.
        val storedName = storeUnreadableKey()
        val corrupted = storedValue(storedName)

        runCatching { keyFor() }

        assertEquals(corrupted, storedValue(storedName))
    }

    @Test
    fun an_absent_key_over_a_database_that_exists_is_refused() {
        // Deleting the stored entry produces this, and so does losing a queued write to
        // process death. Minting here replaces the key the existing database was encrypted
        // under, which cannot open it again. Staged at the path production derives, so the
        // refusal is pinned to that path and not to a file of the test's choosing.
        stagedDatabase("not empty")

        val thrown = assertThrows(KeepMobileException.StorageException::class.java) { dbKey() }
        assertEquals("No stored $KEY for a database that exists", thrown.msg)
        assertEquals("the refusal must not have minted one on its way out", PrefRead.Absent, open().readString(KEY))
    }

    @Test
    fun a_minted_key_that_could_not_be_stored_is_reported_rather_than_returned() {
        // Returning it would have the database created under a key nothing stored, which
        // is exactly the state the refusal above turns into a permanent one.
        val thrown = assertThrows(KeepMobileException.StorageException::class.java) {
            Nip55Database.getOrCreateKey(context, KEY, prefsName = PREFS, prefs = FailingCommitPrefs(open()))
        }
        assertEquals("Minted $KEY could not be stored", thrown.msg)
    }

    @Test
    fun an_absent_key_with_no_database_still_mints() {
        stagedDatabase(null)

        assertEquals(32, dbKey().size)
    }

    @Test
    fun an_absent_key_with_an_empty_database_file_still_mints() {
        // The state a first run can legitimately leave behind, which the next test pins.
        // An empty file holds nothing, so refusing here would break a genuine first run.
        stagedDatabase("")

        assertEquals(32, dbKey().size)
    }

    @Test
    fun room_writes_nothing_to_the_file_until_the_database_is_first_used() {
        // The premise the refusal keys on. If building the database wrote a header, then a
        // launch that built it and died before storing the key would look like a database
        // that exists, and the refusal would brick a first run instead of saving one.
        val path = context.getDatabasePath(DB)
        val db = Room.databaseBuilder(context, Nip55Database::class.java, DB)
            .openHelperFactory(SupportOpenHelperFactory(ByteArray(32)))
            .build()
        try {
            assertFalse("a built database nothing has used has no file at all", path.exists())

            db.openHelper.writableDatabase

            assertTrue("first use is what creates the file", path.length() > 0L)
        } finally {
            db.close()
        }
    }

    /** Preferences whose writes report failure, which a full disk produces. */
    private class FailingCommitPrefs(private val delegate: ReadablePrefs) : ReadablePrefs by delegate {
        override fun edit(): SharedPreferences.Editor = FailingEditor(delegate.edit())

        private class FailingEditor(private val delegate: SharedPreferences.Editor) :
            SharedPreferences.Editor by delegate {
            // Returns itself rather than the delegate, or the chained commit would be the
            // real one and the staged failure would never be reached.
            override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                delegate.putString(key, value)
                return this
            }

            override fun commit(): Boolean = false
        }
    }

    // A value this store will not read as the passphrase's, at a name derived
    // from constants in the build, used to read as a positive absence and was
    // overwritten by the mint. Once a refusal reports itself unreadable, raising
    // on that read would brick an install with nothing worth protecting, so the
    // mint refusal decides: nothing on disk to lose, so mint, and the write
    // sweeps what could not be read.
    @Test
    fun an_unreadable_passphrase_still_mints_when_there_is_nothing_to_lose() {
        val planted = fallbackNameIn(PREFS, KEY)
        rawPrefs(context, PREFS).edit().putString(planted, "not a value this can read").commit()

        // A database name nothing has created, so the mint refusal has nothing
        // to refuse over.
        val key = Nip55Database.getOrCreateDbKey(context, prefsName = PREFS, dbName = "never_created.db")

        assertEquals("a minted passphrase is 32 bytes", 32, key.size)
        assertFalse("and the write sweeps what it could not read", rawPrefs(context, PREFS).contains(planted))
    }

    private companion object {
        const val PREFS = "database_key_mint_test"
        const val DB = "database_key_mint_test.db"
        const val KEY = "db_passphrase"
        const val HMAC_KEY = "hmac_secret"
        const val ANCHOR_COUNT = "audit_anchor_count"
        const val ANCHOR_HASH = "audit_anchor_hash"
    }
}
