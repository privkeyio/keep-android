package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Moving a file off the derivation key a build in the v0.6.0 window persisted.
 *
 * That key is a constant anyone can compute, so every name in such a file is
 * derivable. Staged here the way such a file came to exist: the key is in
 * place before any entry, so entries and the index sit at names derived from it.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsRotationTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun reopen() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    private fun raw() = rawPrefs(context, PREFS_NAME)

    private fun keystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return keyStore.getKey(KEY_ALIAS_PREFIX + PREFS_NAME, null) as SecretKey
    }

    private fun boundValue(plaintext: String, aad: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val body = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return BOUND_PREFIX + Base64.encodeToString(cipher.iv + body, Base64.NO_WRAP)
    }

    private fun legacyValue(plaintext: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val body = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + body, Base64.NO_WRAP)
    }

    /** Puts the published key in place, so the instances opened next resolve it and write under it. */
    private fun carryThePublishedKey() {
        reopen()
        val encoded = Base64.encodeToString(publishedGlobalKey(), Base64.NO_WRAP)
        raw().edit().putString(HMAC_KEY_PREF, boundValue(encoded, HMAC_KEY_PREF)).commit()
    }

    private fun stageFileOnThePublishedKey() {
        carryThePublishedKey()
        assertTrue(reopen().edit().putBoolean(VICTIM, true).putString(SETTING, "kept").commit())
        assertTrue("staging must leave the index at the published name", raw().contains(globalEpochNameOf(KEY_REGISTRY)))
        assertTrue(raw().contains(globalEpochNameOf(VICTIM)))
    }

    @Test
    fun aFileOnThePublishedKeyMovesOffItWithItsEntries() {
        stageFileOnThePublishedKey()
        val before = raw().getString(HMAC_KEY_PREF, null)

        val prefs = reopen()
        assertTrue(prefs.getBoolean(VICTIM, false))
        assertEquals("kept", prefs.getString(SETTING, null))

        assertNotEquals("the file must carry a new key", before, raw().getString(HMAC_KEY_PREF, null))
        for (name in listOf(VICTIM, SETTING, KEY_REGISTRY)) {
            assertFalse("$name must not stay at a name derived from the published key", raw().contains(globalEpochNameOf(name)))
        }
        val again = reopen()
        assertTrue("the move must persist", again.getBoolean(VICTIM, false))
        assertEquals(mapOf(VICTIM to true, SETTING to "kept"), again.all)
    }

    // A value planted at a derivable name for a key the index does not list was
    // refused before the move. It must not land on a name the store trusts.
    @Test
    fun aValuePlantedBeforeTheMoveIsNotCarriedAcross() {
        stageFileOnThePublishedKey()
        raw().edit().putString(globalEpochNameOf(ATTACKER), legacyValue("b:true")).commit()

        val prefs = reopen()
        assertEquals(PrefRead.Absent, prefs.readBoolean(ATTACKER))
        assertFalse(prefs.getBoolean(ATTACKER, false))
        assertTrue("a delete of it must now certify", prefs.edit().remove(ATTACKER).commit())
    }

    // A listed value that will not decrypt is carried across as it is, so it
    // still reads unreadable rather than absent, and a delete still clears it.
    @Test
    fun aListedValueThatWillNotDecryptBecomesClearable() {
        stageFileOnThePublishedKey()
        corruptStoredValue(context, PREFS_NAME, globalEpochNameOf(VICTIM))

        val prefs = reopen()
        assertEquals(PrefRead.Unreadable, prefs.readBoolean(VICTIM))
        assertTrue("the delete must certify", prefs.edit().remove(VICTIM).commit())
        assertEquals(PrefRead.Absent, reopen().readBoolean(VICTIM))
    }

    @Test
    fun theMoveWaitsWhileTheIndexCannotBeRead() {
        stageFileOnThePublishedKey()
        corruptStoredValue(context, PREFS_NAME, globalEpochNameOf(KEY_REGISTRY))
        val before = raw().getString(HMAC_KEY_PREF, null)

        val prefs = reopen()
        assertTrue("a bound value still reads", prefs.getBoolean(VICTIM, false))
        assertEquals("the key must stay", before, raw().getString(HMAC_KEY_PREF, null))
        assertTrue(raw().contains(globalEpochNameOf(VICTIM)))
    }

    // A bound value is read at a derivable name whether or not the index lists
    // it, so moving past an unlisted one would strand a value read today.
    @Test
    fun theMoveWaitsWhileABoundValueIsUnlisted() {
        stageFileOnThePublishedKey()
        raw().edit().putString(globalEpochNameOf(UNLISTED), boundValue("b:true", UNLISTED)).commit()
        val before = raw().getString(HMAC_KEY_PREF, null)

        val prefs = reopen()
        assertTrue("the unlisted value must still read", prefs.getBoolean(UNLISTED, false))
        assertTrue(prefs.getBoolean(VICTIM, false))
        assertEquals("the key must stay", before, raw().getString(HMAC_KEY_PREF, null))
    }

    // A non-String where the index belongs stops the move rather than the store.
    @Test
    fun aNonStringAtTheIndexNameStopsOnlyTheMove() {
        stageFileOnThePublishedKey()
        raw().edit().putInt(globalEpochNameOf(KEY_REGISTRY), 1).commit()
        val before = raw().getString(HMAC_KEY_PREF, null)

        assertTrue(reopen().getBoolean(VICTIM, false))
        assertEquals(before, raw().getString(HMAC_KEY_PREF, null))
    }

    // An instance that resolved the published key before another one moved the
    // file must follow the move, or its writes land at names nothing computes.
    @Test
    fun anInstanceOpenedBeforeTheMoveFollowsIt() {
        carryThePublishedKey()
        val early = reopen()
        assertTrue(early.edit().putBoolean(VICTIM, true).commit())

        assertTrue(reopen().getBoolean(VICTIM, false))
        assertFalse("the move must have happened", raw().contains(globalEpochNameOf(VICTIM)))

        // A key this instance already has a cached name for, which is the write
        // that never reaches a hash on its own.
        assertTrue(early.edit().putBoolean(VICTIM, false).commit())
        assertFalse("a cached write must land where the next open looks", reopen().getBoolean(VICTIM, true))

        assertTrue(early.edit().putString(SETTING, "late").commit())
        assertEquals(
            "and the index must still list every key",
            mapOf(VICTIM to false, SETTING to "late"),
            reopen().all
        )
    }

    // The same after a clear through another instance, which empties the file
    // and its key from under every other one.
    @Test
    fun anInstanceFollowsAClearMadeThroughAnother() {
        val early = reopen()
        assertTrue(early.edit().putBoolean(VICTIM, true).commit())

        assertTrue(reopen().edit().clear().commit())
        assertTrue(early.edit().putBoolean(VICTIM, false).putString(SETTING, "after").commit())

        val later = reopen()
        assertEquals(mapOf(VICTIM to false, SETTING to "after"), later.all)
        assertTrue("a delete of a key never written must still certify", later.edit().remove(ATTACKER).commit())
    }

    private companion object {
        const val PREFS_NAME = "rotation_test_prefs"
        const val KEY_ALIAS_PREFIX = "keep_prefs_"
        const val VICTIM = "opted_in_com.example.victim"
        const val ATTACKER = "opted_in_com.example.attacker"
        const val SETTING = "some_setting"
        const val UNLISTED = "unlisted_setting"
    }
}
