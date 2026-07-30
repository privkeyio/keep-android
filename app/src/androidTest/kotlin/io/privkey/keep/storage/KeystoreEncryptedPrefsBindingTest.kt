package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Values are authenticated, which proves nobody altered them. It does not prove
 * where they belong: without binding, any ciphertext from this file decrypts
 * under any other entry's name. That is enough to grant a package auto-signing
 * by copying another package's stored `true` onto its name, with no forgery and
 * no key access.
 *
 * These tests move real ciphertext between entries and assert the value does not
 * follow, and that values written before binding existed are still readable.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsBindingTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun setup() = clear()
    @After fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    private fun raw() = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private fun open() = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

    /** The stored name a write lands on, identified by what the write adds. */
    private fun writeAndFindStoredName(key: String, value: String): String {
        open().edit().putString("anchor", "0").commit()
        val before = raw().all.keys.toSet()
        open().edit().putString(key, value).commit()
        val added = raw().all.keys.toSet() - before
        assertEquals("expected exactly one new stored entry", 1, added.size)
        return added.first()
    }

    @Test
    fun a_value_cannot_be_moved_onto_another_key() {
        // The whole point. `victim` is what an attacker wants to overwrite;
        // `donor` is a value they can already read off the device.
        val donorName = writeAndFindStoredName("donor", "attacker-chosen")
        val victimName = writeAndFindStoredName("victim", "real")
        val donorCiphertext = raw().getString(donorName, null)!!

        raw().edit().putString(victimName, donorCiphertext).commit()

        assertNull(
            "a value must not decrypt under a key it was not written for",
            open().getString("victim", null)
        )
    }

    @Test
    fun a_transplanted_value_does_not_surface_through_enumeration_either() {
        val donorName = writeAndFindStoredName("donor", "attacker-chosen")
        val victimName = writeAndFindStoredName("victim", "real")
        raw().edit()
            .putString(victimName, raw().getString(donorName, null)!!)
            .commit()

        val all = open().all
        assertTrue(
            "enumeration must refuse the moved value outright: $all",
            !all.containsKey("victim")
        )
    }

    @Test
    fun a_value_still_round_trips_under_its_own_key() {
        // Binding must not break the ordinary case it protects.
        open().edit().putString("alpha", "1").putInt("beta", 7).commit()

        val reopened = open()
        assertEquals("1", reopened.getString("alpha", null))
        assertEquals(7, reopened.getInt("beta", 0))
    }

    @Test
    fun a_value_written_before_binding_existed_is_still_readable() {
        // Upgrading must not orphan anything. A legacy value carries no marker
        // and is read as it was written, unbound.
        val storedName = writeAndFindStoredName("legacy", "written-before")
        raw().edit().putString(storedName, legacyCiphertext("written-before")).commit()

        assertEquals("written-before", open().getString("legacy", null))
    }

    @Test
    fun a_legacy_value_gains_the_binding_when_it_is_next_written() {
        val storedName = writeAndFindStoredName("legacy", "written-before")
        raw().edit().putString(storedName, legacyCiphertext("written-before")).commit()
        assertTrue(
            "precondition: staged value is unmarked",
            !raw().getString(storedName, null)!!.startsWith("v2:")
        )

        open().edit().putString("legacy", "written-after").commit()

        val nowStored = raw().all.entries.first { it.value == raw().getString(storedName, null) }
        assertTrue(
            "a rewritten value should carry the binding: ${nowStored.value}",
            (nowStored.value as String).startsWith("v2:")
        )
        assertEquals("written-after", open().getString("legacy", null))
    }

    @Test
    fun a_legacy_registry_still_decodes_so_every_key_stays_enumerable() {
        // The registry is what makes keys visible after a restart. If a value
        // written before binding stopped decoding here, the whole file would
        // read as empty even though every entry was intact.
        open().edit().putString("alpha", "1").putString("beta", "2").commit()
        val (registryName, plain) = registryNameAndPlaintext()
        raw().edit().putString(registryName, legacyBlob(plain)).commit()
        assertTrue(
            "precondition: the staged registry is unmarked",
            !raw().getString(registryName, null)!!.startsWith("v2:")
        )

        val visible = open().all.keys
        assertTrue("alpha must survive a legacy registry: $visible", visible.contains("alpha"))
        assertTrue("beta must survive a legacy registry: $visible", visible.contains("beta"))
    }

    @Test
    fun a_legacy_derivation_key_still_decrypts() {
        // This one is not a lost value, it is a lost file: every stored name is
        // derived from this key, and a failure here throws out of the read path
        // rather than returning a default.
        open().edit().putString("alpha", "1").commit()
        val stored = raw().getString("__hmac_key__", null)!!
        val decoded = decryptWithAad(stored, "__hmac_key__")
        raw().edit().putString("__hmac_key__", legacyBlobRaw(decoded)).commit()

        assertEquals("1", open().getString("alpha", null))
    }

    @Test
    fun stripping_the_marker_from_a_bound_value_fails_closed() {
        // The format's security claim: a bound value must not become readable by
        // deleting three characters.
        val storedName = writeAndFindStoredName("alpha", "real")
        val bound = raw().getString(storedName, null)!!
        assertTrue("precondition: value is bound", bound.startsWith("v2:"))

        raw().edit().putString(storedName, bound.removePrefix("v2:")).commit()

        assertNull(
            "a value must not read once its binding marker is removed",
            open().getString("alpha", null)
        )
    }

    /**
     * The registry is the one pre-existing entry rewritten by every commit, so a
     * write identifies it. Resolved in a single pass: probing twice would rewrite
     * the first probe's own value under a fresh nonce, leaving two changed
     * entries and no way to tell which is the registry. The probe key is unique
     * for the same reason.
     */
    private fun registryNameAndPlaintext(): Pair<String, String> {
        val before = raw().all.mapValues { it.value as String }
        open().edit().putString("probe-${System.nanoTime()}", "x").commit()
        val after = raw().all.mapValues { it.value as String }
        val name = before.keys.single { after[it] != null && after[it] != before[it] }
        return name to decryptWithAad(after.getValue(name), "__keys__")
    }

    private fun keystoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return keyStore.getKey("keep_prefs_$PREFS_NAME", null) as SecretKey
    }

    private fun decryptWithAad(value: String, aad: String): String {
        val combined = Base64.decode(value.removePrefix("v2:"), Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            keystoreKey(),
            javax.crypto.spec.GCMParameterSpec(128, combined.copyOfRange(0, 12))
        )
        if (value.startsWith("v2:")) cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        return String(cipher.doFinal(combined.copyOfRange(12, combined.size)), Charsets.UTF_8)
    }

    /** Re-encrypts an already-prefixed plaintext the old way: no AAD, no marker. */
    private fun legacyBlobRaw(plaintextWithPrefix: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val iv = cipher.iv
        val body = cipher.doFinal(plaintextWithPrefix.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + body, Base64.NO_WRAP)
    }

    private fun legacyBlob(plaintextWithPrefix: String): String = legacyBlobRaw(plaintextWithPrefix)

    /**
     * Builds a value the way it was written before binding existed: same
     * Keystore key, no associated data, no marker. Mirrors the production
     * derivation rather than assuming a format.
     */
    private fun legacyCiphertext(plaintext: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey("keep_prefs_$PREFS_NAME", null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val body = cipher.doFinal("s:$plaintext".toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + body, Base64.NO_WRAP)
    }

    companion object {
        private const val PREFS_NAME = "keystore_prefs_binding_test"
    }
}
