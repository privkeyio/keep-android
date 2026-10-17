package io.privkey.keep.storage

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Transplanting a value onto another key's name.
 *
 * Stored names are an HMAC over the plaintext key, and the fallback epoch's
 * name is derived from a constant in the APK plus the file name, so anything
 * that can write this directory can place a value at a name of its choosing.
 * Values in one file are otherwise interchangeable: the auto-signing store
 * holds the same plaintext for every opted-in package, so one package's stored
 * `true` copied onto another package's name grants it background auto-signing.
 *
 * Binding the ciphertext to the key name closed that for values written since,
 * because a bound value decrypts only under the name it was written for. The
 * residual these tests pin is the value written before the binding existed: it
 * carries no statement about where it belongs, and at a name an attacker can
 * derive it is accepted as that key's value. It is now read only at the current
 * name, which is hashed under a key that never leaves the Keystore.
 *
 * The staging here is the real thing rather than a stand-in: the legacy value
 * is encrypted with the app's own Keystore key, with no associated data, the
 * way the store wrote values before the binding.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsTransplantTest {

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

    /** Mirrors the store's fallback key derivation, which is what makes the name derivable at all. */
    private fun fallbackNameOf(plainKey: String): String {
        val key = MessageDigest.getInstance("SHA-256")
            .digest("$DETERMINISTIC_SEED:$PREFS_NAME".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return Base64.encodeToString(
            mac.doFinal(plainKey.toByteArray(Charsets.UTF_8)),
            Base64.NO_WRAP or Base64.URL_SAFE
        )
    }

    /**
     * A value in the pre-binding format: encrypted with the file's own Keystore
     * key, with no associated data and no marker. Only the app's uid can produce
     * one, which is the threat model here: an attacker who can write the data
     * directory copies what is already in it rather than making new values.
     */
    private fun legacyValue(plaintext: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(KEY_ALIAS_PREFIX + PREFS_NAME, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val body = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(cipher.iv + body, Base64.NO_WRAP)
    }

    /** Moves [plainKey]'s stored entry to the name the fallback epoch would have used. */
    private fun strandUnderFallbackEpoch(plainKey: String) {
        val name = writeAndFindStoredName(context, PREFS_NAME) {
            reopen().edit().putBoolean(plainKey, true).commit()
        }
        val value = raw().getString(name, null)!!
        raw().edit().remove(name).putString(fallbackNameOf(plainKey), value).commit()
    }

    // The transplant: a value from before the binding, placed at a name the
    // attacker derives for a key of their choosing. It must not be read as that
    // key's value.
    @Test
    fun aLegacyValuePlantedAtTheDerivableNameIsNotRead() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()
        raw().edit().putString(fallbackNameOf(OPTED_IN_ATTACKER), legacyValue("b:true")).commit()

        assertFalse(
            "a value planted at a derivable name must not grant the key it was planted under",
            reopen().getBoolean(OPTED_IN_ATTACKER, false)
        )
        assertEquals(
            "and it must not surface through enumeration either",
            null,
            reopen().all[OPTED_IN_ATTACKER]
        )
    }

    // The control for the refusal above: the same stranded position, reached the
    // way a real fallback-epoch write reaches it, is still recovered. Without
    // this the refusal could be a blanket one and look identical.
    @Test
    fun aBoundValueStrandedUnderTheFallbackEpochIsStillRead() {
        strandUnderFallbackEpoch(OPTED_IN_VICTIM)

        assertTrue(
            "a bound value under the previous epoch must still be recovered",
            reopen().getBoolean(OPTED_IN_VICTIM, false)
        )
    }

    // The upgrade path: a value written before the binding, at its own current
    // name, is still read. That name is hashed under a key that never leaves the
    // Keystore, so it is not a name an attacker can choose, and refusing it
    // would drop the settings of every install that predates the binding.
    @Test
    fun aLegacyValueAtItsOwnCurrentNameIsStillRead() {
        val name = writeAndFindStoredName(context, PREFS_NAME) {
            reopen().edit().putString(LEGACY_KEY, "kept").commit()
        }
        raw().edit().putString(name, legacyValue("s:kept")).commit()

        assertEquals(
            "an unbound value at its own current name must still be read",
            "kept",
            reopen().getString(LEGACY_KEY, null)
        )
    }

    private companion object {
        const val PREFS_NAME = "transplant_test_prefs"
        const val KEY_ALIAS_PREFIX = "keep_prefs_"
        const val DETERMINISTIC_SEED = "keystore_prefs_hmac_key"
        const val OPTED_IN_VICTIM = "opted_in_com.example.victim"
        const val OPTED_IN_ATTACKER = "opted_in_com.example.attacker"
        const val LEGACY_KEY = "legacy_setting"
    }
}
