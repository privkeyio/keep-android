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
 * derive it was accepted as that key's value. Such a value is now read there
 * only for a key the store's own index lists, which separates one stranded by
 * an epoch the store moved through from one planted for a key it never wrote.
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

    private fun fallbackNameOf(plainKey: String): String = fallbackNameIn(PREFS_NAME, plainKey)

    /** Mirrors the store's fallback key derivation, which is what makes the name derivable at all. */
    private fun fallbackNameIn(prefsName: String, plainKey: String): String {
        val key = MessageDigest.getInstance("SHA-256")
            .digest("$DETERMINISTIC_SEED:$prefsName".toByteArray(Charsets.UTF_8))
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
    private fun legacyValue(plaintext: String): String = legacyValueFor(PREFS_NAME, plaintext)

    private fun legacyValueFor(prefsName: String, plaintext: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(KEY_ALIAS_PREFIX + prefsName, null) as SecretKey
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
    }

    // The other half of the rule, and the one a legitimate install depends on:
    // a value stranded under the previous epoch for a key the index lists is
    // still recovered, bound or not. Keys that are written once and never
    // rewritten live here, up to the PIN flag whose absence reads as no PIN.
    @Test
    fun anUnboundValueStrandedForAnIndexedKeyIsStillRead() {
        val name = writeAndFindStoredName(context, PREFS_NAME) {
            reopen().edit().putString(LEGACY_KEY, "written").commit()
        }
        // Stranded and in the pre-binding format, which is the state an install
        // that set this once, long ago, upgrades with.
        raw().edit().remove(name).putString(fallbackNameOf(LEGACY_KEY), legacyValue("s:legacy")).commit()

        assertEquals(
            "a value the index lists must still be recovered from the previous epoch",
            "legacy",
            reopen().getString(LEGACY_KEY, null)
        )
        assertEquals(
            "and must read the same through enumeration",
            "legacy",
            reopen().all[LEGACY_KEY]
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
        assertFalse(
            "and the probe must have moved it off the derivable name, not just read it there",
            raw().contains(fallbackNameOf(OPTED_IN_VICTIM))
        )
    }

    // The upgrade path: a value written before the binding, at its own current
    // name, is still read. That name is hashed under a key that never leaves the
    // Keystore, so it is not a name an attacker can choose, and refusing it
    // would drop the settings of every install that predates the binding.
    @Test
    fun aLegacyValueAtItsOwnCurrentNameIsStillRead() {
        val name = writeAndFindStoredName(context, PREFS_NAME) {
            reopen().edit().putString(LEGACY_KEY, "written").commit()
        }
        // A different plaintext from the one just written, so the assertion can
        // only pass by reading what was planted.
        raw().edit().putString(name, legacyValue("s:legacy")).commit()

        assertEquals(
            "an unbound value at its own current name must still be read",
            "legacy",
            reopen().getString(LEGACY_KEY, null)
        )
    }

    // The consequence the rule exists for, through the store that has it: the
    // PIN flag is written once and never rewritten, so it is exactly the value
    // that can still be sitting under a previous epoch, and reading it as absent
    // means no PIN at all rather than a lost setting.
    @Test
    fun aStrandedPinFlagStillReportsThePinAsEnabled() {
        context.deleteSharedPreferences(PIN_PREFS_NAME)
        try {
            val name = writeAndFindStoredName(context, PIN_PREFS_NAME) {
                KeystoreEncryptedPrefs.create(context, PIN_PREFS_NAME)
                    .edit().putBoolean(PIN_ENABLED_KEY, true).commit()
            }
            val legacy = legacyValueFor(PIN_PREFS_NAME, "b:true")
            rawPrefs(context, PIN_PREFS_NAME).edit()
                .remove(name)
                .putString(fallbackNameIn(PIN_PREFS_NAME, PIN_ENABLED_KEY), legacy)
                .commit()

            assertTrue(
                "a stranded PIN flag must not read as no PIN",
                PinStore(context).isPinEnabled()
            )
        } finally {
            context.deleteSharedPreferences(PIN_PREFS_NAME)
        }
    }

    private companion object {
        const val PREFS_NAME = "transplant_test_prefs"
        const val PIN_PREFS_NAME = "keep_pin_protection"
        const val PIN_ENABLED_KEY = "pin_enabled"
        const val KEY_ALIAS_PREFIX = "keep_prefs_"
        const val DETERMINISTIC_SEED = "keystore_prefs_hmac_key"
        const val OPTED_IN_VICTIM = "opted_in_com.example.victim"
        const val OPTED_IN_ATTACKER = "opted_in_com.example.attacker"
        const val LEGACY_KEY = "legacy_setting"
    }
}
