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
import javax.crypto.Cipher
import javax.crypto.SecretKey

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

    /** A value in the bound format, which only the app's own uid can produce. */
    private fun boundValueFor(prefsName: String, plaintext: String, aad: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(KEY_ALIAS_PREFIX + prefsName, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val body = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return BOUND_PREFIX + Base64.encodeToString(cipher.iv + body, Base64.NO_WRAP)
    }

    /**
     * Leaves the file carrying the derivation key a build in the v0.6.0 window
     * persisted into any file that already had entries: the seed alone, with no
     * file name, so it is a constant anyone can read out of the APK or this
     * repository's history. Nothing migrates a file off it, because a stored key
     * is read and used rather than re-derived.
     */
    private fun carryThePublishedGlobalKey() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()
        val encoded = Base64.encodeToString(publishedGlobalKey(), Base64.NO_WRAP)
        raw().edit()
            .putString(HMAC_KEY_PREF, boundValueFor(PREFS_NAME, encoded, HMAC_KEY_PREF))
            .commit()
    }

    // The same exposure one step further out: here the public key is the file's
    // own persisted one, so the store never looks like it is on a fallback at
    // all, and a name-by-name test would miss it.
    @Test
    fun aPlantedValueIsNotReadWhileTheStoreCarriesThePublishedGlobalKey() {
        carryThePublishedGlobalKey()
        raw().edit().putString(globalEpochNameOf(OPTED_IN_ATTACKER), legacyValue("b:true")).commit()

        assertFalse(
            "a name derived from a published key must not grant the key it was planted under",
            reopen().getBoolean(OPTED_IN_ATTACKER, false)
        )
    }

    // And the store still works for what it writes itself there.
    @Test
    fun theStoreStillReadsItsOwnWritesUnderThePublishedGlobalKey() {
        carryThePublishedGlobalKey()

        assertTrue("a write must still commit", reopen().edit().putString(LEGACY_KEY, "mine").commit())
        assertEquals("and read back", "mine", reopen().getString(LEGACY_KEY, null))
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

    // A marker is only a prefix, and anything that can write the directory can
    // write one. Such a blob must not be laundered onto the current name, where
    // nothing can plant and where it would then report the key as present, and
    // unreadable, for good.
    @Test
    fun aMarkedButUndecryptableValueIsNotMovedToTheCurrentName() {
        reopen().edit().putString(LEGACY_KEY, "written").commit()
        val planted = BOUND_PREFIX + Base64.encodeToString(ByteArray(32) { 7 }, Base64.NO_WRAP)
        raw().edit().putString(fallbackNameOf(OPTED_IN_ATTACKER), planted).commit()

        assertFalse(
            "a marked blob that cannot decrypt must not report the key as present",
            reopen().contains(OPTED_IN_ATTACKER)
        )
        assertTrue(
            "and it must be left where it was planted rather than relocated",
            raw().contains(fallbackNameOf(OPTED_IN_ATTACKER))
        )
    }

    /**
     * Forces the store onto its deterministic key, permanently.
     *
     * Deleting the stored derivation key makes the next open mint a fresh one,
     * and a blob it cannot decrypt at the deterministic registry name makes the
     * migration that would persist it fail before it commits anything, so the
     * open falls back to the deterministic key and every later open repeats it.
     * Both names are pure functions of constants in the APK and the file name.
     */
    private fun forceDeterministicEpoch() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()
        raw().edit()
            .remove(HMAC_KEY_PREF)
            .putString(fallbackNameOf(KEY_REGISTRY), "not a registry this can read")
            .commit()
    }

    // In that state every name the store computes is one the attacker can
    // compute, so the current name earns no more trust than the fallback one.
    // Without the same rule there, the transplant lands at what the store now
    // calls the key's own name.
    @Test
    fun aPlantedValueIsNotReadWhileTheStoreIsOnItsDeterministicKey() {
        forceDeterministicEpoch()
        raw().edit().putString(fallbackNameOf(OPTED_IN_ATTACKER), legacyValue("b:true")).commit()

        assertFalse(
            "a derivable current name must not grant the key it was planted under",
            reopen().getBoolean(OPTED_IN_ATTACKER, false)
        )
    }

    // And the store still works for what it writes itself in that state, so the
    // rule is not a blanket refusal of a file whose key never persisted.
    @Test
    fun theStoreStillReadsItsOwnWritesOnTheDeterministicKey() {
        forceDeterministicEpoch()

        val prefs = reopen()
        assertTrue("a write must still commit", prefs.edit().putString(LEGACY_KEY, "mine").commit())
        // Through the bound branch: a value this store writes carries the
        // binding, so this pins that the rule is not a blanket refusal for
        // anything written since. An unbound value is unreachable here, because
        // reaching this state at all takes an index the store cannot decode.
        assertEquals("and read back", "mine", reopen().getString(LEGACY_KEY, null))
        // And it is written unlisted, since that same index is what the rewrite
        // refuses to overwrite.
        assertEquals("the write must not be listed", null, reopen().all[LEGACY_KEY])
    }

    // The refusal has to reach the caller as what it is. A record that is on
    // disk and cannot be authenticated as this key's is not an absence, and
    // several callers read an absence as licence to overwrite, or as a control
    // that was never set: the kill switch maps a missing record to disengaged
    // and the velocity counters map one to a fresh window.
    @Test
    fun aRefusedValueReadsUnreadableRatherThanAbsent() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()
        raw().edit().putString(fallbackNameOf(OPTED_IN_ATTACKER), legacyValue("b:true")).commit()

        assertEquals(
            "a value refused at a derivable name must not read as never written",
            PrefRead.Unreadable,
            reopen().readBoolean(OPTED_IN_ATTACKER)
        )
        // In the same fixture, so a store failing wholesale cannot satisfy the
        // assertion above: every read would be Unreadable then, including this.
        assertEquals(
            "and a key with nothing behind it must still read absent",
            PrefRead.Absent,
            reopen().readBoolean(NEVER_WRITTEN)
        )
    }

    // And a key that genuinely has nothing must still read absent, or every
    // caller that treats absence as a fresh start fails closed forever.
    @Test
    fun aKeyWithNothingBehindItStillReadsAbsent() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()

        assertEquals(
            "a key nothing was ever written for must read absent",
            PrefRead.Absent,
            reopen().readBoolean(NEVER_WRITTEN)
        )
    }

    // The same on the current name, which is the other refusal leg: while the
    // derivation key is public, that name is one anything can write too.
    @Test
    fun aRefusedValueAtADerivableCurrentNameAlsoReadsUnreadable() {
        carryThePublishedGlobalKey()
        raw().edit().putString(globalEpochNameOf(OPTED_IN_ATTACKER), legacyValue("b:true")).commit()

        assertEquals(
            "the current-name leg must answer the same way as the fallback one",
            PrefRead.Unreadable,
            reopen().readBoolean(OPTED_IN_ATTACKER)
        )
        assertEquals(
            "and a key with nothing behind it must still read absent",
            PrefRead.Absent,
            reopen().readBoolean(NEVER_WRITTEN)
        )
    }

    // A delete over a refused value establishes nothing, so it reports failure
    // and leaves the value alone. Every reason a value is refused can be a
    // property of this process: a decrypt that may succeed later, a minted key
    // that did not commit so every name is derivable for now, an index that
    // could not be read so a listed key looks unlisted. Removing it would be a
    // transient fault read as proof, which is the shape taken out of the audit
    // chain and the share metadata already.
    @Test
    fun aDeleteOverARefusedValueIsRefusedAndLeavesItAlone() {
        reopen().edit().putBoolean(OPTED_IN_VICTIM, true).commit()
        val planted = fallbackNameOf(OPTED_IN_ATTACKER)
        raw().edit().putString(planted, legacyValue("b:true")).commit()

        assertFalse(
            "a delete that could not establish absence must not report success",
            reopen().edit().remove(OPTED_IN_ATTACKER).commit()
        )
        assertTrue("and must leave the value where it was", raw().contains(planted))
    }

    private companion object {
        const val PREFS_NAME = "transplant_test_prefs"
        const val PIN_PREFS_NAME = "keep_pin_protection"
        const val PIN_ENABLED_KEY = "pin_enabled"
        const val KEY_ALIAS_PREFIX = "keep_prefs_"
        const val OPTED_IN_VICTIM = "opted_in_com.example.victim"
        const val OPTED_IN_ATTACKER = "opted_in_com.example.attacker"
        const val LEGACY_KEY = "legacy_setting"
        const val NEVER_WRITTEN = "opted_in_com.example.never.written"
    }
}
