// The legacy store is staged through the same deprecated Jetpack API the
// migration opens it with, so the suppression matches LegacyPrefsMigration's.
@file:Suppress("DEPRECATION")

package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The sibling unit test pins what the carry decides. This pins that the store
 * can hand it the inputs those decisions are made from, which is the half the
 * rule cannot establish about itself: if an unreadable value never arrived as
 * [PrefRead.Unreadable], the rule would be correct and never consulted.
 *
 * The other half is the two copies. Both stores keep their entries in one
 * underlying file, the new one under HMAC-derived names and the legacy one under
 * AES-SIV names encrypted to a different key, and nothing ever deletes the legacy
 * entry. So they fail independently, and a value the new store cannot read is
 * still answerable from the legacy copy. That is read off the real stores here
 * rather than argued, because the whole fallback rests on it.
 *
 * Driven against a file of this test's own. The retire step deletes, so pointing
 * this at the app's own kill-switch file could disengage a live switch.
 */
@RunWith(AndroidJUnit4::class)
class KillSwitchCarryStoreTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before fun startClean() = clear()
    @After fun leaveNothingBehind() = clear()

    private fun clear() {
        context.deleteSharedPreferences(TEST_PREFS)
    }

    private fun store() = KillSwitchStore(context, TEST_PREFS)
    private fun raw() = context.getSharedPreferences(TEST_PREFS, Context.MODE_PRIVATE)

    /** The new store, which is what the running app reads and writes. */
    private fun newStore() = KeystoreEncryptedPrefs.create(context, TEST_PREFS)

    /** The legacy store, opened exactly as the migration opens it. */
    private fun legacyStore(): SharedPreferences = EncryptedSharedPreferences.create(
        context,
        TEST_PREFS,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun engageInNewStore() {
        assertTrue(
            "the staging write has to land, or every assertion below reads an empty file",
            newStore().edit().putBoolean(KillSwitchStore.KEY_ENABLED, true).commit()
        )
    }

    /** Engages the switch the way a pre-upgrade build actually left it. */
    private fun engageInLegacyStore() {
        assertTrue(legacyStore().edit().putBoolean(KillSwitchStore.KEY_ENABLED, true).commit())
    }

    /** The stored name the new store's copy landed on, found by what the write added. */
    private fun storedNameInNewStore(): String {
        // Primed first: the opening write to a fresh file also lays down the
        // file's own key material, so the delta would not be the value alone.
        assertTrue(newStore().edit().putString("anchor", "0").commit())
        val before = raw().all.keys.toSet()
        engageInNewStore()
        val added = raw().all.keys.toSet() - before
        assertEquals("expected exactly one new stored entry", 1, added.size)
        return added.first()
    }

    /**
     * Breaks the new store's copy the way a lost Keystore alias breaks it: the
     * last byte of the ciphertext is flipped, so the failure is the GCM tag check
     * rather than a decode error on some other branch.
     */
    private fun corrupt(storedName: String) {
        val stored = raw().getString(storedName, null)!!
        assertTrue("the value has to carry the marker it is written with", stored.startsWith(BOUND_PREFIX))
        val bytes = Base64.decode(stored.removePrefix(BOUND_PREFIX), Base64.NO_WRAP)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        assertTrue(
            raw().edit()
                .putString(storedName, BOUND_PREFIX + Base64.encodeToString(bytes, Base64.NO_WRAP))
                .commit()
        )
    }

    /** The stored name a legacy write lands on, found by what the write added. */
    private fun legacyStoredNameOf(write: () -> Unit): String {
        // Primed first: the legacy store's opening write also lays down its own
        // keyset entries, so the delta would not be the value alone.
        assertTrue(legacyStore().edit().putString("legacy_anchor", "0").commit())
        val before = raw().all.keys.toSet()
        write()
        val added = raw().all.keys.toSet() - before
        assertEquals("expected exactly one new legacy entry", 1, added.size)
        return added.first()
    }

    /** Breaks a legacy value so its decrypt fails rather than its decode. */
    private fun corruptLegacy(storedName: String) {
        val stored = raw().getString(storedName, null)!!
        val bytes = Base64.decode(stored, Base64.DEFAULT)
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        assertTrue(
            raw().edit().putString(storedName, Base64.encodeToString(bytes, Base64.DEFAULT)).commit()
        )
    }

    @Test
    fun anEngagedSwitchIsReadAsEngaged() {
        engageInNewStore()

        assertEquals(PrefRead.Found(true), store().legacyState())
        assertTrue(carryEngagesKillSwitch(store().legacyState()))
    }

    @Test
    fun nothingInEitherCopyReadsAsAbsent() {
        assertEquals(PrefRead.Absent, store().legacyState())
        assertFalse(
            "an install that never set the switch has to come out able to sign",
            carryEngagesKillSwitch(store().legacyState())
        )
    }

    // The premise of the change. Before it this read as `false`, which is the
    // same answer as a switch the user deliberately turned off.
    @Test
    fun aValueThatWillNotDecryptIsReadAsUnreadableRatherThanDisengaged() {
        corrupt(storedNameInNewStore())

        val state = store().legacyState()

        assertEquals(PrefRead.Unreadable, state)
        assertTrue("and is therefore carried as engaged", carryEngagesKillSwitch(state))
    }

    /**
     * The fallback, end to end on both real stores. This is the case the
     * independence of the two copies buys: the answer is recovered exactly rather
     * than approximated by engaging, so a switch the user never set does not come
     * back engaged.
     */
    @Test
    fun aValueTheNewStoreCannotReadIsRecoveredFromTheLegacyCopy() {
        engageInLegacyStore()
        corrupt(storedNameInNewStore())

        assertEquals(
            "the legacy copy is encrypted to a different key and must still answer",
            PrefRead.Found(true),
            store().legacyState()
        )
    }

    // Same mechanism, the other value, so the fallback cannot be passing by
    // answering `true` to everything it cannot read.
    @Test
    fun aDisengagedLegacyValueIsRecoveredAsDisengaged() {
        assertTrue(legacyStore().edit().putBoolean(KillSwitchStore.KEY_ENABLED, false).commit())
        corrupt(storedNameInNewStore())

        assertEquals(PrefRead.Found(false), store().legacyState())
        assertFalse(carryEngagesKillSwitch(store().legacyState()))
    }

    /**
     * The legacy read raises on a value that will not decrypt, and letting that
     * escape is worse than a wrong answer: it reaches the carry's outer handler,
     * which engages without retiring, so the carry re-applies on every launch and
     * re-engages after the user has cleared it. Classified instead, the carry
     * engages once and retires.
     */
    @Test
    fun aLegacyValueThatWillNotDecryptIsClassifiedRatherThanRaised() {
        val legacyName = legacyStoredNameOf { engageInLegacyStore() }
        corruptLegacy(legacyName)

        val state = store().legacyState()

        assertEquals(PrefRead.Unreadable, state)
        assertTrue("and is carried as engaged", carryEngagesKillSwitch(state))
    }

    // A legacy entry holding some other type does not raise at all: the API
    // answers with the caller's default, which is the conflation the whole change
    // exists to remove. Reading under both defaults is what separates them.
    @Test
    fun aLegacyValueOfAnotherTypeIsNotReadAsAConfirmedFalse() {
        assertTrue(legacyStore().edit().putString(KillSwitchStore.KEY_ENABLED, "not-a-boolean").commit())

        val state = store().legacyState()

        assertEquals(PrefRead.Unreadable, state)
        assertTrue("a value that is not a boolean must not resume signing", carryEngagesKillSwitch(state))
    }

    /**
     * What the fallback depends on, stated as a test because the doc on
     * `markMigrated` now claims it: retiring drops this store's copy only, and
     * the legacy entry in the same file is untouched.
     */
    @Test
    fun retiringTheCarryDropsThisStoresCopyAndLeavesTheLegacyOne() {
        engageInLegacyStore()
        val storedName = storedNameInNewStore()
        assertTrue("precondition: this store's copy is on disk", raw().contains(storedName))

        assertTrue("the retire has to be certified for this to mean anything", store().markMigrated())

        assertFalse("retiring is what drops this store's copy", raw().contains(storedName))
        assertTrue("and the legacy copy has to survive it", legacyStore().contains(KillSwitchStore.KEY_ENABLED))
        assertTrue(store().hasMigrated())
    }

    private companion object {
        const val TEST_PREFS = "test_kill_switch_carry"
        // The marker KeystoreEncryptedPrefs puts on a value bound to its key name.
        const val BOUND_PREFIX = "v2:"
    }
}
