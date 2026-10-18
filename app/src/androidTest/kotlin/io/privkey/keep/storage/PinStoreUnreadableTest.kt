package io.privkey.keep.storage

import android.content.Context
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
 * What the PIN store answers when its record cannot be read.
 *
 * Every value in this file carries a restriction: whether a PIN is set, how long the
 * lockout has left, how much of the attempt budget is spent, and whether a biometric
 * reset is owed. The ordinary getters answered the caller's default for both "nothing
 * stored" and "stored and will not decrypt", and for all four of those the default is
 * the permissive answer, so a record that would not decrypt read as no PIN, no lockout,
 * no attempts used and no reset owed. All three PIN gates ask through
 * requiresAuthentication, so that one answer stopped every one of them asking.
 *
 * Faults are staged on disk in both the shapes a lost Keystore alias produces: one
 * value that will not decrypt, and the file's own HMAC key gone, which makes resolving
 * any name in it raise rather than answer.
 */
@RunWith(AndroidJUnit4::class)
class PinStoreUnreadableTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setup() {
        clear()
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        context.deleteSharedPreferences(PinStore.PREFS_NAME)
    }

    /** Corrupts the stored pin_enabled value alone, leaving the rest of the file sound. */
    private fun breakTheEnabledFlag() {
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putBoolean("pin_enabled", true).commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)
    }

    // The control. Without it every assertion below would pass on a store that reported
    // a fault whatever it read.
    @Test
    fun a_readable_pin_enables_the_gate_and_verifies() {
        val store = PinStore(context)
        assertTrue(store.setPin(GOOD_PIN))

        assertEquals(PinRecord.SET, store.pinRecord())
        assertTrue(store.isPinEnabled())
        assertTrue(store.verifyPin(GOOD_PIN))
        assertFalse(store.verifyPin(WRONG_PIN))
    }

    @Test
    fun a_store_with_no_pin_does_not_ask() {
        val store = PinStore(context)
        assertEquals(PinRecord.NOT_SET, store.pinRecord())
        assertFalse(store.isPinEnabled())
        assertFalse(store.requiresAuthentication())
    }

    /**
     * The headline. A flag that will not decrypt must not read as "no PIN set", because
     * that answer takes the gate off at MainActivity, Nip55Activity and
     * Nip55ContentProvider at once, without anything raising or being logged.
     */
    @Test
    fun an_unreadable_pin_flag_keeps_the_gate_asking() {
        breakTheEnabledFlag()

        val store = PinStore(context)
        assertEquals(PinRecord.UNREADABLE, store.pinRecord())
        assertTrue(
            "an unreadable flag must not read as no PIN",
            store.isPinEnabled()
        )
        assertTrue(
            "and the gates ask through this one",
            store.requiresAuthentication()
        )
        forgetWriteProbe(context, PinStore.PREFS_NAME)
    }

    /**
     * The throttle is the other half: an unreadable record used to report a full attempt
     * budget and no lockout, which is what an attacker able to damage this file would
     * want, since the hash may still be intact and brute-forceable.
     */
    @Test
    fun an_unreadable_pin_record_reports_the_throttle_in_force() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)

        val store = PinStore(context)
        assertEquals(PinRecord.UNREADABLE, store.pinRecord())
        assertTrue("the lockout must not read as expired", store.isLockedOut())
        assertEquals("nor the attempt budget as unspent", 0, store.getRemainingAttempts())
        assertTrue("nor a reset owed as not owed", store.requiresBiometricReset())
        assertFalse("and no PIN can verify against it", store.verifyPin(GOOD_PIN))
    }

    /**
     * Failing closed is only safe because of this: the hash is in the same file, so no
     * PIN can verify, and without a way out the person would be locked out of the app
     * with their keys inside it.
     *
     * Staged with the HMAC key broken, which is the mode where removing a single key
     * raises instead of answering, so this also pins that the clear is the delete that
     * works here.
     */
    @Test
    fun clearing_an_unreadable_pin_record_lets_a_new_pin_be_set() {
        PinStore(context).setPin(GOOD_PIN)
        breakNameResolution(context, PinStore.PREFS_NAME)
        assertTrue(PinStore(context).requiresAuthentication())

        assertTrue("the clear has to answer, not raise", PinStore(context).clearPin())

        val repaired = PinStore(context)
        assertEquals(PinRecord.NOT_SET, repaired.pinRecord())
        assertFalse(repaired.requiresAuthentication())
        assertTrue("and a new PIN can be set afterwards", repaired.setPin(OTHER_PIN))
        assertTrue(repaired.verifyPin(OTHER_PIN))
        assertFalse(repaired.verifyPin(GOOD_PIN))
    }

    /**
     * The clear is reachable from the unlock screen, which is shown to someone who has
     * not authenticated, so it refuses a record it can read. Checked rather than
     * documented, because a comment would not stop the call.
     */
    @Test
    fun the_clear_refuses_a_pin_it_can_read() {
        val store = PinStore(context)
        assertTrue(store.setPin(GOOD_PIN))

        assertFalse("a readable PIN must not be removable this way", store.clearPin())

        val after = PinStore(context)
        assertEquals(PinRecord.SET, after.pinRecord())
        assertTrue("and it still verifies", after.verifyPin(GOOD_PIN))
    }

    /**
     * One damaged lockout timestamp while the rest of the record reads fine.
     *
     * The flag reads as SET here, so the unlock screen shows the lockout rather than the
     * state that offers removal, which makes counting down the only way out. A number
     * substituted for the timestamp on each read would re-anchor the lockout to the
     * moment of every call and hold it at its full length forever. The lockout has to run
     * its full length once and then end.
     */
    @Test
    fun an_unreadable_lockout_anchor_runs_once_and_then_counts_down() {
        KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME).edit()
            .putBoolean("pin_enabled", true)
            .putLong("lockout_duration", LONGEST_LOCKOUT_MS)
            .commit()
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putLong("lockout_set_at_elapsed", 1L).commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)

        assertEquals(PinRecord.SET, PinStore(context).pinRecord())
        val first = PinStore(context).getLockoutRemainingMs()
        assertTrue("a lost anchor must not read as an expired lockout", first > 0)

        Thread.sleep(COUNTDOWN_PROBE_MS)
        val second = PinStore(context).getLockoutRemainingMs()
        assertTrue(
            "the lockout has to count down rather than restart on every read: $first then $second",
            first - second >= COUNTDOWN_PROBE_MS - COUNTDOWN_SLACK_MS
        )
        forgetWriteProbe(context, PinStore.PREFS_NAME)
    }

    /**
     * A hash that will not decrypt beside a flag that reads fine. The flag alone decided
     * the record before, so this read as SET: every PIN was refused as incorrect, no
     * attempt was spent, and the removal was never offered, which on a device with no
     * biometric is a lockout with no way out.
     */
    @Test
    fun an_unreadable_hash_beside_a_readable_flag_is_unreadable() {
        KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME).edit()
            .putBoolean("pin_enabled", true)
            .putString("pin_salt", "AAAAAAAAAAAAAAAAAAAAAA==")
            .commit()
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putString("pin_hash", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)

        val store = PinStore(context)
        assertEquals(PinRecord.UNREADABLE, store.pinRecord())
        assertTrue("and the way out is offered for it", store.clearPin())
        assertEquals(PinRecord.NOT_SET, PinStore(context).pinRecord())
    }

    /**
     * The reverse: a broken flag beside a hash and salt that still read. disablePin removes
     * the hash and salt, so a usable pair means a PIN was set and never disabled. Reading
     * that as UNREADABLE would offer to delete a PIN that can still be verified.
     */
    @Test
    fun a_broken_flag_beside_a_usable_verifier_is_still_set() {
        assertTrue(PinStore(context).setPin(GOOD_PIN))
        // The stored name is an HMAC of the key under the file's own random key, so it is
        // found by removing the flag and seeing which entry goes, then writing it back,
        // which lands on the same name.
        val before = rawPrefs(context, PinStore.PREFS_NAME).all.keys.toSet()
        KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME).edit().remove("pin_enabled").commit()
        val flagName = (before - rawPrefs(context, PinStore.PREFS_NAME).all.keys.toSet()).single()
        KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME).edit().putBoolean("pin_enabled", true).commit()
        corruptStoredValue(context, PinStore.PREFS_NAME, flagName)

        val store = PinStore(context)
        assertEquals(PinRecord.SET, store.pinRecord())
        assertTrue("the PIN still verifies", store.verifyPin(GOOD_PIN))
        assertFalse("so it must not be removable this way", store.clearPin())
    }

    /**
     * Nothing in the app writes the session timeout, so a value here that will not read
     * can never be rewritten. Answering 0 for it made every session invalid for good,
     * which refuses all background signing while a PIN is set. A fresh session has to be
     * valid again.
     */
    @Test
    fun an_unreadable_session_timeout_still_lets_a_session_open() {
        val store = PinStore(context)
        assertTrue(store.setPin(GOOD_PIN))
        val storedName = writeAndFindStoredName(context, PinStore.PREFS_NAME) {
            KeystoreEncryptedPrefs.create(context, PinStore.PREFS_NAME)
                .edit().putLong("session_timeout", 300_000L).commit()
        }
        corruptStoredValue(context, PinStore.PREFS_NAME, storedName)

        val reopened = PinStore(context)
        reopened.refreshSession()
        assertTrue("a session opened now has to count as open", reopened.isSessionValid())
        assertFalse(reopened.requiresAuthentication())
        forgetWriteProbe(context, PinStore.PREFS_NAME)
    }

    @Test
    fun the_clear_refuses_when_no_pin_is_set() {
        assertFalse(PinStore(context).clearPin())
    }

    private companion object {
        // None of these trip isWeakPin: not sequential, not repeated, not in the list.
        const val GOOD_PIN = "4917"
        const val OTHER_PIN = "5283"
        const val WRONG_PIN = "7194"
        // The top of PinStore's lockout ladder.
        const val LONGEST_LOCKOUT_MS = 3_600_000L
        const val COUNTDOWN_PROBE_MS = 200L
        const val COUNTDOWN_SLACK_MS = 50L
    }
}
