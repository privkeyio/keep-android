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

    @Test
    fun the_clear_refuses_when_no_pin_is_set() {
        assertFalse(PinStore(context).clearPin())
    }

    private companion object {
        // None of these trip isWeakPin: not sequential, not repeated, not in the list.
        const val GOOD_PIN = "4917"
        const val OTHER_PIN = "5283"
        const val WRONG_PIN = "7194"
    }
}
