package io.privkey.keep.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The kill switch is carried from the legacy store into the core once, at
 * startup, before any signing gate can run. The carry is what puts the
 * restriction into the core, so a state read as disengaged is one the core is
 * never told about, and signing resumes.
 *
 * That makes the unreadable case the one worth pinning. It used to read as
 * "disengaged", because the ordinary getter answers an unreadable value with the
 * caller's default, so a switch the user had engaged was silently dropped.
 */
class KillSwitchCarryTest {

    @Test
    fun `an engaged switch is carried into the core`() {
        assertTrue(carryEngagesKillSwitch(PrefRead.Found(true)))
    }

    @Test
    fun `a disengaged switch is not`() {
        assertFalse(carryEngagesKillSwitch(PrefRead.Found(false)))
    }

    @Test
    fun `nothing stored in either copy engages nothing`() {
        assertFalse(carryEngagesKillSwitch(PrefRead.Absent))
    }

    @Test
    fun `a state that could not be read is carried as engaged`() {
        assertTrue(
            "a state that could not be confirmed disengaged is not disengaged",
            carryEngagesKillSwitch(PrefRead.Unreadable)
        )
    }

    // The dispatch, exercised as the call site runs it. Worth its own tests
    // because the carry runs once per install and is not repeatable, so an
    // ordering mistake here is not something a later launch corrects.

    @Test
    fun `an engaged switch is engaged once and then retired`() {
        val run = runCarry(PrefRead.Found(true), retireSucceeds = true)

        assertEquals(1, run.engaged)
        assertEquals(1, run.retired)
    }

    @Test
    fun `a disengaged switch is retired without touching the core`() {
        // Never setKillSwitch(false): the core is authoritative after the carry,
        // and writing false here would lift a switch engaged after install.
        val run = runCarry(PrefRead.Found(false), retireSucceeds = true)

        assertEquals("the core must not be written on a disengaged carry", 0, run.engaged)
        assertEquals(1, run.retired)
    }

    @Test
    fun `an unreadable state engages the core and still retires the carry`() {
        val run = runCarry(PrefRead.Unreadable, retireSucceeds = true)

        assertEquals(1, run.engaged)
        // The half that stops this being a one-way door. Leaving the carry open
        // would re-apply it on every launch, and a fault that never lifted would
        // leave no route back; retired, the restriction sits in the core where an
        // authenticated disengage can clear it.
        assertEquals("the carry must be retired, not left to re-apply forever", 1, run.retired)
    }

    @Test
    fun `an absence the store could not certify is treated as a restriction`() {
        // An uncertified retire means the store could not see the value well
        // enough to delete it, so it could not see it well enough to have called
        // it absent a moment earlier either.
        val run = runCarry(PrefRead.Absent, retireSucceeds = false)

        assertEquals("an unproven absence must engage rather than resume", 1, run.engaged)
    }

    @Test
    fun `an uncertified retire does not engage twice when it already engaged`() {
        val run = runCarry(PrefRead.Found(true), retireSucceeds = false)

        assertEquals(1, run.engaged)
    }

    @Test
    fun `a certified absence resumes signing`() {
        // The other direction, so the rule above cannot be satisfied by engaging
        // unconditionally: an install that genuinely never had the switch set
        // must come out of the carry able to sign.
        val run = runCarry(PrefRead.Absent, retireSucceeds = true)

        assertEquals(0, run.engaged)
        assertEquals(1, run.retired)
    }

    private class Run(var engaged: Int = 0, var retired: Int = 0)

    private fun runCarry(legacy: PrefRead<Boolean>, retireSucceeds: Boolean): Run {
        val run = Run()
        carryKillSwitch(
            legacy = legacy,
            engage = { run.engaged++ },
            retire = { run.retired++; retireSucceeds },
        )
        return run
    }
}
