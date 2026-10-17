package io.privkey.keep.storage

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Coverage for [metadataRead], which decides whether a metadata record is
 * stored, absent, or present-but-unreadable.
 *
 * Getting this wrong is not a logging matter. `loadMetadata` turns [NotStored]
 * into `StorageNotFound`, which the core maps to a permissive default for
 * several records: the co-signing kill switch reads as disengaged, the
 * descriptor index reads as empty right before a rewrite that would drop every
 * entry it could not see, and the velocity counters read as fresh. Only
 * [Faulted] reaches those callers as an error they fail closed on.
 */
class MetadataReadTest {

    private val found = PrefRead.Found("value")

    @Test
    fun bothEntriesReadableIsStored() {
        assertEquals(MetadataRead.Stored, metadataRead(found, found))
    }

    @Test
    fun bothEntriesAbsentIsNotStored() {
        // The only combination that cannot be a fault: nothing was ever written.
        assertEquals(MetadataRead.NotStored, metadataRead(PrefRead.Absent, PrefRead.Absent))
    }

    @Test
    fun anUnreadableEntryIsAFaultNotAnAbsence() {
        // The case that defeated the core's fail-closed reads: a blob is there
        // and this layer cannot decrypt it, which must never read as absence.
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Unreadable, PrefRead.Unreadable))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Unreadable, found))
        assertEquals(MetadataRead.Faulted, metadataRead(found, PrefRead.Unreadable))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Unreadable, PrefRead.Absent))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Absent, PrefRead.Unreadable))
    }

    @Test
    fun halfARecordIsAFault() {
        // A record is written as a data/IV pair, so one entry without the other
        // is a torn write or a partial removal, not proof nothing was stored.
        assertEquals(MetadataRead.Faulted, metadataRead(found, PrefRead.Absent))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Absent, found))
    }

    // A single entry still classifies, and an empty call cannot be written at
    // all: the signature takes the first entry separately, so there is no
    // zero-arity case where `all {}` would be vacuously true and report Stored.
    @Test
    fun oneEntryClassifies() {
        assertEquals(MetadataRead.Stored, metadataRead(found))
        assertEquals(MetadataRead.NotStored, metadataRead(PrefRead.Absent))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Unreadable))
    }

    // The DKG secret is written as three entries rather than two, so the rule
    // has to hold at that arity too: all present is stored, all missing is a
    // first use, any mix is a fault.
    @Test
    fun theSameRuleHoldsForAThreeEntryRecord() {
        assertEquals(MetadataRead.Stored, metadataRead(found, found, found))
        assertEquals(
            MetadataRead.NotStored,
            metadataRead(PrefRead.Absent, PrefRead.Absent, PrefRead.Absent),
        )
        assertEquals(MetadataRead.Faulted, metadataRead(found, found, PrefRead.Unreadable))
        assertEquals(MetadataRead.Faulted, metadataRead(found, found, PrefRead.Absent))
        assertEquals(MetadataRead.Faulted, metadataRead(PrefRead.Absent, PrefRead.Absent, found))
    }
}
