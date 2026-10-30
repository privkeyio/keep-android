package io.privkey.keep.nip55

import androidx.room.withTransaction
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The single seam through which the anchored nip55_audit_log table may be mutated.
 * Every append/prune/clear pairs the Room write with an integrity-checked anchor
 * update so no alternate writer can advance the chain without the anchor noticing
 * (gh #308). The anchor (a Keystore-backed prefs commit) is only advanced AFTER the
 * Room transaction commits, so a rollback can never leave it ahead of the DB.
 */
internal class AuditLogWriter(private val database: Nip55Database) {
    private val auditDao = database.auditLogDao()

    // [claim] is asked under the lock, before anything is read or written, so an
    // append whose caller has stopped waiting can still be turned away after it has
    // queued for the lock. Returns whether the row was written.
    suspend fun append(
        buildLog: (previousHash: String?) -> Nip55AuditLog,
        extraInTransaction: (suspend () -> Unit)? = null,
        claim: () -> Boolean = { true }
    ): Boolean = mutex.withLock {
        if (!claim()) return@withLock false
        val state = reconcile()
        var tamper = false
        database.withTransaction {
            tamper = anchorMismatch(state)
            extraInTransaction?.invoke()
            auditDao.insert(buildLog(auditDao.getLastEntryHash()))
        }
        if (tamper) Nip55Database.setAuditTamperDetected()
        advanceAnchor()
        true
    }

    // Head prune (oldest rows only): the tail must be untouched, so a pre-prune
    // mismatch against the anchor is out-of-band tampering. Re-pin to the post-prune
    // state regardless so the legitimately shrunk count is recorded.
    suspend fun prune(before: Long, extraInTransaction: suspend () -> Unit) = mutex.withLock {
        val state = reconcile()
        var tamper = false
        database.withTransaction {
            tamper = anchorMismatch(state)
            auditDao.deleteOlderThan(before)
            extraInTransaction()
        }
        if (tamper) Nip55Database.setAuditTamperDetected()
        advanceAnchor()
    }

    // Two-phase clear: the pending marker is committed before the wipe so a crash
    // between the DB commit and the anchor reset is recoverable (see reconcile).
    suspend fun clear(extraInTransaction: (suspend () -> Unit)? = null) = mutex.withLock {
        Nip55Database.setAuditClearPending()
        database.withTransaction {
            auditDao.deleteAll()
            extraInTransaction?.invoke()
        }
        Nip55Database.resetAuditAnchor()
    }

    // Atomic read of rows + anchor + tamper flag under the same lock every write takes,
    // so no append/prune/clear can interleave between the reads and skew the snapshot.
    suspend fun snapshot(): Triple<List<Nip55AuditLog>, AuditAnchor?, Boolean> = mutex.withLock {
        val state = reconcile()
        // The verify pass sees an unreadable read too, and the next write is not
        // guaranteed to see it again: the only other record is the corrupted entry
        // itself, which whoever wrote it can replace. Record it where it is sticky.
        if (state.unreadable) Nip55Database.setAuditTamperDetected()
        Triple(auditDao.getAllOrdered(), state.anchor, state.tamperDetected)
    }

    // Compare-and-set the anchor under the write lock: only pin to (expectedHash, expectedCount)
    // if the live DB still matches the snapshot the caller reconciled. A concurrent append/prune
    // that already advanced the anchor since the snapshot wins; we must never roll it back.
    suspend fun reconcileAnchor(expectedCount: Long, expectedHash: String) = mutex.withLock {
        val liveTail = auditDao.getLastEntryHash() ?: ""
        val liveCount = auditDao.getCount().toLong()
        if (liveCount == expectedCount && liveTail == expectedHash) {
            Nip55Database.setAuditAnchor(AuditAnchor(expectedHash, expectedCount))
        }
    }

    // One read of the four anchor values, then finish a clear() whose post-commit anchor
    // reset was lost to a crash: an empty DB means the wipe committed, so complete the
    // reset; a non-empty DB means the clear transaction rolled back, so just drop the
    // (attacker-unforgeable) marker.
    //
    // The reset rewrites all four entries readably, so the state it leaves has to be
    // read again, and a fault the first read saw has to be carried across it. Otherwise
    // the reconcile erases the only evidence of that fault before anything records it.
    private suspend fun reconcile(): AuditAnchorState {
        val state = Nip55Database.readAuditAnchorState()
        if (!state.clearPending) return state
        if (auditDao.getCount() != 0) {
            Nip55Database.clearAuditClearPending()
            return state
        }
        Nip55Database.resetAuditAnchor()
        val afterReset = Nip55Database.readAuditAnchorState()
        return if (state.unreadable) afterReset.copy(unreadable = true) else afterReset
    }

    // The row facts the verdict is over. An unreadable read is already tamper, and the
    // caller records it in the sticky flag: the anchor advance that follows every write
    // re-pins the corrupted entry to a readable one, so a write pass sees it once.
    private suspend fun anchorMismatch(state: AuditAnchorState): Boolean =
        anchorMismatchVerdict(
            state,
            auditDao.getCount().toLong(),
            auditDao.getLastEntryHash() ?: "",
            auditDao.getLastPreviousHash()
        )

    private suspend fun advanceAnchor() {
        Nip55Database.setAuditAnchor(
            AuditAnchor(auditDao.getLastEntryHash() ?: "", auditDao.getCount().toLong())
        )
    }

    companion object {
        // Serializes every audit write so an in-flight append cannot observe another
        // writer's half-committed state and raise a false tamper flag.
        private val mutex = Mutex()
    }
}
