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

    suspend fun append(
        buildLog: (previousHash: String?) -> Nip55AuditLog,
        extraInTransaction: (suspend () -> Unit)? = null
    ) = mutex.withLock {
        reconcilePendingClear()
        val anchor = Nip55Database.getAuditAnchor()
        var tamper = false
        database.withTransaction {
            tamper = anchorMismatch(anchor)
            extraInTransaction?.invoke()
            auditDao.insert(buildLog(auditDao.getLastEntryHash()))
        }
        if (tamper) Nip55Database.setAuditTamperDetected()
        advanceAnchor()
    }

    // Head prune (oldest rows only): the tail must be untouched, so a pre-prune
    // mismatch against the anchor is out-of-band tampering. Re-pin to the post-prune
    // state regardless so the legitimately shrunk count is recorded.
    suspend fun prune(before: Long, extraInTransaction: suspend () -> Unit) = mutex.withLock {
        reconcilePendingClear()
        val anchor = Nip55Database.getAuditAnchor()
        var tamper = false
        database.withTransaction {
            tamper = anchorMismatch(anchor)
            auditDao.deleteOlderThan(before)
            extraInTransaction()
        }
        if (tamper) Nip55Database.setAuditTamperDetected()
        advanceAnchor()
    }

    // Two-phase clear: the pending marker is committed before the wipe so a crash
    // between the DB commit and the anchor reset is recoverable (see reconcilePendingClear).
    suspend fun clear(extraInTransaction: (suspend () -> Unit)? = null) = mutex.withLock {
        Nip55Database.setAuditClearPending()
        database.withTransaction {
            auditDao.deleteAll()
            extraInTransaction?.invoke()
        }
        Nip55Database.resetAuditAnchor()
    }

    // Atomic read of rows + anchor under the same lock every write takes, so no
    // append/prune/clear can interleave between the two reads and skew the snapshot.
    suspend fun snapshot(): Pair<List<Nip55AuditLog>, AuditAnchor?> = mutex.withLock {
        reconcilePendingClear()
        auditDao.getAllOrdered() to Nip55Database.getAuditAnchor()
    }

    // Finish a clear() whose post-commit anchor reset was lost to a crash: an empty DB
    // means the wipe committed, so complete the reset; a non-empty DB means the clear
    // transaction rolled back, so just drop the (attacker-unforgeable) marker.
    private suspend fun reconcilePendingClear() {
        if (!Nip55Database.isAuditClearPending()) return
        if (auditDao.getCount() == 0) {
            Nip55Database.resetAuditAnchor()
        } else {
            Nip55Database.clearAuditClearPending()
        }
    }

    private suspend fun anchorMismatch(anchor: AuditAnchor?): Boolean {
        if (anchor == null) return false
        val tail = auditDao.getLastEntryHash() ?: ""
        val count = auditDao.getCount().toLong()
        if (tail == anchor.latestEntryHash && count == anchor.entryCount) return false
        // A legit append whose post-commit anchor advance was lost to a crash leaves the
        // DB one row ahead, chained onto the anchored tail. Re-pin without flagging.
        if (isResumableAppend(anchor, count, auditDao.getLastPreviousHash(), rustIntact = true)) {
            return false
        }
        // Likewise a crash-interrupted head prune: fewer rows but the same tail. The Rust
        // walk at verify time is authoritative for the rustIntact assumption here.
        if (isResumablePrune(anchor, count, tail, rustIntact = true)) {
            return false
        }
        return true
    }

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
