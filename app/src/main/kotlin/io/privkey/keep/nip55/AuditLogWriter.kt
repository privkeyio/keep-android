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

    suspend fun clear(extraInTransaction: (suspend () -> Unit)? = null) = mutex.withLock {
        database.withTransaction {
            auditDao.deleteAll()
            extraInTransaction?.invoke()
        }
        Nip55Database.resetAuditAnchor()
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
