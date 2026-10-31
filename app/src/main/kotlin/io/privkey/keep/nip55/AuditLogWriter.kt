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
        lateinit var row: Nip55AuditLog
        database.withTransaction {
            tamper = anchorMismatch(state)
            extraInTransaction?.invoke()
            row = buildLog(auditDao.getLastEntryHash())
            auditDao.insert(row)
        }
        if (tamper) {
            Nip55Database.setAuditTamperDetected()
            familiarity[database] = AuditFamiliarity(trusted = false)
        } else {
            familiarity[database]?.add(row)
        }
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
        // What the pruned rows contributed is not known here, so it is rebuilt from the
        // rows that remain on the next query.
        if (tamper) familiarity[database] = AuditFamiliarity(trusted = false) else familiarity.remove(database)
        advanceAnchor()
    }

    // Two-phase clear: the pending marker is committed before the wipe so a crash
    // between the DB commit and the anchor reset is recoverable (see reconcile).
    suspend fun clear(extraInTransaction: (suspend () -> Unit)? = null): Unit = mutex.withLock {
        Nip55Database.setAuditClearPending()
        database.withTransaction {
            auditDao.deleteAll()
            extraInTransaction?.invoke()
        }
        Nip55Database.resetAuditAnchor()
        familiarity.remove(database)
    }

    // Atomic read of rows + anchor + tamper flag under the same lock every write takes,
    // so no append/prune/clear can interleave between the reads and skew the snapshot.
    suspend fun snapshot(): Triple<List<Nip55AuditLog>, AuditAnchor?, Boolean> = mutex.withLock {
        val state = reconcile()
        // The verify pass sees an unreadable read too, and the next write is not
        // guaranteed to see it again: the only other record is the corrupted entry
        // itself, which whoever wrote it can replace. Record it where it is sticky.
        if (state.unreadable) {
            Nip55Database.setAuditTamperDetected()
            familiarity[database] = AuditFamiliarity(trusted = false)
        }
        Triple(auditDao.getAllOrdered(), state.anchor, state.tamperDetected)
    }

    // A verification that found the chain broken withdraws familiarity until the log is
    // cleared or pruned, as a broken chain found while building it would.
    suspend fun distrust() = mutex.withLock {
        familiarity[database] = AuditFamiliarity(trusted = false)
    }

    // Whether this caller has a standing approval for this kind. The first call verifies
    // the whole chain under the lock, with [chainIntact] judging the rows, the anchor and
    // the tamper flag, and every append after it updates the result from the row it wrote.
    // So a query costs a lookup rather than a walk of a log any calling app can grow. A
    // chain that does not verify stays untrusted until it is cleared or pruned.
    suspend fun familiar(
        callerPackage: String,
        eventKind: Int,
        chainIntact: (List<Nip55AuditLog>, AuditAnchor?, Boolean) -> Boolean
    ): Boolean = mutex.withLock {
        val known = familiarity[database] ?: run {
            val state = reconcile()
            if (state.unreadable) Nip55Database.setAuditTamperDetected()
            val rows = auditDao.getAllOrdered()
            val trusted = !state.unreadable && chainIntact(rows, state.anchor, state.tamperDetected)
            AuditFamiliarity(trusted).also { built ->
                if (trusted) rows.forEach(built::add)
                familiarity[database] = built
            }
        }
        known.signed(callerPackage, eventKind)
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

        // Per database, guarded by [mutex]: every writer of a database shares one, since
        // more than one writer instance appends to the same log.
        private val familiarity = java.util.WeakHashMap<Nip55Database, AuditFamiliarity>()
    }
}

/**
 * Which callers have a standing approval for which kinds, over rows in id order. Rows
 * without a MAC count for nothing, and an approval followed by an abandoned row with its
 * request id, caller and kind no longer counts, because its caller was told it was
 * refused. An untrusted instance answers no for everything.
 */
internal class AuditFamiliarity(val trusted: Boolean) {
    private val approvals = HashMap<Pair<String, Int?>, Int>()
    private val byRequestId = HashMap<String, Pair<String, Int?>>()

    fun add(row: Nip55AuditLog) {
        if (!trusted || row.entryHash.isEmpty()) return
        val key = row.callerPackage to row.eventKind
        val requestId = row.requestId
        when (row.decision) {
            "allow" -> {
                approvals.merge(key, 1, Int::plus)
                if (requestId != null) byRequestId[requestId] = key
            }
            AUDIT_DECISION_ABANDONED -> if (requestId != null && byRequestId[requestId] == key) {
                byRequestId.remove(requestId)
                approvals.computeIfPresent(key) { _, n -> (n - 1).takeIf { it > 0 } }
            }
        }
    }

    fun signed(callerPackage: String, eventKind: Int): Boolean =
        trusted && (approvals[callerPackage to eventKind] ?: 0) > 0
}
