package io.privkey.keep.nip55

import android.os.SystemClock
import androidx.room.withTransaction
import io.privkey.keep.uniffi.Nip55AuditEntry
import io.privkey.keep.uniffi.Nip55ChainStatus
import io.privkey.keep.uniffi.Nip55PermissionDecision
import io.privkey.keep.uniffi.Nip55PermissionDuration
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55StoredPermission
import io.privkey.keep.uniffi.Nip55VelocityResult
import io.privkey.keep.uniffi.nip55AuditEntryHash
import io.privkey.keep.uniffi.nip55CheckVelocity
import io.privkey.keep.uniffi.nip55EffectiveGrantDuration
import io.privkey.keep.uniffi.nip55ResolveDecision
import io.privkey.keep.uniffi.nip55VerifyAuditChain

private const val MINUTE_MS = 60 * 1000L
private const val HOUR_MS = 60 * MINUTE_MS
private const val DAY_MS = 24 * HOUR_MS
private const val WEEK_MS = 7 * DAY_MS

class PermissionStore(private val database: Nip55Database) {
    private val dao = database.permissionDao()
    private val auditDao = database.auditLogDao()
    private val appSettingsDao = database.appSettingsDao()
    private val velocityDao = database.velocityDao()
    private val auditWriter = AuditLogWriter(database)

    val riskAssessor: RiskAssessor by lazy { RiskAssessor(auditDao, appSettingsDao) }

    suspend fun cleanupExpired() {
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        auditWriter.prune(now - 30 * DAY_MS) {
            dao.deleteExpired(now, nowElapsed)
            dao.deleteNip46Permissions()
            val expiredPackages = appSettingsDao.getExpiredPackages(now, nowElapsed)
            expiredPackages.forEach { pkg ->
                dao.deleteForCaller(pkg)
            }
            appSettingsDao.deleteExpired(now, nowElapsed)
        }
    }

    // Decision resolution (incl. the rule that sensitive kinds never fall back
    // to a generic grant) lives in Rust; Android fetches the candidate rows and
    // supplies the clock readings.
    /**
     * The raw standing-permission candidate rows (exact, generic) for a request,
     * with the relay-scoped specific-then-wildcard selection applied. The
     * allow/deny/ask resolution over these rows lives in Rust
     * (`nip55_resolve_decision`); this only loads the candidates.
     */
    suspend fun getPermissionCandidates(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int? = null,
        relay: String = RELAY_NONE
    ): Pair<Nip55StoredPermission?, Nip55StoredPermission?> {
        val storedKind = eventKind ?: EVENT_KIND_GENERIC
        val nowElapsed = SystemClock.elapsedRealtime()
        val now = System.currentTimeMillis()
        val exact = if (relay.isNotEmpty()) {
            // Relay-scoped (kind 22242): the specific relay first, then the all-relays
            // wildcard. An expired specific row must NOT shadow a still-valid wildcard,
            // so fall back to the wildcard when the specific row is absent or expired.
            dao.getPermission(callerPackage, requestType.name, storedKind, relay)
                ?.takeUnless { it.isExpired(nowElapsed, now) }
                ?: dao.getPermission(callerPackage, requestType.name, storedKind, RELAY_WILDCARD)
        } else {
            dao.getPermission(callerPackage, requestType.name, storedKind, RELAY_NONE)
        }
        val generic = if (eventKind != null) {
            dao.getPermission(callerPackage, requestType.name, EVENT_KIND_GENERIC, RELAY_NONE)
        } else {
            null
        }
        return exact?.toStoredPermission() to generic?.toStoredPermission()
    }

    suspend fun getPermissionDecision(callerPackage: String, requestType: Nip55RequestType, eventKind: Int? = null, relay: String = RELAY_NONE): PermissionDecision? {
        val (exact, generic) = getPermissionCandidates(callerPackage, requestType, eventKind, relay)
        return nip55ResolveDecision(
            exact,
            generic,
            eventKind,
            SystemClock.elapsedRealtime(),
            System.currentTimeMillis()
        )?.toPermissionDecision()
    }

    suspend fun grantPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration,
        relay: String = RELAY_NONE
    ) {
        require(callerPackage.isNotBlank()) { "callerPackage must not be blank" }
        // Sensitive-kind FOREVER -> ONE_DAY clamp lives in Rust.
        val effectiveDuration = nip55EffectiveGrantDuration(eventKind, duration.toUniffi()).toDomain()
        savePermission(callerPackage, requestType, eventKind, effectiveDuration, "allow", relay)
    }

    suspend fun denyPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration,
        relay: String = RELAY_NONE
    ) {
        require(callerPackage.isNotBlank()) { "callerPackage must not be blank" }
        savePermission(callerPackage, requestType, eventKind, duration, "deny", relay)
    }

    private suspend fun savePermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration,
        decision: String,
        relay: String = RELAY_NONE
    ) {
        if (!duration.shouldPersist) return
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        @Suppress("DEPRECATION")
        dao.insertPermission(
            Nip55Permission(
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = eventKind ?: EVENT_KIND_GENERIC,
                relay = relay,
                decision = decision,
                expiresAt = duration.expiresAt(),
                createdAt = now,
                createdAtElapsed = nowElapsed,
                durationMs = duration.millis
            )
        )
    }

    suspend fun revokePermission(callerPackage: String, requestType: Nip55RequestType? = null, eventKind: Int? = null) {
        when {
            requestType == null -> dao.deleteForCaller(callerPackage)
            else -> dao.deleteForCallerAndTypeAndEventKind(callerPackage, requestType.name, eventKind ?: EVENT_KIND_GENERIC)
        }
    }

    suspend fun logOperation(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
        wasAutomatic: Boolean
    ) = logOperation(callerPackage, requestType, eventKind, decision, wasAutomatic, null)

    // [extraInTransaction] lets a related permission write commit atomically with the
    // audit row in a single Room transaction; the anchor is advanced only once that
    // transaction durably commits.
    private suspend fun logOperation(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
        wasAutomatic: Boolean,
        extraInTransaction: (suspend () -> Unit)?
    ) {
        val normalizedEventKind = eventKind ?: EVENT_KIND_GENERIC
        val timestamp = System.currentTimeMillis()
        auditWriter.append({ previousHash ->
            Nip55AuditLog(
                timestamp = timestamp,
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = normalizedEventKind,
                decision = decision,
                wasAutomatic = wasAutomatic,
                previousHash = previousHash,
                entryHash = calculateEntryHash(
                    previousHash = previousHash,
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = normalizedEventKind,
                    decision = decision,
                    timestamp = timestamp,
                    wasAutomatic = wasAutomatic
                )
            )
        }, extraInTransaction)
    }

    /**
     * Record a self-initiated key-management operation (e.g. a private-key export)
     * in the tamper-evident activity log. Unlike [logOperation] this is not an
     * external NIP-55 request, so it uses the reserved [SELF_CALLER] sentinel (not
     * a real package name) and a fixed "allow" decision. Exporting a private key is
     * a high-sensitivity action that must always be audited.
     */
    suspend fun logKeyExport(operation: String) = logSelfEvent(operation)

    /**
     * Record a self-initiated, security-sensitive event (not an external NIP-55
     * request) in the tamper-evident activity log, using the reserved [SELF_CALLER]
     * sentinel and a fixed "allow" decision. [operation] names the event (see the
     * AUDIT_OP_* constants). Used for key exports and for account-lifecycle events
     * (switch, delete) so that operations leaving no NIP-55 request still leave an
     * audit trail.
     */
    suspend fun logSelfEvent(operation: String) {
        val timestamp = System.currentTimeMillis()
        auditWriter.append({ previousHash ->
            Nip55AuditLog(
                timestamp = timestamp,
                callerPackage = SELF_CALLER,
                requestType = operation,
                eventKind = EVENT_KIND_GENERIC,
                decision = "allow",
                wasAutomatic = false,
                previousHash = previousHash,
                entryHash = calculateEntryHash(
                    previousHash = previousHash,
                    callerPackage = SELF_CALLER,
                    requestType = operation,
                    eventKind = EVENT_KIND_GENERIC,
                    decision = "allow",
                    timestamp = timestamp,
                    wasAutomatic = false
                )
            )
        }, null)
    }

    // The hourly/daily/weekly limit thresholds + block decision live in Rust;
    // Android keeps the per-request velocity event log (Room) and feeds the
    // window counts in.
    suspend fun checkAndRecordVelocity(packageName: String, eventKind: Int?, enabled: Boolean = true): VelocityResult {
        if (!enabled) return VelocityResult.Allowed

        return database.withTransaction {
            val now = System.currentTimeMillis()
            val hourly = velocityDao.countSince(packageName, now - HOUR_MS)
            val daily = velocityDao.countSince(packageName, now - DAY_MS)
            val weekly = velocityDao.countSince(packageName, now - WEEK_MS)

            when (val decision = nip55CheckVelocity(hourly.toUInt(), daily.toUInt(), weekly.toUInt())) {
                is Nip55VelocityResult.Blocked -> {
                    val oldest = velocityDao.getOldestInWindow(packageName, now - decision.windowMs)
                    VelocityResult.Blocked(decision.reason, (oldest ?: now) + decision.windowMs)
                }
                Nip55VelocityResult.Allowed -> {
                    velocityDao.insert(VelocityEntry(packageName = packageName, timestamp = now, eventKind = eventKind))
                    velocityDao.deleteOlderThan(now - WEEK_MS)
                    VelocityResult.Allowed
                }
            }
        }
    }

    suspend fun getVelocityUsage(packageName: String): Triple<Int, Int, Int> {
        val now = System.currentTimeMillis()
        return Triple(
            velocityDao.countSince(packageName, now - HOUR_MS),
            velocityDao.countSince(packageName, now - DAY_MS),
            velocityDao.countSince(packageName, now - WEEK_MS)
        )
    }

    // Chain verification (keyed-HMAC walk: legacy/truncated/broken/tampered) lives
    // in Rust; Android supplies the ordered rows and the keystore HMAC key.
    suspend fun verifyAuditChain(): ChainVerificationResult {
        val hmacKey = Nip55Database.getHmacKey()
            ?: throw IllegalStateException("HMAC key not initialized - cannot verify audit chain")
        // Read rows + anchor + tamper flag atomically under the audit write lock so no
        // concurrent append/prune/clear can interleave between the reads. The Rust walk and
        // all reconciliation then run outside the lock on this consistent snapshot.
        val (entries, anchor, tamperDetected) = auditWriter.snapshot()
        val rustResult = nip55VerifyAuditChain(
            entries.map { it.toRustAuditEntry() }, hmacKey
        ).toChainVerificationResult()
        val latest = entries.lastOrNull()
        val count = entries.size.toLong()
        val latestHash = latest?.entryHash ?: ""
        val latestId = latest?.id ?: 0L
        if (anchor == null) {
            if (tamperDetected) return ChainVerificationResult.Tampered(latestId)
            // First verify on an upgraded/fresh install: trust-on-first-use seed the
            // anchor from the current intact tail rather than flagging it.
            if (shouldSeed(anchor, rustResult)) {
                auditWriter.reconcileAnchor(count, latestHash)
            }
            return rustResult
        }
        val rustIntact = rustResult is ChainVerificationResult.Valid ||
            rustResult is ChainVerificationResult.PartiallyVerified
        // A crash between the row insert and the post-commit anchor advance leaves a legit
        // row durable with the anchor trailing by one; heal it rather than report Tampered.
        if (!tamperDetected &&
            isResumableAppend(anchor, count, latest?.previousHash, latestHash, rustIntact)
        ) {
            auditWriter.reconcileAnchor(count, latestHash)
            return rustResult
        }
        // A crash between a head prune commit and its anchor advance leaves fewer rows with
        // the tail unchanged; re-pin to the lower count. Tail truncation changes the tail
        // hash, so it falls through to resolveChainVerification and is still flagged.
        if (!tamperDetected && isResumablePrune(anchor, count, latestHash, rustIntact)) {
            auditWriter.reconcileAnchor(count, latestHash)
            return rustResult
        }
        return resolveChainVerification(
            tamperDetected,
            anchor,
            count,
            latestHash,
            latestId,
            rustResult
        )
    }

    suspend fun getAuditLogCount(): Int = auditDao.getCount()

    suspend fun getAllPermissions(): List<Nip55Permission> = dao.getAll()

    suspend fun getAuditLog(limit: Int = 100): List<Nip55AuditLog> = auditDao.getRecent(limit)

    suspend fun getConnectedApps(): List<ConnectedAppInfo> {
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        val packages = dao.getAllCallerPackages(now, nowElapsed)
        return packages.map { pkg ->
            val appSettings = appSettingsDao.getSettings(pkg)
            ConnectedAppInfo(
                packageName = pkg,
                permissionCount = dao.getPermissionCountForCaller(pkg, now, nowElapsed),
                lastUsedTime = auditDao.getLastUsedTime(pkg),
                expiresAt = appSettings?.expiresAt
            )
        }.sortedByDescending { it.lastUsedTime ?: 0L }
    }

    suspend fun getAppSettings(callerPackage: String): Nip55AppSettings? =
        appSettingsDao.getSettings(callerPackage)

    suspend fun setAppExpiry(callerPackage: String, duration: AppExpiryDuration) {
        @Suppress("DEPRECATION")
        val expiresAt = duration.expiresAt()
        val existing = appSettingsDao.getSettings(callerPackage)
        if (expiresAt == null && existing?.signPolicyOverride == null) {
            appSettingsDao.delete(callerPackage)
        } else {
            val now = System.currentTimeMillis()
            val nowElapsed = SystemClock.elapsedRealtime()
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = expiresAt,
                    signPolicyOverride = existing?.signPolicyOverride,
                    createdAt = now,
                    createdAtElapsed = nowElapsed,
                    durationMs = duration.millis
                )
            )
        }
    }

    suspend fun isAppExpired(callerPackage: String): Boolean {
        val settings = appSettingsDao.getSettings(callerPackage) ?: return false
        return settings.isExpired()
    }

    suspend fun getPermissionsForCaller(callerPackage: String): List<Nip55Permission> =
        dao.getForCaller(callerPackage, System.currentTimeMillis(), SystemClock.elapsedRealtime())

    suspend fun deletePermission(id: Long) = dao.deleteById(id)

    suspend fun updatePermissionDecision(
        id: Long,
        decision: PermissionDecision,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        val permission = dao.getById(id) ?: throw IllegalArgumentException("Permission not found: $id")
        if (permission.callerPackage != callerPackage) {
            throw IllegalArgumentException("CallerPackage mismatch for permission $id")
        }
        if (permission.requestType != requestType.name) {
            throw IllegalArgumentException("RequestType mismatch for permission $id: expected ${permission.requestType}, got ${requestType.name}")
        }
        val storedRequestType = findRequestType(permission.requestType)
            ?: throw IllegalArgumentException("Unknown requestType in permission $id: ${permission.requestType}")
        logOperation(permission.callerPackage, storedRequestType, permission.eventKind, decision.toString(), wasAutomatic = false) {
            dao.updateDecision(id, decision.toString())
        }
    }

    suspend fun setPermissionToAsk(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        logOperation(callerPackage, requestType, eventKind, PermissionDecision.ASK.toString(), wasAutomatic = false) {
            dao.insertPermission(
                Nip55Permission(
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = eventKind ?: EVENT_KIND_GENERIC,
                    decision = PermissionDecision.ASK.toString(),
                    expiresAt = null,
                    createdAt = now,
                    createdAtElapsed = nowElapsed,
                    durationMs = null
                )
            )
        }
    }

    suspend fun revokeAllForApp(callerPackage: String) = dao.deleteForCaller(callerPackage)

    suspend fun revokeAllPermissions() = dao.deleteAll()

    suspend fun clearAllAppSettings() = appSettingsDao.deleteAll()

    suspend fun clearAllVelocity() = velocityDao.deleteAll()

    suspend fun clearAuditLog() = auditWriter.clear()

    suspend fun getDistinctPermissionCallers(): List<String> = dao.getDistinctCallers()

    suspend fun getAuditLogPage(
        limit: Int,
        offset: Int,
        callerPackage: String? = null
    ): List<Nip55AuditLog> {
        val safeLimit = limit.coerceIn(1, 100)
        val safeOffset = offset.coerceAtLeast(0)
        return if (callerPackage != null) {
            auditDao.getPageForCaller(callerPackage, safeLimit, safeOffset)
        } else {
            auditDao.getPage(safeLimit, safeOffset)
        }
    }

    suspend fun getDistinctAuditCallers(): List<String> = auditDao.getDistinctCallers()

    suspend fun getLastUsedTimeForPermission(
        callerPackage: String,
        requestType: String,
        eventKind: Int?
    ): Long? = auditDao.getLastUsedTimeForPermission(callerPackage, requestType, eventKind ?: EVENT_KIND_GENERIC)

    suspend fun getAppSignPolicyOverride(callerPackage: String): Int? =
        appSettingsDao.getSettings(callerPackage)?.signPolicyOverride

    suspend fun setAppSignPolicyOverride(callerPackage: String, signPolicyOrdinal: Int?) {
        val existing = appSettingsDao.getSettings(callerPackage)
        if (signPolicyOrdinal == null && existing?.expiresAt == null) {
            appSettingsDao.delete(callerPackage)
        } else {
            val now = System.currentTimeMillis()
            val nowElapsed = SystemClock.elapsedRealtime()
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = existing?.expiresAt,
                    signPolicyOverride = signPolicyOrdinal,
                    createdAt = existing?.createdAt ?: now,
                    createdAtElapsed = existing?.createdAtElapsed ?: nowElapsed,
                    durationMs = existing?.durationMs
                )
            )
        }
    }

    suspend fun clearAppSettings(callerPackage: String) {
        appSettingsDao.delete(callerPackage)
    }

    suspend fun hasSignedKindBefore(callerPackage: String, eventKind: Int): Boolean =
        auditDao.countByPackageAndKind(callerPackage, eventKind) > 0

    suspend fun getAppAgeMs(callerPackage: String): Long? =
        riskAssessor.getAppAgeMs(callerPackage)
}

fun formatRequestType(type: String): String =
    type.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }

fun formatRelativeTime(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < MINUTE_MS -> "just now"
        diff < HOUR_MS -> "${diff / MINUTE_MS}m ago"
        diff < DAY_MS -> "${diff / HOUR_MS}h ago"
        diff < WEEK_MS -> "${diff / DAY_MS}d ago"
        else -> java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(timestamp))
    }
}

fun findRequestType(name: String): Nip55RequestType? =
    Nip55RequestType.entries.find { it.name == name }

fun formatExpiry(timestamp: Long): String {
    val remaining = timestamp - System.currentTimeMillis()
    return when {
        remaining <= 0 -> "expired"
        remaining < MINUTE_MS -> "<1m"
        remaining < HOUR_MS -> "in ${remaining / MINUTE_MS}m"
        remaining < DAY_MS -> "in ${remaining / HOUR_MS}h"
        remaining < WEEK_MS -> "in ${remaining / DAY_MS}d"
        else -> java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(timestamp))
    }
}

private fun calculateEntryHash(
    previousHash: String?,
    callerPackage: String,
    requestType: String,
    eventKind: Int?,
    decision: String,
    timestamp: Long,
    wasAutomatic: Boolean
): String {
    val hmacKey = Nip55Database.getHmacKey()
        ?: throw IllegalStateException("HMAC key not initialized - cannot compute audit entry hash")
    return nip55AuditEntryHash(
        previousHash,
        callerPackage,
        requestType,
        eventKind,
        decision,
        timestamp,
        wasAutomatic,
        hmacKey
    )
}

private fun Nip55AuditLog.toRustAuditEntry(): Nip55AuditEntry =
    Nip55AuditEntry(
        id = id,
        timestamp = timestamp,
        caller = callerPackage,
        requestType = requestType,
        eventKind = eventKind,
        decision = decision,
        wasAutomatic = wasAutomatic,
        previousHash = previousHash,
        entryHash = entryHash
    )

private fun Nip55ChainStatus.toChainVerificationResult(): ChainVerificationResult =
    when (this) {
        is Nip55ChainStatus.Valid -> ChainVerificationResult.Valid
        is Nip55ChainStatus.PartiallyVerified ->
            ChainVerificationResult.PartiallyVerified(legacyEntriesSkipped.toInt())
        is Nip55ChainStatus.Truncated -> ChainVerificationResult.Truncated(entryId)
        is Nip55ChainStatus.Broken -> ChainVerificationResult.Broken(entryId)
        is Nip55ChainStatus.Tampered -> ChainVerificationResult.Tampered(entryId)
    }

private fun Nip55Permission.toStoredPermission(): Nip55StoredPermission =
    Nip55StoredPermission(
        decision = decision,
        expiresAt = expiresAt,
        createdAt = createdAt,
        createdAtElapsed = createdAtElapsed,
        durationMs = durationMs
    )

private fun Nip55PermissionDecision.toPermissionDecision(): PermissionDecision =
    when (this) {
        Nip55PermissionDecision.ALLOW -> PermissionDecision.ALLOW
        Nip55PermissionDecision.DENY -> PermissionDecision.DENY
        Nip55PermissionDecision.ASK -> PermissionDecision.ASK
    }

private fun PermissionDuration.toUniffi(): Nip55PermissionDuration =
    when (this) {
        PermissionDuration.JUST_THIS_TIME -> Nip55PermissionDuration.JUST_THIS_TIME
        PermissionDuration.ONE_MINUTE -> Nip55PermissionDuration.ONE_MINUTE
        PermissionDuration.FIVE_MINUTES -> Nip55PermissionDuration.FIVE_MINUTES
        PermissionDuration.TEN_MINUTES -> Nip55PermissionDuration.TEN_MINUTES
        PermissionDuration.ONE_HOUR -> Nip55PermissionDuration.ONE_HOUR
        PermissionDuration.ONE_DAY -> Nip55PermissionDuration.ONE_DAY
        PermissionDuration.FOREVER -> Nip55PermissionDuration.FOREVER
    }

private fun Nip55PermissionDuration.toDomain(): PermissionDuration =
    when (this) {
        Nip55PermissionDuration.JUST_THIS_TIME -> PermissionDuration.JUST_THIS_TIME
        Nip55PermissionDuration.ONE_MINUTE -> PermissionDuration.ONE_MINUTE
        Nip55PermissionDuration.FIVE_MINUTES -> PermissionDuration.FIVE_MINUTES
        Nip55PermissionDuration.TEN_MINUTES -> PermissionDuration.TEN_MINUTES
        Nip55PermissionDuration.ONE_HOUR -> PermissionDuration.ONE_HOUR
        Nip55PermissionDuration.ONE_DAY -> PermissionDuration.ONE_DAY
        Nip55PermissionDuration.FOREVER -> PermissionDuration.FOREVER
    }
