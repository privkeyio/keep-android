package io.privkey.keep.nip55

import androidx.room.withTransaction
import io.privkey.keep.uniffi.Nip55RequestType
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val HOUR_MS = 60 * 60 * 1000L
private const val DAY_MS = 24 * HOUR_MS
private const val WEEK_MS = 7 * DAY_MS

class PermissionStore(private val database: Nip55Database) {
    private val dao = database.permissionDao()
    private val auditDao = database.auditLogDao()
    private val appSettingsDao = database.appSettingsDao()
    private val velocityDao = database.velocityDao()

    suspend fun cleanupExpired() {
        val now = System.currentTimeMillis()
        dao.deleteExpired(now)
        auditDao.deleteOlderThan(now - 30L * 24 * 60 * 60 * 1000)
        val expiredPackages = appSettingsDao.getExpiredPackages(now)
        expiredPackages.forEach { pkg ->
            dao.deleteForCaller(pkg)
        }
        appSettingsDao.deleteExpired(now)
    }

    suspend fun getPermissionDecision(callerPackage: String, requestType: Nip55RequestType, eventKind: Int? = null): PermissionDecision? {
        val storedKind = eventKind ?: EVENT_KIND_GENERIC
        val permission = dao.getPermission(callerPackage, requestType.name, storedKind)
        if (permission != null && !permission.isExpired()) return permission.permissionDecision

        if (eventKind != null && !isSensitiveKind(eventKind)) {
            val genericPermission = dao.getPermission(callerPackage, requestType.name, EVENT_KIND_GENERIC)
            if (genericPermission != null && !genericPermission.isExpired()) return genericPermission.permissionDecision
        }
        return null
    }

    suspend fun grantPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration
    ) {
        val effectiveDuration = if (eventKind != null && isSensitiveKind(eventKind) && duration == PermissionDuration.FOREVER) {
            PermissionDuration.ONE_DAY
        } else {
            duration
        }
        savePermission(callerPackage, requestType, eventKind, effectiveDuration, "allow")
    }

    suspend fun denyPermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration
    ) = savePermission(callerPackage, requestType, eventKind, duration, "deny")

    private suspend fun savePermission(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        duration: PermissionDuration,
        decision: String
    ) {
        if (!duration.shouldPersist) return
        dao.insertPermission(
            Nip55Permission(
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = eventKind ?: EVENT_KIND_GENERIC,
                decision = decision,
                expiresAt = duration.expiresAt(),
                createdAt = System.currentTimeMillis()
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
    ) {
        val normalizedEventKind = eventKind ?: EVENT_KIND_GENERIC
        database.withTransaction {
            val previousHash = auditDao.getLastEntryHash()
            val timestamp = System.currentTimeMillis()
            val entryHash = calculateEntryHash(
                previousHash = previousHash,
                callerPackage = callerPackage,
                requestType = requestType.name,
                eventKind = normalizedEventKind,
                decision = decision,
                timestamp = timestamp,
                wasAutomatic = wasAutomatic
            )
            auditDao.insert(
                Nip55AuditLog(
                    timestamp = timestamp,
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = normalizedEventKind,
                    decision = decision,
                    wasAutomatic = wasAutomatic,
                    previousHash = previousHash,
                    entryHash = entryHash
                )
            )
        }
    }

    suspend fun checkAndRecordVelocity(packageName: String, eventKind: Int?, config: VelocityConfig = VelocityConfig()): VelocityResult {
        if (!config.enabled) return VelocityResult.Allowed

        return database.withTransaction {
            val now = System.currentTimeMillis()

            checkLimit(packageName, now, HOUR_MS, config.hourlyLimit, "Hourly")?.let { return@withTransaction it }
            checkLimit(packageName, now, DAY_MS, config.dailyLimit, "Daily")?.let { return@withTransaction it }
            checkLimit(packageName, now, WEEK_MS, config.weeklyLimit, "Weekly")?.let { return@withTransaction it }

            velocityDao.insert(VelocityEntry(packageName = packageName, timestamp = now, eventKind = eventKind))
            velocityDao.deleteOlderThan(now - WEEK_MS)

            VelocityResult.Allowed
        }
    }

    private suspend fun checkLimit(packageName: String, now: Long, windowMs: Long, limit: Int, label: String): VelocityResult.Blocked? {
        val count = velocityDao.countSince(packageName, now - windowMs)
        if (count < limit) return null
        val oldest = velocityDao.getOldestInWindow(packageName, now - windowMs)
        return VelocityResult.Blocked("$label limit ($count/$limit)", (oldest ?: now) + windowMs)
    }

    suspend fun getVelocityUsage(packageName: String): Triple<Int, Int, Int> {
        val now = System.currentTimeMillis()
        return Triple(
            velocityDao.countSince(packageName, now - HOUR_MS),
            velocityDao.countSince(packageName, now - DAY_MS),
            velocityDao.countSince(packageName, now - WEEK_MS)
        )
    }

    suspend fun verifyAuditChain(): ChainVerificationResult {
        val entries = auditDao.getAllOrdered()
        val knownHashes = entries.mapNotNullTo(mutableSetOf()) { it.entryHash.takeIf { h -> h.isNotEmpty() } }
        var inLegacyPhase = true
        var legacyEntriesSkipped = 0
        var truncated = false
        var expectedPrevHash: String? = null

        for (entry in entries) {
            if (inLegacyPhase) {
                if (entry.entryHash.isEmpty()) {
                    legacyEntriesSkipped++
                    continue
                }
                inLegacyPhase = false
                if (!entry.previousHash.isNullOrEmpty()) {
                    if (entry.previousHash !in knownHashes) {
                        truncated = true
                    } else {
                        return ChainVerificationResult.Broken(entry.id)
                    }
                }
            } else {
                if (entry.entryHash.isEmpty()) {
                    return ChainVerificationResult.Broken(entry.id)
                }
                if (!constantTimeEquals(entry.previousHash, expectedPrevHash)) {
                    return ChainVerificationResult.Broken(entry.id)
                }
            }

            val calculated = calculateEntryHash(
                previousHash = entry.previousHash,
                callerPackage = entry.callerPackage,
                requestType = entry.requestType,
                eventKind = entry.eventKind,
                decision = entry.decision,
                timestamp = entry.timestamp,
                wasAutomatic = entry.wasAutomatic
            )
            if (!constantTimeEquals(calculated, entry.entryHash)) {
                return ChainVerificationResult.Tampered(entry.id)
            }

            expectedPrevHash = entry.entryHash
        }

        return when {
            truncated -> ChainVerificationResult.Truncated(entries.first { it.entryHash.isNotEmpty() }.id)
            legacyEntriesSkipped > 0 -> ChainVerificationResult.PartiallyVerified(legacyEntriesSkipped)
            else -> ChainVerificationResult.Valid
        }
    }

    suspend fun getAuditLogCount(): Int = auditDao.getCount()

    suspend fun getAllPermissions(): List<Nip55Permission> = dao.getAll()

    suspend fun getAuditLog(limit: Int = 100): List<Nip55AuditLog> = auditDao.getRecent(limit)

    suspend fun getConnectedApps(): List<ConnectedAppInfo> {
        val now = System.currentTimeMillis()
        val packages = dao.getAllCallerPackages(now)
        return packages.map { pkg ->
            val appSettings = appSettingsDao.getSettings(pkg)
            ConnectedAppInfo(
                packageName = pkg,
                permissionCount = dao.getPermissionCountForCaller(pkg, now),
                lastUsedTime = auditDao.getLastUsedTime(pkg),
                expiresAt = appSettings?.expiresAt
            )
        }.sortedByDescending { it.lastUsedTime ?: 0L }
    }

    suspend fun getAppSettings(callerPackage: String): Nip55AppSettings? =
        appSettingsDao.getSettings(callerPackage)

    suspend fun setAppExpiry(callerPackage: String, duration: AppExpiryDuration) {
        val expiresAt = duration.expiresAt()
        val existing = appSettingsDao.getSettings(callerPackage)
        if (expiresAt == null && existing?.signPolicyOverride == null) {
            appSettingsDao.delete(callerPackage)
        } else {
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = expiresAt,
                    signPolicyOverride = existing?.signPolicyOverride,
                    createdAt = System.currentTimeMillis()
                )
            )
        }
    }

    suspend fun isAppExpired(callerPackage: String): Boolean {
        val settings = appSettingsDao.getSettings(callerPackage) ?: return false
        return settings.isExpired()
    }

    suspend fun getPermissionsForCaller(callerPackage: String): List<Nip55Permission> =
        dao.getForCaller(callerPackage, System.currentTimeMillis())

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
        database.withTransaction {
            dao.updateDecision(id, decision.toString())
            logOperation(permission.callerPackage, storedRequestType, permission.eventKind, decision.toString(), wasAutomatic = false)
        }
    }

    suspend fun setPermissionToAsk(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        database.withTransaction {
            dao.insertPermission(
                Nip55Permission(
                    callerPackage = callerPackage,
                    requestType = requestType.name,
                    eventKind = eventKind ?: EVENT_KIND_GENERIC,
                    decision = PermissionDecision.ASK.toString(),
                    expiresAt = null,
                    createdAt = System.currentTimeMillis()
                )
            )
            logOperation(callerPackage, requestType, eventKind, PermissionDecision.ASK.toString(), wasAutomatic = false)
        }
    }

    suspend fun revokeAllForApp(callerPackage: String) = dao.deleteForCaller(callerPackage)

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
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = existing?.expiresAt,
                    signPolicyOverride = signPolicyOrdinal,
                    createdAt = existing?.createdAt ?: System.currentTimeMillis()
                )
            )
        }
    }

    suspend fun clearAppSettings(callerPackage: String) {
        appSettingsDao.delete(callerPackage)
    }
}

fun formatRequestType(type: String): String =
    type.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }

fun formatRelativeTime(timestamp: Long): String {
    val diff = System.currentTimeMillis() - timestamp
    return when {
        diff < 60_000 -> "just now"
        diff < 3600_000 -> "${diff / 60_000}m ago"
        diff < 86400_000 -> "${diff / 3600_000}h ago"
        diff < 604800_000 -> "${diff / 86400_000}d ago"
        else -> java.text.SimpleDateFormat("MMM d", java.util.Locale.getDefault()).format(java.util.Date(timestamp))
    }
}

fun findRequestType(name: String): Nip55RequestType? =
    Nip55RequestType.entries.find { it.name == name }

fun formatExpiry(timestamp: Long): String {
    val remaining = timestamp - System.currentTimeMillis()
    return when {
        remaining <= 0 -> "expired"
        remaining < 60_000 -> "<1m"
        remaining < 3600_000 -> "in ${remaining / 60_000}m"
        remaining < 86400_000 -> "in ${remaining / 3600_000}h"
        remaining < 604800_000 -> "in ${remaining / 86400_000}d"
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
    val content = "${previousHash ?: ""}|$callerPackage|$requestType|${eventKind ?: ""}|$decision|$timestamp|$wasAutomatic"
    val hmacKey = Nip55Database.getHmacKey()
        ?: throw IllegalStateException("HMAC key not initialized - cannot compute audit entry hash")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))
    val hashBytes = mac.doFinal(content.toByteArray(Charsets.UTF_8))
    return hashBytes.joinToString("") { "%02x".format(it) }
}

private fun constantTimeEquals(a: String?, b: String?): Boolean {
    if (a == null && b == null) return true
    if (a == null || b == null) return false
    return MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}
