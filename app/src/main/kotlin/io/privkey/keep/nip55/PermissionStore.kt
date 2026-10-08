package io.privkey.keep.nip55

import android.os.SystemClock
import android.util.Log
import androidx.room.withTransaction
import io.privkey.keep.BuildConfig
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.uniffi.Nip55AuditEntry
import io.privkey.keep.uniffi.Nip55ChainStatus
import io.privkey.keep.uniffi.Nip55PermissionDecision
import io.privkey.keep.uniffi.Nip55PermissionDuration
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55StoredPermission
import io.privkey.keep.uniffi.Nip55VelocityResult
import io.privkey.keep.uniffi.SignPolicyStore
import io.privkey.keep.uniffi.nip55AuditEntryHash
import io.privkey.keep.uniffi.nip55CheckVelocity
import io.privkey.keep.uniffi.nip55EffectiveGrantDuration
import io.privkey.keep.uniffi.nip55ResolveDecision
import io.privkey.keep.uniffi.nip55VerifyAuditChain
import kotlinx.coroutines.CancellationException

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

    /**
     * Retires what an expired app-settings window granted, so the app has to be approved
     * again rather than dropping back to the global policy.
     *
     * Expiry used to LOOSEN. The sweep deleted every permission row for the caller, which
     * took the user's explicit DENY with it, left the per-package auto-signing opt-in
     * intact, and removed the settings row, so `isAppExpired` then reported false and the
     * app resolved to the global policy. Under a global of Auto or Basic that is silent
     * auto-approval for an app whose window had just closed, and for one the user had
     * explicitly refused. A time box must not end in broader access than it granted.
     *
     * So the per-caller delete now spares a DENY and an explicit ASK, both of which are
     * standing instructions about the app written only by the user's own toggle. What the
     * window granted still goes,
     * because an ALLOW may be [PermissionDuration.FOREVER] and would otherwise outlive
     * the window and auto-approve at the stored-permission gate the moment this sweep
     * drops the settings row. A refusal is not part of what was granted, and it carries
     * its own expiry, so it lives exactly as long as the user asked. [autoSigning] clears
     * the opt-in for each expired package, which is what makes re-approval necessary
     * instead of optional.
     *
     * [signPolicyStore] lets the sweep take the core-owned sign-policy override down
     * with the expiring row. Without it a per-app override would outlive its expiry
     * window, since the core store has no expiry of its own.
     *
     * The app-settings rows are deleted one package at a time after the transaction
     * commits, replacing the bulk `deleteExpired`, because a row must not be dropped
     * unless that package's core override is confirmed gone: the row is the only
     * index Kotlin has for it, so deleting it first would orphan the override
     * permanently and invisibly. Each delete re-checks `isExpired` first, which is the
     * predicate the bulk statement applied at delete time, so a row refreshed between
     * the enumeration and the delete is still spared.
     *
     * The clears run outside the transaction: they are blocking keystore and disk
     * commits, and the transaction holds the process-wide audit mutex.
     */
    suspend fun cleanupExpired(
        signPolicyStore: SignPolicyStore? = null,
        autoSigning: AutoSigningSafeguards? = null
    ) {
        val now = System.currentTimeMillis()
        val nowElapsed = SystemClock.elapsedRealtime()
        var expiredPackages = emptyList<String>()
        auditWriter.prune(now - 30 * DAY_MS) {
            dao.deleteExpired(now, nowElapsed)
            dao.deleteNip46Permissions()
            expiredPackages = appSettingsDao.getExpiredPackages(now, nowElapsed)
            expiredPackages.forEach { pkg ->
                // Grants only. An ALLOW can be PermissionDuration.FOREVER, so per-row
                // expiry would never retire it, and once this sweep drops the settings row
                // the app stops being expired and that ALLOW auto-approves at the stored
                // permission gate. A DENY is left alone: it is not part of what the window
                // granted, and it has its own expiry. Nor is an explicit "always ask".
                dao.deleteGrantsForCaller(pkg)
            }
        }
        for (pkg in expiredPackages) {
            val settings = appSettingsDao.getSettings(pkg) ?: continue
            if (!settings.isExpired()) continue
            val cleared = if (signPolicyStore == null) {
                // Nothing can be cleared or confirmed this session. A row carrying no
                // override has no core counterpart to orphan, so it expires as it
                // always did; one that does is left for a sweep that can confirm it.
                settings.signPolicyOverride == null
            } else {
                coreOverrideCleared(signPolicyStore, pkg)
            }
            // Gated the same way as the core clear, and for the same reason: once the row
            // is gone this package never comes back from getExpiredPackages, so neither
            // can be retried. An opt-in left behind is what lets the policy gate
            // auto-approve the app again, which is the whole point of the sweep.
            if (!cleared || !optInCleared(autoSigning, pkg)) continue
            // Re-read before deleting. Both clears above are blocking keystore and disk
            // commits, so the user can refresh this app's window while they run, and the
            // isExpired check at the top of the loop does not cover the delete. This
            // narrows that window to a single read rather than closing it; a refresh
            // landing between this read and the delete still loses the row.
            val current = appSettingsDao.getSettings(pkg) ?: continue
            if (current.isExpired()) appSettingsDao.delete(pkg)
        }
    }

    /**
     * Whether [callerPackage]'s auto-signing opt-in is durably gone.
     *
     * Re-approval, not reset-to-global: an app that keeps its opt-in is auto-approved by
     * whatever the global policy happens to be on its next request. The clear has to be
     * durable rather than fire-and-forget, because the caller drops the settings row on
     * the strength of it and the package cannot be enumerated as expired again afterwards.
     * No safeguards store this session means it cannot be established, which keeps the row
     * for a sweep that can.
     *
     * Deliberately no `isOptedIn` short-circuit. The encrypted prefs return the default
     * when a value cannot be decrypted, so a false read is indistinguishable from an
     * opt-in that is still on disk, and skipping the write on that basis would drop the
     * row while leaving the opt-in to come back when the read recovers. The cost is one
     * removal per expired package.
     */
    private fun optInCleared(autoSigning: AutoSigningSafeguards?, callerPackage: String): Boolean =
        autoSigning?.clearOptIn(callerPackage) ?: false

    /**
     * Clears [callerPackage]'s core-owned sign-policy override and reports whether that
     * clear durably persisted.
     *
     * `setAppOverride` returns the backing store's own `commit()` result, which is the
     * only signal that separates "gone from disk" from "gone from the in-memory map a
     * failed commit left behind". A read-back cannot tell those apart, because the
     * encrypted prefs serve the cached value. Nor can an absent read stand in for
     * proof: a decrypt fault reads identically to absence, so skipping the write on an
     * absent read would declare a live override cleared and drop the row that indexes
     * it. The clear is therefore issued unconditionally, and anything short of a
     * durable `true` leaves the override in place and the caller keeps that row.
     */
    private fun coreOverrideCleared(signPolicyStore: SignPolicyStore, callerPackage: String): Boolean =
        runCatching { signPolicyStore.setAppOverride(callerPackage, null) }.getOrDefault(false)

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

    /**
     * Wipe every app settings row, clearing each package's core sign-policy override
     * first so no override survives an account switch.
     *
     * Every clear is gated on the core's durable-write result, and a row is dropped only
     * when its tier is confirmed gone or when it never carried one. Any other row is kept:
     * the row is the only record that the package still holds a tier, so a later wipe can
     * resume it, and dropping it would strand a tier Kotlin can no longer see and could
     * never clear again.
     *
     * The candidates are the settings rows plus the permission and audit callers. The
     * core store cannot be enumerated, so a tier whose row is already gone
     * is only reachable through some other record of that package.
     */
    suspend fun clearAllAppSettings(signPolicyStore: SignPolicyStore? = null) {
        if (signPolicyStore == null) {
            // Nothing can be cleared or confirmed this session. Rows carrying no override
            // go. A row that carries one has to stay, because it is the only index of a
            // tier still sitting in the core, but it must not hand the next account the
            // previous one's choice: it is rewritten to the strictest tier with no
            // window, which still indexes the tier for a later wipe to clear. The next
            // wipe that has a store retries them, exactly as the expiry sweep does.
            wipeStep("enumerate rows") { appSettingsDao.getAll() }.orEmpty().forEach { row ->
                wipeStep("rewrite ${row.callerPackage}") {
                    if (row.signPolicyOverride == null) {
                        appSettingsDao.delete(row.callerPackage)
                    } else {
                        strictestTombstone(row.callerPackage)
                    }
                }
            }
            return
        }
        val packages = LinkedHashSet<String>()
        // Best effort, and an enumeration that throws only narrows which tiers get
        // cleared: the per-row rule below is safe whether or not the candidate set is
        // complete, so there is nothing to gate on it.
        wipeStep("enumerate settings callers") { appSettingsDao.getAll().forEach { packages.add(it.callerPackage) } }
        wipeStep("enumerate permission callers") { packages.addAll(dao.getDistinctCallers()) }
        wipeStep("enumerate audit callers") { packages.addAll(auditDao.getDistinctCallers()) }

        val cleared = packages.filter { coreOverrideCleared(signPolicyStore, it) }.toSet()
        // A row goes only when its tier is confirmed gone, or when it never carried one.
        // Any other row stays, which keeps its tier indexed: that row resolves to Manual
        // and a later wipe can retry it, whereas deleting it would leave the tier in the
        // core with nothing pointing at it. Re-reading here rather than reusing the
        // snapshot also covers a row that appeared while the clears were running, which a
        // bulk delete would otherwise have un-indexed.
        // Per row, so one failure cannot leave the rest of the previous account's tiers
        // in place. The enumeration is wrapped for the same reason.
        wipeStep("enumerate rows") { appSettingsDao.getAll() }.orEmpty().forEach { row ->
            wipeStep("clear ${row.callerPackage}") {
                if (row.callerPackage in cleared || row.signPolicyOverride == null) {
                    appSettingsDao.delete(row.callerPackage)
                } else {
                    strictestTombstone(row.callerPackage)
                }
            }
        }
    }

    /**
     * One best-effort step of the account-switch wipe.
     *
     * Each step is isolated so a single failure cannot leave the rest of the previous
     * account's tiers in place. Cancellation is rethrown rather than swallowed, so a
     * cancelled switch stops instead of wiping on, and a real failure is logged under
     * DEBUG, because a wipe that silently touched nothing is indistinguishable from a
     * clean one otherwise.
     */
    private inline fun <T> wipeStep(what: String, block: () -> T): T? =
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e("PermissionStore", "account-switch wipe: $what", e)
            null
        }

    /**
     * Rewrite a kept row to the strictest tier with no expiry window.
     *
     * Used by the account-switch wipe for a row it cannot drop, because that row still
     * indexes a tier sitting in the core. Keeping the row as it stands would carry the
     * previous account's choice and its time-boxed window into the new account, and the
     * resolver takes the stricter of row and core, so the row's tier is load-bearing.
     * Manual with no window keeps the tier reachable for a later wipe without granting
     * the new account anything.
     */
    private suspend fun strictestTombstone(callerPackage: String) {
        appSettingsDao.insertOrUpdate(
            Nip55AppSettings(
                callerPackage = callerPackage,
                expiresAt = null,
                signPolicyOverride = SignPolicy.MANUAL.ordinal,
                createdAt = System.currentTimeMillis(),
                createdAtElapsed = SystemClock.elapsedRealtime(),
                durationMs = null
            )
        )
    }

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

    suspend fun getAllAppSettings(): List<Nip55AppSettings> = appSettingsDao.getAll()

    // The row's copy of the tier. AppSignPolicyOverrides resolves the policy from the
    // core floored by this value, so it is not the policy on its own. Test-only; no
    // main-source caller reads it.
    suspend fun getAppSignPolicyOverride(callerPackage: String): Int? =
        appSettingsDao.getSettings(callerPackage)?.signPolicyOverride

    suspend fun setAppSignPolicyOverride(callerPackage: String, signPolicyOrdinal: Int?) {
        val existing = appSettingsDao.getSettings(callerPackage)
        // A window that has already lapsed must not retroactively expire a fresh choice:
        // the override would resolve to nothing the moment it was set, and the next sweep
        // would drop the app onto the global instead of the tier just picked.
        val lapsed = existing?.isExpired() == true
        if (signPolicyOrdinal == null && (existing?.expiresAt == null || lapsed)) {
            appSettingsDao.delete(callerPackage)
        } else {
            val now = System.currentTimeMillis()
            val nowElapsed = SystemClock.elapsedRealtime()
            appSettingsDao.insertOrUpdate(
                Nip55AppSettings(
                    callerPackage = callerPackage,
                    expiresAt = existing?.expiresAt.takeUnless { lapsed },
                    signPolicyOverride = signPolicyOrdinal,
                    createdAt = existing?.createdAt ?: now,
                    createdAtElapsed = existing?.createdAtElapsed ?: nowElapsed,
                    durationMs = existing?.durationMs.takeUnless { lapsed }
                )
            )
        }
    }

    /**
     * Drops the settings row only. The row is the index for the package's core
     * sign-policy tier, so a caller that wants the override gone has to clear the tier
     * too, as [cleanupExpired] and [clearAllAppSettings] do; otherwise the tier is left
     * in the core where nothing can reach it. Safe as it stands because every caller is
     * test teardown.
     */
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
