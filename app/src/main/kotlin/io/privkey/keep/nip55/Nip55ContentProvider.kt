package io.privkey.keep.nip55

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentProvider
import io.privkey.keep.BiometricHelper
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
import android.os.SystemClock
import android.net.Uri
import android.os.Binder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.privkey.keep.BuildConfig
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.R
import io.privkey.keep.uniffi.AutoSignDecision
import io.privkey.keep.uniffi.Nip55DecisionInputs
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Outcome
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestRateLimiter
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55VelocityCheck
import io.privkey.keep.uniffi.SignPolicySelection
import io.privkey.keep.uniffi.evaluateNip55Request
import io.privkey.keep.uniffi.nip55ExtractRelayHost
import io.privkey.keep.uniffi.nip55SignableEventKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest
import java.util.Calendar
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

// Both NIP-55 entrypoints refuse a request they cannot record, and the refusal is
// the same one: the foreground path (Nip55Activity) reports it from here so a reword
// cannot leave the two paths describing the same fault differently.
internal const val STORE_UNAVAILABLE_MESSAGE = "Permission store is not available"

/** An auto-signed request whose audit row was not observed to land. */
private class AuditAppendIncomplete : Exception("Audit append did not complete")

class Nip55ContentProvider : ContentProvider() {
    companion object {
        private const val TAG = "Nip55ContentProvider"
        private const val AUTHORITY_GET_PUBLIC_KEY = "io.privkey.keep.GET_PUBLIC_KEY"
        private const val AUTHORITY_SIGN_EVENT = "io.privkey.keep.SIGN_EVENT"
        private const val AUTHORITY_NIP04_ENCRYPT = "io.privkey.keep.NIP04_ENCRYPT"
        private const val AUTHORITY_NIP04_DECRYPT = "io.privkey.keep.NIP04_DECRYPT"
        private const val AUTHORITY_NIP44_ENCRYPT = "io.privkey.keep.NIP44_ENCRYPT"
        private const val AUTHORITY_NIP44_DECRYPT = "io.privkey.keep.NIP44_DECRYPT"
        private const val AUTHORITY_NIP44_V3_ENCRYPT = "io.privkey.keep.NIP44_V3_ENCRYPT"
        private const val AUTHORITY_NIP44_V3_DECRYPT = "io.privkey.keep.NIP44_V3_DECRYPT"
        private const val AUTHORITY_DECRYPT_ZAP_EVENT = "io.privkey.keep.DECRYPT_ZAP_EVENT"

        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_CONTENT_LENGTH = 1024 * 1024
        private const val MAX_EXTRA_LENGTH = 2048
        private const val OPERATION_TIMEOUT_MS = 5000L

        // Max IO threads orphaned (timed-out) FFI calls may occupy, so a run of
        // stuck calls cannot pin the whole shared Dispatchers.IO pool. Matches the
        // request-concurrency cap (concurrentRequestSemaphore).
        private const val ORPHAN_IO_PARALLELISM = 4

        private const val BACKGROUND_SIGNING_CHANNEL_ID = "background_signing"

        // How many provider operations may be in flight at once.
        private const val REQUEST_PERMITS = 4

        // How long a caller waits for its audit row before the request is
        // refused. The append itself is not cancelled at it; see appendAudited.
        private const val AUDIT_APPEND_BUDGET_MS = 5_000L


        private val SIGN_COLUMNS = arrayOf("signature", "event", "result")
        private val ENCRYPT_COLUMNS = arrayOf("signature", "result")
        private val REJECTED_COLUMNS = arrayOf("rejected")
        private val ERROR_COLUMNS = arrayOf("error")

        private fun hashPackageName(pkg: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(pkg.toByteArray(Charsets.UTF_8))
            return digest.take(8).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
    }

    private val rateLimiter by lazy { Nip55RequestRateLimiter() }
    private val backgroundNotificationId = AtomicInteger(0)
    private val concurrentRequestSemaphore = Semaphore(REQUEST_PERMITS)

    // Scope for orphaned FFI work. A policy-store / rate-limiter call reaches a
    // blocking, non-cancellable UniFFI call (e.g. SigningRateLimiter.checkAndRecord,
    // a synchronous encrypted keystore write). If such a call overruns its wall-clock
    // budget it is left to finish here instead of pinning the caller. Bounded to a
    // small view of the IO pool via limitedParallelism, so a run of stuck FFI calls
    // stays confined to a few threads rather than starving the app-wide Dispatchers.IO;
    // callers still fail closed at the timeout whether the orphan runs or queues.
    // SupervisorJob so one orphaned failure cannot cancel the others.
    private val orphanScope = CoroutineScope(
        Dispatchers.IO.limitedParallelism(ORPHAN_IO_PARALLELISM) + SupervisorJob(),
    )

    // Audit appends, off the caller's thread so a stalled anchor write cannot
    // hold a request past its budget. Single-threaded because every append
    // serializes on the writer's own lock anyway, so more threads would only
    // queue in a second place; a stalled append therefore delays the next one,
    // which then reports itself not landed and refuses, in that order.
    private val auditScope = CoroutineScope(
        Dispatchers.IO.limitedParallelism(1) + SupervisorJob(),
    )

    private val app: KeepMobileApp? get() = context?.applicationContext as? KeepMobileApp

    // Run `block` under a real wall-clock bound. `block` may reach a blocking,
    // non-cancellable FFI call, which `withTimeoutOrNull` cannot interrupt in place
    // (there is no suspension point to cancel at). So the work runs on [orphanScope]
    // -- deliberately NOT structured under the `runBlocking` below -- and we await it
    // with a timeout: when the budget is exceeded the await is cancelled, releasing
    // the caller's binder thread and the semaphore permit and failing closed (null),
    // while the orphaned call finishes on its own IO thread rather than pinning both
    // for its full, unbounded duration. Cancelling the await does not cancel the
    // orphan (orphanScope owns it). `internal` only so the bound can be unit-tested.
    internal fun <T> runWithTimeout(block: suspend () -> T): T? {
        if (!concurrentRequestSemaphore.tryAcquire()) return null
        return try {
            val deferred = orphanScope.async { block() }
            runBlocking {
                withTimeoutOrNull(OPERATION_TIMEOUT_MS) { deferred.await() }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // `await` rethrows whatever the block threw, which would cross the binder
            // instead of reaching the caller's fail-closed null. Every caller treats
            // null as the closed outcome, so a faulting operation reports it rather
            // than surfacing an exception to the calling app.
            if (BuildConfig.DEBUG) Log.w(TAG, "Provider operation failed: ${e::class.simpleName}")
            null
        } finally {
            concurrentRequestSemaphore.release()
        }
    }

    override fun onCreate(): Boolean {
        createBackgroundSigningChannel()
        return true
    }

    private fun createBackgroundSigningChannel() {
        val ctx = context ?: return
        val channel = NotificationChannel(
            BACKGROUND_SIGNING_CHANNEL_ID,
            ctx.getString(R.string.notification_channel_background_signing),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = ctx.getString(R.string.notification_channel_background_signing_description)
        }
        (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager)
            ?.createNotificationChannel(channel)
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        val currentApp = app ?: return errorCursor("Request denied", null)

        val callerPackage = getVerifiedCaller() ?: return errorCursor("Request denied", null)
        if (callerPackage.isBlank()) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Caller package is blank")
            return errorCursor("Request denied", null)
        }

        if (currentApp.isSigningKilled()) {
            return errorCursor("Signing is disabled (kill switch is active)", null)
        }
        if (currentApp.getPinStore()?.requiresAuthentication() == true) {
            return errorCursor("Keep is locked, please unlock it first", null)
        }
        val h = currentApp.getNip55Handler() ?: return errorCursor("Signing service is not available", null)
        val store = currentApp.getPermissionStore()

        val withinRateLimit = try {
            rateLimiter.check(callerPackage, SystemClock.elapsedRealtime().toULong())
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rate limiter check failed, failing closed: ${e::class.simpleName}")
            false
        }
        if (!withinRateLimit) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rate limit exceeded for ${hashPackageName(callerPackage)}")
            return errorCursor("Too many requests, please try again later", null)
        }

        val requestType = when (val authority = uri.authority) {
            AUTHORITY_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            AUTHORITY_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            AUTHORITY_NIP04_ENCRYPT -> Nip55RequestType.NIP04_ENCRYPT
            AUTHORITY_NIP04_DECRYPT -> Nip55RequestType.NIP04_DECRYPT
            AUTHORITY_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            AUTHORITY_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            AUTHORITY_NIP44_V3_ENCRYPT -> Nip55RequestType.NIP44_V3_ENCRYPT
            AUTHORITY_NIP44_V3_DECRYPT -> Nip55RequestType.NIP44_V3_DECRYPT
            AUTHORITY_DECRYPT_ZAP_EVENT -> Nip55RequestType.DECRYPT_ZAP_EVENT
            else -> {
                if (BuildConfig.DEBUG) Log.w(TAG, "Unexpected authority: $authority")
                return errorCursor("Invalid request", null)
            }
        }

        val rawContent = projection?.getOrNull(0) ?: ""
        val rawPubkey = projection?.getOrNull(1)?.takeIf { it.isNotBlank() }
        val currentUser = projection?.getOrNull(2)?.takeIf { it.isNotBlank() }

        if (rawContent.length > MAX_CONTENT_LENGTH)
            return errorCursor("Request content is too large", null)
        if (rawPubkey != null && rawPubkey.length > MAX_PUBKEY_LENGTH)
            return errorCursor("Invalid public key", null)

        // NIP-44 v3 carries a kind (mandatory) and scope (optional, defaults to "").
        // A v3 request with a missing/invalid kind fails closed: no signing, no prompt.
        val isV3 = requestType.isNip44V3()
        val v3Kind: UInt? = if (isV3) {
            projection?.getOrNull(3)?.toUIntOrNull() ?: return errorCursor("Invalid request", null)
        } else {
            null
        }
        val v3Scope: String? = if (isV3) projection?.getOrNull(4) ?: "" else null
        if (v3Scope != null && v3Scope.length > MAX_EXTRA_LENGTH)
            return errorCursor("Invalid request", null)

        // Derive the kind with the same serde parse the Rust decision uses, so the
        // velocity bucket, permission-candidate lookup, and relay scope are keyed by the
        // exact kind the orchestrator classifies on (no parser-differential drift). For
        // v3 the kind is carried explicitly, so the same plumbing is kind-scoped by it.
        val eventKind = when {
            requestType == Nip55RequestType.SIGN_EVENT -> nip55SignableEventKind(rawContent)?.toInt()
            isV3 -> v3Kind?.toInt()
            else -> null
        }

        if (store == null) return errorCursor(STORE_UNAVAILABLE_MESSAGE, null)

        return decideBackgroundRequest(
            currentApp, store, h, callerPackage, requestType, rawContent, rawPubkey, eventKind, currentUser, v3Kind, v3Scope
        )
    }

    /**
     * Gather the platform inputs and delegate the full auto-sign decision to the
     * Rust orchestrator (`evaluateNip55Request`), then map its outcome to a cursor.
     * The stateful, ordered side effects (the atomic velocity check-and-record and
     * the opt-in rate-limiter record) run here and their results feed the pure
     * decision; the gate sequence, precedence, and DENY-wins rules live in Rust,
     * shared with the foreground path. `null` means "no auto-decision, launch the UI".
     */
    private fun decideBackgroundRequest(
        currentApp: KeepMobileApp,
        store: PermissionStore,
        h: Nip55Handler,
        callerPackage: String,
        requestType: Nip55RequestType,
        rawContent: String,
        rawPubkey: String?,
        eventKind: Int?,
        currentUser: String?,
        v3Kind: UInt?,
        v3Scope: String?
    ): Cursor? {
        // Velocity: the check-and-record is atomic (one DB transaction), so it stays
        // in Kotlin and only its outcome is handed to the decision.
        val velocityCheck = when (runWithTimeout { store.checkAndRecordVelocity(callerPackage, eventKind) }) {
            null -> Nip55VelocityCheck.TIMED_OUT
            is VelocityResult.Blocked -> Nip55VelocityCheck.BLOCKED
            VelocityResult.Allowed -> Nip55VelocityCheck.ALLOWED
        }

        // Relay-auth whitelist (kind 22242): the raw hosts plus a read-failed flag,
        // folded in the same helper the foreground gate uses so the two cannot
        // diverge on what an unreadable list means. No store or an empty list
        // defers; a read error fails closed, which the core turns into auto-reject.
        //
        // The flag used to be set only by a catch, which caught the fault that
        // raises. A value that would not decrypt came back as an empty list with
        // the flag clear, so the core saw a person who had configured no gate and
        // deferred to per-app grants, letting a grant auto-approve a relay the
        // list may have been excluding, with nobody present to see it.
        val (relayWhitelist, relayReadFailed) =
            relayWhitelistInputs(currentApp.getRelayAuthWhitelistStore())

        // Sign-policy precedence: per-app override -> core-owned global -> MANUAL
        // default, resolved in AppSignPolicyOverrides so this and the settings UI
        // cannot drift. The core owns the per-app tier; an app the settings row marks as
        // pinned but whose tier the core cannot produce, including one not yet migrated,
        // resolves to MANUAL rather than to the global. The selection passes through
        // as-is; collapsing BASIC onto AUTO here would discard the stricter Basic
        // auto-approval band the core enforces.
        val policySelection = runWithTimeout {
            AppSignPolicyOverrides.effectivePolicy(currentApp.getSignPolicyStore(), store, callerPackage)
        } ?: SignPolicySelection.MANUAL

        val isOptedIn = currentApp.getAutoSigningSafeguards()?.isOptedIn(callerPackage) == true

        // Opt-in auto-sign limiter: recorded here as a throttle (a null limiter or a
        // check failure falls open to the UI). Recording the attempt up-front mirrors
        // the reference signer's front-door rate limiter.
        val optInRateCheck: AutoSignDecision? = if (isOptedIn) {
            val limiter = currentApp.getSigningRateLimiter()
            if (limiter == null) {
                null
            } else {
                runWithTimeout {
                    try {
                        limiter.checkAndRecord(
                            callerPackage,
                            SystemClock.elapsedRealtime().toULong(),
                            System.currentTimeMillis().toULong()
                        )
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.w(TAG, "Rate limiter check failed, failing closed to UI: ${e::class.simpleName}")
                        null
                    }
                }
            }
        } else {
            null
        }

        val hasSignedKindBefore = if (eventKind != null) {
            // Fail safe on timeout/contention: an unknown history is treated as
            // "not signed before" so the first-kind risk factor is kept (biases the
            // risk assessment toward more scrutiny, not auto-approval).
            runWithTimeout { store.hasSignedKindBefore(callerPackage, eventKind) } ?: false
        } else {
            true
        }
        val appAgeMs = runWithTimeout { store.getAppAgeMs(callerPackage) }
        val appExpired: Boolean? = runWithTimeout { store.isAppExpired(callerPackage) }

        // Standing-permission candidate rows, relay-scoped for kind 22242.
        val relayScope = if (requestType == Nip55RequestType.SIGN_EVENT && eventKind == KIND_NIP42_AUTH) {
            nip55ExtractRelayHost(rawContent) ?: RELAY_NONE
        } else {
            RELAY_NONE
        }
        var lookupOk = true
        val candidates = runWithTimeout {
            store.getPermissionCandidates(callerPackage, requestType, eventKind, relayScope)
        }
        if (candidates == null) lookupOk = false

        val inputs = Nip55DecisionInputs(
            packageName = callerPackage,
            callerVerified = true,
            signingKilled = false,
            isLocked = false,
            requestType = requestType,
            eventJson = rawContent,
            frontDoorWithinLimit = true,
            velocityCheck = velocityCheck,
            relayWhitelist = relayWhitelist,
            relayWhitelistReadFailed = relayReadFailed,
            policySelection = policySelection,
            isOptedIn = isOptedIn,
            optInRateCheck = optInRateCheck,
            hasSignedKindBefore = hasSignedKindBefore,
            appAgeMs = appAgeMs?.toULong(),
            currentHour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY).toUInt(),
            appExpired = appExpired,
            permissionLookupOk = lookupOk,
            storedExactPermission = candidates?.first,
            storedGenericPermission = candidates?.second,
            nowElapsedMs = SystemClock.elapsedRealtime(),
            nowWallMs = System.currentTimeMillis()
        )

        return when (val outcome = evaluateNip55Request(inputs)) {
            Nip55Outcome.AutoApprove ->
                executeBackgroundRequest(h, store, currentApp, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser, v3Kind, v3Scope)
            is Nip55Outcome.Reject -> {
                if (outcome.reason == "deny_expired") runWithTimeout {
                    store.cleanupExpired(
                        currentApp.getSignPolicyStore(),
                        currentApp.getAutoSigningSafeguards()
                    )
                }
                if (!recordAutoDecision(store, callerPackage, requestType, eventKind, outcome.reason)) {
                    // The refusal still stands, since nothing was released and a
                    // policy rejection tells the caller more than a failure would.
                    // Logged in every build because the row that would have
                    // carried it is the thing that did not land.
                    Log.w(TAG, "Auto-refused request not recorded: ${outcome.reason}")
                }
                rejectedCursor(null)
            }
            is Nip55Outcome.Error -> errorCursor(outcome.message, null)
            is Nip55Outcome.RequireUi -> null
        }
    }

    private fun executeBackgroundRequest(
        h: Nip55Handler,
        store: PermissionStore,
        app: KeepMobileApp,
        callerPackage: String,
        requestType: Nip55RequestType,
        content: String,
        pubkey: String?,
        id: String?,
        eventKind: Int?,
        currentUser: String? = null,
        v3Kind: UInt? = null,
        v3Scope: String? = null
    ): Cursor {
        val request = Nip55Request(
            requestType = requestType,
            content = content,
            pubkey = pubkey,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = id,
            currentUser = currentUser,
            permissions = null,
            kind = v3Kind,
            scope = v3Scope
        )

        val km = app.getKeepMobile()
        if (requestType == Nip55RequestType.SIGN_EVENT && km != null) {
            val preApprove = runWithTimeout {
                try {
                    Result.success(km.preApproveNostrEvent(content))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Result.failure<Unit>(e)
                }
            }
            if (preApprove == null || preApprove.isFailure) {
                if (BuildConfig.DEBUG) Log.w(TAG, "preApprove failed: ${preApprove?.exceptionOrNull()?.message ?: "timeout"}")
                runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "preapprove_failed", wasAutomatic = true) }
                return errorCursor("Request failed", id)
            }
        }

        return runCatching { h.handleRequest(request, callerPackage) }
            .mapCatching { response ->
                // Same self-verification as the foreground path: compare the handler's
                // returned pubkey against the independently-read stored group pubkey
                // (keystore share metadata) through the single shared checkPubkey helper.
                checkPubkey(requestType, response.result, app.getStorage()?.getShareMetadata()?.groupPubkey)?.let {
                    throw IllegalStateException("Pubkey verification failed")
                }
                // The row is the operation's only record: the user sees nothing
                // else for a request answered in the background, and the velocity
                // and frequency inputs of later decisions are counted from these
                // rows, so an unrecorded auto-sign also lowers the bar for the
                // next one. An operation that cannot be recorded is refused, which
                // is a real refusal here because the signature has not left the
                // process, and it matches what the foreground path now does with
                // a request it cannot record.
                if (!recordAutoSigned(store, callerPackage, requestType, eventKind)) {
                    throw AuditAppendIncomplete()
                }
                // The notification is not the record and stays best effort.
                runCatching { showBackgroundSigningNotification(callerPackage, requestType, eventKind) }
                    .onFailure { e ->
                        if (BuildConfig.DEBUG) Log.e(TAG, "Background signing notification failed: ${e::class.simpleName}")
                    }
                when (requestType) {
                    Nip55RequestType.SIGN_EVENT, Nip55RequestType.GET_PUBLIC_KEY ->
                        MatrixCursor(SIGN_COLUMNS).apply {
                            addRow(arrayOf(response.result, response.event, response.result))
                        }
                    else ->
                        MatrixCursor(ENCRYPT_COLUMNS).apply {
                            addRow(arrayOf(response.result, response.result))
                        }
                }
            }
            .getOrElse { e ->
                // Logged in every build for this one: it is the case whose record
                // is the thing that failed, so nothing else would carry it.
                if (e is AuditAppendIncomplete) Log.w(TAG, "Auto-signed request refused: audit append did not complete")
                if (BuildConfig.DEBUG) Log.e(TAG, "Background request failed: ${e::class.simpleName}: ${e.message}")
                if (e is BiometricHelper.BiometricNotReadyException) {
                    errorCursor(e.message ?: "Biometric authentication is unavailable", id)
                } else {
                    errorCursor("Request failed", id)
                }
            }
    }

    /**
     * Appends the audit row for an auto-signed request, and reports whether it
     * landed.
     *
     * Deliberately not through [runWithTimeout]. That wrapper takes one of the
     * few permits before it does anything, so contention alone could skip the
     * append entirely, which is how a response came to be returned with no row
     * at all: nothing raised and nothing was logged, because no attempt was
     * made.
     *
     * It runs on its own scope instead, waited for under a budget the caller is
     * released at, with no permit to lose. The writer serializes every append on
     * its own lock, so ordering is unchanged.
     *
     * `internal` so a test can drive it against a real store, since the provider
     * itself refuses a same-uid caller and cannot be exercised end to end from
     * instrumentation.
     */
    internal fun recordAutoSigned(
        store: PermissionStore,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
    ): Boolean = appendAudited(store, callerPackage, requestType, eventKind, "allow")

    /**
     * The same bounded, caller-thread append for a decision that refused.
     *
     * Nothing was released, so the result is not a gate here, but the row still
     * has to land: the frequency input of later risk assessments counts rows
     * without regard to their decision, and a deny burst is the pattern that
     * input exists to catch, so skipped rows lower the bar for what follows.
     *
     * The result is still not checked, and that is the choice rather than an
     * omission: the caller is being refused either way, and turning a refusal
     * into a failure would tell it less about what happened. What it costs is
     * that an unrecorded refusal is invisible, which is why the append runs on
     * this path too rather than only on the one that returns something.
     */
    internal fun recordAutoDecision(
        store: PermissionStore,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
    ): Boolean = appendAudited(store, callerPackage, requestType, eventKind, decision)

    /**
     * One bounded append, reporting whether it landed within the budget.
     *
     * Bounded for the caller, and not through the permit wrapper: the append is
     * the step that must be attempted, and losing a permit to contention is how
     * it came to be skipped in the first place.
     *
     * The budget is kept honest by starting the append outside the wait rather
     * than by cancelling it. Cancellation cannot reach the anchor write that
     * follows the row, which is synchronous and has no suspension point, and a
     * structured call would make the caller wait for it anyway however the
     * budget expired: switching dispatchers moves where that work runs, not
     * whether its parent waits for it. So the append is launched on its own
     * scope and only the wait is cancelled.
     *
     * An append that has not yet taken the writer's lock when the budget
     * expires, typically one waiting behind a stalled append, is fenced and
     * writes nothing, unless it takes the lock in the moment between the timeout
     * and the fence. The price is that an append already writing then is
     * reported as not landed, and its row may commit a moment later, so the log
     * can hold an approval for a response that was never returned. That is the
     * same shape as an append interrupted by process death, which the chain
     * verification already heals, and it is the direction that holds more
     * record rather than less. Asking the log instead of answering from the
     * call would narrow it, and was tried: a row cannot be tied to the append
     * that wrote it without a per-append identity it does not carry, so one
     * request's row answers for another's, which is a weaker gate than the one
     * this exists to be.
     */
    private fun appendAudited(
        store: PermissionStore,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?,
        decision: String,
    ): Boolean {
        return runCatching {
            awaitWithin(auditScope, AUDIT_APPEND_BUDGET_MS) { claim ->
                store.logAutomaticOperationIfClaimed(callerPackage, requestType, eventKind, decision, claim)
                    .takeIf { it }
            }
        }.getOrNull() == true
    }

    @SuppressLint("MissingPermission")
    private fun showBackgroundSigningNotification(
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ) {
        val ctx = context ?: return
        if (ContextCompat.checkSelfPermission(ctx, android.Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) return

        val appLabel = try {
            val appInfo = ctx.packageManager.getApplicationInfo(callerPackage, 0)
            ctx.packageManager.getApplicationLabel(appInfo).toString()
        } catch (_: PackageManager.NameNotFoundException) {
            callerPackage
        }

        val kindText = eventKind?.let { ctx.getString(R.string.notification_kind_suffix, it) } ?: ""
        val notification = NotificationCompat.Builder(ctx, BACKGROUND_SIGNING_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notification_background_signing_title))
            .setContentText(ctx.getString(R.string.notification_background_signing_text, appLabel, requestType.headerTitle(ctx) + kindText))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()

        val notifId = 2000 + Math.floorMod(backgroundNotificationId.getAndIncrement(), 10000)
        NotificationManagerCompat.from(ctx).notify(notifId, notification)
    }

    private fun getVerifiedCaller(): String? {
        val callingUid = Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) return null

        val packages = context?.packageManager?.getPackagesForUid(callingUid)
        if (packages.isNullOrEmpty()) return null
        if (packages.size > 1) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from multi-package UID (count=${packages.size})")
            return null
        }

        val packageName = packages[0]
        val verificationStore = app?.getCallerVerificationStore() ?: return null

        val result = verificationStore.verifyOrTrust(packageName)
        if (result is CallerVerificationStore.VerificationResult.Verified) return packageName

        if (BuildConfig.DEBUG) Log.w(TAG, "Caller verification failed: $result")
        return null
    }

    private fun errorCursor(error: String, id: String?): MatrixCursor {
        return MatrixCursor(ERROR_COLUMNS).apply { addRow(arrayOf(error)) }
    }

    private fun rejectedCursor(id: String?): MatrixCursor {
        return MatrixCursor(REJECTED_COLUMNS).apply { addRow(arrayOf("true")) }
    }

    override fun getType(uri: Uri): String {
        val authority = uri.authority ?: "io.privkey.keep"
        return "vnd.android.cursor.item/vnd.$authority"
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}

/**
 * Runs [block] on [scope] and waits at most [budgetMs] for it. [block] calls the claim
 * it is given right before its first lasting effect and stops if that returns false.
 * Once the wait gives up it takes the claim itself, so a block that has not claimed by
 * then does nothing, and only one already past its claim can finish after its caller
 * was told it did not. It is fenced rather than cancelled, because cancelling a block
 * past its claim could stop it between steps that must happen together.
 */
internal fun <T : Any> awaitWithin(
    scope: CoroutineScope,
    budgetMs: Long,
    block: suspend (claim: () -> Boolean) -> T?,
): T? {
    val claimed = AtomicBoolean(false)
    val claim = { claimed.compareAndSet(false, true) }
    val work = scope.async { block(claim) }
    try {
        return runBlocking { withTimeoutOrNull(budgetMs) { work.await() } }
    } finally {
        // Also when the wait throws, such as on an interrupted thread. A block past
        // its claim already holds it, so this changes nothing for it.
        claim()
    }
}
