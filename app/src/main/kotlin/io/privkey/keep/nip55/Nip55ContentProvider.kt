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
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.uniffi.AutoSignDecision
import io.privkey.keep.uniffi.Nip55DecisionInputs
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Outcome
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestRateLimiter
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55VelocityCheck
import io.privkey.keep.uniffi.PolicyMode
import io.privkey.keep.uniffi.evaluateNip55Request
import io.privkey.keep.uniffi.nip55ExtractRelayHost
import io.privkey.keep.uniffi.nip55SignableEventKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest
import java.util.Calendar
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

class Nip55ContentProvider : ContentProvider() {
    companion object {
        private const val TAG = "Nip55ContentProvider"
        private const val AUTHORITY_GET_PUBLIC_KEY = "io.privkey.keep.GET_PUBLIC_KEY"
        private const val AUTHORITY_SIGN_EVENT = "io.privkey.keep.SIGN_EVENT"
        private const val AUTHORITY_NIP04_ENCRYPT = "io.privkey.keep.NIP04_ENCRYPT"
        private const val AUTHORITY_NIP04_DECRYPT = "io.privkey.keep.NIP04_DECRYPT"
        private const val AUTHORITY_NIP44_ENCRYPT = "io.privkey.keep.NIP44_ENCRYPT"
        private const val AUTHORITY_NIP44_DECRYPT = "io.privkey.keep.NIP44_DECRYPT"
        private const val AUTHORITY_DECRYPT_ZAP_EVENT = "io.privkey.keep.DECRYPT_ZAP_EVENT"

        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_CONTENT_LENGTH = 1024 * 1024
        private const val OPERATION_TIMEOUT_MS = 5000L

        private const val BACKGROUND_SIGNING_CHANNEL_ID = "background_signing"

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
    private val concurrentRequestSemaphore = Semaphore(4)

    private val app: KeepMobileApp? get() = context?.applicationContext as? KeepMobileApp

    private fun <T> runWithTimeout(block: suspend () -> T): T? {
        if (!concurrentRequestSemaphore.tryAcquire()) return null
        return try {
            runBlocking(Dispatchers.IO) {
                withTimeoutOrNull(OPERATION_TIMEOUT_MS) { block() }
            }
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

        // Derive the kind with the same serde parse the Rust decision uses, so the
        // velocity bucket, permission-candidate lookup, and relay scope are keyed by the
        // exact kind the orchestrator classifies on (no parser-differential drift).
        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) nip55SignableEventKind(rawContent)?.toInt() else null

        if (store == null) return errorCursor("Permission store is not available", null)

        return decideBackgroundRequest(
            currentApp, store, h, callerPackage, requestType, rawContent, rawPubkey, eventKind, currentUser
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
        currentUser: String?
    ): Cursor? {
        // Velocity: the check-and-record is atomic (one DB transaction), so it stays
        // in Kotlin and only its outcome is handed to the decision.
        val velocityCheck = when (runWithTimeout { store.checkAndRecordVelocity(callerPackage, eventKind) }) {
            null -> Nip55VelocityCheck.TIMED_OUT
            is VelocityResult.Blocked -> Nip55VelocityCheck.BLOCKED
            VelocityResult.Allowed -> Nip55VelocityCheck.ALLOWED
        }

        // Relay-auth whitelist (kind 22242): the raw hosts plus a read-failed flag.
        // No store or an empty list defers; a read error fails closed to auto-reject.
        val whitelistStore = currentApp.getRelayAuthWhitelistStore()
        var relayReadFailed = false
        val relayWhitelist: List<String> = if (whitelistStore == null) {
            emptyList()
        } else {
            try {
                whitelistStore.getHosts()
            } catch (_: Exception) {
                relayReadFailed = true
                emptyList()
            }
        }

        // Sign-policy precedence: per-app override -> global -> MANUAL default.
        val effectivePolicy = runWithTimeout {
            store.getAppSignPolicyOverride(callerPackage)?.let { SignPolicy.fromOrdinal(it) }
                ?: currentApp.getSignPolicyStore()?.getGlobalPolicy()
                ?: SignPolicy.MANUAL
        } ?: SignPolicy.MANUAL
        val policyMode = when (effectivePolicy) {
            SignPolicy.MANUAL -> PolicyMode.MANUAL
            SignPolicy.AUTO, SignPolicy.BASIC -> PolicyMode.AUTO
        }

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
            runWithTimeout { store.hasSignedKindBefore(callerPackage, eventKind) } ?: true
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
            policyMode = policyMode,
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
                executeBackgroundRequest(h, store, currentApp, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser)
            is Nip55Outcome.Reject -> {
                if (outcome.reason == "deny_expired") runWithTimeout { store.cleanupExpired() }
                runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, outcome.reason, wasAutomatic = true) }
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
        currentUser: String? = null
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
            permissions = null
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
                if (requestType == Nip55RequestType.GET_PUBLIC_KEY) {
                    if (response.result.isEmpty()) {
                        throw IllegalStateException("Handler returned empty pubkey")
                    }
                    val groupPubkey = app.getStorage()?.getShareMetadata()?.groupPubkey
                    if (groupPubkey == null || groupPubkey.isEmpty()) {
                        throw IllegalStateException("Stored pubkey unavailable for verification")
                    }
                    val storedPubkey = groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                    if (!MessageDigest.isEqual(response.result.toByteArray(Charsets.UTF_8), storedPubkey.toByteArray(Charsets.UTF_8))) {
                        if (BuildConfig.DEBUG) Log.e(TAG, "Pubkey verification failed: mismatch detected")
                        throw IllegalStateException("Pubkey verification failed")
                    }
                }
                runCatching {
                    runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "allow", wasAutomatic = true) }
                    showBackgroundSigningNotification(callerPackage, requestType, eventKind)
                }.onFailure { e ->
                    if (BuildConfig.DEBUG) Log.e(TAG, "Post-success side effects failed: ${e::class.simpleName}")
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
                if (BuildConfig.DEBUG) Log.e(TAG, "Background request failed: ${e::class.simpleName}: ${e.message}")
                if (e is BiometricHelper.BiometricNotReadyException) {
                    errorCursor(e.message ?: "Biometric authentication is unavailable", id)
                } else {
                    errorCursor("Request failed", id)
                }
            }
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
