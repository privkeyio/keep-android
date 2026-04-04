package io.privkey.keep.nip55

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.database.MatrixCursor
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
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.PolicyMode
import io.privkey.keep.uniffi.SignPolicyEvaluation
import io.privkey.keep.uniffi.SigningRequestContext
import io.privkey.keep.uniffi.evaluateSignPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

class Nip55ContentProvider : ContentProvider() {
    companion object {
        private const val TAG = "Nip55ContentProvider"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"

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

    private val rateLimiter = RateLimiter()
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
        val currentApp = app ?: return errorCursor(GENERIC_ERROR_MESSAGE, null)
        if (currentApp.getKillSwitchStore()?.isEnabled() == true) {
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }
        if (currentApp.getPinStore()?.requiresAuthentication() == true) {
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }
        val h = currentApp.getNip55Handler() ?: return errorCursor(GENERIC_ERROR_MESSAGE, null)
        val store = currentApp.getPermissionStore()

        val callerPackage = getVerifiedCaller() ?: return errorCursor(GENERIC_ERROR_MESSAGE, null)
        if (callerPackage.isBlank()) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Caller package is blank")
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }

        if (!rateLimiter.checkRateLimit(callerPackage)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rate limit exceeded for ${hashPackageName(callerPackage)}")
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
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
                return errorCursor(GENERIC_ERROR_MESSAGE, null)
            }
        }

        val rawContent = projection?.getOrNull(0) ?: ""
        val rawPubkey = projection?.getOrNull(1)?.takeIf { it.isNotBlank() }
        val currentUser = projection?.getOrNull(2)?.takeIf { it.isNotBlank() }

        if (rawContent.length > MAX_CONTENT_LENGTH)
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        if (rawPubkey != null && rawPubkey.length > MAX_PUBKEY_LENGTH)
            return errorCursor(GENERIC_ERROR_MESSAGE, null)

        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(rawContent)?.takeIf { it >= 0 } else null

        if (store == null) return errorCursor(GENERIC_ERROR_MESSAGE, null)

        val velocityCursor = checkVelocityLimits(store, callerPackage, requestType, eventKind)
        if (velocityCursor != null) return velocityCursor

        val policyCursor = evaluateAutoSignPolicy(
            currentApp, store, h, callerPackage, requestType, rawContent, rawPubkey, eventKind, currentUser
        )
        if (policyCursor != null) {
            if (policyCursor is PolicyResult.FallToUi) {
                return checkPermissionWithRisk(
                    store, h, currentApp, callerPackage, requestType, rawContent, rawPubkey, eventKind, currentUser,
                    policyCursor.hasSignedKindBefore, policyCursor.appAgeMs
                )
            }
            return policyCursor.cursorOrNull
        }

        return checkPermissionWithRisk(
            store, h, currentApp, callerPackage, requestType, rawContent, rawPubkey, eventKind, currentUser
        )
    }

    private fun checkVelocityLimits(
        store: PermissionStore,
        callerPackage: String,
        requestType: Nip55RequestType,
        eventKind: Int?
    ): Cursor? {
        val velocityResult = runWithTimeout { store.checkAndRecordVelocity(callerPackage, eventKind) }
        if (velocityResult == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Velocity check failed (timeout or concurrency limit), denying request")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny_velocity_timeout", wasAutomatic = true) }
            return rejectedCursor(null)
        }
        if (velocityResult is VelocityResult.Blocked) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Velocity limit: ${velocityResult.reason}")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "velocity_blocked", wasAutomatic = true) }
            return rejectedCursor(null)
        }
        return null
    }

    private sealed class PolicyResult {
        val cursorOrNull: Cursor? get() = (this as? Decided)?.cursor
        class Decided(val cursor: Cursor?) : PolicyResult()
        class FallToUi(val hasSignedKindBefore: Boolean, val appAgeMs: Long?) : PolicyResult()
    }

    private fun evaluateAutoSignPolicy(
        currentApp: KeepMobileApp,
        store: PermissionStore,
        h: Nip55Handler,
        callerPackage: String,
        requestType: Nip55RequestType,
        rawContent: String,
        rawPubkey: String?,
        eventKind: Int?,
        currentUser: String?
    ): PolicyResult? {
        val effectivePolicy = runWithTimeout {
            store.getAppSignPolicyOverride(callerPackage)
                ?.let { SignPolicy.fromOrdinal(it) }
                ?: currentApp.getSignPolicyStore()?.getGlobalPolicy()
                ?: SignPolicy.MANUAL
        } ?: SignPolicy.MANUAL

        val policyMode = when (effectivePolicy) {
            SignPolicy.MANUAL -> PolicyMode.MANUAL
            SignPolicy.AUTO, SignPolicy.BASIC -> PolicyMode.AUTO
        }

        val safeguards = currentApp.getAutoSigningSafeguards()
        val isOptedIn = safeguards?.isOptedIn(callerPackage) == true

        val defaultVelocity = VelocityConfig()
        val rateCheck = if (safeguards != null && isOptedIn) {
            mapUsageResult(safeguards.checkAndRecordUsage(callerPackage), defaultVelocity)
        } else {
            AutoSignDecision.Allowed(0u, 0u, 0u, defaultVelocity.hourlyLimit.toUInt(), defaultVelocity.dailyLimit.toUInt())
        }

        val hasSignedKindBefore = if (eventKind != null) {
            runWithTimeout { store.hasSignedKindBefore(callerPackage, eventKind) } ?: true
        } else true
        val appAgeMs = runWithTimeout { store.getAppAgeMs(callerPackage) }

        val ctx = SigningRequestContext(
            operation = requestType,
            packageName = callerPackage,
            eventKind = eventKind?.takeIf { it >= 0 }?.toUInt(),
            hasSignedKindBefore = hasSignedKindBefore,
            appAgeMs = appAgeMs?.toULong()
        )

        val evaluation = evaluateSignPolicy(policyMode, ctx, isOptedIn, rateCheck)

        return when (evaluation) {
            SignPolicyEvaluation.AUTO_APPROVE -> {
                PolicyResult.Decided(executeBackgroundRequest(h, store, currentApp, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser))
            }
            SignPolicyEvaluation.FALL_TO_UI -> PolicyResult.FallToUi(hasSignedKindBefore, appAgeMs)
        }
    }

    private fun mapUsageResult(result: AutoSigningSafeguards.UsageCheckResult, velocity: VelocityConfig): AutoSignDecision =
        when (result) {
            is AutoSigningSafeguards.UsageCheckResult.Allowed ->
                AutoSignDecision.Allowed(result.hourlyCount.toUInt(), result.dailyCount.toUInt(), 0u, velocity.hourlyLimit.toUInt(), velocity.dailyLimit.toUInt())
            is AutoSigningSafeguards.UsageCheckResult.HourlyLimitExceeded ->
                AutoSignDecision.HourlyLimitExceeded
            is AutoSigningSafeguards.UsageCheckResult.DailyLimitExceeded ->
                AutoSignDecision.DailyLimitExceeded
            is AutoSigningSafeguards.UsageCheckResult.UnusualActivity ->
                AutoSignDecision.UnusualActivity
            is AutoSigningSafeguards.UsageCheckResult.CoolingOff ->
                AutoSignDecision.CoolingOff(result.until.toULong())
        }

    private fun checkPermissionWithRisk(
        store: PermissionStore,
        h: Nip55Handler,
        currentApp: KeepMobileApp,
        callerPackage: String,
        requestType: Nip55RequestType,
        rawContent: String,
        rawPubkey: String?,
        eventKind: Int?,
        currentUser: String?,
        precomputedHasSignedKindBefore: Boolean? = null,
        precomputedAppAgeMs: Long? = null
    ): Cursor? {
        val isAppExpired = runWithTimeout { store.isAppExpired(callerPackage) }
        if (isAppExpired == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "isAppExpired check timed out for ${hashPackageName(callerPackage)}, denying request")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny_timeout", wasAutomatic = true) }
            return rejectedCursor(null)
        }

        if (isAppExpired) {
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny_expired", wasAutomatic = true) }
            runWithTimeout { store.cleanupExpired() }
            return rejectedCursor(null)
        }

        var decision: PermissionDecision? = null
        val decisionLoaded = runWithTimeout {
            decision = store.getPermissionDecision(callerPackage, requestType, eventKind)
            true
        }
        if (decisionLoaded == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Permission lookup timed out for ${hashPackageName(callerPackage)}/$requestType, denying request")
            return rejectedCursor(null)
        }

        if (decision == PermissionDecision.ALLOW) {
        }

        return when (decision) {
            PermissionDecision.ALLOW -> executeBackgroundRequest(h, store, currentApp, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser)
            PermissionDecision.DENY -> {
                runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny", wasAutomatic = true) }
                rejectedCursor(null)
            }
            PermissionDecision.ASK, null -> null
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
                val isSign = requestType == Nip55RequestType.SIGN_EVENT || requestType == Nip55RequestType.GET_PUBLIC_KEY
                if (isSign) {
                    MatrixCursor(SIGN_COLUMNS).apply {
                        addRow(arrayOf(response.result, response.event, response.result))
                    }
                } else {
                    MatrixCursor(ENCRYPT_COLUMNS).apply {
                        addRow(arrayOf(response.result, response.result))
                    }
                }
            }
            .getOrElse { e ->
                if (BuildConfig.DEBUG) Log.e(TAG, "Background request failed: ${e::class.simpleName}: ${e.message}")
                errorCursor(GENERIC_ERROR_MESSAGE, id)
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

        val kindText = eventKind?.let { " (kind $it)" } ?: ""
        val notification = NotificationCompat.Builder(ctx, BACKGROUND_SIGNING_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notification_background_signing_title))
            .setContentText(ctx.getString(R.string.notification_background_signing_text, appLabel, requestType.headerTitle() + kindText))
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
