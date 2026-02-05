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
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

class Nip55ContentProvider : ContentProvider() {
    companion object {
        private const val TAG = "Nip55ContentProvider"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"

        private const val AUTHORITY_GET_PUBLIC_KEY = "io.privkey.keep.GET_PUBLIC_KEY"
        private const val AUTHORITY_SIGN_EVENT = "io.privkey.keep.SIGN_EVENT"
        private const val AUTHORITY_NIP44_ENCRYPT = "io.privkey.keep.NIP44_ENCRYPT"
        private const val AUTHORITY_NIP44_DECRYPT = "io.privkey.keep.NIP44_DECRYPT"

        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_CONTENT_LENGTH = 1024 * 1024
        private const val OPERATION_TIMEOUT_MS = 5000L

        private const val BACKGROUND_SIGNING_CHANNEL_ID = "background_signing"

        private val RESULT_COLUMNS = arrayOf("result", "event", "error", "id", "pubkey", "rejected")

        private fun hashPackageName(pkg: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(pkg.toByteArray(Charsets.UTF_8))
            return digest.take(8).joinToString("") { "%02x".format(it) }
        }
    }

    private val rateLimiter = RateLimiter()
    private val backgroundNotificationId = AtomicInteger(2000)

    private val app: KeepMobileApp? get() = context?.applicationContext as? KeepMobileApp

    private fun <T> runWithTimeout(block: suspend () -> T): T? = runBlocking {
        withTimeoutOrNull(OPERATION_TIMEOUT_MS) { block() }
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

        if (!rateLimiter.checkRateLimit(callerPackage)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rate limit exceeded for ${hashPackageName(callerPackage)}")
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }

        val requestType = when (uri.authority) {
            AUTHORITY_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            AUTHORITY_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            AUTHORITY_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            AUTHORITY_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            else -> return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }

        val rawContent = projection?.getOrNull(0) ?: ""
        val rawPubkey = projection?.getOrNull(1)?.takeIf { it.isNotBlank() }
        val currentUser = projection?.getOrNull(2)?.takeIf { it.isNotBlank() }

        if (rawContent.length > MAX_CONTENT_LENGTH)
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        if (rawPubkey != null && rawPubkey.length > MAX_PUBKEY_LENGTH)
            return errorCursor(GENERIC_ERROR_MESSAGE, null)

        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(rawContent) else null

        if (store == null) return null

        val velocityResult = runWithTimeout { store.checkAndRecordVelocity(callerPackage, eventKind) }
        if (velocityResult == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Velocity check timed out, denying request")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny_velocity_timeout", wasAutomatic = true) }
            return rejectedCursor(null)
        }
        if (velocityResult is VelocityResult.Blocked) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Velocity limit: ${velocityResult.reason}")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "velocity_blocked", wasAutomatic = true) }
            return rejectedCursor(null)
        }

        val effectivePolicy = runWithTimeout {
            store.getAppSignPolicyOverride(callerPackage)
                ?.let { SignPolicy.fromOrdinal(it) }
                ?: currentApp.getSignPolicyStore()?.getGlobalPolicy()
                ?: SignPolicy.MANUAL
        } ?: SignPolicy.MANUAL

        if (effectivePolicy == SignPolicy.MANUAL) return null

        if (effectivePolicy == SignPolicy.AUTO) {
            if (eventKind != null && isSensitiveKind(eventKind)) {
                if (BuildConfig.DEBUG) Log.d(TAG, "AUTO mode blocked for sensitive event kind $eventKind from ${hashPackageName(callerPackage)}")
                return null
            }

            val safeguards = currentApp.getAutoSigningSafeguards()
            if (safeguards == null) {
                if (BuildConfig.DEBUG) Log.w(TAG, "AUTO signing denied: AutoSigningSafeguards unavailable for ${hashPackageName(callerPackage)}")
                runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "deny_safeguards_unavailable", wasAutomatic = true) }
                return rejectedCursor(null)
            }

            if (!safeguards.isOptedIn(callerPackage)) {
                if (BuildConfig.DEBUG) Log.d(TAG, "AUTO signing not opted-in for ${hashPackageName(callerPackage)}")
                return null
            }

            val denyReason = when (val usageResult = safeguards.checkAndRecordUsage(callerPackage)) {
                is AutoSigningSafeguards.UsageCheckResult.Allowed ->
                    return executeBackgroundRequest(h, store, currentApp, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser)
                is AutoSigningSafeguards.UsageCheckResult.HourlyLimitExceeded -> "deny_hourly_limit"
                is AutoSigningSafeguards.UsageCheckResult.DailyLimitExceeded -> "deny_daily_limit"
                is AutoSigningSafeguards.UsageCheckResult.UnusualActivity -> "deny_unusual_activity"
                is AutoSigningSafeguards.UsageCheckResult.CoolingOff -> "deny_cooling_off"
            }
            if (BuildConfig.DEBUG) Log.w(TAG, "Auto-signing denied for ${hashPackageName(callerPackage)}: $denyReason")
            runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, denyReason, wasAutomatic = true) }
            return rejectedCursor(null)
        }

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
            val risk = runWithTimeout { store.riskAssessor.assess(callerPackage, eventKind) }
            if (risk == null) {
                if (BuildConfig.DEBUG) Log.w(TAG, "Risk assessment timed out for ${hashPackageName(callerPackage)}, falling back to UI")
                return null
            }
            if (risk.requiredAuth != AuthLevel.NONE) {
                if (BuildConfig.DEBUG) Log.d(TAG, "Risk escalation for ${hashPackageName(callerPackage)}: score=${risk.score}, auth=${risk.requiredAuth}")
                return null
            }
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
                if (requestType == Nip55RequestType.GET_PUBLIC_KEY && response.result != null) {
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
                val cursor = MatrixCursor(RESULT_COLUMNS)
                val pubkeyValue = if (requestType == Nip55RequestType.GET_PUBLIC_KEY) response.result else null
                cursor.addRow(arrayOf(response.result, response.event, response.error, id, pubkeyValue, null))
                cursor
            }
            .getOrElse { e ->
                if (BuildConfig.DEBUG) Log.e(TAG, "Background request failed: ${e::class.simpleName}")
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

        NotificationManagerCompat.from(ctx).notify(backgroundNotificationId.getAndIncrement(), notification)
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
        val cursor = MatrixCursor(RESULT_COLUMNS)
        cursor.addRow(arrayOf(null, null, error, id, null, null))
        return cursor
    }

    private fun rejectedCursor(id: String?): MatrixCursor {
        val cursor = MatrixCursor(RESULT_COLUMNS)
        cursor.addRow(arrayOf(null, null, null, id, null, "true"))
        return cursor
    }

    override fun getType(uri: Uri): String {
        val authority = uri.authority ?: "io.privkey.keep"
        return "vnd.android.cursor.item/vnd.$authority"
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
