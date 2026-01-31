package io.privkey.keep.nip55

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import android.util.Log
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.storage.SignPolicy
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

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
        private const val RATE_LIMIT_WINDOW_MS = 1000L
        private const val RATE_LIMIT_MAX_REQUESTS = 10

        private val RESULT_COLUMNS = arrayOf("result", "event", "error", "id", "pubkey", "rejected")
    }

    private data class RateLimitEntry(var count: Int, var windowStart: Long)
    private val rateLimitMap = ConcurrentHashMap<String, RateLimitEntry>()

    private fun checkRateLimit(callerPackage: String): Boolean {
        val now = System.currentTimeMillis()
        val entry = rateLimitMap.compute(callerPackage) { _, existing ->
            if (existing == null || now - existing.windowStart >= RATE_LIMIT_WINDOW_MS) {
                RateLimitEntry(1, now)
            } else {
                existing.count++
                existing
            }
        }
        return entry != null && entry.count <= RATE_LIMIT_MAX_REQUESTS
    }

    private val app: KeepMobileApp? get() = context?.applicationContext as? KeepMobileApp

    private fun <T> runWithTimeout(block: suspend () -> T): T? = runBlocking {
        withTimeoutOrNull(OPERATION_TIMEOUT_MS) { block() }
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        val currentApp = app ?: return errorCursor("not_initialized", null)
        if (currentApp.getKillSwitchStore()?.isEnabled() == true) {
            return errorCursor(GENERIC_ERROR_MESSAGE, null)
        }
        val pinStore = currentApp.getPinStore()
        if (pinStore != null && pinStore.isPinEnabled() && !pinStore.isSessionValid()) {
            return errorCursor("locked", null)
        }
        val h = currentApp.getNip55Handler() ?: return errorCursor("not_initialized", null)
        val store = currentApp.getPermissionStore()

        val callerPackage = getCallerPackage() ?: return errorCursor("unknown_caller", null)

        if (!checkRateLimit(callerPackage)) {
            Log.w(TAG, "Rate limit exceeded for $callerPackage")
            return errorCursor("rate_limited", null)
        }

        val requestType = when (uri.authority) {
            AUTHORITY_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            AUTHORITY_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            AUTHORITY_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            AUTHORITY_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            else -> return errorCursor("invalid_uri", null)
        }

        val rawContent = projection?.getOrNull(0) ?: ""
        val rawPubkey = projection?.getOrNull(1)?.takeIf { it.isNotBlank() }
        val currentUser = projection?.getOrNull(2)?.takeIf { it.isNotBlank() }

        if (rawContent.length > MAX_CONTENT_LENGTH)
            return errorCursor("invalid input length", null)
        if (rawPubkey != null && rawPubkey.length > MAX_PUBKEY_LENGTH)
            return errorCursor("invalid input length", null)

        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(rawContent) else null

        if (store == null) return null

        val effectivePolicy = runBlocking {
            withTimeoutOrNull(OPERATION_TIMEOUT_MS) {
                store.getAppSignPolicyOverride(callerPackage)
                    ?.let { SignPolicy.fromOrdinal(it) }
                    ?: currentApp.getSignPolicyStore()?.getGlobalPolicy()
                    ?: SignPolicy.MANUAL
            } ?: SignPolicy.MANUAL
        }

        if (effectivePolicy == SignPolicy.MANUAL) return null

        if (effectivePolicy == SignPolicy.AUTO) {
            return executeBackgroundRequest(h, store, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser)
        }

        val isAppExpired = runWithTimeout { store.isAppExpired(callerPackage) }
        if (isAppExpired == null) {
            Log.w(TAG, "isAppExpired check timed out for $callerPackage, denying request")
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
            Log.w(TAG, "Permission lookup timed out for $callerPackage/$requestType, denying request")
            return rejectedCursor(null)
        }

        return when (decision) {
            PermissionDecision.ALLOW -> executeBackgroundRequest(h, store, callerPackage, requestType, rawContent, rawPubkey, null, eventKind, currentUser)
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
            .onSuccess {
                runWithTimeout { store.logOperation(callerPackage, requestType, eventKind, "allow", wasAutomatic = true) }
            }
            .map { response ->
                val cursor = MatrixCursor(RESULT_COLUMNS)
                val pubkeyValue = if (requestType == Nip55RequestType.GET_PUBLIC_KEY) response.result else null
                cursor.addRow(arrayOf(response.result, response.event, response.error, id, pubkeyValue, null))
                cursor
            }
            .getOrElse { e ->
                Log.e(TAG, "Background request failed: ${e::class.simpleName}")
                errorCursor("request_failed", id)
            }
    }

    private fun getCallerPackage(): String? {
        val callingUid = Binder.getCallingUid()
        if (callingUid == android.os.Process.myUid()) {
            return null
        }
        val packages = context?.packageManager?.getPackagesForUid(callingUid)
        return when {
            packages.isNullOrEmpty() -> null
            packages.size == 1 -> packages[0]
            else -> {
                Log.w(TAG, "Rejecting request from multi-package UID (count=${packages.size})")
                null
            }
        }
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
