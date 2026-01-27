package io.privkey.keep.nip55

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import android.util.Log
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking

class Nip55ContentProvider : ContentProvider() {
    private var handler: Nip55Handler? = null
    private var permissionStore: PermissionStore? = null

    companion object {
        private const val TAG = "Nip55ContentProvider"

        private const val AUTHORITY_GET_PUBLIC_KEY = "io.privkey.keep.GET_PUBLIC_KEY"
        private const val AUTHORITY_SIGN_EVENT = "io.privkey.keep.SIGN_EVENT"
        private const val AUTHORITY_NIP44_ENCRYPT = "io.privkey.keep.NIP44_ENCRYPT"
        private const val AUTHORITY_NIP44_DECRYPT = "io.privkey.keep.NIP44_DECRYPT"

        private const val MAX_ID_LENGTH = 128
        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_CONTENT_LENGTH = 1024 * 1024

        private val RESULT_COLUMNS = arrayOf("result", "event", "error", "id", "pubkey", "rejected")
    }

    override fun onCreate(): Boolean {
        return true
    }

    private val app get() = context?.applicationContext as? KeepMobileApp

    private fun getHandler(): Nip55Handler? {
        return handler ?: app?.getNip55Handler()?.also { handler = it }
    }

    private fun getPermissionStore(): PermissionStore? {
        return permissionStore ?: app?.getPermissionStore()?.also { permissionStore = it }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? {
        val h = getHandler() ?: return errorCursor("not_initialized", null)
        val store = getPermissionStore()

        val callerPackage = getCallerPackage() ?: return errorCursor("unknown_caller", null)

        val requestType = when (uri.authority) {
            AUTHORITY_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            AUTHORITY_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            AUTHORITY_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            AUTHORITY_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            else -> return errorCursor("invalid_uri", null)
        }

        val rawId = uri.getQueryParameter("id")
        val rawContent = uri.getQueryParameter("content") ?: ""
        val rawPubkey = uri.getQueryParameter("pubkey")

        if (rawId != null && rawId.length > MAX_ID_LENGTH)
            return errorCursor("id exceeds max length of $MAX_ID_LENGTH", null)
        if (rawContent.length > MAX_CONTENT_LENGTH)
            return errorCursor("content exceeds max length of $MAX_CONTENT_LENGTH", null)
        if (rawPubkey != null && rawPubkey.length > MAX_PUBKEY_LENGTH)
            return errorCursor("pubkey exceeds max length of $MAX_PUBKEY_LENGTH", null)

        val id = rawId
        val content = rawContent
        val pubkey = rawPubkey

        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(content) else null

        if (store == null) return errorCursor("permission_store_unavailable", id)

        val permissionResult = runBlocking { store.hasPermission(callerPackage, requestType, eventKind) }
            ?: return errorCursor("permission_store_unavailable", id)

        if (!permissionResult) {
            runBlocking { store.logOperation(callerPackage, requestType, eventKind, "deny", wasAutomatic = true) }
            return rejectedCursor(id)
        }
        return executeBackgroundRequest(h, store, callerPackage, requestType, content, pubkey, id, eventKind)
    }

    private fun executeBackgroundRequest(
        h: Nip55Handler,
        store: PermissionStore,
        callerPackage: String,
        requestType: Nip55RequestType,
        content: String,
        pubkey: String?,
        id: String?,
        eventKind: Int?
    ): Cursor {
        val request = Nip55Request(
            requestType = requestType,
            content = content,
            pubkey = pubkey,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = id,
            currentUser = null,
            permissions = null
        )

        return runCatching { h.handleRequest(request, callerPackage) }
            .onSuccess {
                runBlocking { store.logOperation(callerPackage, requestType, eventKind, "allow", wasAutomatic = true) }
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
        return if (packages?.size == 1) packages[0] else null
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

    override fun getType(uri: Uri): String = "vnd.android.cursor.item/vnd.${uri.authority}"

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
