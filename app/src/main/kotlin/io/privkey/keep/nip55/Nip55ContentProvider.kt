package io.privkey.keep.nip55

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
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
        private const val AUTHORITY = "io.privkey.keep.nip55"

        private const val MAX_ID_LENGTH = 128
        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_CONTENT_LENGTH = 1024 * 1024

        private const val CODE_GET_PUBLIC_KEY = 1
        private const val CODE_SIGN_EVENT = 2
        private const val CODE_NIP44_ENCRYPT = 5
        private const val CODE_NIP44_DECRYPT = 6

        private val uriMatcher = UriMatcher(UriMatcher.NO_MATCH).apply {
            addURI(AUTHORITY, "get_public_key", CODE_GET_PUBLIC_KEY)
            addURI(AUTHORITY, "sign_event", CODE_SIGN_EVENT)
            addURI(AUTHORITY, "nip44_encrypt", CODE_NIP44_ENCRYPT)
            addURI(AUTHORITY, "nip44_decrypt", CODE_NIP44_DECRYPT)
        }

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
        val h = handler ?: return errorCursor("not_initialized", null)
        val store = permissionStore

        val callerPackage = getCallerPackage() ?: return errorCursor("unknown_caller", null)

        val requestType = when (uriMatcher.match(uri)) {
            CODE_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            CODE_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            CODE_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            CODE_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            else -> return errorCursor("invalid_uri", null)
        }

        val id = uri.getQueryParameter("id")?.take(MAX_ID_LENGTH)
        val content = uri.getQueryParameter("content")?.take(MAX_CONTENT_LENGTH) ?: ""
        val pubkey = uri.getQueryParameter("pubkey")?.take(MAX_PUBKEY_LENGTH)

        val eventKind = if (requestType == Nip55RequestType.SIGN_EVENT) parseEventKind(content) else null

        val permissionResult = if (store != null) {
            runBlocking { store.hasPermission(callerPackage, requestType, eventKind) }
        } else null

        if (permissionResult == null) return null
        if (!permissionResult) {
            runBlocking { store?.logOperation(callerPackage, requestType, eventKind, "deny", wasAutomatic = true) }
            return rejectedCursor(id)
        }
        return executeBackgroundRequest(h, store, callerPackage, requestType, content, pubkey, id, eventKind)
    }

    private fun executeBackgroundRequest(
        h: Nip55Handler,
        store: PermissionStore?,
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
            callbackUrl = null,
            id = id,
            currentUser = null,
            permissions = null
        )

        return runCatching { h.handleRequest(request, callerPackage) }
            .onSuccess {
                runBlocking { store?.logOperation(callerPackage, requestType, eventKind, "allow", wasAutomatic = true) }
            }
            .map { response ->
                val cursor = MatrixCursor(RESULT_COLUMNS)
                val pubkeyValue = if (requestType == Nip55RequestType.GET_PUBLIC_KEY) response.result else null
                cursor.addRow(arrayOf(response.result, response.event, response.error, id, pubkeyValue, null))
                cursor
            }
            .getOrElse { e ->
                Log.e(TAG, "Background request failed", e)
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

    override fun getType(uri: Uri): String = "vnd.android.cursor.item/vnd.$AUTHORITY"

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
