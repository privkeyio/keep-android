package io.privkey.keep.nip55

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType

class Nip55ContentProvider : ContentProvider() {
    private var handler: Nip55Handler? = null
    private val permissionStore = PermissionStore()

    companion object {
        private const val TAG = "Nip55ContentProvider"
        private const val AUTHORITY = "io.privkey.keep.nip55"

        private const val CODE_GET_PUBLIC_KEY = 1
        private const val CODE_SIGN_EVENT = 2
        private const val CODE_NIP44_ENCRYPT = 3
        private const val CODE_NIP44_DECRYPT = 4

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

    private fun getHandler(): Nip55Handler? {
        if (handler == null) {
            handler = (context?.applicationContext as? KeepMobileApp)?.getNip55Handler()
        }
        return handler
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor {
        val h = getHandler() ?: return errorCursor("not_initialized", null)

        val callerPackage = getCallerPackage()
        if (callerPackage == null) {
            return errorCursor("unknown_caller", null)
        }

        val requestType = when (uriMatcher.match(uri)) {
            CODE_GET_PUBLIC_KEY -> Nip55RequestType.GET_PUBLIC_KEY
            CODE_SIGN_EVENT -> Nip55RequestType.SIGN_EVENT
            CODE_NIP44_ENCRYPT -> Nip55RequestType.NIP44_ENCRYPT
            CODE_NIP44_DECRYPT -> Nip55RequestType.NIP44_DECRYPT
            else -> return errorCursor("invalid_uri", null)
        }

        val id = uri.getQueryParameter("id")
        val content = uri.getQueryParameter("content") ?: ""
        val pubkey = uri.getQueryParameter("pubkey")
        val currentUser = uri.getQueryParameter("current_user")

        if (!permissionStore.hasPermission(callerPackage, requestType)) {
            return rejectedCursor(id)
        }

        val request = Nip55Request(
            requestType = requestType,
            content = content,
            pubkey = pubkey,
            returnType = "signature",
            callbackUrl = null,
            id = id,
            currentUser = currentUser,
            permissions = null
        )

        return try {
            val response = h.handleRequest(request, callerPackage)
            val cursor = MatrixCursor(RESULT_COLUMNS)
            val pubkeyValue = if (requestType == Nip55RequestType.GET_PUBLIC_KEY) {
                response.result
            } else null
            cursor.addRow(arrayOf(
                response.result,
                response.event,
                response.error,
                response.id,
                pubkeyValue,
                null
            ))
            cursor
        } catch (e: Exception) {
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

class PermissionStore {
    private val permissions = mutableMapOf<String, MutableSet<Nip55RequestType>>()

    @Synchronized
    fun grantPermission(callerPackage: String, requestType: Nip55RequestType) {
        permissions.getOrPut(callerPackage) { mutableSetOf() }.add(requestType)
    }

    @Synchronized
    fun revokePermission(callerPackage: String, requestType: Nip55RequestType) {
        permissions[callerPackage]?.remove(requestType)
    }

    @Synchronized
    fun hasPermission(callerPackage: String, requestType: Nip55RequestType): Boolean {
        return permissions[callerPackage]?.contains(requestType) == true
    }

    @Synchronized
    fun revokeAll(callerPackage: String) {
        permissions.remove(callerPackage)
    }
}
