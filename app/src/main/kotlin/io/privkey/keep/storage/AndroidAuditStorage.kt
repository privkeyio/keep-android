package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.uniffi.KeepMobileException
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject

class AndroidAuditStorage(context: Context) {

    companion object {
        private const val PREFS_NAME = "keep_audit_log"
        private const val KEY_ENTRIES = "audit_entries"
        private const val MAX_ENTRIES = 1000
        private const val MAX_ENTRY_SIZE_BYTES = 64 * 1024
    }

    private val prefs: SharedPreferences = run {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    @Synchronized
    fun storeEntry(entryJson: String) {
        if (entryJson.toByteArray(Charsets.UTF_8).size > MAX_ENTRY_SIZE_BYTES) {
            throw KeepMobileException.StorageException("Audit entry exceeds maximum size limit")
        }
        try {
            JSONObject(entryJson)
        } catch (e: JSONException) {
            throw KeepMobileException.StorageException("Invalid JSON format for audit entry")
        }
        val entries = loadEntriesInternal().apply { add(entryJson) }
        saveEntries(entries.takeLast(MAX_ENTRIES))
    }

    @Synchronized
    fun loadEntries(limit: UInt?): List<String> {
        val entries = loadEntriesInternal()
        return limit?.let { entries.takeLast(it.coerceAtMost(Int.MAX_VALUE.toUInt()).toInt()) } ?: entries
    }

    @Synchronized
    fun clearEntries() {
        prefs.edit().remove(KEY_ENTRIES).apply()
    }

    private fun loadEntriesInternal(): MutableList<String> {
        val stored = prefs.getString(KEY_ENTRIES, null) ?: return mutableListOf()
        return try {
            val jsonArray = JSONArray(stored)
            (0 until jsonArray.length()).mapTo(mutableListOf()) { jsonArray.getString(it) }
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to load audit entries")
        }
    }

    private fun saveEntries(entries: List<String>) {
        val jsonArray = JSONArray()
        entries.forEach { jsonArray.put(it) }
        val saved = prefs.edit().putString(KEY_ENTRIES, jsonArray.toString()).commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save audit entry")
        }
    }
}
