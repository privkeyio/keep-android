package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.uniffi.AuditStorage
import io.privkey.keep.uniffi.KeepMobileException
import org.json.JSONArray

class AndroidAuditStorage(context: Context) : AuditStorage {

    companion object {
        private const val PREFS_NAME = "keep_audit_log"
        private const val KEY_ENTRIES = "audit_entries"
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
    override fun storeEntry(entryJson: String) {
        val entries = loadEntriesInternal()
        entries.add(entryJson)
        saveEntries(entries)
    }

    override fun loadEntries(limit: UInt?): List<String> {
        val entries = loadEntriesInternal()
        return if (limit != null) {
            val n = limit.toInt()
            if (n >= entries.size) entries else entries.subList(entries.size - n, entries.size)
        } else {
            entries
        }
    }

    @Synchronized
    override fun clearEntries() {
        prefs.edit().remove(KEY_ENTRIES).apply()
    }

    private fun loadEntriesInternal(): MutableList<String> {
        val stored = prefs.getString(KEY_ENTRIES, null) ?: return mutableListOf()
        return try {
            val jsonArray = JSONArray(stored)
            val result = mutableListOf<String>()
            for (i in 0 until jsonArray.length()) {
                result.add(jsonArray.getString(i))
            }
            result
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to load audit entries: ${e.message}")
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
