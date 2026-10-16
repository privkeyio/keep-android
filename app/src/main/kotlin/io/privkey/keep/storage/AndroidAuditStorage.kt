package io.privkey.keep.storage

import android.content.Context
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

    private val prefs: ReadablePrefs = run {
        val newPrefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)
        LegacyPrefsMigration.migrateIfNeeded(context, PREFS_NAME, newPrefs)
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
        val stored = when (val read = prefs.readString(KEY_ENTRIES)) {
            is PrefRead.Found -> read.value
            PrefRead.Absent -> return mutableListOf()
            // The log is on disk and this read cannot produce it. An empty list would
            // send storeEntry on to write a single entry over the whole of it, which is
            // the one outcome a tamper-evident log must not have; entries that will not
            // parse already throw below, and this is the same answer for a worse fault.
            PrefRead.Unreadable ->
                throw KeepMobileException.StorageException("Failed to load audit entries")
        }
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
