package io.privkey.keep.storage

import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.nip55.EVENT_KIND_GENERIC
import io.privkey.keep.nip55.Nip55AuditLogDao
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SigningAuditStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import io.privkey.keep.nip55.Nip55AuditLog
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "SigningAuditStorage"
private const val MAX_QUERY_LIMIT = 10_000

class AndroidSigningAuditStorage(
    private val auditDao: Nip55AuditLogDao
) : SigningAuditStorage {

    override fun storeEntry(entryJson: String) {
        val json = try {
            JSONObject(entryJson)
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Invalid JSON for signing audit entry")
        }

        val rustRequestType = json.getString("request_type")
        val rustDecision = json.getString("decision")

        val prevHashBytes = json.optJSONArray("prev_hash")
        val hashBytes = json.optJSONArray("hash")

        val log = Nip55AuditLog(
            timestamp = json.getLong("timestamp") * 1000,
            callerPackage = json.getString("caller"),
            requestType = fromRustRequestType(rustRequestType),
            eventKind = if (json.has("event_kind") && !json.isNull("event_kind")) json.getInt("event_kind") else EVENT_KIND_GENERIC,
            decision = fromRustDecision(rustDecision),
            wasAutomatic = json.getBoolean("was_automatic"),
            previousHash = prevHashBytes?.toHexString(),
            entryHash = hashBytes?.toHexString() ?: ""
        )
        runBlocking(Dispatchers.IO) { auditDao.insert(log) }
    }

    override fun loadEntries(limit: UInt?): List<String> {
        val entries = runBlocking(Dispatchers.IO) {
            if (limit != null) {
                auditDao.getRecent(limit.toInt().coerceAtLeast(0).coerceAtMost(MAX_QUERY_LIMIT))
            } else {
                auditDao.getAllOrdered()
            }
        }
        return entries.map { it.toRustJson() }
    }

    override fun loadEntriesPage(offset: UInt, limit: UInt, callerFilter: String?): List<String> {
        val safeLimit = limit.toInt().coerceAtLeast(0).coerceAtMost(MAX_QUERY_LIMIT)
        val safeOffset = offset.toInt().coerceAtLeast(0)
        val entries = runBlocking(Dispatchers.IO) {
            if (callerFilter != null) {
                auditDao.getPageForCaller(callerFilter, safeLimit, safeOffset)
            } else {
                auditDao.getPage(safeLimit, safeOffset)
            }
        }
        return entries.map { it.toRustJson() }
    }

    override fun distinctCallers(): List<String> {
        return runBlocking(Dispatchers.IO) { auditDao.getDistinctCallers() }
    }

    override fun entryCount(): UInt {
        return runBlocking(Dispatchers.IO) { auditDao.getCount().toUInt() }
    }

    companion object {
        private val REQUEST_TYPE_TO_RUST = mapOf(
            "SIGN_EVENT" to "SignEvent",
            "GET_PUBLIC_KEY" to "GetPublicKey",
            "CONNECT" to "Connect",
            "DISCONNECT" to "Disconnect",
            "NIP04_ENCRYPT" to "Nip04Encrypt",
            "NIP04_DECRYPT" to "Nip04Decrypt",
            "NIP44_ENCRYPT" to "Nip44Encrypt",
            "NIP44_DECRYPT" to "Nip44Decrypt",
            "KILL_SWITCH" to "KillSwitch"
        )

        private val RUST_TO_REQUEST_TYPE = REQUEST_TYPE_TO_RUST.entries.associate { (k, v) -> v to k }

        private val DECISION_TO_RUST = mapOf(
            "allow" to "Approved",
            "deny" to "Denied",
            "ask" to "Denied"
        )

        private val RUST_TO_DECISION = mapOf(
            "Approved" to "allow",
            "Denied" to "deny"
        )

        fun toRustRequestType(roomType: String): String =
            REQUEST_TYPE_TO_RUST[roomType] ?: "SignEvent"

        private fun fromRustRequestType(rustType: String): String {
            val mapped = RUST_TO_REQUEST_TYPE[rustType]
            if (mapped == null && BuildConfig.DEBUG) {
                Log.w(TAG, "Unknown request type from Rust: $rustType, defaulting to SIGN_EVENT")
            }
            return mapped ?: "SIGN_EVENT"
        }

        fun toRustDecision(roomDecision: String): String =
            DECISION_TO_RUST[roomDecision] ?: "Denied"

        private fun fromRustDecision(rustDecision: String): String =
            RUST_TO_DECISION[rustDecision] ?: "deny"
    }
}

private fun JSONArray.toHexString(): String? {
    if (length() == 0) return null
    val bytes = ByteArray(length()) { i -> getInt(i).toByte() }
    return bytes.joinToString("") { "%02x".format(it) }
}

private fun hexToJsonArray(hex: String?): JSONArray {
    if (hex.isNullOrEmpty()) return JSONArray()
    val arr = JSONArray()
    for (i in hex.indices step 2) {
        arr.put(hex.substring(i, (i + 2).coerceAtMost(hex.length)).toInt(16))
    }
    return arr
}

private fun Nip55AuditLog.toRustJson(): String {
    val json = JSONObject()
    json.put("timestamp", timestamp / 1000)
    json.put("request_type", AndroidSigningAuditStorage.toRustRequestType(requestType))
    json.put("decision", AndroidSigningAuditStorage.toRustDecision(decision))
    json.put("was_automatic", wasAutomatic)
    json.put("caller", callerPackage)
    json.put("caller_name", JSONObject.NULL)
    if (eventKind != null && eventKind != -1) {
        json.put("event_kind", eventKind)
    } else {
        json.put("event_kind", JSONObject.NULL)
    }
    json.put("reason", JSONObject.NULL)
    json.put("prev_hash", hexToJsonArray(previousHash))
    json.put("hash", hexToJsonArray(entryHash.takeIf { it.isNotEmpty() }))
    return json.toString()
}
