package io.privkey.keep.storage

import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.nip55.Nip55AuditLog
import io.privkey.keep.nip55.Nip55AuditLogDao
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SigningAuditStorage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
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
            throw KeepMobileException.StorageException("Invalid JSON for signing audit entry: ${e.message}")
        }

        val rustRequestType = json.getString("request_type")
        val rustDecision = json.getString("decision")

        val prevHashBytes = json.optJSONArray("prev_hash")
        val hashBytes = json.optJSONArray("hash")

        val log = Nip55AuditLog(
            timestamp = json.getLong("timestamp") * 1000,
            callerPackage = json.getString("caller"),
            requestType = fromRustRequestType(rustRequestType),
            eventKind = if (!json.isNull("event_kind")) json.getInt("event_kind") else null,
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
                val safeLimit = limit.toLong().coerceAtMost(MAX_QUERY_LIMIT.toLong()).toInt()
                auditDao.getRecent(safeLimit)
            } else {
                auditDao.getRecent(MAX_QUERY_LIMIT)
            }
        }
        return entries.map { it.toRustJson() }
    }

    override fun loadEntriesPage(offset: UInt, limit: UInt, callerFilter: String?): List<String> {
        val safeLimit = limit.toLong().coerceAtMost(MAX_QUERY_LIMIT.toLong()).toInt()
        val safeOffset = offset.toLong().coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
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
            "ask" to "Pending"
        )

        private val RUST_TO_DECISION = mapOf(
            "Approved" to "allow",
            "Denied" to "deny",
            "Pending" to "ask"
        )

        fun toRustRequestType(roomType: String): String {
            val mapped = REQUEST_TYPE_TO_RUST[roomType]
            if (mapped == null) {
                Log.w(TAG, "Unknown request type: $roomType, defaulting to SignEvent")
            }
            return mapped ?: "SignEvent"
        }

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
    val bytes = ByteArray(length()) { i ->
        val v = getInt(i)
        require(v in 0..255) { "Byte value out of range at index $i: $v" }
        v.toByte()
    }
    return bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}

private fun hexToJsonArray(hex: String?): JSONArray {
    if (hex.isNullOrEmpty()) return JSONArray()
    require(hex.length % 2 == 0) { "Odd-length hex string: ${hex.length}" }
    val arr = JSONArray()
    for (i in hex.indices step 2) {
        arr.put(hex.substring(i, i + 2).toInt(16))
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
    json.put("event_kind", eventKind?.takeIf { it != -1 } ?: JSONObject.NULL)
    json.put("reason", JSONObject.NULL)
    json.put("prev_hash", hexToJsonArray(previousHash))
    json.put("hash", hexToJsonArray(entryHash.takeIf { it.isNotEmpty() }))
    return json.toString()
}
