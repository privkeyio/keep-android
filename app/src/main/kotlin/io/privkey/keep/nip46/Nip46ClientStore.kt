package io.privkey.keep.nip46

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

object Nip46ClientStore {

    private const val PREFS_NAME = "keep_nip46_clients"
    private const val KEY_CLIENTS = "clients"

    private fun getPrefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveClient(context: Context, pubkey: String, name: String, relays: List<String>) {
        val normalizedPubkey = pubkey.lowercase()
        val clients = getClients(context).toMutableMap()
        clients[normalizedPubkey] = Nip46ClientInfo(
            pubkey = normalizedPubkey,
            name = name,
            relays = relays,
            connectedAt = System.currentTimeMillis()
        )
        saveClients(context, clients)
    }

    fun getClients(context: Context): Map<String, Nip46ClientInfo> {
        val prefs = getPrefs(context)
        val stored = prefs.getString(KEY_CLIENTS, null) ?: return emptyMap()
        return runCatching {
            val json = JSONArray(stored)
            val result = mutableMapOf<String, Nip46ClientInfo>()
            for (i in 0 until json.length()) {
                val obj = json.getJSONObject(i)
                val pubkey = obj.getString("pubkey")
                val relaysArray = obj.getJSONArray("relays")
                val relays = (0 until relaysArray.length()).map { relaysArray.getString(it) }
                result[pubkey] = Nip46ClientInfo(
                    pubkey = pubkey,
                    name = obj.optString("name", "Unknown"),
                    relays = relays,
                    connectedAt = obj.optLong("connectedAt", 0)
                )
            }
            result
        }.getOrDefault(emptyMap())
    }

    fun getClient(context: Context, pubkey: String): Nip46ClientInfo? =
        getClients(context)[pubkey.lowercase()]

    fun removeClient(context: Context, pubkey: String) {
        val clients = getClients(context).toMutableMap()
        clients.remove(pubkey.lowercase())
        saveClients(context, clients)
    }

    private fun saveClients(context: Context, clients: Map<String, Nip46ClientInfo>) {
        val json = JSONArray()
        clients.values.forEach { client ->
            json.put(JSONObject().apply {
                put("pubkey", client.pubkey)
                put("name", client.name)
                put("relays", JSONArray(client.relays))
                put("connectedAt", client.connectedAt)
            })
        }
        getPrefs(context).edit().putString(KEY_CLIENTS, json.toString()).apply()
    }
}

data class Nip46ClientInfo(
    val pubkey: String,
    val name: String,
    val relays: List<String>,
    val connectedAt: Long
)
