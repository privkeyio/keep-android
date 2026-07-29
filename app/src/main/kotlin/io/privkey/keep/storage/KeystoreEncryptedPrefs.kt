package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.privkey.keep.BuildConfig
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object KeystoreEncryptedPrefs {

    private val initLocks = ConcurrentHashMap<String, Any>()
    private fun initLockFor(prefsName: String): Any =
        initLocks.getOrPut(prefsName) { Any() }

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "keep_prefs_"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private const val PREFIX_STRING = "s:"
    private const val PREFIX_INT = "i:"
    private const val PREFIX_LONG = "l:"
    private const val PREFIX_FLOAT = "f:"
    private const val PREFIX_BOOL = "b:"
    private const val PREFIX_STRING_SET = "ss:"
    private const val STRING_SET_DELIMITER = "\u0000"
    private const val KEY_REGISTRY = "__keys__"
    private const val KEY_REGISTRY_DELIMITER = "\u0000"
    private const val HMAC_KEY_PREF = "__hmac_key__"
    private const val HMAC_KEY_LENGTH = 32
    private const val DETERMINISTIC_HMAC_SEED = "keystore_prefs_hmac_key"

    fun create(context: Context, prefsName: String): SharedPreferences {
        val keyAlias = KEY_ALIAS_PREFIX + prefsName
        val secretKey = getOrCreateKey(context, keyAlias)
        val basePrefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        return EncryptingSharedPreferences(basePrefs, secretKey, prefsName)
    }

    private fun isStrongBoxAvailable(context: Context): Boolean = runCatching {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }.getOrDefault(false)

    private fun getOrCreateKey(context: Context, alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(alias)) {
            return keyStore.getKey(alias, null) as? SecretKey
                ?: throw IllegalStateException("Key $alias is not a SecretKey")
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        if (isStrongBoxAvailable(context)) {
            try {
                builder.setIsStrongBoxBacked(true)
                keyGenerator.init(builder.build())
                return keyGenerator.generateKey()
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "StrongBox unavailable, falling back", e)
                builder.setIsStrongBoxBacked(false)
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    private fun encrypt(key: SecretKey, plaintext: String): String {
        require(plaintext.isNotEmpty()) { "Plaintext must not be empty" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decrypt(key: SecretKey, ciphertext: String): String {
        require(ciphertext.isNotEmpty()) { "Ciphertext must not be empty" }
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, GCM_IV_BYTES)
        val encrypted = combined.copyOfRange(GCM_IV_BYTES, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private class EncryptingSharedPreferences(
        private val basePrefs: SharedPreferences,
        private val secretKey: SecretKey,
        private val prefsName: String
    ) : SharedPreferences {

        private val keyCache = ConcurrentHashMap<String, String>()
        private val reverseKeyCache = ConcurrentHashMap<String, String>()

        /// Whether the persisted key registry has been folded into [keyCache] for
        /// this instance. The registry is rewritten from that cache on every
        /// commit, and the cache only holds keys this instance has touched, so
        /// the first write after a process start would otherwise truncate the
        /// registry to those keys and orphan the rest.
        ///
        /// Guarded by the per-file monitor, and set only once the fold has
        /// finished. A flag published before the work completes would let a
        /// second writer proceed against a half-filled cache and persist the very
        /// truncation this exists to prevent.
        private var registrySeeded = false
        @Volatile
        private var hmacKey: ByteArray? = null
        private val listenerMap = ConcurrentHashMap<SharedPreferences.OnSharedPreferenceChangeListener, SharedPreferences.OnSharedPreferenceChangeListener>()

        // Migration-only fallback: predictable by design since it only obfuscates
        // preference key names, not values (values are AES-GCM encrypted with Keystore).
        // Used only when the random HMAC key cannot be persisted or the registry is
        // unreadable. Once migration succeeds, the random key replaces this.
        private fun deterministicHmacKey(): ByteArray =
            MessageDigest.getInstance("SHA-256")
                .digest("$DETERMINISTIC_HMAC_SEED:$prefsName".toByteArray(Charsets.UTF_8))

        private fun getHmacKey(): ByteArray {
            hmacKey?.let { return it }
            synchronized(initLockFor(prefsName)) {
                hmacKey?.let { return it }
                val stored = basePrefs.getString(HMAC_KEY_PREF, null)
                if (stored != null) {
                    val decrypted = decrypt(secretKey, stored)
                    val key = Base64.decode(decrypted, Base64.NO_WRAP)
                    // Our own 32-byte key, stored base64 then GCM-encrypted; GCM authentication
                    // rules out external tampering, so a wrong length here is an internal bug.
                    // Fail fast: Mac/SecretKeySpec accept any key length and would otherwise
                    // silently diverge the audit-chain HMACs and key-name hashes.
                    check(key.size == HMAC_KEY_LENGTH) { "Decoded HMAC key has wrong length: ${key.size}" }
                    hmacKey = key
                    return key
                }
                val key = ByteArray(HMAC_KEY_LENGTH).also { SecureRandom().nextBytes(it) }
                val encoded = Base64.encodeToString(key, Base64.NO_WRAP)
                val encryptedHmacKey = encrypt(secretKey, encoded)
                val registryHash = hmacWithKey(KEY_REGISTRY, deterministicHmacKey())
                val hasExistingEntries = basePrefs.contains(registryHash)
                val persisted = if (hasExistingEntries) {
                    migrateFromDeterministicKey(key, encryptedHmacKey).also { ok ->
                        if (!ok && BuildConfig.DEBUG) Log.e("KeystoreEncryptedPrefs", "HMAC migration failed, using deterministic fallback key")
                    }
                } else {
                    basePrefs.edit().putString(HMAC_KEY_PREF, encryptedHmacKey).commit().also { ok ->
                        if (!ok && BuildConfig.DEBUG) Log.e("KeystoreEncryptedPrefs", "Failed to persist new HMAC key")
                    }
                }
                val result = if (persisted) key else deterministicHmacKey()
                hmacKey = result
                return result
            }
        }

        private fun hmacWithKey(plainKey: String, key: ByteArray): String {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            val hash = mac.doFinal(plainKey.toByteArray(Charsets.UTF_8))
            return Base64.encodeToString(hash, Base64.NO_WRAP or Base64.URL_SAFE)
        }

        private fun recoverPlainKeysFromRegistry(oldKey: ByteArray): List<String>? {
            val registryHash = hmacWithKey(KEY_REGISTRY, oldKey)
            val encryptedRegistry = basePrefs.getString(registryHash, null) ?: return null
            return try {
                val decrypted = decrypt(secretKey, encryptedRegistry)
                if (!decrypted.startsWith(PREFIX_STRING)) return null
                val registryContent = decrypted.removePrefix(PREFIX_STRING)
                if (registryContent.isEmpty()) return emptyList()
                registryContent.split(KEY_REGISTRY_DELIMITER).filter { it.isNotEmpty() && it != KEY_REGISTRY }
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to read registry during migration", e)
                null
            }
        }

        private fun migrateFromDeterministicKey(newKey: ByteArray, encryptedHmacKey: String): Boolean {
            val oldKey = deterministicHmacKey()
            val plainKeys = recoverPlainKeysFromRegistry(oldKey)
            if (plainKeys == null) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Registry unreadable during HMAC migration, falling back to deterministic key")
                return false
            }
            val editor = basePrefs.edit()
            editor.putString(HMAC_KEY_PREF, encryptedHmacKey)
            if (plainKeys.isEmpty()) {
                return editor.commit()
            }
            data class KeyMapping(val plainKey: String, val oldHash: String, val newHash: String)
            val mappings = mutableListOf<KeyMapping>()
            for (plainKey in plainKeys) {
                val oldHash = hmacWithKey(plainKey, oldKey)
                val newHash = hmacWithKey(plainKey, newKey)
                val value = basePrefs.getString(oldHash, null) ?: continue
                editor.putString(newHash, value)
                editor.remove(oldHash)
                mappings.add(KeyMapping(plainKey, oldHash, newHash))
            }
            val oldRegistryHash = hmacWithKey(KEY_REGISTRY, oldKey)
            val newRegistryHash = hmacWithKey(KEY_REGISTRY, newKey)
            val registryValue = basePrefs.getString(oldRegistryHash, null)
            if (registryValue != null) {
                editor.putString(newRegistryHash, registryValue)
                editor.remove(oldRegistryHash)
            }
            if (!editor.commit()) {
                if (BuildConfig.DEBUG) Log.e("KeystoreEncryptedPrefs", "HMAC migration commit failed")
                return false
            }
            for (m in mappings) {
                keyCache[m.plainKey] = m.newHash
                reverseKeyCache.remove(m.oldHash)
                reverseKeyCache[m.newHash] = m.plainKey
            }
            return true
        }

        private fun calculateKeyHash(plainKey: String): String =
            hmacWithKey(plainKey, getHmacKey())

        private fun getEncryptedKeyName(plainKey: String): String {
            keyCache[plainKey]?.let { return it }
            val hash = calculateKeyHash(plainKey)
            keyCache[plainKey] = hash
            reverseKeyCache[hash] = plainKey
            return hash
        }

        private fun findEncryptedKey(plainKey: String): String? {
            keyCache[plainKey]?.let { encKey ->
                if (basePrefs.contains(encKey)) return encKey
            }
            val hash = calculateKeyHash(plainKey)
            return if (basePrefs.contains(hash)) {
                keyCache[plainKey] = hash
                reverseKeyCache[hash] = plainKey
                hash
            } else null
        }

        /// Fold the persisted registry into [keyCache] once per instance, so a
        /// registry rewrite unions with what is already stored instead of
        /// replacing it. Skipped when a clear is in flight, which legitimately
        /// empties the registry.
        ///
        /// Callers hold the per-file monitor, which also serialises this against
        /// a concurrent clear. Without that, the fold could read the registry
        /// under one derivation key and hash its names under a newer one, caching
        /// hashes that point nowhere and writing cleared names back into the
        /// registry.
        private fun ensureRegistrySeeded() {
            if (registrySeeded) return
            rebuildKeyCacheFromRegistry()
            registrySeeded = true
        }

        private fun rebuildKeyCacheFromRegistry() {
            val registryHash = calculateKeyHash(KEY_REGISTRY)
            val encryptedRegistry = basePrefs.getString(registryHash, null) ?: return
            try {
                val decrypted = decrypt(secretKey, encryptedRegistry)
                if (!decrypted.startsWith(PREFIX_STRING)) return
                val registryContent = decrypted.removePrefix(PREFIX_STRING)
                if (registryContent.isEmpty()) return
                for (plainKey in registryContent.split(KEY_REGISTRY_DELIMITER)) {
                    if (plainKey.isEmpty() || plainKey == KEY_REGISTRY) continue
                    val hash = calculateKeyHash(plainKey)
                    keyCache[plainKey] = hash
                    reverseKeyCache[hash] = plainKey
                }
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Registry corrupted, will rebuild as keys are accessed", e)
            }
        }

        override fun getAll(): MutableMap<String, *> {
            if (reverseKeyCache.isEmpty()) {
                rebuildKeyCacheFromRegistry()
            }
            val result = mutableMapOf<String, Any?>()
            for ((encKey, encValue) in basePrefs.all) {
                val plainKey = reverseKeyCache[encKey] ?: continue
                if (plainKey == KEY_REGISTRY) continue
                try {
                    val plainValue = when (encValue) {
                        is String -> decryptValue(encValue)
                        else -> encValue
                    }
                    result[plainKey] = plainValue
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to decrypt value for key $encKey", e)
                    continue
                }
            }
            return result
        }

        private fun decryptValue(encrypted: String): Any? {
            val decrypted = decrypt(secretKey, encrypted)
            return when {
                decrypted.startsWith(PREFIX_STRING) -> decrypted.removePrefix(PREFIX_STRING)
                decrypted.startsWith(PREFIX_INT) -> decrypted.removePrefix(PREFIX_INT).toIntOrNull()
                decrypted.startsWith(PREFIX_LONG) -> decrypted.removePrefix(PREFIX_LONG).toLongOrNull()
                decrypted.startsWith(PREFIX_FLOAT) -> decrypted.removePrefix(PREFIX_FLOAT).toFloatOrNull()
                decrypted.startsWith(PREFIX_BOOL) -> decrypted.removePrefix(PREFIX_BOOL) == "true"
                decrypted.startsWith(PREFIX_STRING_SET) -> decrypted.removePrefix(PREFIX_STRING_SET).split(STRING_SET_DELIMITER).toSet()
                else -> decrypted
            }
        }

        private fun encryptValue(value: Any?): String {
            val prefixed = when (value) {
                is String -> PREFIX_STRING + value
                is Int -> PREFIX_INT + value
                is Long -> PREFIX_LONG + value
                is Float -> PREFIX_FLOAT + value
                is Boolean -> PREFIX_BOOL + value
                is Set<*> -> PREFIX_STRING_SET + value.joinToString(STRING_SET_DELIMITER)
                else -> throw IllegalArgumentException("Unsupported type: ${value?.javaClass}")
            }
            return encrypt(secretKey, prefixed)
        }

        private inline fun <T> getTypedValue(
            key: String,
            defValue: T,
            prefix: String,
            crossinline parse: (String) -> T
        ): T {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith(prefix)) parse(decrypted.removePrefix(prefix)) else defValue
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to decrypt typed value for key $key", e)
                defValue
            }
        }

        override fun getString(key: String, defValue: String?): String? =
            getTypedValue(key, defValue, PREFIX_STRING) { it }

        override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
            getTypedValue(key, defValues, PREFIX_STRING_SET) { raw ->
                raw.split(STRING_SET_DELIMITER).filter { it.isNotEmpty() }.toMutableSet()
            }

        override fun getInt(key: String, defValue: Int): Int =
            getTypedValue(key, defValue, PREFIX_INT) { it.toInt() }

        override fun getLong(key: String, defValue: Long): Long =
            getTypedValue(key, defValue, PREFIX_LONG) { it.toLong() }

        override fun getFloat(key: String, defValue: Float): Float =
            getTypedValue(key, defValue, PREFIX_FLOAT) { it.toFloat() }

        override fun getBoolean(key: String, defValue: Boolean): Boolean =
            getTypedValue(key, defValue, PREFIX_BOOL) { it == "true" }

        override fun contains(key: String): Boolean = findEncryptedKey(key) != null

        override fun edit(): SharedPreferences.Editor = EncryptingEditor()

        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
            if (listener == null) return
            val wrappedListener = SharedPreferences.OnSharedPreferenceChangeListener { _, encKey ->
                val plainKey = reverseKeyCache[encKey]
                if (plainKey != null) {
                    listener.onSharedPreferenceChanged(this, plainKey)
                }
            }
            listenerMap[listener] = wrappedListener
            basePrefs.registerOnSharedPreferenceChangeListener(wrappedListener)
        }

        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
            if (listener == null) return
            val wrappedListener = listenerMap.remove(listener)
            if (wrappedListener != null) {
                basePrefs.unregisterOnSharedPreferenceChangeListener(wrappedListener)
            }
        }

        private inner class EncryptingEditor : SharedPreferences.Editor {
            private val baseEditor = basePrefs.edit()
            private val pendingPuts = mutableMapOf<String, Any?>()
            private val pendingRemoves = mutableSetOf<String>()
            private var clearRequested = false

            override fun putString(key: String, value: String?): SharedPreferences.Editor {
                if (value == null) return remove(key)
                pendingPuts[key] = value
                return this
            }

            override fun putStringSet(key: String, values: MutableSet<String>?): SharedPreferences.Editor {
                if (values == null) return remove(key)
                pendingPuts[key] = values
                return this
            }

            override fun putInt(key: String, value: Int): SharedPreferences.Editor {
                pendingPuts[key] = value
                return this
            }

            override fun putLong(key: String, value: Long): SharedPreferences.Editor {
                pendingPuts[key] = value
                return this
            }

            override fun putFloat(key: String, value: Float): SharedPreferences.Editor {
                pendingPuts[key] = value
                return this
            }

            override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor {
                pendingPuts[key] = value
                return this
            }

            override fun remove(key: String): SharedPreferences.Editor {
                pendingRemoves.add(key)
                pendingPuts.remove(key)
                return this
            }

            override fun clear(): SharedPreferences.Editor {
                clearRequested = true
                pendingPuts.clear()
                pendingRemoves.clear()
                return this
            }

            // Both paths take the per-file monitor, not just the clearing one.
            // The registry is rewritten from a shared cache, so two concurrent
            // writers could otherwise each snapshot it before the other's key was
            // added and the later commit would persist a registry missing it,
            // stranding that entry. Serialising also keeps the registry fold from
            // tearing against a clear. The monitor is reentrant, so the nested
            // derivation-key lookup is safe.
            override fun commit(): Boolean = synchronized(initLockFor(prefsName)) {
                applyChanges()
                baseEditor.commit()
            }

            override fun apply() = synchronized(initLockFor(prefsName)) {
                applyChanges()
                baseEditor.apply()
            }

            private fun applyChanges() {
                if (clearRequested) {
                    baseEditor.clear()
                    keyCache.clear()
                    reverseKeyCache.clear()
                    hmacKey = null
                } else {
                    // Fold in what is already on disk before the registry is
                    // rewritten below from the in-memory cache. Without this, the
                    // first write in a process drops every key this instance has
                    // not touched: the entries survive on disk but disappear from
                    // the registry, so `getAll` stops seeing them and the
                    // deterministic-key migration, which only re-hashes
                    // registry-listed keys, leaves them stranded under the old
                    // hash. For the rate-limiter store that means a package's
                    // usage counters and cooling-off entries silently stop being
                    // found, which reads as "no usage yet".
                    ensureRegistrySeeded()
                }

                for (plainKey in pendingRemoves) {
                    val encKey = findEncryptedKey(plainKey)
                    if (encKey != null) {
                        baseEditor.remove(encKey)
                        reverseKeyCache.remove(encKey)
                    }
                    // Drop the name even when nothing was found on disk, so a
                    // registry entry whose value is already gone is not carried
                    // forward forever now that the registry is seeded rather than
                    // rebuilt from scratch each time.
                    keyCache.remove(plainKey)
                }

                for ((plainKey, value) in pendingPuts) {
                    val encKey = getEncryptedKeyName(plainKey)
                    val encValue = encryptValue(value)
                    baseEditor.putString(encKey, encValue)
                }

                updateKeyRegistry()
            }

            private fun updateKeyRegistry() {
                val allKeys = keyCache.keys.filter { it != KEY_REGISTRY }.toSet()
                if (allKeys.isEmpty() && clearRequested) return
                val registryContent = allKeys.joinToString(KEY_REGISTRY_DELIMITER)
                val encKey = getEncryptedKeyName(KEY_REGISTRY)
                val encValue = encryptValue(registryContent)
                baseEditor.putString(encKey, encValue)
            }
        }
    }
}
