package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object KeystoreEncryptedPrefs {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_PREFIX = "keep_prefs_"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_IV_LENGTH = 12
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    fun create(context: Context, prefsName: String): SharedPreferences {
        val keyAlias = KEY_ALIAS_PREFIX + prefsName
        val secretKey = getOrCreateKey(keyAlias)
        val basePrefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        return EncryptingSharedPreferences(basePrefs, secretKey)
    }

    private fun getOrCreateKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(alias)) {
            return keyStore.getKey(alias, null) as SecretKey
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun encrypt(key: SecretKey, plaintext: String): String {
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
        val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encrypted = combined.copyOfRange(GCM_IV_LENGTH, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private fun encryptKey(key: SecretKey, keyName: String): String = encrypt(key, keyName)

    private fun decryptKey(key: SecretKey, encryptedKey: String): String = decrypt(key, encryptedKey)

    private class EncryptingSharedPreferences(
        private val basePrefs: SharedPreferences,
        private val secretKey: SecretKey
    ) : SharedPreferences {

        private val keyCache = mutableMapOf<String, String>()

        private fun getEncryptedKeyName(plainKey: String): String {
            return keyCache.getOrPut(plainKey) { encryptKey(secretKey, plainKey) }
        }

        private fun findEncryptedKey(plainKey: String): String? {
            keyCache[plainKey]?.let { return it }
            for (encKey in basePrefs.all.keys) {
                try {
                    val decrypted = decryptKey(secretKey, encKey)
                    keyCache[decrypted] = encKey
                    if (decrypted == plainKey) return encKey
                } catch (_: Exception) {
                    continue
                }
            }
            return null
        }

        override fun getAll(): MutableMap<String, *> {
            val result = mutableMapOf<String, Any?>()
            for ((encKey, encValue) in basePrefs.all) {
                try {
                    val plainKey = decryptKey(secretKey, encKey)
                    val plainValue = when (encValue) {
                        is String -> decryptValue(encValue)
                        else -> encValue
                    }
                    result[plainKey] = plainValue
                } catch (_: Exception) {
                    continue
                }
            }
            return result
        }

        private fun decryptValue(encrypted: String): Any? {
            val decrypted = decrypt(secretKey, encrypted)
            return when {
                decrypted.startsWith("s:") -> decrypted.substring(2)
                decrypted.startsWith("i:") -> decrypted.substring(2).toIntOrNull()
                decrypted.startsWith("l:") -> decrypted.substring(2).toLongOrNull()
                decrypted.startsWith("f:") -> decrypted.substring(2).toFloatOrNull()
                decrypted.startsWith("b:") -> decrypted.substring(2) == "true"
                decrypted.startsWith("ss:") -> decrypted.substring(3).split("\u0000").toSet()
                else -> decrypted
            }
        }

        private fun encryptValue(value: Any?): String {
            val prefixed = when (value) {
                is String -> "s:$value"
                is Int -> "i:$value"
                is Long -> "l:$value"
                is Float -> "f:$value"
                is Boolean -> "b:$value"
                is Set<*> -> "ss:" + value.joinToString("\u0000")
                else -> throw IllegalArgumentException("Unsupported type: ${value?.javaClass}")
            }
            return encrypt(secretKey, prefixed)
        }

        override fun getString(key: String, defValue: String?): String? {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("s:")) decrypted.substring(2) else decrypted
            } catch (_: Exception) {
                defValue
            }
        }

        override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? {
            val encKey = findEncryptedKey(key) ?: return defValues
            val encValue = basePrefs.getString(encKey, null) ?: return defValues
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("ss:")) {
                    decrypted.substring(3).split("\u0000").filter { it.isNotEmpty() }.toMutableSet()
                } else defValues
            } catch (_: Exception) {
                defValues
            }
        }

        override fun getInt(key: String, defValue: Int): Int {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("i:")) decrypted.substring(2).toInt() else defValue
            } catch (_: Exception) {
                defValue
            }
        }

        override fun getLong(key: String, defValue: Long): Long {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("l:")) decrypted.substring(2).toLong() else defValue
            } catch (_: Exception) {
                defValue
            }
        }

        override fun getFloat(key: String, defValue: Float): Float {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("f:")) decrypted.substring(2).toFloat() else defValue
            } catch (_: Exception) {
                defValue
            }
        }

        override fun getBoolean(key: String, defValue: Boolean): Boolean {
            val encKey = findEncryptedKey(key) ?: return defValue
            val encValue = basePrefs.getString(encKey, null) ?: return defValue
            return try {
                val decrypted = decrypt(secretKey, encValue)
                if (decrypted.startsWith("b:")) decrypted.substring(2) == "true" else defValue
            } catch (_: Exception) {
                defValue
            }
        }

        override fun contains(key: String): Boolean = findEncryptedKey(key) != null

        override fun edit(): SharedPreferences.Editor = EncryptingEditor()

        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
            basePrefs.registerOnSharedPreferenceChangeListener(listener)
        }

        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {
            basePrefs.unregisterOnSharedPreferenceChangeListener(listener)
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

            override fun commit(): Boolean {
                applyChanges()
                return baseEditor.commit()
            }

            override fun apply() {
                applyChanges()
                baseEditor.apply()
            }

            private fun applyChanges() {
                if (clearRequested) {
                    baseEditor.clear()
                    keyCache.clear()
                }

                for (plainKey in pendingRemoves) {
                    val encKey = findEncryptedKey(plainKey)
                    if (encKey != null) {
                        baseEditor.remove(encKey)
                        keyCache.remove(plainKey)
                    }
                }

                for ((plainKey, value) in pendingPuts) {
                    val existingEncKey = findEncryptedKey(plainKey)
                    if (existingEncKey != null) {
                        baseEditor.remove(existingEncKey)
                    }
                    val newEncKey = getEncryptedKeyName(plainKey)
                    val encValue = encryptValue(value)
                    baseEditor.putString(newEncKey, encValue)
                }
            }
        }
    }
}
