package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SecureStorage
import io.privkey.keep.uniffi.ShareMetadataInfo
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class AndroidKeystoreStorage(private val context: Context) : SecureStorage {

    companion object {
        private const val KEYSTORE_ALIAS = "keep_frost_share"
        private const val KEYSTORE_PREFIX = "keep_frost_"
        private const val PREFS_NAME = "keep_secure_prefs"
        private const val PREFS_PREFIX = "keep_share_"
        private const val MULTI_PREFS_NAME = "keep_multi_share_prefs"
        private const val KEY_SHARE_DATA = "share_data"
        private const val KEY_SHARE_IV = "share_iv"
        private const val KEY_SHARE_NAME = "share_name"
        private const val KEY_SHARE_INDEX = "share_index"
        private const val KEY_SHARE_THRESHOLD = "share_threshold"
        private const val KEY_SHARE_TOTAL = "share_total"
        private const val KEY_SHARE_GROUP_PUBKEY = "share_group_pubkey"
        private const val KEY_ACTIVE_SHARE = "active_share_key"
        private const val KEY_ALL_SHARE_KEYS = "all_share_keys"
    }

    private val pendingCipher = AtomicReference<Cipher?>(null)

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val prefs: SharedPreferences by lazy {
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

    private val multiSharePrefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            MULTI_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun sanitizeKey(key: String): String {
        return key.map { c ->
            if (c.isLetterOrDigit() || c == '_' || c == '.' || c == '-') c else '_'
        }.joinToString("")
    }

    private fun migrateKeyIfNeeded(rawKey: String, sanitizedKey: String) {
        if (rawKey == sanitizedKey) return

        val oldAlias = "$KEYSTORE_PREFIX$rawKey"
        val newAlias = "$KEYSTORE_PREFIX$sanitizedKey"
        if (keyStore.containsAlias(oldAlias) && !keyStore.containsAlias(newAlias)) {
            val oldKey = keyStore.getKey(oldAlias, null) as? SecretKey
            if (oldKey != null) {
                keyStore.deleteEntry(oldAlias)
            }
        }
    }

    private fun getSharePrefs(key: String): SharedPreferences {
        val sanitizedKey = sanitizeKey(key)
        migrateKeyIfNeeded(key, sanitizedKey)
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            "$PREFS_PREFIX$sanitizedKey",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun getKeystoreAlias(key: String): String = "$KEYSTORE_PREFIX${sanitizeKey(key)}"

    @Synchronized
    private fun getOrCreateKey(): SecretKey {
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            val builder = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)

            if (isStrongBoxAvailable()) {
                builder.setIsStrongBoxBacked(true)
            }

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }

        return keyStore.getKey(KEYSTORE_ALIAS, null) as SecretKey
    }

    private fun isStrongBoxAvailable(): Boolean {
        return try {
            context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
        } catch (e: Exception) {
            false
        }
    }

    fun getSecurityLevel(): String {
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) return "none"
        return try {
            val key = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey ?: return "unknown"
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "unknown"
            }
        } catch (e: Exception) {
            "unknown"
        }
    }

    fun getCipherForEncryption(): Cipher = initCipher(Cipher.ENCRYPT_MODE, null)

    fun getCipherForDecryption(): Cipher? {
        val iv = prefs.getString(KEY_SHARE_IV, null) ?: return null
        return initCipher(Cipher.DECRYPT_MODE, iv)
    }

    private fun initCipher(mode: Int, ivBase64: String?): Cipher {
        try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            if (ivBase64 != null) {
                val spec = GCMParameterSpec(128, Base64.decode(ivBase64, Base64.NO_WRAP))
                cipher.init(mode, key, spec)
            } else {
                cipher.init(mode, key)
            }
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeepMobileException.StorageException("Biometric enrollment changed - please re-import your share")
        } catch (e: Throwable) {
            val operation = if (mode == Cipher.ENCRYPT_MODE) "encryption" else "decryption"
            throw KeepMobileException.StorageException("Failed to initialize cipher for $operation")
        }
    }

    fun storeShareWithCipher(cipher: Cipher, data: ByteArray, metadata: ShareMetadataInfo) {
        val encrypted = try {
            cipher.doFinal(data)
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to encrypt share")
        }
        val iv = cipher.iv
        saveShareData(encrypted, iv, metadata)
    }

    fun loadShareWithCipher(cipher: Cipher): ByteArray {
        val encryptedData = prefs.getString(KEY_SHARE_DATA, null)
            ?: throw KeepMobileException.StorageException("No share stored")
        return try {
            cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to decrypt share")
        }
    }

    fun setPendingCipher(cipher: Cipher) {
        pendingCipher.set(cipher)
    }

    fun clearPendingCipher() {
        pendingCipher.set(null)
    }

    override fun storeShare(data: ByteArray, metadata: ShareMetadataInfo) {
        val cipher = pendingCipher.getAndSet(null)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available")
        storeShareWithCipher(cipher, data, metadata)
    }

    private fun saveShareData(encrypted: ByteArray, iv: ByteArray, metadata: ShareMetadataInfo) {
        val saved = prefs.edit()
            .putString(KEY_SHARE_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString(KEY_SHARE_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_SHARE_NAME, metadata.name)
            .putInt(KEY_SHARE_INDEX, metadata.identifier.toInt())
            .putInt(KEY_SHARE_THRESHOLD, metadata.threshold.toInt())
            .putInt(KEY_SHARE_TOTAL, metadata.totalShares.toInt())
            .putString(
                KEY_SHARE_GROUP_PUBKEY,
                Base64.encodeToString(metadata.groupPubkey, Base64.NO_WRAP)
            )
            .commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save share data")
        }
    }

    override fun loadShare(): ByteArray {
        val cipher = pendingCipher.getAndSet(null)
            ?: getCipherForDecryption()
            ?: throw KeepMobileException.StorageException("No share stored")
        return loadShareWithCipher(cipher)
    }

    override fun hasShare(): Boolean {
        return prefs.contains(KEY_SHARE_DATA)
    }

    override fun getShareMetadata(): ShareMetadataInfo? {
        if (!hasShare()) return null

        return try {
            val groupPubkeyB64 = prefs.getString(KEY_SHARE_GROUP_PUBKEY, "") ?: ""
            val groupPubkey = Base64.decode(groupPubkeyB64, Base64.NO_WRAP)

            ShareMetadataInfo(
                name = prefs.getString(KEY_SHARE_NAME, "") ?: "",
                identifier = prefs.getInt(KEY_SHARE_INDEX, 0).toUShort(),
                threshold = prefs.getInt(KEY_SHARE_THRESHOLD, 0).toUShort(),
                totalShares = prefs.getInt(KEY_SHARE_TOTAL, 0).toUShort(),
                groupPubkey = groupPubkey
            )
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteShare() {
        val cleared = prefs.edit().clear().commit()
        if (!cleared) {
            throw KeepMobileException.StorageException("Failed to clear share metadata")
        }
        try {
            if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
                keyStore.deleteEntry(KEYSTORE_ALIAS)
            }
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to delete keystore entry")
        }
    }

    @Synchronized
    private fun getOrCreateKeyForShare(key: String): SecretKey {
        val alias = getKeystoreAlias(key)
        if (!keyStore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            val builder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)

            if (isStrongBoxAvailable()) {
                builder.setIsStrongBoxBacked(true)
            }

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }

        return keyStore.getKey(alias, null) as SecretKey
    }

    private fun initCipherForShare(key: String, mode: Int, ivBase64: String?): Cipher {
        try {
            val secretKey = getOrCreateKeyForShare(key)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            if (ivBase64 != null) {
                val spec = GCMParameterSpec(128, Base64.decode(ivBase64, Base64.NO_WRAP))
                cipher.init(mode, secretKey, spec)
            } else {
                cipher.init(mode, secretKey)
            }
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeepMobileException.StorageException("Biometric enrollment changed - please re-import your share")
        } catch (e: Throwable) {
            val operation = if (mode == Cipher.ENCRYPT_MODE) "encryption" else "decryption"
            throw KeepMobileException.StorageException("Failed to initialize cipher for $operation")
        }
    }

    fun getCipherForShareEncryption(key: String): Cipher = initCipherForShare(key, Cipher.ENCRYPT_MODE, null)

    fun getCipherForShareDecryption(key: String): Cipher? {
        val sharePrefs = getSharePrefs(key)
        val iv = sharePrefs.getString(KEY_SHARE_IV, null) ?: return null
        return initCipherForShare(key, Cipher.DECRYPT_MODE, iv)
    }

    fun storeShareByKeyWithCipher(cipher: Cipher, key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        val encrypted = try {
            cipher.doFinal(data)
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to encrypt share")
        }
        val iv = cipher.iv
        saveShareDataByKey(key, encrypted, iv, metadata)
    }

    fun loadShareByKeyWithCipher(cipher: Cipher, key: String): ByteArray {
        val sharePrefs = getSharePrefs(key)
        val encryptedData = sharePrefs.getString(KEY_SHARE_DATA, null)
            ?: throw KeepMobileException.StorageException("No share stored for key: $key")
        return try {
            cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to decrypt share")
        }
    }

    private fun saveShareDataByKey(key: String, encrypted: ByteArray, iv: ByteArray, metadata: ShareMetadataInfo) {
        val sharePrefs = getSharePrefs(key)
        val saved = sharePrefs.edit()
            .putString(KEY_SHARE_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString(KEY_SHARE_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_SHARE_NAME, metadata.name)
            .putInt(KEY_SHARE_INDEX, metadata.identifier.toInt())
            .putInt(KEY_SHARE_THRESHOLD, metadata.threshold.toInt())
            .putInt(KEY_SHARE_TOTAL, metadata.totalShares.toInt())
            .putString(
                KEY_SHARE_GROUP_PUBKEY,
                Base64.encodeToString(metadata.groupPubkey, Base64.NO_WRAP)
            )
            .commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save share data")
        }

        val existingKeys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        val updatedKeys = existingKeys + key
        val registryUpdated = multiSharePrefs.edit().putStringSet(KEY_ALL_SHARE_KEYS, updatedKeys).commit()
        if (!registryUpdated) {
            throw KeepMobileException.StorageException("Failed to update share registry")
        }
    }

    override fun storeShareByKey(key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        val cipher = pendingCipher.getAndSet(null)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available")
        storeShareByKeyWithCipher(cipher, key, data, metadata)
    }

    override fun loadShareByKey(key: String): ByteArray {
        val cipher = pendingCipher.getAndSet(null)
            ?: getCipherForShareDecryption(key)
            ?: throw KeepMobileException.StorageException("No share stored for key: $key")
        return loadShareByKeyWithCipher(cipher, key)
    }

    override fun listAllShares(): List<ShareMetadataInfo> {
        val keys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        return keys.mapNotNull { key ->
            getShareMetadataByKey(key)
        }
    }

    private fun getShareMetadataByKey(key: String): ShareMetadataInfo? {
        val sharePrefs = getSharePrefs(key)
        if (!sharePrefs.contains(KEY_SHARE_DATA)) return null

        return try {
            val groupPubkeyB64 = sharePrefs.getString(KEY_SHARE_GROUP_PUBKEY, "") ?: ""
            val groupPubkey = Base64.decode(groupPubkeyB64, Base64.NO_WRAP)

            ShareMetadataInfo(
                name = sharePrefs.getString(KEY_SHARE_NAME, "") ?: "",
                identifier = sharePrefs.getInt(KEY_SHARE_INDEX, 0).toUShort(),
                threshold = sharePrefs.getInt(KEY_SHARE_THRESHOLD, 0).toUShort(),
                totalShares = sharePrefs.getInt(KEY_SHARE_TOTAL, 0).toUShort(),
                groupPubkey = groupPubkey
            )
        } catch (e: Exception) {
            null
        }
    }

    override fun deleteShareByKey(key: String) {
        val sharePrefs = getSharePrefs(key)
        val cleared = sharePrefs.edit().clear().commit()
        if (!cleared) {
            throw KeepMobileException.StorageException("Failed to clear share metadata")
        }

        val alias = getKeystoreAlias(key)
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to delete keystore entry")
        }

        val existingKeys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        val updatedKeys = existingKeys - key
        val activeKey = multiSharePrefs.getString(KEY_ACTIVE_SHARE, null)
        val editor = multiSharePrefs.edit().putStringSet(KEY_ALL_SHARE_KEYS, updatedKeys)
        if (activeKey == key) {
            editor.remove(KEY_ACTIVE_SHARE)
        }
        val registryUpdated = editor.commit()
        if (!registryUpdated) {
            throw KeepMobileException.StorageException("Failed to update share registry")
        }
    }

    override fun getActiveShareKey(): String? {
        return multiSharePrefs.getString(KEY_ACTIVE_SHARE, null)
    }

    override fun setActiveShareKey(key: String?) {
        val saved = if (key != null) {
            multiSharePrefs.edit().putString(KEY_ACTIVE_SHARE, key).commit()
        } else {
            multiSharePrefs.edit().remove(KEY_ACTIVE_SHARE).commit()
        }
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save active share key")
        }
    }
}
