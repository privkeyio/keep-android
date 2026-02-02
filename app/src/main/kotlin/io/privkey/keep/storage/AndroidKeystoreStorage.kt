package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
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
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class AndroidKeystoreStorage(private val context: Context) : SecureStorage {

    companion object {
        private const val TAG = "AndroidKeystoreStorage"
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

    private val pendingCipher = AtomicReference<Pair<String, Cipher>?>(null)

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun createEncryptedPrefs(name: String): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val prefs: SharedPreferences by lazy { createEncryptedPrefs(PREFS_NAME) }

    private val multiSharePrefs: SharedPreferences by lazy { createEncryptedPrefs(MULTI_PREFS_NAME) }

    private fun sanitizeKey(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(key.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun getLegacyKeystoreAlias(key: String): String {
        val legacySanitized = key.map { c ->
            if (c.isLetterOrDigit() || c == '_' || c == '.' || c == '-') c else '_'
        }.joinToString("")
        return "$KEYSTORE_PREFIX$legacySanitized"
    }

    private fun getSharePrefs(key: String): SharedPreferences =
        createEncryptedPrefs("$PREFS_PREFIX${sanitizeKey(key)}")

    private fun getKeystoreAlias(key: String): String = "$KEYSTORE_PREFIX${sanitizeKey(key)}"

    @Synchronized
    private fun getOrCreateKey(): SecretKey = getOrCreateKeyWithAlias(KEYSTORE_ALIAS)

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

    private fun initCipher(mode: Int, ivBase64: String?): Cipher =
        initCipherWithKey(getOrCreateKey(), mode, ivBase64)

    private fun initCipherWithKey(key: SecretKey, mode: Int, ivBase64: String?): Cipher {
        try {
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

    fun setPendingCipher(requestId: String, cipher: Cipher) {
        pendingCipher.set(Pair(requestId, cipher))
    }

    fun clearPendingCipher(requestId: String) {
        pendingCipher.updateAndGet { current ->
            if (current?.first == requestId) null else current
        }
    }

    fun consumePendingCipher(requestId: String): Cipher? {
        var result: Cipher? = null
        pendingCipher.updateAndGet { current ->
            if (current?.first == requestId) {
                result = current.second
                null
            } else {
                current
            }
        }
        return result
    }

    override fun storeShare(data: ByteArray, metadata: ShareMetadataInfo) {
        val pending = pendingCipher.getAndSet(null)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available")
        storeShareWithCipher(pending.second, data, metadata)
    }

    private fun saveShareData(encrypted: ByteArray, iv: ByteArray, metadata: ShareMetadataInfo) {
        writeShareToPrefs(prefs, encrypted, iv, metadata)
    }

    private fun writeShareToPrefs(
        sharePrefs: SharedPreferences,
        encrypted: ByteArray,
        iv: ByteArray,
        metadata: ShareMetadataInfo
    ) {
        val saved = sharePrefs.edit()
            .putString(KEY_SHARE_DATA, Base64.encodeToString(encrypted, Base64.NO_WRAP))
            .putString(KEY_SHARE_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_SHARE_NAME, metadata.name)
            .putInt(KEY_SHARE_INDEX, metadata.identifier.toInt())
            .putInt(KEY_SHARE_THRESHOLD, metadata.threshold.toInt())
            .putInt(KEY_SHARE_TOTAL, metadata.totalShares.toInt())
            .putString(KEY_SHARE_GROUP_PUBKEY, Base64.encodeToString(metadata.groupPubkey, Base64.NO_WRAP))
            .commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save share data")
        }
    }

    override fun loadShare(): ByteArray {
        val pending = pendingCipher.getAndSet(null)
        val cipher = pending?.second
            ?: getCipherForDecryption()
            ?: throw KeepMobileException.StorageException("No share stored")
        return loadShareWithCipher(cipher)
    }

    @Synchronized
    override fun hasShare(): Boolean {
        if (prefs.contains(KEY_SHARE_DATA)) return true

        val activeKey = getActiveShareKey()
        if (activeKey != null && getSharePrefs(activeKey).contains(KEY_SHARE_DATA)) {
            return true
        }

        val registryKeys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        val hasRegistryShares = registryKeys.isNotEmpty()

        if (activeKey != null && !hasRegistryShares) {
            multiSharePrefs.edit().remove(KEY_ACTIVE_SHARE).commit()
        }

        return hasRegistryShares
    }

    override fun getShareMetadata(): ShareMetadataInfo? {
        if (prefs.contains(KEY_SHARE_DATA)) {
            return readMetadataFromPrefs(prefs)
        }
        val activeKey = getActiveShareKey() ?: return null
        return getShareMetadataByKey(activeKey)
    }

    private fun readMetadataFromPrefs(sharePrefs: SharedPreferences): ShareMetadataInfo? = try {
        val groupPubkeyB64 = sharePrefs.getString(KEY_SHARE_GROUP_PUBKEY, "") ?: ""
        ShareMetadataInfo(
            name = sharePrefs.getString(KEY_SHARE_NAME, "") ?: "",
            identifier = sharePrefs.getInt(KEY_SHARE_INDEX, 0).toUShort(),
            threshold = sharePrefs.getInt(KEY_SHARE_THRESHOLD, 0).toUShort(),
            totalShares = sharePrefs.getInt(KEY_SHARE_TOTAL, 0).toUShort(),
            groupPubkey = Base64.decode(groupPubkeyB64, Base64.NO_WRAP)
        )
    } catch (e: Exception) {
        Log.e(TAG, "Failed to parse stored key metadata", e)
        null
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
        val legacyAlias = getLegacyKeystoreAlias(key)
        if (keyStore.containsAlias(legacyAlias)) {
            return keyStore.getKey(legacyAlias, null) as SecretKey
        }
        return getOrCreateKeyWithAlias(getKeystoreAlias(key))
    }

    @Synchronized
    private fun getOrCreateKeyWithAlias(alias: String): SecretKey {
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

    private fun initCipherForShare(key: String, mode: Int, ivBase64: String?): Cipher =
        initCipherWithKey(getOrCreateKeyForShare(key), mode, ivBase64)

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
        writeShareToPrefs(getSharePrefs(key), encrypted, iv, metadata)
        addKeyToRegistry(key)
    }

    private fun addKeyToRegistry(key: String) {
        val existingKeys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        val registryUpdated = multiSharePrefs.edit()
            .putStringSet(KEY_ALL_SHARE_KEYS, existingKeys + key)
            .commit()
        if (!registryUpdated) {
            throw KeepMobileException.StorageException("Failed to update share registry")
        }
    }

    override fun storeShareByKey(key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        val pending = pendingCipher.getAndSet(null)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available")
        storeShareByKeyWithCipher(pending.second, key, data, metadata)
    }

    override fun loadShareByKey(key: String): ByteArray {
        val pending = pendingCipher.getAndSet(null)
        val cipher = pending?.second
            ?: getCipherForShareDecryption(key)
            ?: throw KeepMobileException.StorageException("No share stored for key: $key")
        return loadShareByKeyWithCipher(cipher, key)
    }

    override fun listAllShares(): List<ShareMetadataInfo> {
        val keys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        return keys.mapNotNull(::getShareMetadataByKey)
    }

    private fun getShareMetadataByKey(key: String): ShareMetadataInfo? {
        val sharePrefs = getSharePrefs(key)
        if (!sharePrefs.contains(KEY_SHARE_DATA)) return null
        return readMetadataFromPrefs(sharePrefs)
    }

    override fun deleteShareByKey(key: String) {
        val sharePrefs = getSharePrefs(key)
        val cleared = sharePrefs.edit().clear().commit()
        if (!cleared) {
            throw KeepMobileException.StorageException("Failed to clear share metadata")
        }

        val alias = getKeystoreAlias(key)
        val legacyAlias = getLegacyKeystoreAlias(key)
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
            if (keyStore.containsAlias(legacyAlias)) {
                keyStore.deleteEntry(legacyAlias)
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
        val editor = multiSharePrefs.edit()
        val saved = if (key != null) editor.putString(KEY_ACTIVE_SHARE, key) else editor.remove(KEY_ACTIVE_SHARE)
        if (!saved.commit()) {
            throw KeepMobileException.StorageException("Failed to save active share key")
        }
    }
}
