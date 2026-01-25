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
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class AndroidKeystoreStorage(private val context: Context) : SecureStorage {

    companion object {
        private const val KEYSTORE_ALIAS = "keep_frost_share"
        private const val PREFS_NAME = "keep_secure_prefs"
        private const val KEY_SHARE_DATA = "share_data"
        private const val KEY_SHARE_IV = "share_iv"
        private const val KEY_SHARE_NAME = "share_name"
        private const val KEY_SHARE_INDEX = "share_index"
        private const val KEY_SHARE_THRESHOLD = "share_threshold"
        private const val KEY_SHARE_TOTAL = "share_total"
        private const val KEY_SHARE_GROUP_PUBKEY = "share_group_pubkey"
    }

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
                .setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG)
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
            val key = keyStore.getKey(KEYSTORE_ALIAS, null) as SecretKey
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

    fun getCipherForEncryption(): Cipher {
        try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeepMobileException.StorageException("Biometric enrollment changed - please re-import your share")
        } catch (e: Throwable) {
            throw KeepMobileException.StorageException("Failed to initialize cipher for encryption")
        }
    }

    fun getCipherForDecryption(): Cipher? {
        val iv = prefs.getString(KEY_SHARE_IV, null) ?: return null
        try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP))
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            return cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeepMobileException.StorageException("Biometric enrollment changed - please re-import your share")
        } catch (e: Throwable) {
            throw KeepMobileException.StorageException("Failed to initialize cipher for decryption")
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

    override fun storeShare(data: ByteArray, metadata: ShareMetadataInfo) {
        val cipher = getCipherForEncryption()
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
        val cipher = getCipherForDecryption()
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
}
