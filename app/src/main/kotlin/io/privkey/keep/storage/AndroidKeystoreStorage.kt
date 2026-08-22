package io.privkey.keep.storage

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.SecureStorage
import io.privkey.keep.uniffi.ShareMetadataInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.ProviderException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class AndroidKeystoreStorage(
    private val context: Context,
    private val requireUserAuth: Boolean = true
) : SecureStorage {

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
        // Non-authoritative UI cache. The Rust-side metadata via keepMobile.getActiveShareMetadata()
        // is the source of truth; this pref exists for fast reads and must not gate sensitive UI.
        private const val KEY_SHARE_DID_BACKUP = "share_did_backup"
        private const val KEY_ACTIVE_SHARE = "active_share_key"
        private const val KEY_ALL_SHARE_KEYS = "all_share_keys"
        private const val PENDING_CIPHER_TIMEOUT_MS = 60_000L
        private const val METADATA_KEY_ALIAS = "keep_metadata"
        private const val METADATA_KEY_PREFIX = "__keep_"

        // Pending-DKG secret: its own auth-gated (requireUserAuth) alias, distinct
        // from the non-auth metadata namespace above and from the per-share AES
        // path. It is an RSA keypair so the completed-ceremony stash can be written
        // headlessly (public-key encrypt needs no auth) yet read only behind a
        // biometric (private-key decrypt is auth-gated), keeping the ephemeral
        // ceremony passphrase inside it non-app-uid-readable at rest (keep-6ik).
        private const val DKG_SECRET_STORAGE_KEY = "__keep_dkg_secret_v1"
        private const val DKG_SECRET_ALIAS = "keep_dkg_secret"
        private const val DKG_SECRET_PREFS = "keep_dkg_secret_prefs"
        private const val KEY_DKG_WRAPPED = "dkg_wrapped_key"
        private const val KEY_DKG_IV = "dkg_iv"
        private const val KEY_DKG_DATA = "dkg_data"
        // Non-sensitive marker written by the Rust layer; keeping it (and the secret)
        // intact on a decrypt failure is what makes a live pending share survive a
        // transient read error instead of being wiped (INVARIANTS #1).
        private const val DKG_MARKER_STORAGE_KEY = "__keep_dkg_pending_v1"
        private const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    }

    /** The operation a pending [Cipher] is for, so it is consumed by the matching callback. */
    enum class CipherRole { ENCRYPT, DECRYPT }

    private data class PendingCipherData(
        val cipher: Cipher,
        val role: CipherRole?,
        val creatingThreadId: Long,
        val createdAtMs: Long,
        val timeoutMs: Long,
        val onConsumed: (() -> Unit)?
    )
    private val pendingCiphers = ConcurrentHashMap<String, ArrayDeque<PendingCipherData>>()

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun createEncryptedPrefs(name: String): SharedPreferences =
        KeystoreEncryptedPrefs.create(context, name)

    private val prefs: SharedPreferences by lazy { createEncryptedPrefs(PREFS_NAME) }

    private val multiSharePrefs: SharedPreferences by lazy { createEncryptedPrefs(MULTI_PREFS_NAME) }

    private fun isMetadataKey(key: String): Boolean = key.startsWith(METADATA_KEY_PREFIX)

    @Synchronized
    private fun getOrCreateMetadataKey(): SecretKey =
        getOrCreateKeyWithAlias(METADATA_KEY_ALIAS, requireUserAuth = false)

    @Synchronized
    private fun storeMetadata(key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        val cipher = initCipherForEncryption(getOrCreateMetadataKey())
        writeShareToPrefs(getSharePrefs(key), encryptWithCipher(cipher, data), cipher.iv, metadata)
    }

    @Synchronized
    private fun loadMetadata(key: String): ByteArray {
        val sharePrefs = getSharePrefs(key)
        val encryptedData = sharePrefs.getString(KEY_SHARE_DATA, null)
            ?: throw KeepMobileException.StorageNotFound()
        val ivBase64 = sharePrefs.getString(KEY_SHARE_IV, null)
            ?: throw KeepMobileException.StorageNotFound()
        return try {
            val cipher = initCipherForDecryption(getOrCreateMetadataKey(), ivBase64)
            decryptWithCipher(cipher, encryptedData)
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Metadata key recovery: ${e::class.simpleName}", e)
            // For a pending-DKG stash a decrypt failure may be transient (e.g. the
            // metadata key is momentarily unavailable), and the marker points at a
            // completed share the peers already treat as live. Wiping it here would
            // destroy the only record that recovery is owed (INVARIANTS #1), so
            // preserve it and let the caller retry. Other metadata is
            // reconstructible, so the corrupt entry is still flushed to unblock reads.
            if (!shouldPreserveOnDecryptFailure(key)) {
                // Durably flush the wipe of the undecryptable entry before propagating, so a
                // crash right after this cannot leave the corrupt prefs behind. Runs on a
                // background FFI-callback thread (@Synchronized), so commit() won't jank the UI.
                sharePrefs.edit().clear().commit()
            }
            throw KeepMobileException.StorageException("No metadata stored")
        }
    }

    private fun shouldPreserveOnDecryptFailure(key: String): Boolean =
        key == DKG_MARKER_STORAGE_KEY

    private fun isDkgSecretKey(key: String): Boolean = key == DKG_SECRET_STORAGE_KEY

    private fun sanitizeKey(key: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(key.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
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
    private fun getOrCreateKey(): SecretKey = getOrCreateKeyWithAlias(KEYSTORE_ALIAS, requireUserAuth)

    private fun isStrongBoxAvailable(): Boolean = runCatching {
        context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore")
    }.getOrDefault(false)

    fun getSecurityLevel(): String {
        if (!keyStore.containsAlias(KEYSTORE_ALIAS)) return "none"
        val keyInfo = runCatching {
            val key = keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey ?: return "unknown"
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        }.getOrNull() ?: return "unknown"
        return when (keyInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
            else -> "unknown"
        }
    }

    fun getCipherForEncryption(): Cipher = initCipherForEncryption(getOrCreateKey())

    fun getCipherForDecryption(): Cipher? {
        val legacyIv = prefs.getString(KEY_SHARE_IV, null)
        val legacyData = prefs.getString(KEY_SHARE_DATA, null)
        if (legacyIv != null && legacyData != null) {
            return initCipherForDecryption(getOrCreateKey(), legacyIv)
        }

        val activeKey = getActiveShareKey() ?: return null
        return getCipherForShareDecryption(activeKey)
    }

    // Encryption and decryption are separate entry points on purpose, rather than
    // one function taking a mode and a nullable IV. Under AES-GCM, reusing an IV
    // with one key destroys both confidentiality and authenticity.
    //
    // For these particular keys the platform is expected to catch it: Keystore
    // keys are generated with randomized encryption required by default, which
    // rejects a caller-supplied IV at init time. That is a runtime backstop from
    // another component, it does not hold for a key that is not Keystore-backed,
    // and it is not what a reader of this call site can see. Every caller
    // happened to pass null on the encrypt path; nothing stopped one from
    // passing an IV. Splitting the functions makes it a compile error here, and
    // leaves the provider to draw a fresh IV.
    private fun initCipherForEncryption(key: SecretKey): Cipher = runCatching {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher
    }.getOrElse { e -> throw cipherInitFailure(e, "encryption") }

    private fun initCipherForDecryption(key: SecretKey, ivBase64: String): Cipher = runCatching {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(ivBase64, Base64.NO_WRAP)))
        cipher
    }.getOrElse { e -> throw cipherInitFailure(e, "decryption") }

    private fun cipherInitFailure(e: Throwable, operation: String): KeepMobileException {
        if (e is KeyPermanentlyInvalidatedException) {
            return KeepMobileException.StorageException("Biometric enrollment changed - please re-import your share")
        }
        return KeepMobileException.StorageException("Failed to initialize cipher for $operation")
    }

    private fun encryptWithCipher(cipher: Cipher, data: ByteArray): ByteArray = runCatching {
        cipher.doFinal(data)
    }.getOrElse { throw KeepMobileException.StorageException("Failed to encrypt share") }

    private fun decryptWithCipher(cipher: Cipher, encryptedBase64: String): ByteArray = runCatching {
        cipher.doFinal(Base64.decode(encryptedBase64, Base64.NO_WRAP))
    }.getOrElse { e ->
        if (BuildConfig.DEBUG) Log.e(TAG, "Decryption failed: ${e::class.simpleName}: ${e.message}", e)
        throw KeepMobileException.StorageException("Failed to decrypt share")
    }

    fun storeShareWithCipher(cipher: Cipher, data: ByteArray, metadata: ShareMetadataInfo) {
        saveShareData(encryptWithCipher(cipher, data), cipher.iv, metadata)
    }

    fun loadShareWithCipher(cipher: Cipher): ByteArray {
        val legacyIv = prefs.getString(KEY_SHARE_IV, null)
        val legacyData = prefs.getString(KEY_SHARE_DATA, null)
        val encryptedData = if (legacyIv != null && legacyData != null) {
            legacyData
        } else {
            getActiveShareKey()?.let { getSharePrefs(it).getString(KEY_SHARE_DATA, null) }
        } ?: throw KeepMobileException.StorageException("No share stored")
        return decryptWithCipher(cipher, encryptedData)
    }

    @Suppress("DEPRECATION")
    fun setPendingCipher(
        requestId: String,
        cipher: Cipher,
        role: CipherRole? = null,
        timeoutMs: Long = PENDING_CIPHER_TIMEOUT_MS,
        onConsumed: (() -> Unit)? = null,
    ) {
        cleanupExpiredCiphers()
        val data = PendingCipherData(
            cipher = cipher,
            role = role,
            creatingThreadId = Thread.currentThread().id,
            createdAtMs = SystemClock.elapsedRealtime(),
            timeoutMs = timeoutMs,
            onConsumed = onConsumed
        )
        while (true) {
            // compute() atomically inserts a queue if absent, but a concurrent clearPendingCipher
            // or cleanupExpiredCiphers may remove it before we take its lock. Re-check identity
            // under the lock and retry if the map no longer points at our queue instance.
            val queue = pendingCiphers.compute(requestId) { _, existing -> existing ?: ArrayDeque() }!!
            val added = synchronized(queue) {
                if (pendingCiphers[requestId] === queue) {
                    queue.add(data)
                    true
                } else false
            }
            if (added) break
        }
    }

    private fun cleanupExpiredCiphers() {
        val now = SystemClock.elapsedRealtime()
        pendingCiphers.entries.forEach { entry ->
            synchronized(entry.value) {
                // Drop only the stale entries, preserving fresh ones that may sit behind them.
                entry.value.removeAll { now - it.createdAtMs > it.timeoutMs }
                if (entry.value.isEmpty()) {
                    pendingCiphers.remove(entry.key, entry.value)
                }
            }
        }
    }

    // Drops all pending ciphers and callbacks for the given requestId.
    fun clearPendingCipher(requestId: String) {
        val queue = pendingCiphers[requestId] ?: return
        synchronized(queue) {
            queue.clear()
            pendingCiphers.remove(requestId, queue)
        }
    }

    // Consumes a pending cipher for [requestId]. When [requiredRole] is given and a queued
    // cipher carries that role, that one is taken (so the decrypt vs encrypt cipher is
    // selected by the operation, not by enqueue order). Untagged ciphers fall back to FIFO,
    // so single-cipher flows are unaffected; this makes the two-cipher flows (decrypt +
    // encrypt under one requestId, e.g. markShareBackedUp/renameShare) order-independent.
    fun consumePendingCipher(requestId: String, requiredRole: CipherRole? = null): Cipher? {
        val queue = pendingCiphers[requestId] ?: return null
        var poppedCipher: Cipher? = null
        var callbackToFire: (() -> Unit)? = null
        synchronized(queue) {
            val now = SystemClock.elapsedRealtime()
            // Strip stale entries before popping so a stale head does not mask fresh followers
            // and stale tails do not linger past their expiry.
            queue.removeAll { now - it.createdAtMs > it.timeoutMs }
            if (queue.isEmpty()) {
                pendingCiphers.remove(requestId, queue)
                return null
            }
            val roleIdx = if (requiredRole != null) queue.indexOfFirst { it.role == requiredRole } else -1
            val popped = if (roleIdx >= 0) queue.removeAt(roleIdx) else queue.removeFirst()
            poppedCipher = popped.cipher
            callbackToFire = popped.onConsumed
            if (queue.isEmpty()) {
                pendingCiphers.remove(requestId, queue)
            }
        }
        callbackToFire?.invoke()
        return poppedCipher
    }

    private val requestIdContext = ThreadLocal<String>()

    fun setRequestIdContext(requestId: String) {
        requestIdContext.set(requestId)
    }

    fun clearRequestIdContext() {
        requestIdContext.remove()
    }

    override fun storeShare(data: ByteArray, metadata: ShareMetadataInfo) {
        require(data.isNotEmpty()) { "Share data must not be empty" }
        val requestId = requestIdContext.get()
            ?: throw KeepMobileException.StorageException("No request context - call setRequestIdContext first")
        val cipher = consumePendingCipher(requestId, CipherRole.ENCRYPT)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available for this request")
        storeShareWithCipher(cipher, data, metadata)
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
            .putBoolean(KEY_SHARE_DID_BACKUP, metadata.didBackup)
            .commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save share data")
        }
    }

    override fun loadShare(): ByteArray {
        val requestId = requestIdContext.get()
            ?: throw KeepMobileException.StorageException("No request context - call setRequestIdContext first")
        val cipher = consumePendingCipher(requestId, CipherRole.DECRYPT)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available for this request")
        val data = loadShareWithCipher(cipher)
        check(data.isNotEmpty()) { "Loaded share data must not be empty" }
        return data
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
        val identifier = sharePrefs.getInt(KEY_SHARE_INDEX, 0)
        val threshold = sharePrefs.getInt(KEY_SHARE_THRESHOLD, 0)
        val totalShares = sharePrefs.getInt(KEY_SHARE_TOTAL, 0)
        val ushortRange = UShort.MIN_VALUE.toInt()..UShort.MAX_VALUE.toInt()
        require(identifier in ushortRange && threshold in ushortRange && totalShares in ushortRange) {
            "Share metadata values out of UShort range"
        }
        ShareMetadataInfo(
            name = sharePrefs.getString(KEY_SHARE_NAME, "") ?: "",
            identifier = identifier.toUShort(),
            threshold = threshold.toUShort(),
            totalShares = totalShares.toUShort(),
            groupPubkey = Base64.decode(groupPubkeyB64, Base64.NO_WRAP),
            didBackup = sharePrefs.getBoolean(KEY_SHARE_DID_BACKUP, false)
        )
    } catch (e: Exception) {
        if (BuildConfig.DEBUG) Log.e(TAG, "Failed to parse stored key metadata", e)
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
        val newAlias = getKeystoreAlias(key)
        if (keyStore.containsAlias(newAlias)) {
            return keyStore.getKey(newAlias, null) as? SecretKey
                ?: throw KeepMobileException.StorageException("Key $newAlias is not a SecretKey")
        }
        val legacyAlias = getLegacyKeystoreAlias(key)
        if (keyStore.containsAlias(legacyAlias)) {
            return keyStore.getKey(legacyAlias, null) as? SecretKey
                ?: throw KeepMobileException.StorageException("Key $legacyAlias is not a SecretKey")
        }
        if (keyStore.containsAlias(KEYSTORE_ALIAS) && isLegacyAccount(key)) {
            return keyStore.getKey(KEYSTORE_ALIAS, null) as? SecretKey
                ?: throw KeepMobileException.StorageException("Key $KEYSTORE_ALIAS is not a SecretKey")
        }
        return getOrCreateKeyWithAlias(newAlias, requireUserAuth)
    }

    private fun isLegacyAccount(key: String): Boolean {
        val sharePrefs = getSharePrefs(key)
        if (!sharePrefs.contains(KEY_SHARE_DATA)) return false
        return !keyStore.containsAlias(getKeystoreAlias(key)) &&
            !keyStore.containsAlias(getLegacyKeystoreAlias(key))
    }

    @Synchronized
    private fun getOrCreateKeyWithAlias(alias: String, requireUserAuth: Boolean = true): SecretKey {
        if (!keyStore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            fun buildSpec(useStrongBox: Boolean): KeyGenParameterSpec =
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                ).apply {
                    setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    setKeySize(256)
                    if (requireUserAuth) {
                        setUserAuthenticationRequired(true)
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                        setInvalidatedByBiometricEnrollment(true)
                    }
                    if (useStrongBox) {
                        setIsStrongBoxBacked(true)
                    }
                }.build()

            if (isStrongBoxAvailable()) {
                // StrongBox can generate an AES-GCM key cleanly and still fail at
                // use time (some Keymint implementations reject the operation only
                // when the cipher runs, e.g. Pixel 9a on Android 17 throwing at
                // doFinal). Generation-only fallback misses that, so a non-auth key
                // is probed with a throwaway encrypt and a failure falls back to
                // TEE. An auth-gated key cannot be exercised without a biometric, so
                // it is left as generated and validated when the user authenticates.
                val strongBoxOk = try {
                    keyGenerator.init(buildSpec(useStrongBox = true))
                    keyGenerator.generateKey()
                    requireUserAuth || canEncryptWithKey(alias)
                } catch (e: Exception) {
                    if (e !is ProviderException && e !is InvalidAlgorithmParameterException) throw e
                    if (BuildConfig.DEBUG) Log.w(TAG, "StrongBox key generation failed, falling back to TEE", e)
                    false
                }
                if (!strongBoxOk) {
                    if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
                    keyGenerator.init(buildSpec(useStrongBox = false))
                    keyGenerator.generateKey()
                }
            } else {
                keyGenerator.init(buildSpec(useStrongBox = false))
                keyGenerator.generateKey()
            }
        }

        return keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeepMobileException.StorageException("Key $alias is not a SecretKey")
    }

    // A non-auth AES key is exercised with a throwaway encrypt so a StrongBox key
    // that generated cleanly but rejects the operation at use time is caught here
    // rather than surfacing later as "Failed to encrypt share".
    private fun canEncryptWithKey(alias: String): Boolean = runCatching {
        val key = keyStore.getKey(alias, null) as? SecretKey ?: return false
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.doFinal(ByteArray(1))
        true
    }.getOrElse { e ->
        if (BuildConfig.DEBUG) Log.w(TAG, "StrongBox key failed use-time probe, falling back to TEE", e)
        false
    }

    fun getCipherForShareEncryption(key: String): Cipher =
        initCipherForEncryption(getOrCreateKeyForShare(key))

    fun getCipherForShareDecryption(key: String): Cipher? {
        val sharePrefs = getSharePrefs(key)
        val iv = sharePrefs.getString(KEY_SHARE_IV, null) ?: return null
        return initCipherForDecryption(getOrCreateKeyForShare(key), iv)
    }

    fun storeShareByKeyWithCipher(cipher: Cipher, key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        saveShareDataByKey(key, encryptWithCipher(cipher, data), cipher.iv, metadata)
    }

    fun loadShareByKeyWithCipher(cipher: Cipher, key: String): ByteArray {
        val encryptedData = getSharePrefs(key).getString(KEY_SHARE_DATA, null)
            ?: throw KeepMobileException.StorageException("No share stored for key: $key")
        return decryptWithCipher(cipher, encryptedData)
    }

    private fun saveShareDataByKey(key: String, encrypted: ByteArray, iv: ByteArray, metadata: ShareMetadataInfo) {
        writeShareToPrefs(getSharePrefs(key), encrypted, iv, metadata)
        addKeyToRegistry(key)
    }

    private fun addKeyToRegistry(key: String) {
        val existingKeys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        // Already listed: do not rewrite. The read above returns the default
        // when the registry cannot be decrypted, so a rewrite in that state
        // would persist a set containing only this key and deregister every
        // other group. Their share files would survive while becoming invisible
        // to listing, the active-share lookup and the has-share check, none of
        // which rebuild it.
        if (existingKeys.contains(key)) return
        val registryUpdated = multiSharePrefs.edit()
            .putStringSet(KEY_ALL_SHARE_KEYS, existingKeys + key)
            .commit()
        if (!registryUpdated) {
            throw KeepMobileException.StorageException("Failed to update share registry")
        }
    }

    override fun storeShareByKey(key: String, data: ByteArray, metadata: ShareMetadataInfo) {
        require(key.isNotBlank()) { "Share key must not be blank" }
        require(data.isNotEmpty()) { "Share data must not be empty" }
        if (isDkgSecretKey(key)) {
            storeDkgSecret(data)
            return
        }
        if (isMetadataKey(key)) {
            storeMetadata(key, data, metadata)
            return
        }
        val requestId = requestIdContext.get()
            ?: throw KeepMobileException.StorageException("No request context - call setRequestIdContext first")
        val cipher = consumePendingCipher(requestId, CipherRole.ENCRYPT)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available for this request")
        storeShareByKeyWithCipher(cipher, key, data, metadata)
    }

    override fun loadShareByKey(key: String): ByteArray {
        require(key.isNotBlank()) { "Share key must not be blank" }
        if (isDkgSecretKey(key)) {
            return loadDkgSecret()
        }
        if (isMetadataKey(key)) {
            return loadMetadata(key)
        }
        val requestId = requestIdContext.get()
            ?: throw KeepMobileException.StorageException("No request context - call setRequestIdContext first")
        val cipher = consumePendingCipher(requestId, CipherRole.DECRYPT)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available for this request")
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
        require(key.isNotBlank()) { "Share key must not be blank" }
        if (isDkgSecretKey(key)) {
            deleteDkgSecret()
            return
        }
        if (isMetadataKey(key)) {
            val cleared = getSharePrefs(key).edit().clear().commit()
            if (!cleared) {
                throw KeepMobileException.StorageException("Failed to clear metadata")
            }
            return
        }

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

    @Synchronized
    override fun getActiveShareKey(): String? {
        val keys = multiSharePrefs.getStringSet(KEY_ALL_SHARE_KEYS, emptySet()) ?: emptySet()
        if (keys.isEmpty()) return null
        val active = multiSharePrefs.getString(KEY_ACTIVE_SHARE, null)
        if (active != null && keys.contains(active) &&
            getSharePrefs(active).contains(KEY_SHARE_DATA)) return active
        val fallbackKey = keys.sorted().firstOrNull { getSharePrefs(it).contains(KEY_SHARE_DATA) }
            ?: return null
        setActiveShareKey(fallbackKey)
        return fallbackKey
    }

    @Synchronized
    override fun setActiveShareKey(key: String?) {
        if (key != null) require(key.isNotBlank()) { "Active share key must not be blank" }
        val editor = multiSharePrefs.edit()
        if (key != null) {
            editor.putString(KEY_ACTIVE_SHARE, key)
        } else {
            editor.remove(KEY_ACTIVE_SHARE)
        }
        if (!editor.commit()) {
            throw KeepMobileException.StorageException("Failed to save active share key")
        }
    }

    fun migrateLegacyShareToRegistrySync() {
        migrateLegacyShareToRegistryInternal()
    }

    suspend fun migrateLegacyShareToRegistry() = withContext(Dispatchers.IO) {
        migrateLegacyShareToRegistryInternal()
    }

    private fun migrateLegacyShareToRegistryInternal() {
        if (!prefs.contains(KEY_SHARE_DATA)) return
        val metadata = readMetadataFromPrefs(prefs) ?: return
        val groupPubkeyHex = metadata.groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        if (groupPubkeyHex.isBlank()) return

        val sharePrefs = getSharePrefs(groupPubkeyHex)

        // The legacy copy is only ever discarded once the destination is holding
        // the share, and "holding" means the values come back, not that their
        // names resolve. Two weaker checks were used here before and both erased
        // the source with nothing to show for it: the registry key list, which
        // records that a group exists rather than that its data survived, and a
        // presence check, which resolves a name without decrypting and is
        // satisfied by an entry that will not open. Reading both values is the
        // only test that means what the sentence above says.
        //
        // The iv is checked too because a share without it is unusable: the
        // decryption path returns nothing when it is missing, so keeping the
        // data alone would still lose the share.
        if (sharePrefs.getString(KEY_SHARE_DATA, null) != null &&
            sharePrefs.getString(KEY_SHARE_IV, null) != null
        ) {
            addKeyToRegistry(groupPubkeyHex)
            prefs.edit().clear().apply()
            return
        }

        // Read into locals and refuse to proceed on a null. Encrypted prefs
        // return the default when a value cannot be decrypted, so a failed read
        // is indistinguishable from an absent one here, and writing null removes
        // the destination key rather than storing nothing. The commit would then
        // report success having written no share, and the clear below would
        // destroy the only copy. This is the one failure in this file that
        // cannot be recovered from.
        val shareData = prefs.getString(KEY_SHARE_DATA, null)
        val shareIv = prefs.getString(KEY_SHARE_IV, null)
        if (shareData == null || shareIv == null) {
            return
        }

        val saved = sharePrefs.edit()
            .putString(KEY_SHARE_DATA, shareData)
            .putString(KEY_SHARE_IV, shareIv)
            .putString(KEY_SHARE_NAME, metadata.name)
            .putInt(KEY_SHARE_INDEX, metadata.identifier.toInt())
            .putInt(KEY_SHARE_THRESHOLD, metadata.threshold.toInt())
            .putInt(KEY_SHARE_TOTAL, metadata.totalShares.toInt())
            .putString(KEY_SHARE_GROUP_PUBKEY, Base64.encodeToString(metadata.groupPubkey, Base64.NO_WRAP))
            .putBoolean(KEY_SHARE_DID_BACKUP, metadata.didBackup)
            .commit()
        if (!saved) return

        // Confirm the destination reads back before the source is destroyed. The
        // commit reports that the write reached disk, not that what landed can
        // be retrieved, and the gap between those two is where a share would be
        // lost. Compared against what was written rather than merely non-null,
        // and covering the iv, since data without it cannot be decrypted.
        if (sharePrefs.getString(KEY_SHARE_DATA, null) != shareData) return
        if (sharePrefs.getString(KEY_SHARE_IV, null) != shareIv) return

        addKeyToRegistry(groupPubkeyHex)
        if (getActiveShareKey() == null) {
            multiSharePrefs.edit().putString(KEY_ACTIVE_SHARE, groupPubkeyHex).commit()
        }
        prefs.edit().clear().apply()
    }

    // ---- Pending-DKG secret: auth-gated RSA hybrid envelope --------------------
    //
    // The secret is written during the headless ceremony (no biometric on hand)
    // yet must only be read behind one. A single AES key with requireUserAuth
    // can't express that — it gates encrypt too — so the alias is an RSA keypair:
    // the public key hybrid-wraps a fresh AES key (headless), and only the
    // private-key unwrap is auth-gated. The larger share+passphrase blob rides
    // under AES-GCM, whose key is the only thing RSA-wrapped (RSA-OAEP can't span
    // it directly).

    private val dkgSecretPrefs: SharedPreferences by lazy { createEncryptedPrefs(DKG_SECRET_PREFS) }

    @Synchronized
    private fun getOrCreateDkgSecretKeypair() {
        if (keyStore.containsAlias(DKG_SECRET_ALIAS)) return
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            "AndroidKeyStore"
        )

        fun buildSpec(useStrongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                DKG_SECRET_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(2048)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .apply { if (useStrongBox) setIsStrongBoxBacked(true) }
                .build()

        if (isStrongBoxAvailable()) {
            try {
                generator.initialize(buildSpec(useStrongBox = true))
                generator.generateKeyPair()
            } catch (e: Exception) {
                if (e !is ProviderException && e !is InvalidAlgorithmParameterException) throw e
                if (BuildConfig.DEBUG) Log.w(TAG, "StrongBox DKG keypair generation failed, falling back to TEE", e)
                if (keyStore.containsAlias(DKG_SECRET_ALIAS)) keyStore.deleteEntry(DKG_SECRET_ALIAS)
                generator.initialize(buildSpec(useStrongBox = false))
                generator.generateKeyPair()
            }
        } else {
            generator.initialize(buildSpec(useStrongBox = false))
            generator.generateKeyPair()
        }
    }

    // OAEP digest SHA-256 with an MGF1-SHA1 mask. AndroidKeyStore authorizes only
    // MGF1-SHA1 for an OAEP key unless `setMgf1Digests` says otherwise, and that
    // setter is API 35 while `minSdk` is 33 — calling it throws NoSuchMethodError
    // on 33/34, and gating it by version would instead desync the two halves,
    // since the authorized digest is fixed when the key is generated and does not
    // change if the device later upgrades. Matching AndroidKeyStore's default on
    // every API level keeps generation and cipher init consistent for the life of
    // the key. RFC 8017 permits a different hash for the mask function, and
    // MGF1-SHA1 is not a weakness in OAEP.
    private fun oaepSpec(): OAEPParameterSpec =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    /** Headless write: hybrid-encrypt under the RSA public key. No auth required. */
    @Synchronized
    private fun storeDkgSecret(data: ByteArray) {
        getOrCreateDkgSecretKeypair()
        // The Keystore-returned public key carries the auth restriction, which some
        // OEM providers reject at encrypt-init. Reconstruct an unrestricted public
        // key from its encoding so the headless wrap always succeeds.
        val certKey = keyStore.getCertificate(DKG_SECRET_ALIAS)?.publicKey
            ?: throw KeepMobileException.StorageException("No DKG secret key available")
        val publicKey = KeyFactory.getInstance(certKey.algorithm)
            .generatePublic(X509EncodedKeySpec(certKey.encoded))

        val aesKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val gcm = Cipher.getInstance("AES/GCM/NoPadding")
        gcm.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val ciphertext = gcm.doFinal(data)
        val iv = gcm.iv

        val rsa = Cipher.getInstance(RSA_TRANSFORMATION)
        rsa.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec())
        val wrapped = runCatching { rsa.doFinal(aesKey) }
            .getOrElse { throw KeepMobileException.StorageException("Failed to wrap DKG secret") }
        java.util.Arrays.fill(aesKey, 0)

        val saved = dkgSecretPrefs.edit()
            .putString(KEY_DKG_WRAPPED, Base64.encodeToString(wrapped, Base64.NO_WRAP))
            .putString(KEY_DKG_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_DKG_DATA, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .commit()
        if (!saved) {
            throw KeepMobileException.StorageException("Failed to save DKG secret")
        }
    }

    /**
     * Auth-gated read: unwrap the AES key with the biometric-authorized RSA
     * private-key [Cipher] queued for this request, then AES-GCM decrypt. The
     * cipher must be produced by [getDkgSecretDecryptCipher] behind a
     * BiometricPrompt and queued via [setPendingCipher] (role DECRYPT), the same
     * shape as the per-share path but on the dedicated DKG alias.
     */
    private fun loadDkgSecret(): ByteArray {
        val requestId = requestIdContext.get()
            ?: throw KeepMobileException.StorageException("No request context - call setRequestIdContext first")
        val rsa = consumePendingCipher(requestId, CipherRole.DECRYPT)
            ?: throw KeepMobileException.StorageException("No authenticated cipher available for this request")

        val wrapped = dkgSecretPrefs.getString(KEY_DKG_WRAPPED, null)
            ?: throw KeepMobileException.StorageNotFound()
        val ivB64 = dkgSecretPrefs.getString(KEY_DKG_IV, null)
            ?: throw KeepMobileException.StorageNotFound()
        val dataB64 = dkgSecretPrefs.getString(KEY_DKG_DATA, null)
            ?: throw KeepMobileException.StorageNotFound()

        val aesKey = runCatching { rsa.doFinal(Base64.decode(wrapped, Base64.NO_WRAP)) }
            .getOrElse { throw KeepMobileException.StorageException("Failed to unwrap DKG secret") }
        return try {
            val gcm = Cipher.getInstance("AES/GCM/NoPadding")
            gcm.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(aesKey, "AES"),
                GCMParameterSpec(128, Base64.decode(ivB64, Base64.NO_WRAP))
            )
            gcm.doFinal(Base64.decode(dataB64, Base64.NO_WRAP))
        } catch (e: Exception) {
            // A decrypt failure here is not proof of corruption (e.g. a spent
            // cipher). Never wipe the stash on a read error — it guards a live
            // share (INVARIANTS #1); the caller retries or discards explicitly.
            throw KeepMobileException.StorageException("Failed to decrypt DKG secret")
        } finally {
            java.util.Arrays.fill(aesKey, 0)
        }
    }

    /**
     * A biometric-bindable RSA-decrypt [Cipher] for the pending-DKG secret, to be
     * wrapped in a BiometricPrompt.CryptoObject and, once authorized, queued via
     * [setPendingCipher] before calling `recoverDkgShare`. Null when no secret is
     * stored, so the UI can skip the prompt.
     */
    fun getDkgSecretDecryptCipher(): Cipher? {
        if (!dkgSecretPrefs.contains(KEY_DKG_WRAPPED)) return null
        if (!keyStore.containsAlias(DKG_SECRET_ALIAS)) return null
        val privateKey = keyStore.getKey(DKG_SECRET_ALIAS, null)
            ?: throw KeepMobileException.StorageException("DKG secret key missing")
        return runCatching {
            Cipher.getInstance(RSA_TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, privateKey, oaepSpec())
            }
        }.getOrElse { e -> throw cipherInitFailure(e, "decryption") }
    }

    @Synchronized
    private fun deleteDkgSecret() {
        if (!dkgSecretPrefs.edit().clear().commit()) {
            throw KeepMobileException.StorageException("Failed to clear DKG secret")
        }
        try {
            if (keyStore.containsAlias(DKG_SECRET_ALIAS)) {
                keyStore.deleteEntry(DKG_SECRET_ALIAS)
            }
        } catch (e: Exception) {
            throw KeepMobileException.StorageException("Failed to delete DKG secret key")
        }
    }
}
