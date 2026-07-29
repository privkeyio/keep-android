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
        initLocks.computeIfAbsent(prefsName) { Any() }

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

    /** Sanity bounds on a decoded registry, whose contents are not bound to its location. */
    // Above anything production writes: the longest real names are a fixed
    // prefix plus a 255-char package name. A legitimate key filtered here would
    // be silently dropped from the list on the next rewrite.
    private const val MAX_KEY_NAME_LENGTH = 512
    private const val MAX_REGISTRY_ENTRIES = 4096

    /** Refolds tolerated before an unreadable current registry stops being retried. */
    private const val MAX_FOLD_ATTEMPTS = 3

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

        /** Failed folds so far; bounds the retry so an unreadable copy cannot cost a decrypt per commit forever. */
        private var foldAttempts = 0

        /**
         * Whether the current name's registry was absent or decoded cleanly.
         *
         * Rewriting the list is safe exactly then, because the cache covers
         * everything that copy listed. If it was present and unreadable the
         * rewrite would truncate it, so the rewrite is skipped.
         */
        private var currentRegistryReadable = false

        /**
         * Whether every registry copy found on disk decoded successfully.
         *
         * Only then may the stale copy be dropped: an undecodable copy may list
         * keys held nowhere else, and deleting it destroys the one record of
         * them. Kept separate from [currentRegistryReadable] on purpose. Gating
         * the rewrite on this too would let a single planted value at the
         * fallback name, which is derivable from the APK, stop the key list
         * being maintained at all.
         */
        private var allRegistriesReadable = false
        @Volatile
        private var hmacKey: ByteArray? = null
        private val listenerMap = ConcurrentHashMap<SharedPreferences.OnSharedPreferenceChangeListener, SharedPreferences.OnSharedPreferenceChangeListener>()

        // Migration-only fallback: predictable by design since it only obfuscates
        // preference key names, not values (values are AES-GCM encrypted with Keystore).
        // Used only when the random HMAC key cannot be persisted or the registry is
        // unreadable. Once migration succeeds, the random key replaces this.
        // Pure function of the file name, and now consulted on every write and on
        // every lookup miss, so derive it once.
        private val deterministicKey: ByteArray by lazy {
            MessageDigest.getInstance("SHA-256")
                .digest("$DETERMINISTIC_HMAC_SEED:$prefsName".toByteArray(Charsets.UTF_8))
        }

        private fun deterministicHmacKey(): ByteArray = deterministicKey

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
            if (basePrefs.contains(hash)) {
                keyCache[plainKey] = hash
                reverseKeyCache[hash] = plainKey
                return hash
            }
            // An entry written while the store was using its fallback derivation
            // key stays hashed under that key after the store recovers, so a
            // lookup under the current key misses it and the entry reads as if it
            // had never been written. For the signer's rate-limiter store that
            // presents as a package with no recorded usage, which restarts its
            // window; for a policy override it presents as no override at all.
            //
            // Probe the fallback epoch before giving up, and move what it finds to
            // the current name rather than remembering the old one.
            //
            // Remembering is not enough: the registry fold rewrites this cache
            // with current-epoch names at the head of the next write, so the write
            // lands at the current name while the stale copy survives. A later
            // delete then removes only the new copy and the next read returns the
            // pre-delete value. For a policy selection that resurrects a setting
            // the user replaced, which can be the looser one.
            //
            // The registry is excluded: it is resolved directly elsewhere, and a
            // relocation racing that lookup could leave readers and writers
            // disagreeing about where the index lives.
            if (plainKey == KEY_REGISTRY) return null
            val fallbackHash = fallbackHashOf(plainKey)
            if (fallbackHash == hash || !basePrefs.contains(fallbackHash)) return null

            val relocated = synchronized(initLockFor(prefsName)) {
                val value = basePrefs.getString(fallbackHash, null)
                value != null &&
                    basePrefs.edit().putString(hash, value).remove(fallbackHash).commit()
            }
            return if (relocated) {
                keyCache[plainKey] = hash
                reverseKeyCache[hash] = plainKey
                hash
            } else {
                // Consolidation did not stick. Report where the entry actually is
                // so this lookup is still correct, but do not cache it: a cached
                // old location would send the next write there and leave a second
                // copy behind it.
                fallbackHash
            }
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
        /**
         * @param countAttempt whether a failed fold counts toward the retry
         *   bound. Only the commit path passes true: a read must not be able to
         *   spend the budget and change what a later write is allowed to do.
         */
        private fun ensureRegistrySeeded(countAttempt: Boolean = false) {
            if (registrySeeded) return
            rebuildKeyCacheFromRegistry()
            if (currentRegistryReadable) {
                registrySeeded = true
                foldAttempts = 0
                return
            }
            // Bound the cost, never the guard. An unreadable copy would
            // otherwise buy a failing Keystore round trip on every commit, taken
            // under this monitor on the signing path. Stop re-folding, but keep
            // refusing to rewrite: forcing the rewrite here would truncate the
            // very list this exists to protect, on an assumption the code cannot
            // check, since a decrypt failure may be transient. A new instance
            // folds again, so a transient fault still recovers on the next
            // process rather than being made permanent now.
            if (countAttempt && ++foldAttempts >= MAX_FOLD_ATTEMPTS) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Registry unreadable after $foldAttempts folds; stopping retries")
                registrySeeded = true
            }
        }

        private fun fallbackHashOf(plainKey: String): String =
            hmacWithKey(plainKey, deterministicHmacKey())

        /**
         * The outcome of reading one registry copy.
         *
         * [Malformed] and [Unreadable] must not be conflated. A blob that
         * decrypted but is not a registry is deterministically wrong, so
         * replacing it loses nothing that could ever be read back. A blob that
         * would not decrypt may be a transient Keystore fault, and overwriting
         * it would destroy a list that was about to become readable again.
         */
        private sealed interface RegistryRead {
            /** [complete] is false when entries were dropped as implausible, so the cache does not cover the copy. */
            data class Decoded(val keys: List<String>, val complete: Boolean) : RegistryRead
            object Malformed : RegistryRead
            object Unreadable : RegistryRead
        }

        /**
         * Decodes one registry copy.
         *
         * Decrypting successfully is not enough to trust the contents. Values
         * carry no associated data, so any string value from this file decrypts
         * here just as well, and the fallback copy's location is derivable from
         * the APK. Without bounds, a transplanted value would have each of its
         * fragments adopted as a key name and written into the real registry on
         * the next commit, where nothing ever removes them.
         */
        private fun decodeRegistry(blob: String): RegistryRead = try {
            val decrypted = decrypt(secretKey, blob)
            if (!decrypted.startsWith(PREFIX_STRING)) {
                RegistryRead.Malformed
            } else {
                val parts = decrypted.removePrefix(PREFIX_STRING)
                    .split(KEY_REGISTRY_DELIMITER)
                    .filter { it.isNotEmpty() && it != KEY_REGISTRY }
                val kept = parts
                    .filter { it.length <= MAX_KEY_NAME_LENGTH && it.none(Char::isISOControl) }
                    .take(MAX_REGISTRY_ENTRIES)
                if (kept.size != parts.size && BuildConfig.DEBUG) {
                    Log.w("KeystoreEncryptedPrefs", "Dropped ${parts.size - kept.size} implausible registry entries")
                }
                RegistryRead.Decoded(kept, complete = kept.size == parts.size)
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Registry copy could not be decrypted", e)
            RegistryRead.Unreadable
        }

        /**
         * Seeds the key cache from every registry copy on disk, unioning them.
         *
         * The migration off the previous derivation epoch runs only while no
         * derivation key is persisted yet, so a registry written during a later
         * fallback window keeps the old name and is never moved.
         *
         * Both names are read rather than preferring the current one, because
         * the damaging state has a copy under each: a device that already
         * performed the truncating write this fixes has a short list under the
         * current name and the full list under the fallback. Reading only the
         * current one would seed a partial cache and then authorize deleting the
         * copy that still held the missing keys.
         *
         * Sets [currentRegistryReadable] and [allRegistriesReadable].
         */
        private fun rebuildKeyCacheFromRegistry() {
            val currentHash = calculateKeyHash(KEY_REGISTRY)
            val fallbackHash = fallbackHashOf(KEY_REGISTRY)
            val names = if (fallbackHash == currentHash) listOf(currentHash) else listOf(currentHash, fallbackHash)

            var found = false
            var currentReadable = true
            var allReadable = true
            for (name in names) {
                val blob = basePrefs.getString(name, null) ?: continue
                found = true
                when (val read = decodeRegistry(blob)) {
                    is RegistryRead.Decoded -> {
                        read.keys.forEach { cacheRegistryKey(it) }
                        if (!read.complete) {
                            // Entries were dropped, so the cache does not cover
                            // what this copy listed. Rewriting from it now would
                            // deregister them permanently.
                            allReadable = false
                            if (name == currentHash) currentReadable = false
                        }
                    }
                    // Decrypted but not a registry, which no retry can change.
                    // Replacing it loses nothing that could ever be read back.
                    RegistryRead.Malformed -> allReadable = false
                    // May be a transient Keystore fault. Preserve it: a copy that
                    // is about to become readable again must not be overwritten.
                    RegistryRead.Unreadable -> {
                        allReadable = false
                        if (name == currentHash) currentReadable = false
                    }
                }
            }

            if (!found && names.size > 1) {
                // A commit writes the current name and removes the fallback in one
                // editor, so a read interleaved between the two lookups above can
                // see neither. Re-read before concluding there is no registry:
                // concluding that wrongly is what authorizes the truncating write.
                basePrefs.getString(currentHash, null)?.let { blob ->
                    when (val read = decodeRegistry(blob)) {
                        is RegistryRead.Decoded -> {
                            read.keys.forEach { cacheRegistryKey(it) }
                            if (!read.complete) { currentReadable = false; allReadable = false }
                        }
                        RegistryRead.Malformed -> allReadable = false
                        RegistryRead.Unreadable -> { currentReadable = false; allReadable = false }
                    }
                }
            }
            currentRegistryReadable = currentReadable
            allRegistriesReadable = allReadable
        }

        /**
         * Records a registry-listed key under its current-epoch name only.
         *
         * A fallback-epoch name is deliberately never admitted to the reverse
         * cache. That table is trusted for resolution by enumeration and by the
         * change listener, and the fallback name is derivable from the APK, so
         * admitting it would let a transplanted ciphertext be served under
         * another key's name. Stranded values are instead reached by probing
         * forward from the plaintext key, which cannot be redirected.
         */
        private fun cacheRegistryKey(plainKey: String) {
            val hash = calculateKeyHash(plainKey)
            keyCache[plainKey] = hash
            reverseKeyCache[hash] = plainKey
        }

        /**
         * Enumerates by resolving each known key forward, the way the typed
         * getters do, rather than mapping stored names back through a reverse
         * table.
         *
         * Mapping backwards would have to trust whatever name is on disk. Values
         * carry no associated data, so a ciphertext is not bound to the name it
         * sits under, and the fallback-epoch name is derivable from the APK.
         * Anyone able to write to the data directory could therefore copy an
         * authentic ciphertext to the fallback name of another key and have
         * enumeration hand it back for that key, while the typed getters, which
         * recompute the hash from the plaintext, kept returning the real value.
         * Resolving forward and preferring the current name removes that split.
         *
         * Runs under the per-file monitor because the fold publishes the gate
         * flags that the commit path reads; the two must not interleave.
         */
        override fun getAll(): MutableMap<String, *> = synchronized(initLockFor(prefsName)) {
            ensureRegistrySeeded()
            val stored = basePrefs.all
            val result = mutableMapOf<String, Any?>()
            for (plainKey in keyCache.keys.toList()) {
                if (plainKey == KEY_REGISTRY) continue
                val currentName = calculateKeyHash(plainKey)
                val name = when {
                    stored.containsKey(currentName) -> currentName
                    else -> fallbackHashOf(plainKey).takeIf { it != currentName && stored.containsKey(it) }
                } ?: continue
                // Only encrypted String entries. Anything else was never written
                // by this class, and returning it verbatim would hand back
                // unauthenticated data placed at a derivable name.
                val encValue = stored[name] as? String ?: continue
                try {
                    result[plainKey] = decryptValue(encValue)
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to decrypt value for key $plainKey", e)
                    continue
                }
            }
            result
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
                    // Nothing on disk survives a clear, so the emptied cache is
                    // the intended list rather than an incomplete read of an
                    // older one. Without this a clear followed by a put in the
                    // same editor would take the guard below and write no
                    // registry at all, leaving the put unlisted.
                    currentRegistryReadable = true
                    allRegistriesReadable = true
                    // Re-fold next time. If this clear's commit fails, every
                    // entry is still on disk while the caches are empty, and a
                    // stale latch here would let the next put rewrite the
                    // registry from those empty caches and orphan the rest.
                    registrySeeded = false
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
                    ensureRegistrySeeded(countAttempt = true)
                }

                for (plainKey in pendingRemoves) {
                    val encKey = findEncryptedKey(plainKey)
                    if (encKey != null) {
                        baseEditor.remove(encKey)
                        reverseKeyCache.remove(encKey)
                    }
                    dropFallbackCopy(plainKey, encKey)
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
                    dropFallbackCopy(plainKey, encKey)
                }

                updateKeyRegistry()
            }

            /// Removes a copy stranded under the fallback derivation epoch, so a
            /// write or delete leaves exactly one copy of [plainKey].
            ///
            /// Writes resolve names through the cache without probing the fallback
            /// epoch, so without this a write lands under the current name while an
            /// older value survives beneath it, and a later delete removes only the
            /// new one. The next read then finds the superseded value, which for a
            /// policy selection means one the user replaced, possibly a looser one.
            private fun dropFallbackCopy(plainKey: String, currentName: String?) {
                if (plainKey == KEY_REGISTRY) return
                val fallbackHash = fallbackHashOf(plainKey)
                if (fallbackHash == currentName || !basePrefs.contains(fallbackHash)) return
                baseEditor.remove(fallbackHash)
                reverseKeyCache.remove(fallbackHash)
            }

            private fun updateKeyRegistry() {
                // Same bounds the reader enforces. Writing a list the reader
                // would refuse to decode lets the store invalidate its own state.
                val allKeys = keyCache.keys
                    .filter { it != KEY_REGISTRY && it.length <= MAX_KEY_NAME_LENGTH && it.none(Char::isISOControl) }
                    .sorted()
                    .take(MAX_REGISTRY_ENTRIES)
                    .toSet()
                if (allKeys.isEmpty() && clearRequested) return
                // The current copy was present but could not be decoded, so the
                // cache is not known to cover what it listed and rewriting from
                // it would truncate. Leave it; the keys stay directly readable,
                // and the next commit re-folds and can still recover.
                if (!currentRegistryReadable) {
                    // The queued puts still commit, so they exist on disk while
                    // absent from every registry copy. They stay readable by
                    // name, and this instance re-registers them once a fold
                    // succeeds, but a restart before that leaves them unlisted.
                    if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Registry unreadable; entries written now are unlisted")
                    return
                }
                val registryContent = allKeys.joinToString(KEY_REGISTRY_DELIMITER)
                val encKey = getEncryptedKeyName(KEY_REGISTRY)
                val encValue = encryptValue(registryContent)
                baseEditor.putString(encKey, encValue)
                // The current name now carries the full list, so drop a registry
                // stranded under the previous epoch. The read path falls back to
                // that name, and leaving it would let a stale key list resurface
                // the moment the current one became unreadable.
                val fallbackHash = fallbackHashOf(KEY_REGISTRY)
                if (allRegistriesReadable && fallbackHash != encKey && basePrefs.contains(fallbackHash)) {
                    baseEditor.remove(fallbackHash)
                }
            }
        }
    }
}
