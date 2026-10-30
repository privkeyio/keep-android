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

    // Set beside a derivation key minted over entries that predate it, and kept
    // under a literal name like the key itself, since the point of it is that the
    // hashed names on this file cannot all be computed any more. Read on every
    // open: the instance that mints is rarely the one a later delete runs on.
    private const val STRANDED_EPOCH_PREF = "__stranded_epoch__"
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

    fun create(context: Context, prefsName: String): ReadablePrefs {
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

    /// Marks a value whose ciphertext is bound to the key it is stored under.
    ///
    /// Values written before this existed carry no marker and are still read,
    /// unbound, so upgrading loses nothing. They gain the binding when they are
    /// next written.
    ///
    /// There is no convergence: a value that is never rewritten stays unbound
    /// for the life of the install, and stays transplantable. That is the
    /// pre-existing behaviour rather than a new weakness, but it means an
    /// upgraded device keeps the exposure for exactly the entries that predate
    /// the upgrade, which is where existing grants live. Closing it needs the
    /// reader to re-encrypt a legacy value once it has decrypted it, and then a
    /// per-file marker so unbound values stop being accepted at all. Deliberately
    /// not done here: that adds a write to the read path in the file that holds
    /// share material, and belongs in its own change.
    ///
    /// The delimiter is outside the Base64 alphabet on purpose. A marker made of
    /// alphabet characters could occur at the start of a legacy value and would
    /// make it decrypt as bound, which fails. No legacy value can contain a
    /// colon at all.
    private const val BOUND_PREFIX = "v2:"

    /// Encrypts `plaintext` bound to `aad`, the logical key name it is stored
    /// under.
    ///
    /// Without this, authentication covers the value alone and says nothing
    /// about where it belongs, so any ciphertext from this file can be copied
    /// onto another entry's name and still decrypt and authenticate. That is
    /// enough to grant a package auto-signing by copying another package's
    /// stored `true` onto its name.
    ///
    /// Bound to the logical name rather than the stored one on purpose: the
    /// same logical key legitimately moves between stored names when an entry
    /// left under a previous derivation epoch is relocated, and binding to the
    /// stored name would invalidate the value the moment it was recovered.
    private fun encrypt(key: SecretKey, plaintext: String, aad: String): String {
        require(plaintext.isNotEmpty()) { "Plaintext must not be empty" }
        // An empty AAD is the same as no AAD to GCM, so it would produce a value
        // that looks bound and carries no binding.
        require(aad.isNotEmpty()) { "Associated data must not be empty" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = ByteArray(iv.size + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encrypted, 0, combined, iv.size, encrypted.size)
        return BOUND_PREFIX + Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decrypt(key: SecretKey, ciphertext: String, aad: String): String {
        require(ciphertext.isNotEmpty()) { "Ciphertext must not be empty" }
        val bound = ciphertext.startsWith(BOUND_PREFIX)
        val body = if (bound) ciphertext.removePrefix(BOUND_PREFIX) else ciphertext
        val combined = Base64.decode(body, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, GCM_IV_BYTES)
        val encrypted = combined.copyOfRange(GCM_IV_BYTES, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        // Only the marked format carries the binding. An unmarked value predates
        // it and is read as it was written; authentication still covers the
        // value itself, just not its location.
        if (bound) {
            cipher.updateAAD(aad.toByteArray(Charsets.UTF_8))
        }
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    private class EncryptingSharedPreferences(
        private val basePrefs: SharedPreferences,
        private val secretKey: SecretKey,
        private val prefsName: String
    ) : ReadablePrefs {

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

        /**
         * Whether this file already held entries when the derivation key in use
         * was minted, named with a key that is not on disk any more.
         *
         * Names are hashed with a per-file key, so this store can only look
         * under the key it holds. Entries named with a previous one are at names
         * nothing here can compute: a lookup for them misses exactly as a key
         * that was never written does. That is the state the core's delete
         * contract calls key derivation being unavailable, and the reason it
         * asks for a failed delete rather than a claimed absence, because a
         * restore that brings the old key back brings those entries back with
         * it, enforcing again after something was told they were gone.
         *
         * Minting over them is still the only move available: their key is gone,
         * so nothing can be read or rewritten under it. What changes is only
         * what a delete is then allowed to claim.
         */
        private var namesPredateThisKey = false
        @Volatile
        private var hmacKey: ByteArray? = null

        /**
         * The stored key record [hmacKey] was resolved against, null when none
         * was on disk.
         *
         * Several instances can hold the same file, and they share its
         * [SharedPreferences], so one that rotates, mints or clears changes the
         * record under the others. An instance still hashing under the key it
         * cached would then write at names the next open cannot compute.
         */
        @Volatile
        private var loadedKeyRecord: String? = null
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

        /**
         * The derivation key a build in the v0.6.0 window persisted into any
         * file that already held entries: the seed alone, with no file name.
         *
         * It is a constant in this repository's history and in released APKs,
         * so a file carrying it hashes every name under something anyone can
         * compute, which is the same exposure as the fallback epoch and not a
         * name-by-name one. [rotateOffPublishedKey] moves a file off it on
         * open, and a file it cannot move keeps it until an open that can.
         */
        private val legacyGlobalKey: ByteArray by lazy {
            MessageDigest.getInstance("SHA-256")
                .digest(DETERMINISTIC_HMAC_SEED.toByteArray(Charsets.UTF_8))
        }

        /**
         * Whether the names this store computes are ones anything that can read
         * the APK can compute too.
         *
         * Asked of the key rather than of a name: both exposures are the key
         * being public, and comparing the key covers the one that is persisted
         * as this file's own and would otherwise look like any other.
         */
        private fun namesAreDerivable(): Boolean {
            val key = getHmacKey()
            return key.contentEquals(deterministicKey) || key.contentEquals(legacyGlobalKey)
        }

        private fun getHmacKey(): ByteArray {
            currentHmacKey()?.let { return it }
            synchronized(initLockFor(prefsName)) {
                currentHmacKey()?.let { return it }
                if (hmacKey != null) forgetStaleKey()
                val key = resolveHmacKey()
                loadedKeyRecord = basePrefs.getString(HMAC_KEY_PREF, null)
                hmacKey = key
                return key
            }
        }

        private fun currentHmacKey(): ByteArray? =
            hmacKey?.takeIf { basePrefs.getString(HMAC_KEY_PREF, null) == loadedKeyRecord }

        /** Drops everything derived from a key another instance has replaced. Callers hold the per-file monitor. */
        private fun forgetStaleKey() {
            hmacKey = null
            keyCache.clear()
            reverseKeyCache.clear()
            registrySeeded = false
            foldAttempts = 0
        }

        private fun resolveHmacKey(): ByteArray {
            val stored = basePrefs.getString(HMAC_KEY_PREF, null)
            namesPredateThisKey = basePrefs.contains(STRANDED_EPOCH_PREF)
            if (stored != null) {
                val decrypted = decrypt(secretKey, stored, HMAC_KEY_PREF)
                val key = Base64.decode(decrypted, Base64.NO_WRAP)
                // Our own 32-byte key, stored base64 then GCM-encrypted; GCM authentication
                // rules out external tampering, so a wrong length here is an internal bug.
                // Fail fast: Mac/SecretKeySpec accept any key length and would otherwise
                // silently diverge the audit-chain HMACs and key-name hashes.
                check(key.size == HMAC_KEY_LENGTH) { "Decoded HMAC key has wrong length: ${key.size}" }
                return if (key.contentEquals(legacyGlobalKey)) rotateOffPublishedKey(key) else key
            }
            val key = ByteArray(HMAC_KEY_LENGTH).also { SecureRandom().nextBytes(it) }
            val encoded = Base64.encodeToString(key, Base64.NO_WRAP)
            val encryptedHmacKey = encrypt(secretKey, encoded, HMAC_KEY_PREF)
            val registryHash = hmacWithKey(KEY_REGISTRY, deterministicHmacKey())
            val hasExistingEntries = basePrefs.contains(registryHash)
            val fileHoldsEntries =
                basePrefs.all.keys.any { it != HMAC_KEY_PREF && it != STRANDED_EPOCH_PREF }
            val persisted = if (hasExistingEntries) {
                migrateFromDeterministicKey(key, encryptedHmacKey).also { ok ->
                    if (!ok && BuildConfig.DEBUG) Log.e("KeystoreEncryptedPrefs", "HMAC migration failed, using deterministic fallback key")
                }
            } else {
                // One commit: the marker has to land with the key it describes,
                // or a restart reads a key that looks like it has always been
                // this file's and certifies deletes over the stranded entries.
                val editor = basePrefs.edit().putString(HMAC_KEY_PREF, encryptedHmacKey)
                if (fileHoldsEntries) editor.putString(STRANDED_EPOCH_PREF, "1")
                editor.commit().also { ok ->
                    if (!ok && BuildConfig.DEBUG) Log.e("KeystoreEncryptedPrefs", "Failed to persist new HMAC key")
                }
            }
            // Entries this cannot name: either nothing here could read an
            // index for them, so they predate the key being minted now, or
            // the key just minted did not persist and the store carries on
            // under its deterministic one while they sit at names derived
            // with neither. A rollback of this file produces the first; a
            // value planted at the deterministic index name, which anything
            // that can write this directory can derive, produces the second
            // and would otherwise read as a deterministic-epoch file whose
            // entries are all accounted for.
            //
            // Not durable in the second case, and it does not need to be:
            // nothing committed, so every later open resolves the same way
            // and recomputes it.
            val stranded = fileHoldsEntries && (!hasExistingEntries || !persisted)
            namesPredateThisKey = namesPredateThisKey || stranded
            return if (persisted) key else deterministicHmacKey()
        }

        /**
         * Moves a file off the published global key onto a fresh random one,
         * re-hashing what its index lists the way the deterministic epoch is left.
         *
         * Keeps the published key when the index at its name is missing, will
         * not decode or dropped entries, or when the commit fails, and the next
         * open tries again. Names the index does not list stay where they are,
         * at names nothing computes after this: a value there was refused while
         * the key was public, since nothing unlisted and unbound is read at a
         * derivable name, so leaving it costs no value this store reads today.
         */
        private fun rotateOffPublishedKey(published: ByteArray): ByteArray {
            val blob = basePrefs.getString(hmacWithKey(KEY_REGISTRY, published), null) ?: return published
            val index = decodeRegistry(blob) as? RegistryRead.Decoded ?: return published
            if (!index.complete) return published
            val fresh = ByteArray(HMAC_KEY_LENGTH).also { SecureRandom().nextBytes(it) }
            val encrypted = encrypt(secretKey, Base64.encodeToString(fresh, Base64.NO_WRAP), HMAC_KEY_PREF)
            return if (rehashEntries(published, fresh, encrypted, index.keys)) fresh else published
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
                val decrypted = decrypt(secretKey, encryptedRegistry, KEY_REGISTRY)
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
            return rehashEntries(oldKey, newKey, encryptedHmacKey, plainKeys)
        }

        private fun rehashEntries(
            oldKey: ByteArray,
            newKey: ByteArray,
            encryptedHmacKey: String,
            plainKeys: List<String>
        ): Boolean {
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

        /**
         * What a lookup found at the names a key can live under.
         *
         * [Absent] and [Refused] are both "no name answered with a value this
         * will hand back", and they must not be conflated: one says nothing is
         * there, the other says something is and this will not read it as this
         * key's. Reporting the second as the first is how a record that exists
         * reaches a caller as a positive absence, which several of them treat as
         * licence to overwrite or as a control that was never set.
         */
        private sealed interface KeyLookup {
            /** A name holding a value that may be read as this key's. */
            data class Found(val encKey: String) : KeyLookup

            /** No name holds anything for this key. */
            object Absent : KeyLookup

            /** [encKey] holds a value this will not read as this key's. */
            data class Refused(val encKey: String) : KeyLookup
        }

        /** The name to read, for callers that have nothing to do with a refusal. */
        private fun findEncryptedKey(plainKey: String): String? =
            (locateKey(plainKey) as? KeyLookup.Found)?.encKey

        private fun locateKey(plainKey: String): KeyLookup {
            keyCache[plainKey]?.let { encKey ->
                if (basePrefs.contains(encKey)) return KeyLookup.Found(encKey)
            }
            val hash = calculateKeyHash(plainKey)
            if (basePrefs.contains(hash)) {
                // While this store's derivation key is one anything can compute,
                // the name it just computed is one anything can compute too, so
                // it takes the same rule the fallback name does. The registry is
                // excluded here as it is below: it resolves through its own
                // decode rather than this lookup.
                if (plainKey != KEY_REGISTRY && namesAreDerivable() &&
                    acceptableValueAt(plainKey, hash) == null
                ) {
                    return KeyLookup.Refused(hash)
                }
                keyCache[plainKey] = hash
                reverseKeyCache[hash] = plainKey
                return KeyLookup.Found(hash)
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
            if (plainKey == KEY_REGISTRY) return KeyLookup.Absent
            val fallbackHash = fallbackHashOf(plainKey)
            if (fallbackHash == hash) return KeyLookup.Absent
            if (acceptableValueAt(plainKey, fallbackHash) == null) {
                // Present and refused, or not there at all. Only the first is a
                // refusal, and contains() is what separates them without reading.
                return if (basePrefs.contains(fallbackHash)) KeyLookup.Refused(fallbackHash)
                else KeyLookup.Absent
            }

            // Three outcomes, kept apart because they are not the same answer:
            // the value is no longer there to move, the move stuck, or the move
            // did not stick and the value is still at the old name.
            val movedTo = synchronized(initLockFor(prefsName)) {
                // Re-read under the lock, and through the same rule: what is
                // there now is what gets relocated to a name this will trust
                // from then on.
                val value = acceptableValueAt(plainKey, fallbackHash)
                when {
                    value == null -> null
                    basePrefs.edit().putString(hash, value).remove(fallbackHash).commit() -> hash
                    else -> fallbackHash
                }
            }
            return when (movedTo) {
                // Gone or no longer acceptable between the two reads. Saying
                // Found here would report a name holding nothing readable, which
                // a delete would then certify as an absence it never established.
                null -> if (basePrefs.contains(fallbackHash)) KeyLookup.Refused(fallbackHash)
                else KeyLookup.Absent
                hash -> {
                    keyCache[plainKey] = hash
                    reverseKeyCache[hash] = plainKey
                    KeyLookup.Found(hash)
                }
                // Consolidation did not stick. Report where the entry actually is
                // so this lookup is still correct, but do not cache it: a cached
                // old location would send the next write there and leave a second
                // copy behind it.
                else -> KeyLookup.Found(fallbackHash)
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
         * The value at a name anything could have written, if it may be read as
         * [plainKey]'s.
         *
         * That name is an HMAC over the plaintext key under a key derived from a
         * constant in the APK and the file name, so anything that can write this
         * directory can place a value at a name of its choosing, and values in
         * one file are otherwise interchangeable: authentication covers the value
         * alone, and the auto-signing file stores the same plaintext for every
         * opted-in package. Copying one onto another package's fallback name is
         * the transplant this refuses.
         *
         * A bound value answers it by itself: it decrypts only under the logical
         * name it was written for, and producing a new one needs the Keystore
         * key. A value from before the binding carries no such statement, so it
         * is accepted only for a key this store's own index lists, which is the
         * difference between a value stranded by an epoch this store moved
         * through and a value planted for a key it has never written. An
         * attacker cannot list a name of their choosing: the index is encrypted,
         * and a copied blob only ever lists names that were already in it.
         *
         * Refusing an unlisted unbound value costs nothing legitimate, since
         * nothing wrote it, while refusing a listed one would silently drop
         * settings of exactly the shape that is never rewritten.
         *
         * The PIN flag is the example to keep in mind and the one this does not
         * reach: its store reads through the ordinary getters, which collapse an
         * unreadable value to the caller's default exactly as they collapse an
         * absent one, so a refusal there still reads as no PIN. Closing that
         * means moving those reads onto the three-way ones, which is its own
         * change.
         *
         * A store whose derivation key is itself public hashes every name under
         * it, so the current name is derivable too and earns no more trust than
         * the fallback one; the lookup applies this there as well, for a store
         * left on its deterministic key and for one carrying the global key a
         * build in the v0.6.0 window persisted. What discriminates
         * there is mostly boundness rather than the index: reaching that state
         * takes an index this cannot decode, which is also what stops the index
         * being rebuilt, so nothing is listed and nothing unbound is admitted.
         * That is the intended answer, since a file genuinely holding
         * deterministic-epoch entries migrates off that key on first access and
         * never reads through this at all. The index still decides the narrow
         * case where the index decoded and the minted key failed to commit.
         *
         * The cost is paid on a cold hit only, and it is one decrypt the read
         * repeats a moment later; a repeat read answers from the name cache
         * without reaching here.
         */
        private fun acceptableValueAt(plainKey: String, storedName: String): String? {
            // A non-String planted at this name makes the platform getter throw
            // on its unchecked cast, which is the same writer this is defending
            // against, so it answers as nothing rather than raising.
            val value = runCatching { basePrefs.getString(storedName, null) }.getOrNull() ?: return null
            if (!value.startsWith(BOUND_PREFIX)) {
                synchronized(initLockFor(prefsName)) { ensureRegistrySeeded() }
                if (!keyCache.containsKey(plainKey)) return null
            }
            // Decrypt before answering, because answering also moves the value
            // to the current name and caches it there. A marker is only a prefix
            // and an attacker can write one, so without this a blob that will
            // never decrypt is laundered onto a name nothing can plant at, where
            // it reads as unreadable rather than absent for the life of the
            // install. One decrypt, on a cold miss that found something.
            return value.takeIf { runCatching { decrypt(secretKey, it, plainKey) }.isSuccess }
        }

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
            val decrypted = decrypt(secretKey, blob, KEY_REGISTRY)
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
                // No marker check here: this loop only ever walks keys the index
                // lists, which is the condition the probe admits an unbound value
                // under, so enumeration and a direct read answer the same.
                val name = when {
                    stored.containsKey(currentName) -> currentName
                    else -> fallbackHashOf(plainKey).takeIf { it != currentName && stored.containsKey(it) }
                } ?: continue
                // Only encrypted String entries. Anything else was never written
                // by this class, and returning it verbatim would hand back
                // unauthenticated data placed at a derivable name.
                val encValue = stored[name] as? String ?: continue
                try {
                    result[plainKey] = decryptValue(encValue, plainKey)
                } catch (e: Exception) {
                    // The stored name, not the plaintext one: these files key on
                    // caller package names, which are hashed before logging
                    // elsewhere, so logging them here would undo that.
                    if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to decrypt value for stored key $name", e)
                    continue
                }
            }
            result
        }

        private fun decryptValue(encrypted: String, plainKey: String): Any? {
            val decrypted = decrypt(secretKey, encrypted, plainKey)
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

        private fun encryptValue(value: Any?, plainKey: String): String {
            val prefixed = when (value) {
                is String -> PREFIX_STRING + value
                is Int -> PREFIX_INT + value
                is Long -> PREFIX_LONG + value
                is Float -> PREFIX_FLOAT + value
                is Boolean -> PREFIX_BOOL + value
                is Set<*> -> PREFIX_STRING_SET + value.joinToString(STRING_SET_DELIMITER)
                else -> throw IllegalArgumentException("Unsupported type: ${value?.javaClass}")
            }
            return encrypt(secretKey, prefixed, plainKey)
        }

        /**
         * The one read path. [getTypedValue] resolves anything but a value to the
         * caller's default, which is what [SharedPreferences] promises; a caller that
         * cannot treat an unreadable value as absent asks through [ReadablePrefs]
         * instead and gets the case itself.
         *
         * A parse that throws counts as unreadable rather than absent: the value is
         * there and this layer cannot produce it, which is the same answer a failed
         * decrypt gives.
         *
         * So does a name that resolved while its value is gone. [locateKey]
         * returns a name only after finding a value at it, so reaching that needs a
         * remove or clear landing between the two, and "the name is still indexed and
         * the value is not there" is something this layer cannot account for rather
         * than proof nothing was ever written. Both of these resolve to the caller's
         * default through [getTypedValue] either way, so the distinction is only
         * visible to a [ReadablePrefs] caller, where it is the safe direction.
         *
         * So does a value [locateKey] refuses, which is on disk and not readable as
         * this key's. That is the third outcome it reports and the one an absence
         * would misdescribe: several callers read an absence as a control that was
         * never set, or as licence to overwrite what they could not read.
         */
        private inline fun <T> readTyped(
            key: String,
            prefix: String,
            crossinline parse: (String) -> T
        ): PrefRead<T> {
            val encKey = when (val found = locateKey(key)) {
                is KeyLookup.Found -> found.encKey
                KeyLookup.Absent -> return PrefRead.Absent
                // On disk and not readable as this key's, which is what this
                // answer means. Reporting it absent is what let a record that
                // exists reach a caller as a control that was never set.
                is KeyLookup.Refused -> return PrefRead.Unreadable
            }
            val encValue = basePrefs.getString(encKey, null) ?: return PrefRead.Unreadable
            return try {
                val decrypted = decrypt(secretKey, encValue, key)
                if (decrypted.startsWith(prefix)) {
                    PrefRead.Found(parse(decrypted.removePrefix(prefix)))
                } else {
                    PrefRead.Unreadable
                }
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Failed to decrypt typed value for key $key", e)
                PrefRead.Unreadable
            }
        }

        private inline fun <T> getTypedValue(
            key: String,
            defValue: T,
            prefix: String,
            crossinline parse: (String) -> T
        ): T = when (val read = readTyped(key, prefix, parse)) {
            is PrefRead.Found -> read.value
            else -> defValue
        }

        /**
         * [readTyped] with name resolution inside the guard, which is what makes a
         * [ReadablePrefs] read total.
         *
         * Resolving a name goes through this file's own HMAC key, and that decrypt is
         * unguarded, so losing the Keystore alias makes every lookup here raise instead
         * of answering. The ordinary getters let it propagate, which is what callers of
         * this class have always seen and what the share storage above converts at the
         * FFI boundary. A three-way read cannot propagate it: a caller choosing what to
         * do about an unreadable value is exactly the caller that must not be handed an
         * exception from the read instead. Exception rather than Throwable, since an
         * Error is not a storage fault.
         */
        private inline fun <T> guardedRead(
            key: String,
            prefix: String,
            crossinline parse: (String) -> T
        ): PrefRead<T> = try {
            readTyped(key, prefix, parse)
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.w("KeystoreEncryptedPrefs", "Could not resolve key $key", e)
            PrefRead.Unreadable
        }

        override fun readString(key: String): PrefRead<String> =
            guardedRead(key, PREFIX_STRING) { it }

        override fun readStringSet(key: String): PrefRead<Set<String>> =
            guardedRead(key, PREFIX_STRING_SET) { raw ->
                raw.split(STRING_SET_DELIMITER).filter { it.isNotEmpty() }.toSet()
            }

        override fun readInt(key: String): PrefRead<Int> =
            guardedRead(key, PREFIX_INT) { it.toInt() }

        override fun readLong(key: String): PrefRead<Long> =
            guardedRead(key, PREFIX_LONG) { it.toLong() }

        override fun readBoolean(key: String): PrefRead<Boolean> =
            guardedRead(key, PREFIX_BOOL) { it == "true" }

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
                // Both have to hold. The write reaching disk is not enough when a
                // removal could not be certified: the core reads a true here as
                // "that key is gone from the durable store", and acts on it.
                val certified = applyChanges()
                baseEditor.commit() && certified
            }

            // apply() has no result to carry an uncertified removal in, which is
            // the reason every storage class here commits instead.
            override fun apply() = synchronized(initLockFor(prefsName)) {
                // Hoisted, like commit(): as an operand it would be skipped
                // wherever the DEBUG check short-circuits, which is every release
                // build, and nothing would be staged at all.
                val certified = applyChanges()
                if (!certified && BuildConfig.DEBUG) {
                    Log.w("KeystoreEncryptedPrefs", "apply() cannot report an uncertified removal")
                }
                baseEditor.apply()
            }

            /**
             * Stages this editor onto [baseEditor], and reports whether every
             * removal in it was certified.
             *
             * A removal is certified when the entry was found and dropped, or
             * when the key is genuinely absent. "No entry answered the lookup" is
             * not by itself the second of those: the core's delete contract asks
             * an implementation whose key derivation or index is unavailable to
             * report failure rather than read its own blindness as absence, since
             * a live entry reported as deleted stays on disk and becomes
             * enforceable again once lookup recovers.
             *
             * A named lookup here resolves forward: it recomputes the hash from
             * the plaintext key and probes both derivation epochs for it. So a
             * miss is conclusive whenever this store holds the key those names
             * were derived with, and the one state where it is not is the file
             * that already held entries when the key in use was minted. That is
             * what [namesPredateThisKey] records and all this refuses on.
             *
             * Uncertified removals do not hold back the rest of the editor. The
             * puts and the removals that did resolve are real work, and discarding
             * them would trade a wrong answer for lost writes; the caller is told
             * instead, through the one channel it has.
             */
            private fun applyChanges(): Boolean {
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

                var certified = true
                for (plainKey in pendingRemoves) {
                    val located = locateKey(plainKey)
                    if (located is KeyLookup.Refused) {
                        // Present, and not established as absent, so the delete
                        // says so rather than claiming it. Not removed either:
                        // every reason this answer is given can be a property of
                        // this process rather than of the value. A decrypt that
                        // failed can succeed on the next open, the minted key may
                        // simply not have committed, which leaves this process on
                        // the deterministic key with every name derivable, and an
                        // index that could not be read lists nothing, so a key
                        // that is listed looks unlisted. Removing it here is the
                        // shape the audit chain and the share metadata both had
                        // taken out of them: a transient fault read as proof, and
                        // the record destroyed on the strength of it.
                        certified = false
                        continue
                    }
                    val encKey = (located as? KeyLookup.Found)?.encKey
                    if (encKey == null && namesPredateThisKey) {
                        // Nothing answered, and this file holds entries at names
                        // derived with a key that is gone, so a miss here does not
                        // separate "never written" from "written under that key".
                        // Keep the name rather than deregistering a key that may
                        // still exist at a name nothing can compute. The copy at
                        // the name this can compute is still swept, since nothing
                        // answered for it and the caller asked for that key to be
                        // gone.
                        //
                        // Deliberately not keyed on the registry: it lists plain
                        // key names, which is less than the caller just passed in,
                        // and a lookup resolves forward from that name under both
                        // derivation epochs without consulting it. An unreadable
                        // registry makes a lookup slower, not less conclusive, so
                        // refusing on it would fail deletes that did establish
                        // absence, and would hand an attacker who can write the
                        // file a latch: the fallback copy's name is derivable from
                        // the APK and nothing drops a copy it cannot decode.
                        certified = false
                        dropFallbackCopy(plainKey, null)
                        continue
                    }
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
                    val encValue = encryptValue(value, plainKey)
                    baseEditor.putString(encKey, encValue)
                    dropFallbackCopy(plainKey, encKey)
                }

                updateKeyRegistry()
                return certified
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
                // Deliberately unfiltered. Narrowing the list here would persist
                // a strict subset of what the read gate just certified the cache
                // covers, silently deregistering the difference: the same bug
                // this change exists to fix, through a second door. If a list
                // ever exceeds the reader's bounds, the reader reports it
                // incomplete and the rewrite is skipped, which is conservative.
                val allKeys = keyCache.keys.filter { it != KEY_REGISTRY }.toSet()
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
                val encValue = encryptValue(registryContent, KEY_REGISTRY)
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
