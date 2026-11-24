package io.privkey.keep.storage

import android.content.Context
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Two instances creating the same Keystore alias for the first time at once must end up
 * with one key between them (#638). Each used to see the alias absent and generate its
 * own, the second replacing the first, so data written under the first stopped decrypting.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreKeyCreationRaceTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val run = "race${System.nanoTime()}"
    private val shareAliases = mutableListOf<String>()

    @After
    fun teardown() {
        keyStore.aliases().toList().filter { run in it || it in shareAliases }.forEach { keyStore.deleteEntry(it) }
        context.dataDir.resolve("shared_prefs").listFiles()
            ?.filter { run in it.name }
            ?.forEach { context.deleteSharedPreferences(it.name.removeSuffix(".xml")) }
    }

    private fun <T> concurrently(first: () -> T, second: () -> T): Pair<T, T> {
        val barrier = CyclicBarrier(2)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val a = pool.submit<T> { barrier.await(); first() }
            val b = pool.submit<T> { barrier.await(); second() }
            return a.get(60, TimeUnit.SECONDS) to b.get(60, TimeUnit.SECONDS)
        } finally {
            pool.shutdownNow()
        }
    }

    private fun assertSameKey(round: Int, first: SecretKey, second: SecretKey) {
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, first) }
        val sealed = encrypt.doFinal(PLAINTEXT)
        val decrypt = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, second, GCMParameterSpec(128, encrypt.iv)) }
        assertEquals("round $round", String(PLAINTEXT), String(decrypt.doFinal(sealed)))
    }

    private fun storage(alias: String, suffix: String) =
        AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = alias, prefsSuffix = suffix)

    @Test
    fun concurrentFirstCreationOfTheStorageAliasYieldsOneKey() {
        repeat(ROUNDS) { round ->
            val alias = "keep_${run}_$round"
            val (a, b) = concurrently(
                { storage(alias, "_${run}_a$round").getCipherForEncryption() },
                { storage(alias, "_${run}_b$round").getCipherForEncryption() },
            )
            val stored = keyStore.getKey(alias, null) as SecretKey
            val sealedA = a.doFinal(PLAINTEXT)
            val sealedB = b.doFinal(PLAINTEXT)
            listOf(a.iv to sealedA, b.iv to sealedB).forEach { (iv, sealed) ->
                val decrypt = Cipher.getInstance("AES/GCM/NoPadding")
                    .apply { init(Cipher.DECRYPT_MODE, stored, GCMParameterSpec(128, iv)) }
                assertEquals("round $round", String(PLAINTEXT), String(decrypt.doFinal(sealed)))
            }
        }
    }

    @Test
    fun concurrentFirstCreationOfAShareKeyYieldsOneKey() {
        repeat(ROUNDS) { round ->
            val share = "${run}_share$round"
            val first = storage("keep_${run}_sa$round", "_${run}_a$round")
            val second = storage("keep_${run}_sb$round", "_${run}_b$round")
            shareAliases += first.keystoreAliasFor(share)
            val (a, b) = concurrently({ first.ensureShareKey(share) }, { second.ensureShareKey(share) })
            assertSameKey(round, a, b)
        }
    }

    /**
     * While one instance is between generating a StrongBox share key and finding it
     * unusable, the alias already exists. Another instance must not take that key from
     * its fast path, as the first then deletes it and generates the TEE key in its place.
     */
    @Test
    fun shareKeyFastPathWaitsOutAStrongBoxFallback() {
        assumeTrue(context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore"))
        assumeTrue(
            "requires an enrolled strong biometric",
            BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        )
        repeat(ROUNDS) { round ->
            val share = "${run}_fallback$round"
            val probing = CountDownLatch(1)
            val first = AndroidKeystoreStorage(
                context,
                requireUserAuth = true,
                strongBoxUseTimeProbe = { probing.countDown(); Thread.sleep(PROBE_HOLD_MS); false },
                keystoreAlias = "keep_${run}_fa$round",
                prefsSuffix = "_${run}_fa$round",
            )
            val second = AndroidKeystoreStorage(
                context,
                requireUserAuth = true,
                keystoreAlias = "keep_${run}_fb$round",
                prefsSuffix = "_${run}_fb$round",
            )
            shareAliases += first.keystoreAliasFor(share)
            val (a, b) = concurrently(
                { first.ensureShareKey(share) },
                { check(probing.await(30, TimeUnit.SECONDS)); second.ensureShareKey(share) },
            )
            val stored = keyStore.getKey(first.keystoreAliasFor(share), null) as SecretKey
            listOf(a, b).forEach { key ->
                assertEquals("round $round", stored, key)
                assertEquals("round $round", KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, securityLevelOf(key))
                Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, key)
            }
        }
    }

    private fun securityLevelOf(key: SecretKey): Int =
        (SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo)
            .securityLevel

    @Test
    fun concurrentFirstOpenOfEncryptedPrefsSharesOneKey() {
        repeat(ROUNDS) { round ->
            val name = "${run}_prefs$round"
            val (a, b) = concurrently(
                { KeystoreEncryptedPrefs.create(context, name) },
                { KeystoreEncryptedPrefs.create(context, name) },
            )
            check(a.edit().putString("value", "from a").commit())
            assertEquals("round $round", "from a", b.getString("value", null))
            assertEquals("round $round", "from a", KeystoreEncryptedPrefs.create(context, name).getString("value", null))
        }
    }

    private companion object {
        const val ROUNDS = 5
        const val PROBE_HOLD_MS = 1_000L
        val PLAINTEXT = "keep-638".toByteArray()
    }
}
