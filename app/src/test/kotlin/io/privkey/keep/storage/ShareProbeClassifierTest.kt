package io.privkey.keep.storage

import io.privkey.keep.uniffi.ShareProbe
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class ShareProbeClassifierTest {

    private val plain = "frost share".toByteArray()

    private fun aesKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private fun seal(key: SecretKey): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        return cipher.iv to cipher.doFinal(plain)
    }

    private class FakeKeystore(
        val keys: Map<String, SecretKey> = emptyMap(),
        val authKeys: Set<SecretKey> = emptySet(),
        val invalidated: Set<SecretKey> = emptySet(),
        val throwsOn: Set<String> = emptySet(),
        var canary: List<Boolean> = listOf(true, true),
        val authenticated: Cipher? = null,
    ) : ShareProbeKeystore {
        var canaryReads = 0
        var authenticatedTaken = 0

        override fun canaryPresent(): Boolean = canary[canaryReads++]

        override fun secretKey(alias: String): SecretKey? {
            if (alias in throwsOn) throw ProviderException("keystore fault")
            return keys[alias]
        }

        override fun requiresUserAuth(key: SecretKey): Boolean = key in authKeys

        override fun open(key: SecretKey, iv: ByteArray): OpenedKey = when (key) {
            in invalidated -> OpenedKey.Invalidated
            else -> OpenedKey.Ready(Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            })
        }

        override fun authenticatedCipher(): Cipher? = authenticated.also { authenticatedTaken++ }
    }

    private fun decryptCipher(key: SecretKey, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }

    private val aliases = listOf("per-key", "legacy", "global")

    @Test
    fun everyAliasAbsentWithTheCanaryAnsweringIsLost() {
        assertEquals(ShareProbe.Lost, classifyShare(aliases, null, null, FakeKeystore()))
    }

    @Test
    fun aKeyWhoseRecordIsConfirmedEmptyIsLost() {
        val keystore = FakeKeystore(keys = mapOf("global" to aesKey()))
        assertEquals(ShareProbe.Lost, classifyShare(aliases, null, null, keystore, recordEmpty = true))
    }

    @Test
    fun aKeyWithNoRecordReadIsUnknownUnlessTheRecordIsConfirmedEmpty() {
        val keystore = FakeKeystore(keys = mapOf("global" to aesKey()))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, null, keystore, recordEmpty = false))
    }

    @Test
    fun halfARecordIsUnknownEvenWhenTheFileLooksEmpty() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, null, FakeKeystore(keys = mapOf("per-key" to key)), recordEmpty = true))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, ct, FakeKeystore(keys = mapOf("per-key" to key)), recordEmpty = true))
    }

    @Test
    fun aMissingCanaryBeforeOrAfterIsUnknown() {
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, null, FakeKeystore(canary = listOf(false, true))))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, null, FakeKeystore(canary = listOf(true, false))))
    }

    @Test
    fun aLookupThatThrowsIsUnknown() {
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, null, FakeKeystore(throwsOn = setOf("legacy"))))
    }

    @Test
    fun aShareThatDecryptsLoads() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        val probe = classifyShare(aliases, iv, ct, FakeKeystore(keys = mapOf("per-key" to key)))
        assertArrayEquals(plain, (probe as ShareProbe.Loads).data)
    }

    @Test
    fun anyKeyThatDecryptsLoadsEvenBesideALostOne() {
        val good = aesKey()
        val (iv, ct) = seal(good)
        val probe = classifyShare(aliases, iv, ct, FakeKeystore(keys = mapOf("per-key" to aesKey(), "global" to good)))
        assertTrue(probe is ShareProbe.Loads)
    }

    @Test
    fun anInvalidatedKeyIsLost() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        assertEquals(ShareProbe.Lost, classifyShare(aliases, iv, ct, FakeKeystore(keys = mapOf("per-key" to key), invalidated = setOf(key))))
    }

    @Test
    fun aBadTagOnACleanReadIsLost() {
        val (iv, ct) = seal(aesKey())
        assertEquals(ShareProbe.Lost, classifyShare(aliases, iv, ct, FakeKeystore(keys = mapOf("per-key" to aesKey()))))
    }

    @Test
    fun aCiphertextShorterThanTheTagIsLost() {
        val key = aesKey()
        val (iv, _) = seal(key)
        assertEquals(ShareProbe.Lost, classifyShare(aliases, iv, ByteArray(15), FakeKeystore(keys = mapOf("per-key" to key))))
    }

    @Test
    fun anUnreadIvOrCiphertextWithAKeyPresentIsUnknown() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        val keystore = { FakeKeystore(keys = mapOf("per-key" to key)) }
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, null, ct, keystore()))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, null, keystore()))
    }

    @Test
    fun anAuthKeyWithoutTheAuthenticatedCipherIsUnknown() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, ct, FakeKeystore(keys = mapOf("per-key" to key), authKeys = setOf(key))))
    }

    @Test
    fun anAuthKeyDecryptsOnlyWithTheAuthenticatedCipher() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        val keystore = FakeKeystore(keys = mapOf("per-key" to key), authKeys = setOf(key), authenticated = decryptCipher(key, iv))
        assertTrue(classifyShare(aliases, iv, ct, keystore) is ShareProbe.Loads)
        assertEquals(1, keystore.authenticatedTaken)
    }

    @Test
    fun anAuthKeyFailingItsTagWithTheAuthenticatedCipherIsLost() {
        val key = aesKey()
        val (iv, ct) = seal(aesKey())
        val keystore = FakeKeystore(keys = mapOf("per-key" to key), authKeys = setOf(key), authenticated = decryptCipher(key, iv))
        assertEquals(ShareProbe.Lost, classifyShare(aliases, iv, ct, keystore))
    }

    @Test
    fun anAuthenticatedCipherOnAnotherIvIsUnknown() {
        val key = aesKey()
        val (staleIv, _) = seal(key)
        val (iv, ct) = seal(key)
        val keystore = FakeKeystore(keys = mapOf("per-key" to key), authKeys = setOf(key), authenticated = decryptCipher(key, staleIv))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, ct, keystore))
    }

    @Test
    fun moreThanOneAuthKeyIsUnknown() {
        val a = aesKey()
        val b = aesKey()
        val (iv, ct) = seal(a)
        val keystore = FakeKeystore(keys = mapOf("per-key" to a, "global" to b), authKeys = setOf(a, b), authenticated = decryptCipher(a, iv))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, ct, keystore))
        assertEquals(0, keystore.authenticatedTaken)
    }

    @Test
    fun aLostKeyBesideAnUnconfirmedOneIsUnknown() {
        val auth = aesKey()
        val (iv, ct) = seal(aesKey())
        val keystore = FakeKeystore(keys = mapOf("per-key" to aesKey(), "global" to auth), authKeys = setOf(auth))
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, ct, keystore))
    }

    @Test
    fun aDecryptFailureOtherThanTheTagIsUnknown() {
        val key = aesKey()
        val (iv, ct) = seal(key)
        val keystore = object : ShareProbeKeystore by FakeKeystore(keys = mapOf("per-key" to key)) {
            override fun open(key: SecretKey, iv: ByteArray): OpenedKey =
                OpenedKey.Ready(Cipher.getInstance("AES/GCM/NoPadding"))
        }
        assertEquals(ShareProbe.Unknown, classifyShare(aliases, iv, ct, keystore))
    }
}
