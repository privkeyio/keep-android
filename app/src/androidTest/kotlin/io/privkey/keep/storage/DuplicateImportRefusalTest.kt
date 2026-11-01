package io.privkey.keep.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.importFailureMessage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.ShareInfo
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * An import over a stored key is refused by the core, and the app names the refusal
 * instead of asking the owner to try again.
 */
@RunWith(AndroidJUnit4::class)
class DuplicateImportRefusalTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableSetOf<String>()

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
    }

    @After
    fun teardown() {
        created.forEach { group ->
            runCatching { mobile.deleteShareByKey(group) }
            context.deleteSharedPreferences(storage.sharePrefsNameFor(group))
        }
        context.deleteSharedPreferences(MULTI_PREFS)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun stored(call: () -> ShareInfo): ShareInfo {
        val requestId = "dup-import-test-${System.nanoTime()}"
        storage.setPendingCipher(requestId, storage.getCipherForEncryption())
        storage.setRequestIdContext(requestId)
        try {
            return call().also { created += it.groupPubkey }
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    private fun <E : KeepMobileException> refusal(type: Class<E>, call: () -> ShareInfo): Int =
        importFailureMessage(assertThrows(type) { stored(call) })

    @Test
    fun aStoredKeyAgainIsNamedAsAlreadyStored() {
        val mnemonic = mobile.generateMnemonic(12u)
        stored { mobile.createAccountFromMnemonic(mnemonic.copyOf(), "", "dup-import-test") }

        assertEquals(
            R.string.account_import_already_stored,
            refusal(KeepMobileException.KeyAlreadyStored::class.java) { mobile.createAccountFromMnemonic(mnemonic.copyOf(), "", "dup-import-test") }
        )
    }

    @Test
    fun anotherShareOfTheGroupIsNamedAsSuch() {
        val shares = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dup-import-test", PASSPHRASE).shares
        stored { mobile.importShare(shares[0].exportData, PASSPHRASE, "dup-import-test") }

        assertEquals(
            R.string.account_import_other_share_stored,
            refusal(KeepMobileException.GroupShareAlreadyStored::class.java) { mobile.importShare(shares[1].exportData, PASSPHRASE, "dup-import-test") }
        )
    }

    @Test
    fun theSameShareAgainIsNamedAsAlreadyStored() {
        val shares = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "dup-import-test", PASSPHRASE).shares
        stored { mobile.importShare(shares[0].exportData, PASSPHRASE, "dup-import-test") }

        assertEquals(
            R.string.account_import_share_stored,
            refusal(KeepMobileException.ShareAlreadyStored::class.java) { mobile.importShare(shares[0].exportData, PASSPHRASE, "dup-import-test") }
        )
    }

    private companion object {
        const val SUFFIX = "_dup_import_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val MULTI_PREFS = "keep_multi_share_prefs$SUFFIX"
        const val PASSPHRASE = "dup-import-test-passphrase"
    }
}
