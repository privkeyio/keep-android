package io.privkey.keep.nip55

import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import org.junit.Assert.assertEquals
import org.junit.AssumptionViolatedException
import javax.crypto.Cipher

object FrostSignTestSupport {

    fun noAuthStorage(): AndroidKeystoreStorage {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return AndroidKeystoreStorage(context, requireUserAuth = false)
    }

    fun importShareNoAuth(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        exportData: String,
        requestId: String,
    ) {
        val existing = mobile.getShareInfo()
        if (existing != null) {
            if (existing.groupPubkey == FrostSignFixture.EXPECTED_GROUP_PUBKEY) return
            throw AssumptionViolatedException(
                "Device holds an unexpected share (group=${existing.groupPubkey}); refusing to " +
                    "delete it. Manually clear the device before running this test."
            )
        }
        withCipher(storage, requestId, storage.getCipherForEncryption()) {
            mobile.importShare(exportData, FrostSignFixture.PASSPHRASE, "test")
        }
    }

    fun initializeWithDecryptContext(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        requestId: String,
    ) {
        withCipher(storage, requestId, requireNotNull(storage.getCipherForDecryption()) { "decryption cipher must not be null" }) {
            mobile.initialize(listOf(FrostSignFixture.RELAY))
        }
    }

    /** Runs [block] with [cipher] staged as the keystore context the core reads for [requestId]. */
    fun <T> withCipher(storage: AndroidKeystoreStorage, requestId: String, cipher: Cipher, block: () -> T): T {
        storage.setPendingCipher(requestId, cipher)
        storage.setRequestIdContext(requestId)
        try {
            return block()
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    // Fails loudly when the device holds a share from a different group than the
    // committed fixture (e.g. left over from a prior run or another test), instead
    // of letting the round fail later as an opaque peer/timeout error.
    fun assertFixtureShareLoaded(mobile: KeepMobile): String {
        val groupPubkey = requireNotNull(mobile.getShareInfo()) { "ShareInfo must not be null" }.groupPubkey
        assertEquals(
            "Loaded share must match the committed fixture group pubkey",
            FrostSignFixture.EXPECTED_GROUP_PUBKEY,
            groupPubkey
        )
        return groupPubkey
    }
}
