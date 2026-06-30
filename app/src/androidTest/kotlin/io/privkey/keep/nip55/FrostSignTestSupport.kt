package io.privkey.keep.nip55

import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import org.junit.Assert.assertEquals
import org.junit.AssumptionViolatedException

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
        val cipher = storage.getCipherForEncryption()
        storage.setRequestIdContext(requestId)
        storage.setPendingCipher(requestId, cipher)
        try {
            mobile.importShare(exportData, FrostSignFixture.PASSPHRASE, "test")
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
        }
    }

    fun initializeWithDecryptContext(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        requestId: String,
    ) {
        val cipher = requireNotNull(storage.getCipherForDecryption()) { "decryption cipher must not be null" }
        storage.setPendingCipher(requestId, cipher)
        storage.setRequestIdContext(requestId)
        try {
            mobile.initialize(listOf(FrostSignFixture.RELAY))
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
