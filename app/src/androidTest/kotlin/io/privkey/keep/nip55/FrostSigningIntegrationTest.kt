package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FrostSigningIntegrationTest {

    private var app: KeepMobileApp? = null
    private var handler: Nip55Handler? = null

    @Before
    fun setup() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        app = context.applicationContext as? KeepMobileApp
        ensureShareExists()
    }

    private fun ensureShareExists() {
        val mobile = app?.getKeepMobile() ?: return
        val storage = app?.getStorage() ?: return
        if (storage.hasShare()) return

        val result = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "test", "test")
        val exportData = result.shares.first().exportData
        mobile.importShare(exportData, "test", "test")
    }

    @Test
    fun appInitialized_keepMobileExists() {
        assertNotNull("KeepMobileApp should be available", app)
        assertNotNull("KeepMobile instance should exist", app!!.getKeepMobile())
        assertNull("No init error expected", app!!.getInitError())
    }

    @Test
    fun nip55Handler_isAvailable() {
        assertNotNull("Nip55Handler should be initialized", app!!.getNip55Handler())
    }

    @Test
    fun storage_hasShareLoaded() {
        val storage = app!!.getStorage()
        assertNotNull("Storage should be available", storage)
        assertTrue("Share should be stored after import", storage!!.hasShare())
    }

    @Test
    fun shareMetadata_isValid() {
        val storage = app!!.getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull("Share metadata should be readable", metadata)

        assertTrue("Identifier should be positive", metadata!!.identifier > 0u.toUShort())
        assertTrue("Threshold should be >= 2", metadata.threshold >= 2u.toUShort())
        assertTrue("Total shares should be >= threshold", metadata.totalShares >= metadata.threshold)
        assertTrue("Group pubkey should not be empty", metadata.groupPubkey.isNotEmpty())
    }

    @Test
    fun shareMetadata_hasExpectedThresholdAndTotal() {
        val storage = app!!.getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull("Share metadata should be present", metadata)

        assertEquals(
            "FROST threshold should be 2",
            2u.toUShort(),
            metadata!!.threshold
        )
        assertEquals(
            "FROST totalShares should be 2",
            2u.toUShort(),
            metadata.totalShares
        )
    }

    @Test
    fun shareMetadata_groupPubkey_is32Bytes() {
        val storage = app!!.getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull(metadata)
        assertEquals(
            "Group pubkey should be 32 bytes (secp256k1 x-only)",
            32,
            metadata!!.groupPubkey.size
        )
    }

    @Test
    fun shareMetadata_groupPubkey_asHex_is64Chars() {
        val storage = app!!.getStorage()
        val metadata = storage?.getShareMetadata()
        assertNotNull(metadata)
        val hex = metadata!!.groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals("Hex pubkey should be 64 chars", 64, hex.length)
        assertTrue("Hex pubkey should only contain hex chars", hex.matches(Regex("[0-9a-f]+")))
    }

    @Test
    fun nip55Handler_getPublicKey_returnsValidPubkey() {
        val handler = requireNotNull(app!!.getNip55Handler()) { "Nip55Handler must not be null" }
        val mobile = requireNotNull(app!!.getKeepMobile()) { "KeepMobile must not be null" }
        val shareInfo = requireNotNull(mobile.getShareInfo()) { "ShareInfo must not be null" }

        val request = Nip55Request(
            requestType = Nip55RequestType.GET_PUBLIC_KEY,
            content = "",
            pubkey = null,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = "test-frost-pubkey",
            currentUser = null,
            permissions = null
        )

        val response = handler.handleRequest(request, "io.privkey.keep.test")
        assertNotNull("Response should not be null", response)
        assertTrue("Result should be 64-char hex pubkey", response.result.length == 64)
        assertTrue("Result should match share info pubkey", response.result == shareInfo.groupPubkey)
        assertNull("Error should be null", response.error)
    }

    @Test
    fun nip55Handler_getPublicKey_matchesStoredMetadata() {
        val handler = requireNotNull(app!!.getNip55Handler()) { "Nip55Handler must not be null" }
        val storage = requireNotNull(app!!.getStorage()) { "Storage must not be null" }
        val metadata = requireNotNull(storage.getShareMetadata()) { "ShareMetadata must not be null" }

        val request = Nip55Request(
            requestType = Nip55RequestType.GET_PUBLIC_KEY,
            content = "",
            pubkey = null,
            returnType = "signature",
            compressionType = "none",
            callbackUrl = null,
            id = "test-frost-pubkey-match",
            currentUser = null,
            permissions = null
        )

        val response = handler.handleRequest(request, "io.privkey.keep.test")
        val storedPubkey = metadata.groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals(
            "Handler pubkey should match stored metadata pubkey",
            storedPubkey,
            response.result
        )
    }

    @Test
    fun permissionStore_isAvailable() {
        assertNotNull("PermissionStore should be initialized", app!!.getPermissionStore())
    }

    @Test
    fun callerVerificationStore_isAvailable() {
        assertNotNull("CallerVerificationStore should be initialized", app!!.getCallerVerificationStore())
    }

    @Test
    fun killSwitch_isDisabledByDefault() {
        val killSwitchStore = app!!.getKillSwitchStore()
        assertNotNull(killSwitchStore)
        assertFalse("Kill switch should be disabled by default", killSwitchStore!!.isEnabled())
    }

    @Test
    fun securityLevel_isNotNone() {
        val storage = app!!.getStorage()
        assertNotNull(storage)
        val level = storage!!.getSecurityLevel()
        assertNotEquals("Security level should not be 'none'", "none", level)
        assertTrue(
            "Security level should be tee or strongbox",
            level == "tee" || level == "strongbox"
        )
    }
}
