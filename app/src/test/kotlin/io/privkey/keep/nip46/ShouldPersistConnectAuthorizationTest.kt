package io.privkey.keep.nip46

import io.privkey.keep.uniffi.ConnectAuthorization
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Coverage for [shouldPersistConnectAuthorization], the security-critical decision
 * on whether a completed NIP-46 connect is persisted as an authorized client.
 * Only explicit-consent reasons persist; an auto-approved connect must not, so a
 * future core that fires on_connect without a secret/prompt cannot silently grant
 * a client standing authorization.
 */
class ShouldPersistConnectAuthorizationTest {

    @Test
    fun secretMatchedPersists() {
        assertTrue(shouldPersistConnectAuthorization(ConnectAuthorization.SECRET_MATCHED))
    }

    @Test
    fun userApprovedPersists() {
        assertTrue(shouldPersistConnectAuthorization(ConnectAuthorization.USER_APPROVED))
    }

    @Test
    fun autoApprovedDoesNotPersist() {
        assertFalse(shouldPersistConnectAuthorization(ConnectAuthorization.AUTO_APPROVED))
    }
}
