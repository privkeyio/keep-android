package io.privkey.keep.approver

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.ApproverCallbacks
import io.privkey.keep.uniffi.ApproverEvent
import io.privkey.keep.uniffi.ApproverHandler
import io.privkey.keep.uniffi.ApproverStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * End-to-end: the app's own approver, paired with a gateway that never answers over a
 * public relay, is stopped by the core when a certificate pin changes and started again
 * by the app. Manual-only, since it needs the relay: run it with `-e approverManual 1`.
 * The test key needs no biometric, unlike the app's approver key, and is deleted after.
 */
@RunWith(AndroidJUnit4::class)
class ApproverPinChangeE2ETest {

    private val args = InstrumentationRegistry.getArguments()
    private val app = InstrumentationRegistry.getInstrumentation()
        .targetContext.applicationContext as KeepMobileApp

    @Test
    fun aPinChangeStopsTheApproverAndTheAppStartsItAgain() {
        assumeTrue(args.getString("approverManual") == "1")
        val relay = args.getString("approverRelay") ?: "wss://nos.lol"
        val controller = checkNotNull(app.getApproverController()) { "no approver" }
        val handler = ApproverController::class.java.getDeclaredField("handler")
            .apply { isAccessible = true }
            .get(controller) as ApproverHandler
        val before = handler.status()
        assumeTrue("a real pairing is on this device", !before.paired && !before.pairing)
        // The run clears every pin, so the device's own are put back after it.
        val mobile = checkNotNull(app.getKeepMobile()) { "Keep not initialized" }
        val devicePins = mobile.getCertificatePins()

        val secret = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        val uri = "keep-approver:v1?gateway=$GATEWAY&secret=$secret&relay=$relay"
        try {
            val start = handler.beginPairing(uri, testKey(handler.pairingAttestationChallenge(uri)), "pin-e2e")
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(keyStore().getKey(ALIAS, null) as PrivateKey)
                update(start.digest)
                sign()
            }
            val attestation = keyStore().getCertificateChain(ALIAS).map { it.encoded }
            handler.finishPairing(signature, attestation, NoCallbacks)
            assertTrue("serving the pairing", awaitStatus(handler) { it.pairing && it.running })

            restartsAfter(handler, "stage") { assertTrue(app.stageCertificatePin(PIN_HOST, PIN_HASH)) }
            restartsAfter(handler, "stage again") { assertTrue(app.stageCertificatePin(PIN_HOST, PIN_HASH_2)) }
            restartsAfter(handler, "remove") { assertTrue(app.removeCertificatePin(PIN_HOST, PIN_HASH)?.pinRemoved == true) }
            restartsAfter(handler, "clear host") { app.clearCertificatePin(PIN_HOST) }
            restartsAfter(handler, "clear all") { app.clearAllCertificatePins() }
            assertFalse(handler.status().paired)
        } finally {
            runCatching { handler.forget() }
            mobile.clearCertificatePins()
            devicePins.forEach { mobile.stageCertificatePin(it.hostname, it.spkiHash) }
            runCatching { controller.startIfPaired() }
            runCatching { keyStore().deleteEntry(ALIAS) }
        }
        assertFalse(handler.status().running)
        assertEquals(devicePins, mobile.getCertificatePins())
    }

    private fun restartsAfter(handler: ApproverHandler, change: String, action: () -> Unit) {
        // An alert stands until the owner acknowledges it, and the same one is not raised twice.
        handler.status().alerts.maxOfOrNull { it.seq }?.let(handler::acknowledgeAlerts)
        action()
        assertTrue(
            "the core stopped the approver after $change",
            awaitStatus(handler) { s -> s.alerts.any { it.message == CERT_PIN_STOP } },
        )
        assertTrue("the app started the approver again after $change", awaitStatus(handler) { it.running && it.pairing })
    }

    private fun awaitStatus(handler: ApproverHandler, check: (ApproverStatus) -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + 45_000
        while (System.currentTimeMillis() < deadline) {
            if (check(handler.status())) return true
            Thread.sleep(200)
        }
        return check(handler.status())
    }

    private fun testKey(challenge: ByteArray): ByteArray {
        keyStore().deleteEntry(ALIAS)
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()
        val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
        val w = (pair.public as ECPublicKey).w
        return ApproverKey.compress(w.affineX, w.affineY)
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private object NoCallbacks : ApproverCallbacks {
        override fun onEvent(event: ApproverEvent) = Unit
    }

    private companion object {
        const val ALIAS = "keep_approver_pin_e2e"
        const val GATEWAY = "npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d"
        const val PIN_HOST = "pin-e2e.example.com"
        const val PIN_HASH = "0000000000000000000000000000000000000000000000000000000000000001"
        const val PIN_HASH_2 = "0000000000000000000000000000000000000000000000000000000000000002"
        const val CERT_PIN_STOP = "Approvals stopped because the certificate pins changed. Start the approver again."
    }
}
