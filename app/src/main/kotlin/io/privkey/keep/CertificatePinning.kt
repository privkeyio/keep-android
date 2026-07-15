package io.privkey.keep

import io.privkey.keep.uniffi.KeepMobile

data class CertificatePin(
    val hostname: String,
    val spkiHash: String
)

/**
 * Outcome of retiring a single pin, mirroring the keep-mobile `CertPinRemovalResult`.
 * [hostNowUnpinned] is true when the host has no pins left, so the next connection
 * trusts-on-first-use and re-pins whatever certificate is presented.
 */
data class CertPinRemoval(
    val pinRemoved: Boolean,
    val hostNowUnpinned: Boolean
)

private const val CERT_PIN_TAG = "CertificatePinning"

private fun Any.readBoolProperty(name: String): Boolean {
    val getter = "get" + name.replaceFirstChar { it.uppercase() }
    javaClass.methods.firstOrNull { it.name == getter && it.parameterCount == 0 }
        ?.let { return it.invoke(this) as Boolean }
    return javaClass.getField(name).getBoolean(this)
}

fun KeepMobile.getCertificatePinsCompat(): List<CertificatePin> = runCatching {
    val method = javaClass.methods.firstOrNull { it.name == "getCertificatePins" }
    if (method == null) {
        android.util.Log.w("CertificatePinning", "getCertificatePins method not found via reflection, pinning disabled")
        return emptyList()
    }
    val result = method.invoke(this) as? List<*> ?: return emptyList()
    result.filterNotNull().mapNotNull { pin ->
        val cls = pin::class.java
        val hostname = cls.getField("hostname").get(pin) as? String ?: return@mapNotNull null
        val spkiHash = cls.getField("spkiHash").get(pin) as? String ?: return@mapNotNull null
        CertificatePin(hostname, spkiHash)
    }
}.getOrDefault(emptyList())

/**
 * Stage an additional (backup) SPKI pin for [hostname] alongside its current pins,
 * so a relay certificate rotation verifies against either during the overlap
 * (RFC 7469). Returns false if the method is unavailable or the call fails.
 */
fun KeepMobile.stageCertificatePinCompat(hostname: String, spkiHash: String): Boolean = runCatching {
    val method = javaClass.methods.firstOrNull {
        it.name == "stageCertificatePin" && it.parameterCount == 2
    }
    if (method == null) {
        android.util.Log.w(CERT_PIN_TAG, "stageCertificatePin method not found via reflection")
        return false
    }
    method.invoke(this, hostname, spkiHash)
    true
}.getOrDefault(false)

/**
 * Retire a single [spkiHash] from [hostname], leaving the host's other pins active
 * (unlike clearing the whole host). Returns null if the method is unavailable or
 * the call fails; otherwise reports whether a pin was removed and whether the host
 * is now fully unpinned.
 */
fun KeepMobile.removeCertificatePinCompat(hostname: String, spkiHash: String): CertPinRemoval? = runCatching {
    val method = javaClass.methods.firstOrNull {
        it.name == "removeCertificatePin" && it.parameterCount == 2
    }
    if (method == null) {
        android.util.Log.w(CERT_PIN_TAG, "removeCertificatePin method not found via reflection")
        return null
    }
    val result = method.invoke(this, hostname, spkiHash) ?: return null
    CertPinRemoval(
        pinRemoved = result.readBoolProperty("pinRemoved"),
        hostNowUnpinned = result.readBoolProperty("hostNowUnpinned")
    )
}.getOrNull()
