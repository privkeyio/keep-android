package io.privkey.keep

import io.privkey.keep.uniffi.KeepMobile

data class CertificatePin(
    val hostname: String,
    val spkiHash: String
)

fun KeepMobile.getCertificatePinsCompat(): List<CertificatePin> = runCatching {
    val method = javaClass.methods.firstOrNull { it.name == "getCertificatePins" } ?: return emptyList()
    val result = method.invoke(this) as? List<*> ?: return emptyList()
    result.mapNotNull { pin ->
        if (pin == null) return@mapNotNull null
        val cls = pin::class.java
        val hostname = cls.getField("hostname").get(pin) as? String ?: return@mapNotNull null
        val spkiHash = cls.getField("spkiHash").get(pin) as? String ?: return@mapNotNull null
        CertificatePin(hostname, spkiHash)
    }
}.getOrDefault(emptyList())
