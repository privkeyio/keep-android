package io.privkey.keep.nip55

import androidx.test.core.app.ApplicationProvider
import org.junit.rules.ExternalResource

/**
 * The audit anchor and tamper flag live in the app's prefs, not in the database, and
 * every audit write through an in-memory database moves them to that database's chain.
 * Each test starts from a reset anchor, and what the device's own chain had is put back
 * afterwards, whether the test passed or not, so no class depends on the ones before it.
 */
class AuditAnchorIsolation : ExternalResource() {
    private var saved: AuditAnchorState? = null

    override fun before() {
        Nip55Database.getInstance(ApplicationProvider.getApplicationContext())
        saved = Nip55Database.readAuditAnchorState()
        Nip55Database.resetAuditAnchor()
    }

    override fun after() {
        val state = saved ?: return
        Nip55Database.resetAuditAnchor()
        state.anchor?.let(Nip55Database::setAuditAnchor)
        if (state.tamperDetected) Nip55Database.setAuditTamperDetected()
        if (state.clearPending) Nip55Database.setAuditClearPending()
    }
}
