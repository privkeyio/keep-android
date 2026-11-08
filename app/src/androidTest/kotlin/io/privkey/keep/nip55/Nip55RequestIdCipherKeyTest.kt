package io.privkey.keep.nip55

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.R
import java.util.UUID
import javax.crypto.Cipher
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Nip55RequestIdCipherKeyTest {

    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createEmptyComposeRule()

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun aCallerIdEqualToAnotherFlowsKeyLeavesThatFlowsCipherQueued() {
        val app = context.applicationContext as KeepMobileApp
        val storage = app.getStorage() ?: error("storage not initialized")
        val sharedId = "in-flight-${UUID.randomUUID()}"
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        storage.setPendingCipher(sharedId, cipher)
        try {
            val intent = Intent(context, Nip55Activity::class.java).apply {
                action = Intent.ACTION_VIEW
                data = Uri.parse("nostrsigner:")
                putExtra("type", "get_public_key")
                putExtra("id", sharedId)
            }
            ActivityScenario.launchActivityForResult<Nip55Activity>(intent).use { scenario ->
                val approve = context.getString(R.string.connections_nip55_approve)
                compose.waitUntil(10_000) {
                    compose.onAllNodes(hasText(approve)).fetchSemanticsNodes().isNotEmpty()
                }
                compose.onNodeWithText(approve).performClick()
                scenario.result
            }
            assertSame(cipher, storage.consumePendingCipher(sharedId))
        } finally {
            storage.clearPendingCipher(sharedId)
        }
    }
}
