package io.privkey.keep.nip46

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NostrConnectLinkTest {

    @Test
    fun keepOpensNostrConnectLinksInItsApprovalScreen() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("nostrconnect://${"a".repeat(64)}?relay=wss%3A%2F%2Frelay.example.com&secret=abcd"))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(context.packageName)
        val handlers = context.packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        assertEquals(listOf(NostrConnectActivity::class.java.name), handlers.map { it.activityInfo.name })
    }
}
