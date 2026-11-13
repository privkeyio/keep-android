package io.privkey.keep

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.ui.theme.KeepAndroidTheme
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class QrBitmapWipeTest {

    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun qrDisplaysDrawSwapFramesAndLeaveWithoutTouchingAWipedBitmap() {
        var shown by mutableStateOf(true)
        var single by mutableStateOf("single-a")
        var frames by mutableStateOf(listOf("frame-a1", "frame-a2"))
        compose.setContent {
            KeepAndroidTheme {
                if (shown) {
                    QrCodeDisplay(data = single, label = "single-qr")
                    AnimatedQrCodeDisplay(frames = frames, label = "animated-qr", fullData = "full")
                }
            }
        }
        compose.waitUntil(10_000) {
            compose.onAllNodesWithContentDescription("single-qr").fetchSemanticsNodes().isNotEmpty() &&
                compose.onAllNodesWithContentDescription("animated-qr").fetchSemanticsNodes().isNotEmpty()
        }
        single = "single-b"
        frames = listOf("frame-b1", "frame-b2", "frame-b3")
        compose.mainClock.advanceTimeBy(2_000)
        compose.waitForIdle()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithContentDescription("single-qr").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithContentDescription("animated-qr").assertExists()
        shown = false
        compose.waitForIdle()
        compose.onNodeWithContentDescription("single-qr").assertDoesNotExist()
    }

    @Test
    fun aGeneratedQrCodeCanBeErasedBeforeItIsReleased() {
        val bmp = generateQrCode("ncryptsec1qgg9947rlpvqu76pj5ecreduyjvj")
        assertNotNull(bmp)
        bmp!!
        assertTrue("the QR bitmap must be mutable so its pixels can be zeroed", bmp.isMutable)
        val pixels = IntArray(bmp.width * bmp.height)
        bmp.getPixels(pixels, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        assertTrue(pixels.any { it == Color.BLACK })

        bmp.eraseColor(0)
        bmp.getPixels(pixels, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        assertTrue(pixels.all { it == 0 })

        bmp.wipe()
        assertTrue(bmp.isRecycled)
    }
    @Test
    fun wipingTwiceOrWipingAnImmutableBitmapDoesNotThrow() {
        val qr = generateQrCode("x")!!
        qr.wipe()
        qr.wipe()
        assertTrue(qr.isRecycled)

        val immutable = Bitmap.createBitmap(IntArray(4), 2, 2, Bitmap.Config.ARGB_8888)
        assertFalse(immutable.isMutable)
        immutable.wipe()
        assertTrue(immutable.isRecycled)
    }
}
