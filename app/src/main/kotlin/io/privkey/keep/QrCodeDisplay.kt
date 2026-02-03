package io.privkey.keep

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import io.privkey.keep.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Arrays

private const val MAX_PASSPHRASE_LENGTH = 256
private const val QR_SIZE = 300
private const val FRAME_DURATION_MS = 800
private const val CLIPBOARD_CLEAR_DELAY_MS = 10_000L

internal class SecurePassphrase {
    private var chars: CharArray = CharArray(0)

    val length: Int get() = chars.size

    fun update(newValue: String) {
        if (newValue.length <= MAX_PASSPHRASE_LENGTH) {
            Arrays.fill(chars, '\u0000')
            chars = newValue.toCharArray()
        }
    }

    fun clear() {
        Arrays.fill(chars, '\u0000')
        chars = CharArray(0)
    }

    fun toCharArray(): CharArray = chars.copyOf()

    fun contentEquals(other: SecurePassphrase): Boolean = chars.contentEquals(other.chars)

    fun any(predicate: (Char) -> Boolean): Boolean = chars.any(predicate)
}

internal class SecureShareData(private val maxLength: Int) {
    private var chars: CharArray = CharArray(0)

    val length: Int get() = chars.size

    fun update(newValue: String) {
        if (newValue.length <= maxLength) {
            Arrays.fill(chars, '\u0000')
            chars = newValue.toCharArray()
        }
    }

    fun clear() {
        Arrays.fill(chars, '\u0000')
        chars = CharArray(0)
    }

    fun isNotBlank(): Boolean = chars.isNotEmpty() && chars.any { !it.isWhitespace() }

    override fun toString(): String = String(chars)
}

@Composable
private fun QrDisplayContainer(
    label: String,
    copyData: String,
    onCopied: () -> Unit,
    modifier: Modifier = Modifier,
    extraContent: @Composable (ColumnScope.() -> Unit)? = null,
    qrContent: @Composable BoxScope.() -> Unit
) {
    val context = LocalContext.current

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(QR_SIZE.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(Color.White)
                .clickable {
                    copySensitiveText(context, copyData)
                    onCopied()
                },
            contentAlignment = Alignment.Center,
            content = qrContent
        )

        if (extraContent != null) {
            Spacer(modifier = Modifier.height(8.dp))
            extraContent()
        }

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = label,
            style = MaterialTheme.typography.titleMedium
        )

        Text(
            text = "Tap to copy",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun rememberAnimatedFrameIndex(frameCount: Int): Int {
    val safeCount = frameCount.coerceAtLeast(1)
    val infiniteTransition = rememberInfiniteTransition(label = "qr_frame")
    val frameProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = safeCount.toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = safeCount * FRAME_DURATION_MS,
                easing = LinearEasing
            )
        ),
        label = "frame_index"
    )
    return frameProgress.toInt().coerceIn(0, safeCount - 1)
}

@Composable
fun QrCodeDisplay(
    data: String,
    label: String,
    modifier: Modifier = Modifier,
    onCopied: () -> Unit = {}
) {
    var bitmap by remember { mutableStateOf<Bitmap?>(null) }
    var previousBitmap by remember { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(data) {
        previousBitmap = bitmap
        bitmap = withContext(Dispatchers.Default) { generateQrCode(data) }
        previousBitmap?.recycle()
        previousBitmap = null
    }

    DisposableEffect(Unit) {
        onDispose {
            bitmap?.recycle()
            previousBitmap?.recycle()
        }
    }

    QrDisplayContainer(
        label = label,
        copyData = data,
        onCopied = onCopied,
        modifier = modifier,
        qrContent = {
            val bmp = bitmap
            if (bmp != null) {
                Image(
                    bitmap = bmp.asImageBitmap(),
                    contentDescription = label,
                    modifier = Modifier.size((QR_SIZE - 32).dp)
                )
            } else {
                CircularProgressIndicator()
            }
        }
    )
}

@Composable
fun AnimatedQrCodeDisplay(
    frames: List<String>,
    label: String,
    fullData: String,
    modifier: Modifier = Modifier,
    onCopied: () -> Unit = {}
) {
    var bitmaps by remember { mutableStateOf<List<Bitmap>>(emptyList()) }
    var previousBitmaps by remember { mutableStateOf<List<Bitmap>>(emptyList()) }
    var generationError by remember { mutableStateOf(false) }

    LaunchedEffect(frames) {
        previousBitmaps = bitmaps
        val generated = withContext(Dispatchers.Default) {
            frames.mapNotNull { generateQrCode(it) }
        }
        generationError = generated.size != frames.size
        bitmaps = generated
        previousBitmaps.forEach { it.recycle() }
        previousBitmaps = emptyList()
    }

    DisposableEffect(Unit) {
        onDispose {
            bitmaps.forEach { it.recycle() }
            previousBitmaps.forEach { it.recycle() }
        }
    }

    val currentFrame = rememberAnimatedFrameIndex(bitmaps.size)

    QrDisplayContainer(
        label = label,
        copyData = fullData,
        onCopied = onCopied,
        modifier = modifier,
        extraContent = {
            if (generationError) {
                Text(
                    text = "Some frames failed to generate",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
            if (bitmaps.size > 1) {
                LinearProgressIndicator(
                    progress = (currentFrame + 1).toFloat() / bitmaps.size,
                    modifier = Modifier.width(QR_SIZE.dp)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Frame ${currentFrame + 1} of ${bitmaps.size}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        qrContent = {
            if (bitmaps.isNotEmpty() && currentFrame < bitmaps.size) {
                Image(
                    bitmap = bitmaps[currentFrame].asImageBitmap(),
                    contentDescription = label,
                    modifier = Modifier.size((QR_SIZE - 32).dp)
                )
            } else {
                CircularProgressIndicator()
            }
        }
    )
}

private fun generateQrCode(content: String): Bitmap? {
    return try {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M
        )
        val bitMatrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE, hints)
        val black = Color.Black.toArgb()
        val white = Color.White.toArgb()
        val pixels = IntArray(bitMatrix.width * bitMatrix.height) { i ->
            if (bitMatrix[i % bitMatrix.width, i / bitMatrix.width]) black else white
        }
        Bitmap.createBitmap(pixels, bitMatrix.width, bitMatrix.height, Bitmap.Config.ARGB_8888)
    } catch (e: Exception) {
        if (BuildConfig.DEBUG) {
            android.util.Log.w("QrCodeDisplay", "Failed to generate QR code", e)
        }
        null
    }
}

private object ClipboardClearManager {
    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null
    private var clipboardRef: java.lang.ref.WeakReference<ClipboardManager>? = null

    fun scheduleClear(clipboard: ClipboardManager, delayMs: Long) {
        pendingClear?.let { handler.removeCallbacks(it) }
        clipboardRef = java.lang.ref.WeakReference(clipboard)
        val runnable = Runnable {
            pendingClear = null
            clipboardRef?.get()?.let { cb ->
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    cb.clearPrimaryClip()
                } else {
                    cb.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
            clipboardRef = null
        }
        pendingClear = runnable
        handler.postDelayed(runnable, delayMs)
    }
}

internal fun copySensitiveText(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("share", text)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    clipboard.setPrimaryClip(clip)
    ClipboardClearManager.scheduleClear(clipboard, CLIPBOARD_CLEAR_DELAY_MS)
}

internal fun setSecureScreen(context: Context, secure: Boolean) {
    val activity = context as? Activity ?: return
    if (secure) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    } else {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
