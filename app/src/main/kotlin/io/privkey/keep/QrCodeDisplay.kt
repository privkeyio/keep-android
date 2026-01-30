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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val QR_SIZE = 300
private const val FRAME_DURATION_MS = 800
private const val CLIPBOARD_CLEAR_DELAY_MS = 15_000L

@Composable
private fun QrDisplayContainer(
    modifier: Modifier = Modifier,
    label: String,
    copyData: String,
    onCopied: () -> Unit,
    extraContent: (@Composable ColumnScope.() -> Unit)? = null,
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
    val count = frameCount.coerceAtLeast(1)
    val infiniteTransition = rememberInfiniteTransition(label = "qr_frame")
    val frameProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = count.toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = count * FRAME_DURATION_MS,
                easing = LinearEasing
            )
        ),
        label = "frame_index"
    )
    return frameProgress.toInt().coerceIn(0, (frameCount - 1).coerceAtLeast(0))
}

@Composable
fun QrCodeDisplay(
    data: String,
    label: String,
    modifier: Modifier = Modifier,
    onCopied: () -> Unit = {}
) {
    var bitmap by remember { mutableStateOf<Bitmap?>(null) }

    LaunchedEffect(data) {
        bitmap?.recycle()
        bitmap = withContext(Dispatchers.Default) { generateQrCode(data) }
    }

    DisposableEffect(Unit) {
        onDispose { bitmap?.recycle() }
    }

    QrDisplayContainer(
        modifier = modifier,
        label = label,
        copyData = data,
        onCopied = onCopied,
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
    var generationError by remember { mutableStateOf(false) }

    LaunchedEffect(frames) {
        bitmaps.forEach { it.recycle() }
        val generated = withContext(Dispatchers.Default) {
            frames.mapNotNull { generateQrCode(it) }
        }
        generationError = generated.size != frames.size
        bitmaps = generated
    }

    DisposableEffect(Unit) {
        onDispose { bitmaps.forEach { it.recycle() } }
    }

    val currentFrame = rememberAnimatedFrameIndex(bitmaps.size)

    QrDisplayContainer(
        modifier = modifier,
        label = label,
        copyData = fullData,
        onCopied = onCopied,
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
        val writer = QRCodeWriter()
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M
        )
        val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE, hints)
        val width = bitMatrix.width
        val height = bitMatrix.height
        val black = Color.Black.toArgb()
        val white = Color.White.toArgb()
        val pixels = IntArray(width * height) { i ->
            if (bitMatrix[i % width, i / width]) black else white
        }
        Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)
    } catch (_: Exception) {
        null
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

    Handler(Looper.getMainLooper()).postDelayed({
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }, CLIPBOARD_CLEAR_DELAY_MS)
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
