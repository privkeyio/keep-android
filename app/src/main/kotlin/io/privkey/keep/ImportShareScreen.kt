package io.privkey.keep

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.AspectRatioStrategy
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.Arrays
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher

private const val MAX_SHARE_LENGTH = 8192

internal fun isValidKshareFormat(data: String): Boolean {
    if (data.length > MAX_SHARE_LENGTH) return false
    if (!data.startsWith("kshare1")) return false
    val payload = data.removePrefix("kshare1")
    return payload.isNotEmpty() && payload.all { io.privkey.keep.uniffi.isValidBech32Char(it.toString()) }
}

sealed class ImportState {
    object Idle : ImportState()
    object Importing : ImportState()
    data class Error(val message: String) : ImportState()
    data class Success(val name: String) : ImportState()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportShareScreen(
    onImport: (data: String, passphrase: String, name: String, cipher: Cipher) -> Unit,
    onGetCipher: () -> Cipher,
    onBiometricAuth: (Cipher, (Cipher?) -> Unit) -> Unit,
    onDismiss: () -> Unit,
    importState: ImportState
) {
    val context = LocalContext.current
    val shareData = remember { SecureShareData(MAX_SHARE_LENGTH) }
    var shareDataDisplay by remember { mutableStateOf("") }
    val passphrase = remember { SecurePassphrase() }
    var passphraseDisplay by remember { mutableStateOf("") }
    var shareName by remember { mutableStateOf("Mobile Share") }
    var showScanner by remember { mutableStateOf(false) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error

    DisposableEffect(context) {
        setSecureScreen(context, true)
        onDispose { setSecureScreen(context, false) }
    }

    LaunchedEffect(importState) {
        if (importState is ImportState.Success) {
            shareData.clear()
            shareDataDisplay = ""
            passphrase.clear()
            passphraseDisplay = ""
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            shareData.clear()
            shareDataDisplay = ""
            passphrase.clear()
            passphraseDisplay = ""
        }
    }

    if (showScanner) {
        QrScannerScreen(
            onCodeScanned = { code ->
                shareData.update(code)
                shareDataDisplay = code
                showScanner = false
            },
            onDismiss = { showScanner = false }
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Import FROST Share",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        ImportShareInputFields(
            shareDataDisplay = shareDataDisplay,
            onShareDataChange = { value ->
                if (value.length <= MAX_SHARE_LENGTH) {
                    shareData.update(value)
                    shareDataDisplay = value
                }
            },
            passphraseDisplay = passphraseDisplay,
            onPassphraseChange = { value ->
                passphrase.update(value)
                passphraseDisplay = value
            },
            shareName = shareName,
            onShareNameChange = { if (it.length <= 64) shareName = it },
            onScanClick = { showScanner = true },
            isInputEnabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(24.dp))

        ImportStatusAndActions(
            importState = importState,
            canImport = shareData.isNotBlank() && passphrase.length > 0 && isInputEnabled,
            onDismiss = onDismiss,
            onImportClick = { onError ->
                val passphraseChars = passphrase.toCharArray()
                fun clearChars() = Arrays.fill(passphraseChars, '\u0000')
                try {
                    val cipher = onGetCipher()
                    onBiometricAuth(cipher) { authedCipher ->
                        try {
                            if (authedCipher != null) {
                                onImport(shareData.valueUnsafe(), String(passphraseChars), shareName, authedCipher)
                            }
                        } finally {
                            clearChars()
                        }
                    }
                } catch (e: KeyPermanentlyInvalidatedException) {
                    clearChars()
                    if (BuildConfig.DEBUG) Log.e("ImportShare", "Biometric key invalidated during cipher init: ${e::class.simpleName}")
                    onError("Biometric key invalidated. Please re-enroll biometrics.")
                } catch (e: Exception) {
                    clearChars()
                    if (BuildConfig.DEBUG) Log.e("ImportShare", "Failed to initialize cipher for biometric auth: ${e::class.simpleName}")
                    onError("Failed to initialize encryption")
                }
            }
        )
    }
}

@Composable
private fun ImportShareInputFields(
    shareDataDisplay: String,
    onShareDataChange: (String) -> Unit,
    passphraseDisplay: String,
    onPassphraseChange: (String) -> Unit,
    shareName: String,
    onShareNameChange: (String) -> Unit,
    onScanClick: () -> Unit,
    isInputEnabled: Boolean
) {
    OutlinedTextField(
        value = shareDataDisplay,
        onValueChange = onShareDataChange,
        label = { Text("Share Data") },
        placeholder = { Text("kshare1q...") },
        modifier = Modifier.fillMaxWidth(),
        minLines = 3,
        maxLines = 5,
        enabled = isInputEnabled
    )

    Spacer(modifier = Modifier.height(8.dp))

    OutlinedButton(
        onClick = onScanClick,
        modifier = Modifier.fillMaxWidth(),
        enabled = isInputEnabled
    ) {
        Text("Scan QR Code")
    }

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedTextField(
        value = passphraseDisplay,
        onValueChange = onPassphraseChange,
        label = { Text("Passphrase") },
        modifier = Modifier.fillMaxWidth(),
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        enabled = isInputEnabled
    )

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedTextField(
        value = shareName,
        onValueChange = onShareNameChange,
        label = { Text("Share Name") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        enabled = isInputEnabled
    )
}

@Composable
private fun ImportStatusAndActions(
    importState: ImportState,
    canImport: Boolean,
    onDismiss: () -> Unit,
    onImportClick: (onError: (String) -> Unit) -> Unit
) {
    if (importState is ImportState.Error) {
        StatusCard(
            text = importState.message,
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer
        )
        Spacer(modifier = Modifier.height(16.dp))
    }

    if (importState is ImportState.Success) {
        StatusCard(
            text = "Share '${importState.name}' imported successfully",
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer
        )
        Spacer(modifier = Modifier.height(16.dp))
    }

    if (importState is ImportState.Importing) {
        CircularProgressIndicator()
    } else {
        ImportButtons(
            importState = importState,
            canImport = canImport,
            onDismiss = onDismiss,
            onImportClick = onImportClick
        )
    }
}

@Composable
internal fun ImportButtons(
    importState: ImportState,
    canImport: Boolean,
    onDismiss: () -> Unit,
    onImportClick: (onError: (String) -> Unit) -> Unit
) {
    var cipherError by remember { mutableStateOf<String?>(null) }

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            OutlinedButton(
                onClick = onDismiss,
                modifier = Modifier.weight(1f)
            ) {
                Text(if (importState is ImportState.Success) "Done" else "Cancel")
            }
            if (importState !is ImportState.Success) {
                Button(
                    onClick = { onImportClick { cipherError = it } },
                    modifier = Modifier.weight(1f),
                    enabled = canImport
                ) {
                    Text("Import")
                }
            }
        }

        cipherError?.let { error ->
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }
    }
}

@Composable
internal fun StatusCard(
    text: String,
    containerColor: Color,
    contentColor: Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Text(text = text, modifier = Modifier.padding(16.dp), color = contentColor)
    }
}

@Composable
fun QrScannerScreen(
    onCodeScanned: (String) -> Unit,
    onDismiss: () -> Unit,
    validator: (String) -> Boolean = ::isValidKshareFormat,
    title: String = "Scan FROST Share QR Code"
) {
    val context = LocalContext.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasCameraPermission = granted
        if (!granted) onDismiss()
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    if (!hasCameraPermission) {
        Box(modifier = Modifier.fillMaxSize().statusBarsPadding(), contentAlignment = Alignment.Center) {
            Text("Camera permission required")
        }
        return
    }

    CameraPreview(context, onCodeScanned, onDismiss, validator, title)
}

@Composable
private fun CameraPreview(
    context: Context,
    onCodeScanned: (String) -> Unit,
    onDismiss: () -> Unit,
    validator: (String) -> Boolean,
    title: String
) {
    val lifecycleOwner = LocalLifecycleOwner.current

    Box(modifier = Modifier.fillMaxSize()) {
        var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
        val previewView = remember { PreviewView(context) }
        val scanner = remember { BarcodeScanning.getClient() }
        val executor = remember { Executors.newSingleThreadExecutor() }
        val scanned = remember { AtomicBoolean(false) }
        val closed = remember { AtomicBoolean(false) }

        fun cleanupResources() {
            if (closed.compareAndSet(false, true)) {
                runCatching { scanner.close() }
                runCatching { executor.shutdownNow() }
            }
        }

        DisposableEffect(Unit) {
            onDispose { cleanupResources() }
        }

        LaunchedEffect(Unit) {
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener({ cameraProvider = future.get() }, ContextCompat.getMainExecutor(context))
        }

        DisposableEffect(cameraProvider) {
            val provider = cameraProvider ?: return@DisposableEffect onDispose {}

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            val resolutionSelector = ResolutionSelector.Builder()
                .setAspectRatioStrategy(AspectRatioStrategy.RATIO_16_9_FALLBACK_AUTO_STRATEGY)
                .build()
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(resolutionSelector)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()

            analysis.setAnalyzer(executor) { imageProxy ->
                val mediaImage = imageProxy.image
                if (mediaImage == null) {
                    imageProxy.close()
                    return@setAnalyzer
                }
                val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
                scanner.process(image)
                    .addOnSuccessListener { barcodes ->
                        if (scanned.get()) return@addOnSuccessListener
                        barcodes.firstOrNull { it.valueType == Barcode.TYPE_TEXT }
                            ?.rawValue
                            ?.takeIf { validator(it) }
                            ?.let {
                                if (scanned.compareAndSet(false, true)) {
                                    onCodeScanned(it)
                                }
                            }
                    }
                    .addOnCompleteListener { imageProxy.close() }
            }

            try {
                provider.unbindAll()
                provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            } catch (e: Exception) {
                cleanupResources()
                onDismiss()
            }

            onDispose {
                provider.unbindAll()
                cleanupResources()
            }
        }

        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())

        ScannerOverlay(title, onDismiss)
    }
}

@Composable
private fun ScannerOverlay(title: String, onDismiss: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().statusBarsPadding().padding(24.dp),
        verticalArrangement = Arrangement.SpaceBetween,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurface
        )

        OutlinedButton(onClick = onDismiss) {
            Text("Cancel")
        }
    }
}
