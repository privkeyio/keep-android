package io.privkey.keep

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Log
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
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
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher

private const val BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
private const val MAX_SHARE_LENGTH = 8192

internal fun isValidKshareFormat(data: String): Boolean {
    if (data.length > MAX_SHARE_LENGTH) return false
    if (!data.startsWith("kshare1")) return false
    val payload = data.removePrefix("kshare1")
    return payload.isNotEmpty() && payload.all { it in BECH32_CHARSET }
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
    var shareData by remember { mutableStateOf("") }
    var passphrase by remember { mutableStateOf("") }
    var shareName by remember { mutableStateOf("Mobile Share") }
    var showScanner by remember { mutableStateOf(false) }

    val isInputEnabled = importState is ImportState.Idle || importState is ImportState.Error

    LaunchedEffect(importState) {
        if (importState is ImportState.Success) {
            shareData = ""
            passphrase = ""
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            shareData = ""
            passphrase = ""
        }
    }

    if (showScanner) {
        QrScannerScreen(
            onCodeScanned = { code ->
                shareData = code
                showScanner = false
            },
            onDismiss = { showScanner = false }
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Import FROST Share",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(24.dp))

        OutlinedTextField(
            value = shareData,
            onValueChange = { if (it.length <= MAX_SHARE_LENGTH) shareData = it },
            label = { Text("Share Data") },
            placeholder = { Text("kshare1q...") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 5,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = { showScanner = true },
            modifier = Modifier.fillMaxWidth(),
            enabled = isInputEnabled
        ) {
            Text("Scan QR Code")
        }

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = passphrase,
            onValueChange = { if (it.length <= 256) passphrase = it },
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
            onValueChange = { if (it.length <= 64) shareName = it },
            label = { Text("Share Name") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            enabled = isInputEnabled
        )

        Spacer(modifier = Modifier.height(24.dp))

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
                canImport = shareData.isNotBlank() && passphrase.isNotBlank() && isInputEnabled,
                onDismiss = onDismiss,
                onImportClick = {
                    try {
                        val cipher = onGetCipher()
                        onBiometricAuth(cipher) { authedCipher ->
                            if (authedCipher != null) {
                                onImport(shareData, passphrase, shareName, authedCipher)
                            }
                        }
                        null
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        Log.e("ImportShare", "Biometric key invalidated during cipher init", e)
                        "Biometric key invalidated. Please re-enroll biometrics."
                    } catch (e: Exception) {
                        Log.e("ImportShare", "Failed to initialize cipher for biometric auth", e)
                        "Failed to initialize encryption"
                    }
                }
            )
        }
    }
}

@Composable
private fun ImportButtons(
    importState: ImportState,
    canImport: Boolean,
    onDismiss: () -> Unit,
    onImportClick: () -> String?
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
                    onClick = {
                        cipherError = onImportClick()
                    },
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
private fun StatusCard(
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
    onDismiss: () -> Unit
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
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Camera permission required")
        }
        return
    }

    CameraPreview(context, onCodeScanned, onDismiss)
}

@Composable
private fun CameraPreview(
    context: Context,
    onCodeScanned: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val lifecycleOwner = LocalLifecycleOwner.current

    Box(modifier = Modifier.fillMaxSize()) {
        var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
        val previewView = remember { PreviewView(context) }
        val scanner = remember { BarcodeScanning.getClient() }
        val executor = remember { Executors.newSingleThreadExecutor() }
        val scanned = remember { AtomicBoolean(false) }

        val closed = remember { AtomicBoolean(false) }

        DisposableEffect(Unit) {
            onDispose {
                if (closed.compareAndSet(false, true)) {
                    try { scanner.close() } catch (_: Exception) {}
                    try { executor.shutdown() } catch (_: Exception) {}
                }
            }
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

            val analysis = ImageAnalysis.Builder()
                .setTargetResolution(Size(1280, 720))
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
                            ?.takeIf { isValidKshareFormat(it) }
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
                scanner.close()
                executor.shutdown()
                onDismiss()
            }

            onDispose {
                provider.unbindAll()
                scanner.close()
                executor.shutdown()
            }
        }

        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())

        ScannerOverlay(onDismiss)
    }
}

@Composable
private fun ScannerOverlay(onDismiss: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.SpaceBetween,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Scan FROST Share QR Code",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onSurface
        )

        OutlinedButton(onClick = onDismiss) {
            Text("Cancel")
        }
    }
}
