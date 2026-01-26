package io.privkey.keep

import android.Manifest
import android.content.pm.PackageManager
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
import javax.crypto.Cipher

sealed class ImportState {
    object Idle : ImportState()
    object Scanning : ImportState()
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
            onValueChange = { shareData = it },
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
            onValueChange = { passphrase = it },
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
            onValueChange = { shareName = it },
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
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier.weight(1f),
                    enabled = importState !is ImportState.Importing
                ) {
                    Text(if (importState is ImportState.Success) "Done" else "Cancel")
                }
                if (importState !is ImportState.Success) {
                    Button(
                        onClick = {
                            val cipher = onGetCipher()
                            onBiometricAuth(cipher) { authedCipher ->
                                if (authedCipher != null) {
                                    onImport(shareData, passphrase, shareName, authedCipher)
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = shareData.isNotBlank() && passphrase.isNotBlank() && isInputEnabled
                    ) {
                        Text("Import")
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(
    text: String,
    containerColor: androidx.compose.ui.graphics.Color,
    contentColor: androidx.compose.ui.graphics.Color
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Text(
            text = text,
            modifier = Modifier.padding(16.dp),
            color = contentColor
        )
    }
}

@Composable
fun QrScannerScreen(
    onCodeScanned: (String) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (!granted) onDismiss()
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    if (!hasCameraPermission) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Text("Camera permission required")
        }
        return
    }

    Box(modifier = Modifier.fillMaxSize()) {
        var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
        val previewView = remember { PreviewView(context) }
        val scanner = remember { BarcodeScanning.getClient() }
        val executor = remember { Executors.newSingleThreadExecutor() }

        LaunchedEffect(Unit) {
            val future = ProcessCameraProvider.getInstance(context)
            future.addListener({
                cameraProvider = future.get()
            }, ContextCompat.getMainExecutor(context))
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
                if (mediaImage != null) {
                    val image = InputImage.fromMediaImage(
                        mediaImage,
                        imageProxy.imageInfo.rotationDegrees
                    )
                    scanner.process(image)
                        .addOnSuccessListener { barcodes ->
                            for (barcode in barcodes) {
                                if (barcode.valueType == Barcode.TYPE_TEXT) {
                                    barcode.rawValue?.let { value ->
                                        if (value.startsWith("kshare") && value.length <= 8192) {
                                            onCodeScanned(value)
                                        }
                                    }
                                }
                            }
                        }
                        .addOnCompleteListener {
                            imageProxy.close()
                        }
                } else {
                    imageProxy.close()
                }
            }

            try {
                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis
                )
            } catch (e: Exception) {
                onDismiss()
            }

            onDispose {
                provider.unbindAll()
                executor.shutdown()
            }
        }

        AndroidView(
            factory = { previewView },
            modifier = Modifier.fillMaxSize()
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
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
}
