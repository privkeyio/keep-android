package io.privkey.keep.nip55

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.privkey.keep.BiometricHelper
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.service.SigningNotificationManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.storage.PinStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.BuildConfig
import io.privkey.keep.uniffi.Nip55Response
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class Nip55Activity : FragmentActivity() {
    private lateinit var biometricHelper: BiometricHelper
    private var handler: Nip55Handler? = null
    private var storage: AndroidKeystoreStorage? = null
    private var permissionStore: PermissionStore? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var pinStore: PinStore? = null
    private var callerVerificationStore: CallerVerificationStore? = null
    private var request: Nip55Request? = null
    private var requestId: String? = null
    private var callerPackage: String? = null
    private var callerVerified: Boolean = false
    private var callerSignatureHash: String? = null
    private var callerPendingFirstUse: Boolean = false
    private var notificationManager: SigningNotificationManager? = null
    private var intentUri: String? = null
    private var notificationRequestId: String? = null
    private var isNotificationOriginated: Boolean = false

    companion object {
        private const val TAG = "Nip55Activity"
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        biometricHelper = BiometricHelper(this)
        val app = application as? KeepMobileApp
        handler = app?.getNip55Handler()
        storage = app?.getStorage()
        permissionStore = app?.getPermissionStore()
        killSwitchStore = app?.getKillSwitchStore()
        pinStore = app?.getPinStore()
        notificationManager = app?.getSigningNotificationManager()
        callerVerificationStore = app?.getCallerVerificationStore()
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (killSwitchStore?.isEnabled() == true) finishWithError("signing_disabled")
    }

    private fun handleIntent(intent: Intent) {
        if (killSwitchStore?.isEnabled() == true) return finishWithError("signing_disabled")
        if (pinStore?.requiresAuthentication() == true) return finishWithError("locked")

        identifyCaller(intent)
        if (callerPackage == null) {
            Log.w(TAG, "Rejecting request from unverified caller")
            return finishWithError("unknown_caller")
        }

        requestId = intent.getStringExtra("id")
        intentUri = intent.data?.toString()
        parseAndSetRequest(intent)
        if (request != null) {
            showNotification()
            setupContent()
        }
    }

    private fun identifyCaller(intent: Intent) {
        val verificationStore = callerVerificationStore
        isNotificationOriginated = false

        val nonce = intent.getStringExtra("nip55_nonce")
        if (nonce != null && verificationStore != null) {
            val nonceResult = verificationStore.consumeNonce(nonce)
            if (nonceResult is CallerVerificationStore.NonceResult.Valid) {
                val result = verificationStore.verifyOrTrust(nonceResult.packageName)
                if (result is CallerVerificationStore.VerificationResult.SignatureMismatch) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Signature mismatch for ${nonceResult.packageName}")
                    clearCallerState()
                } else {
                    isNotificationOriginated = true
                    applyVerificationResult(nonceResult.packageName, result)
                }
                return
            }
            if (BuildConfig.DEBUG) Log.w(TAG, "Invalid or expired nonce")
        }

        val directCallerPackage = callingActivity?.packageName
        if (directCallerPackage != null && verificationStore != null) {
            val result = verificationStore.verifyOrTrust(directCallerPackage)
            if (result is CallerVerificationStore.VerificationResult.SignatureMismatch) {
                if (BuildConfig.DEBUG) Log.w(TAG, "Signature mismatch for $directCallerPackage")
                clearCallerState()
            } else {
                applyVerificationResult(directCallerPackage, result)
            }
            return
        }

        clearCallerState()
    }

    private fun applyVerificationResult(packageName: String, result: CallerVerificationStore.VerificationResult) {
        callerPackage = packageName
        callerVerified = result is CallerVerificationStore.VerificationResult.Verified
        callerSignatureHash = result.signatureHash
        callerPendingFirstUse = result is CallerVerificationStore.VerificationResult.FirstUseRequiresApproval
    }

    private fun clearCallerState() {
        callerPackage = null
        callerVerified = false
        callerSignatureHash = null
        callerPendingFirstUse = false
    }

    private fun showNotification() {
        val req = request ?: return
        val uri = intentUri ?: return
        notificationRequestId = notificationManager?.showSigningRequest(
            requestType = req.requestType,
            callerPackage = callerPackage,
            intentUri = uri,
            requestId = requestId
        )
    }

    private fun setupContent() {
        val currentRequest = request ?: return
        val currentCallerPackage = callerPackage
        val currentCallerVerified = callerVerified
        val currentPendingFirstUse = callerPendingFirstUse
        val currentSignatureHash = callerSignatureHash

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ApprovalScreen(
                        request = currentRequest,
                        callerPackage = currentCallerPackage,
                        callerVerified = currentCallerVerified,
                        showFirstUseWarning = currentPendingFirstUse,
                        callerSignatureFingerprint = if (currentPendingFirstUse) currentSignatureHash else null,
                        onApprove = ::handleApprove,
                        onReject = ::handleReject
                    )
                }
            }
        }
    }

    private fun parseAndSetRequest(intent: Intent) {
        val uri = intent.data?.toString() ?: return finishWithError("Invalid request")
        val h = handler ?: return finishWithError("Handler not initialized")

        val parsed = runCatching { h.parseIntentUri(uri) }.getOrNull()
            ?: return finishWithError("Invalid request")

        request = parsed
        if (requestId.isNullOrBlank()) {
            requestId = parsed.id
        }
    }

    private fun handleApprove(duration: PermissionDuration) {
        if (killSwitchStore?.isEnabled() == true) {
            return finishWithError("signing_disabled")
        }
        val req = request ?: return
        val nip55Handler = handler ?: return finishWithError("Handler not initialized")
        val keystoreStorage = storage
        val callerId = callerPackage ?: run {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from unknown caller for ${req.requestType.name}")
            return finishWithError("unknown_caller")
        }
        val store = permissionStore
        val eventKind = req.eventKind()
        val needsBiometric = req.requestType != Nip55RequestType.GET_PUBLIC_KEY

        if (callerPendingFirstUse && callerSignatureHash != null) {
            if (callerVerificationStore != null) {
                callerVerificationStore?.trustPackage(callerId, callerSignatureHash!!)
                callerPendingFirstUse = false
                callerVerified = true
            } else {
                Log.w(TAG, "Trust persistence skipped: verification store unavailable")
            }
        }

        lifecycleScope.launch {
            if (needsBiometric && !authenticateForRequest(keystoreStorage, req)) return@launch

            try {
                store?.grantPermission(callerId, req.requestType, eventKind, duration)

                withContext(Dispatchers.Default) { runCatching { nip55Handler.handleRequest(req, callerId) } }
                    .onSuccess { response ->
                        store?.logOperation(callerId, req.requestType, eventKind, "allow", wasAutomatic = false)
                        finishWithResult(response)
                    }
                    .onFailure { e ->
                        Log.e(TAG, "Request failed: ${e::class.simpleName}")
                        finishWithError(mapExceptionToError(e))
                    }
            } finally {
                keystoreStorage?.clearPendingCipher()
            }
        }
    }

    private suspend fun authenticateForRequest(keystoreStorage: AndroidKeystoreStorage?, req: Nip55Request): Boolean {
        if (keystoreStorage == null) {
            finishWithError("Storage unavailable")
            return false
        }

        val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
            .onFailure { Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
            .getOrNull()

        if (cipher == null) {
            finishWithError(if (keystoreStorage.hasShare()) "Storage error" else "No share stored")
            return false
        }

        val authedCipher = runCatching {
            biometricHelper.authenticateWithCrypto(
                cipher = cipher,
                title = "Approve Request",
                subtitle = req.requestType.displayName()
            )
        }.onFailure { Log.e(TAG, "Biometric authentication failed: ${it::class.simpleName}") }
            .getOrNull()

        if (authedCipher == null) {
            finishWithError("Authentication failed")
            return false
        }

        keystoreStorage.setPendingCipher(authedCipher)
        return true
    }

    private fun mapExceptionToError(e: Throwable): String = when (e) {
        is KeepMobileException.RateLimited -> "rate_limited"
        is KeepMobileException.NotInitialized -> "not_initialized"
        is KeepMobileException.PubkeyMismatch -> "pubkey_mismatch"
        is KeepMobileException.InvalidTimestamp -> "invalid_timestamp"
        else -> "request_failed"
    }

    private fun handleReject(duration: PermissionDuration) {
        val req = request ?: return finishWithError("User rejected")
        val callerId = callerPackage
        val store = permissionStore
        val eventKind = req.eventKind()

        lifecycleScope.launch {
            if (store != null && callerId != null) {
                store.denyPermission(callerId, req.requestType, eventKind, duration)
                store.logOperation(callerId, req.requestType, eventKind, "deny", wasAutomatic = false)
            }
            finishWithError("User rejected")
        }
    }

    private fun finishWithResult(response: Nip55Response) {
        notificationManager?.cancelNotification(notificationRequestId)
        val req = request
        val resultIntent = Intent().apply {
            putExtra("result", response.result)
            putExtra("package", packageName)
            response.event?.let { putExtra("event", it) }
            requestId?.let { putExtra("id", it) }
            if (req?.requestType == Nip55RequestType.GET_PUBLIC_KEY) {
                putExtra("pubkey", response.result)
            }
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    private fun finishWithError(error: String) {
        notificationManager?.cancelNotification(notificationRequestId)
        if (BuildConfig.DEBUG) {
            val idSuffix = requestId?.let { " (requestId=$it)" }.orEmpty()
            Log.e(TAG, "NIP-55 request failed: $error$idSuffix")
        }
        val resultIntent = Intent().apply {
            putExtra("error", GENERIC_ERROR_MESSAGE)
        }
        setResult(RESULT_CANCELED, resultIntent)
        finish()
    }
}
