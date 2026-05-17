package io.privkey.keep.nip55

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.privkey.keep.BiometricHelper
import io.privkey.keep.BuildConfig
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
import io.privkey.keep.uniffi.Nip55Response
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URL
import java.security.MessageDigest
import java.util.UUID

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
    private var riskAssessment: RiskAssessment? = null

    companion object {
        private const val TAG = "Nip55Activity"
        private val signingDispatcher = Dispatchers.Default.limitedParallelism(1)
        private const val MAX_CONTENT_LENGTH = 1024 * 1024
        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_EXTRA_LENGTH = 2048
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        val app = application as? KeepMobileApp
        biometricHelper = BiometricHelper(this, app?.getBiometricTimeoutStore())
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
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from unverified caller")
            return finishWithError("unknown_caller")
        }

        val rawId = intent.getStringExtra("id")
        if (rawId != null && rawId.length > MAX_EXTRA_LENGTH) return finishWithError("Invalid request")
        requestId = rawId
        intentUri = intent.data?.let { uri ->
            if (uri.scheme != "nostrsigner") return finishWithError("Invalid URI scheme")
            uri.toString()
        }
        parseAndSetRequest(intent)
        if (request != null) {
            showNotification()
            calculateRiskAndSetupContent()
        }
    }

    private fun calculateRiskAndSetupContent() {
        val req = request ?: return
        val pkg = callerPackage
        val store = permissionStore

        if (pkg == null || store == null) {
            setupContent()
            return
        }

        lifecycleScope.launch {
            riskAssessment = runCatching {
                store.riskAssessor.assess(pkg, req.eventKind(), req.requestType)
            }.getOrElse {
                RiskAssessment(
                    score = 100,
                    factors = listOf(RiskFactor.HIGH_FREQUENCY),
                    requiredAuth = AuthLevel.EXPLICIT
                )
            }
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
                val directCaller = callingActivity?.packageName
                if (directCaller != null && directCaller != nonceResult.packageName) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Nonce package mismatch: nonce=${nonceResult.packageName}, caller=$directCaller")
                    clearCallerState()
                    return
                }
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
        val currentRisk = riskAssessment

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
                        riskAssessment = currentRisk,
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
            ?: (if (uri.startsWith("nostrsigner:")) parseRequestFromExtras(intent, uri) else null)
            ?: return finishWithError("Invalid request")

        request = parsed
        if (BuildConfig.DEBUG) Log.d(TAG, "Parsed request: type=${parsed.requestType.name}, contentLen=${parsed.content.length}, pubkey=${parsed.pubkey?.take(8)}")
        if (requestId.isNullOrBlank()) {
            requestId = parsed.id
        }
    }

    private fun parseRequestFromExtras(intent: Intent, uri: String): Nip55Request? {
        val extras = intent.extras ?: return null
        val type = when (extras.getString("type")) {
            "get_public_key" -> Nip55RequestType.GET_PUBLIC_KEY
            "sign_event" -> Nip55RequestType.SIGN_EVENT
            "nip04_encrypt" -> Nip55RequestType.NIP04_ENCRYPT
            "nip04_decrypt" -> Nip55RequestType.NIP04_DECRYPT
            "nip44_encrypt" -> Nip55RequestType.NIP44_ENCRYPT
            "nip44_decrypt" -> Nip55RequestType.NIP44_DECRYPT
            "decrypt_zap_event" -> Nip55RequestType.DECRYPT_ZAP_EVENT
            else -> return null
        }
        val uriBody = android.net.Uri.parse(uri).schemeSpecificPart?.substringBefore('?') ?: ""
        val content = if (uriBody.isNotEmpty()) {
            uriBody
        } else {
            extras.getString("data") ?: ""
        }
        if (content.length > MAX_CONTENT_LENGTH) return null

        val pubkey = extras.getString("pubKey") ?: extras.getString("pubkey")
        if (pubkey != null && pubkey.length > MAX_PUBKEY_LENGTH) return null

        val returnType = extras.getString("returnType") ?: "signature"
        val compressionType = extras.getString("compressionType") ?: "none"
        val currentUser = extras.getString("current_user")
        val permissions = extras.getString("permissions")

        if (returnType.length > MAX_EXTRA_LENGTH) return null
        if (compressionType.length > MAX_EXTRA_LENGTH) return null
        if (currentUser != null && currentUser.length > MAX_PUBKEY_LENGTH) return null
        if (permissions != null && permissions.length > MAX_EXTRA_LENGTH) return null

        val callbackUrl = extras.getString("callbackUrl")
            ?.takeIf { it.length <= MAX_EXTRA_LENGTH }
            ?.takeIf { runCatching { URL(it) }.getOrNull()?.protocol == "https" }

        return Nip55Request(
            requestType = type,
            content = content,
            pubkey = pubkey,
            returnType = returnType,
            compressionType = compressionType,
            callbackUrl = callbackUrl,
            id = extras.getString("id")?.takeIf { it.length <= MAX_EXTRA_LENGTH },
            currentUser = currentUser,
            permissions = permissions
        )
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
        val riskRequiresAuth = (riskAssessment?.requiredAuth ?: AuthLevel.NONE).atLeast(AuthLevel.PIN)
        val needsBiometric = riskRequiresAuth || req.requestType != Nip55RequestType.GET_PUBLIC_KEY

        lifecycleScope.launch {
            val currentApp = application as? KeepMobileApp

            if (keystoreStorage != null && currentApp != null && req.requestType != Nip55RequestType.GET_PUBLIC_KEY) {
                try {
                    val initError = initializeNodeIfNeeded(keystoreStorage, currentApp)
                    if (initError != null) {
                        finishWithError("Node initialization failed", initError)
                        return@launch
                    }
                } catch (e: BiometricHelper.BiometricNotReadyException) {
                    finishWithError("biometric_not_ready", e.message)
                    return@launch
                }
            }

            if (needsBiometric && !authenticateForRequest(keystoreStorage, req)) return@launch

            try {
                val permResult = runCatching {
                    store?.grantPermission(callerId, req.requestType, eventKind, duration)
                    if (eventKind != null && !isSensitiveKind(eventKind) && duration != PermissionDuration.JUST_THIS_TIME) {
                        store?.grantPermission(callerId, req.requestType, null, duration)
                    }
                    if (duration == PermissionDuration.FOREVER && store != null) {
                        Nip55RequestType.entries.forEach { type ->
                            if (type != req.requestType) {
                                store.grantPermission(callerId, type, null, duration)
                            }
                        }
                    }

                    if (callerPendingFirstUse) {
                        val sigHash = callerSignatureHash
                        val verificationStore = callerVerificationStore
                        if (sigHash != null && verificationStore != null) {
                            verificationStore.trustPackage(callerId, sigHash)
                            callerPendingFirstUse = false
                            callerVerified = true
                        } else {
                            if (BuildConfig.DEBUG) Log.w(TAG, "Trust persistence skipped: verification store unavailable")
                        }
                    }
                }
                if (permResult.isFailure) {
                    if (BuildConfig.DEBUG) Log.e(TAG, "Permission/trust write failed: ${permResult.exceptionOrNull()?.message}")
                    finishWithError("request_failed")
                    return@launch
                }

                withContext(signingDispatcher) {
                    requestId?.let { keystoreStorage?.setRequestIdContext(it) }
                    try {
                        if (req.requestType == Nip55RequestType.SIGN_EVENT) {
                            val km = currentApp?.getKeepMobile()
                            if (km != null) {
                                runCatching { km.preApproveNostrEvent(req.content) }
                                    .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "preApprove failed: ${it.message}") }
                            }
                        }
                        runCatching { nip55Handler.handleRequest(req, callerId) }
                    } finally {
                        keystoreStorage?.clearRequestIdContext()
                    }
                }
                    .onSuccess { response ->
                        store?.logOperation(callerId, req.requestType, eventKind, "allow", wasAutomatic = false)
                        finishWithResult(response)
                    }
                    .onFailure { e ->
                        if (BuildConfig.DEBUG) Log.e(TAG, "Request failed: ${e::class.simpleName}: ${e.message}")
                        finishWithError(mapExceptionToError(e))
                    }
            } finally {
                requestId?.let { keystoreStorage?.clearPendingCipher(it) }
            }
        }
    }

    private suspend fun authenticateForRequest(keystoreStorage: AndroidKeystoreStorage?, req: Nip55Request): Boolean {
        if (keystoreStorage == null) {
            finishWithError("Storage unavailable")
            return false
        }

        val biometricStatus = biometricHelper.checkBiometricStatus()
        if (biometricStatus != BiometricHelper.BiometricStatus.AVAILABLE) {
            finishWithError("biometric_not_ready", BiometricHelper.getBiometricNotReadyMessage(this, biometricStatus))
            return false
        }

        val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
            .getOrNull()

        if (cipher == null) {
            finishWithError(if (keystoreStorage.hasShare()) "Storage error" else "No share stored")
            return false
        }

        val authedCipher = runCatching {
            biometricHelper.authenticateWithCrypto(
                cipher = cipher,
                title = "Approve Request",
                subtitle = req.requestType.displayName(this)
            )
        }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Biometric authentication failed: ${it::class.simpleName}") }
            .getOrNull()

        if (authedCipher == null) {
            finishWithError("Authentication failed")
            return false
        }

        val reqId = requestId ?: UUID.randomUUID().toString().also { requestId = it }
        keystoreStorage.setPendingCipher(reqId, authedCipher)
        return true
    }

    private suspend fun initializeNodeIfNeeded(keystoreStorage: AndroidKeystoreStorage, app: KeepMobileApp): String? {
        val mobile = app.getKeepMobile() ?: return "No key is stored in Keep"
        if (!mobile.hasShare()) return "No key is stored in Keep"

        if (app.liveState != null) return null

        BiometricHelper.requireBiometricReady(this, biometricHelper.checkBiometricStatus())

        val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
            .getOrNull() ?: return "Failed to access stored keys"

        val authedCipher = runCatching {
            biometricHelper.authenticateWithCrypto(
                cipher = cipher,
                title = "Connect to Network",
                subtitle = "Authenticate to enable signing"
            )
        }.getOrNull() ?: return "Authentication failed"

        val initId = UUID.randomUUID().toString()
        keystoreStorage.setPendingCipher(initId, authedCipher)
        return try {
            app.ensureInitialized(requestId = initId)
            null
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Node initialization failed: ${e::class.simpleName}")
            "Failed to connect to network"
        } finally {
            keystoreStorage.clearPendingCipher(initId)
        }
    }

    private fun mapErrorToUserMessage(error: String): String = when (error) {
        "signing_disabled" -> "Signing is disabled (kill switch is active)"
        "locked" -> "Keep is locked, please unlock it first"
        "unknown_caller" -> "Request from unverified app"
        "Storage unavailable" -> "Key storage is not available"
        "Storage error" -> "Failed to access stored keys"
        "No share stored" -> "No key is stored in Keep"
        "Authentication failed" -> "Biometric authentication failed"
        "request_failed" -> "Request failed"
        "rate_limited" -> "Too many requests, please try again later"
        "not_initialized" -> "Keep is not connected to the network"
        "pubkey_mismatch" -> "Public key does not match the stored key"
        "invalid_timestamp" -> "Request has an invalid timestamp"
        "pubkey_verification_failed" -> "Public key verification failed"
        "Node initialization failed" -> "Failed to connect to network"
        "User rejected" -> "Request was declined"
        "biometric_not_ready" -> "Biometric authentication is currently unavailable"
        else -> "Request failed"
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

        if (req?.requestType == Nip55RequestType.GET_PUBLIC_KEY) {
            if (response.result.isEmpty()) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Handler returned empty pubkey result")
                return finishWithError("pubkey_verification_failed")
            }
            val groupPubkey = storage?.getShareMetadata()?.groupPubkey
            if (groupPubkey == null || groupPubkey.isEmpty()) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Stored pubkey unavailable for verification")
                return finishWithError("pubkey_verification_failed")
            }
            val storedPubkey = groupPubkey.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            if (!MessageDigest.isEqual(response.result.toByteArray(Charsets.UTF_8), storedPubkey.toByteArray(Charsets.UTF_8))) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Pubkey verification failed: mismatch detected")
                return finishWithError("pubkey_verification_failed")
            }
        }

        if (BuildConfig.DEBUG) Log.d(TAG, "Returning result for ${req?.requestType?.name} (requestId=${requestId})")
        val resultIntent = Intent().apply {
            putExtra("signature", response.result)
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

    private fun finishWithError(error: String, userMessage: String? = null) {
        notificationManager?.cancelNotification(notificationRequestId)
        if (BuildConfig.DEBUG) {
            val idSuffix = requestId?.let { " (requestId=$it)" }.orEmpty()
            Log.e(TAG, "NIP-55 request failed: $error$idSuffix")
        }
        val resultIntent = Intent().apply {
            putExtra("error", userMessage ?: mapErrorToUserMessage(error))
        }
        setResult(RESULT_CANCELED, resultIntent)
        finish()
    }
}
