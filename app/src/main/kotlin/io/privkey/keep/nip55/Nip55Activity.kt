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
import java.net.URLDecoder
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
        private const val GENERIC_ERROR_MESSAGE = "An error occurred"
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

        requestId = intent.getStringExtra("id")?.takeIf { it.length <= MAX_EXTRA_LENGTH }
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
            runCatching { URLDecoder.decode(uriBody, "UTF-8") }.getOrNull() ?: return null
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
        if (permissions != null && permissions.length > MAX_CONTENT_LENGTH) return null

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

            if (keystoreStorage != null && currentApp != null) {
                if (!initializeNodeIfNeeded(keystoreStorage, currentApp)) {
                    finishWithError("Node initialization failed")
                    return@launch
                }
            }

            if (needsBiometric && !authenticateForRequest(keystoreStorage, req)) return@launch

            try {
                store?.grantPermission(callerId, req.requestType, eventKind, duration)

                withContext(signingDispatcher) {
                    requestId?.let { keystoreStorage?.setRequestIdContext(it) }
                    try {
                        runCatching { nip55Handler.handleRequest(req, callerId) }
                    } finally {
                        keystoreStorage?.clearRequestIdContext()
                    }
                }
                    .onSuccess { response ->
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
                subtitle = req.requestType.displayName()
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

    private suspend fun initializeNodeIfNeeded(keystoreStorage: AndroidKeystoreStorage, app: KeepMobileApp): Boolean {
        val mobile = app.getKeepMobile() ?: return false
        val nodeReady = mobile.getShareInfo() != null &&
            runCatching { withContext(Dispatchers.IO) { mobile.getPeers() } }.isSuccess
        if (nodeReady) return true

        val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
            .getOrNull() ?: return false

        val authedCipher = runCatching {
            biometricHelper.authenticateWithCrypto(
                cipher = cipher,
                title = "Connect to Network",
                subtitle = "Authenticate to enable signing"
            )
        }.getOrNull() ?: return false

        val initId = UUID.randomUUID().toString()
        keystoreStorage.setPendingCipher(initId, authedCipher)
        return try {
            app.ensureInitialized(requestId = initId)
            true
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Node initialization failed: ${e::class.simpleName}")
            false
        } finally {
            keystoreStorage.clearPendingCipher(initId)
        }
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
