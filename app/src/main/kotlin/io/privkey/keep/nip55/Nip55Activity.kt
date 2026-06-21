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
import io.privkey.keep.R
import io.privkey.keep.service.SigningNotificationManager
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.PinStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.Nip55DeclaredPermission
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Request
import io.privkey.keep.uniffi.Nip55RequestType
import io.privkey.keep.uniffi.Nip55RelayAuthGate
import io.privkey.keep.uniffi.Nip55Response
import io.privkey.keep.uniffi.nip55ExtractRelayHost
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URL
import java.util.UUID
import javax.crypto.Cipher

class Nip55Activity : FragmentActivity() {
    private lateinit var biometricHelper: BiometricHelper
    private val keepApp: KeepMobileApp? get() = application as? KeepMobileApp
    private var handler: Nip55Handler? = null
    private var storage: AndroidKeystoreStorage? = null
    private var permissionStore: PermissionStore? = null
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

    // Accumulated requests for batch / multi-event signing. Sign requests from the
    // same caller that arrive (via onNewIntent) before the user acts are collected
    // here; size 1 renders the single-request UI, size >1 the multi-event UI.
    private val pending = mutableListOf<PendingNip55Request>()
    private var batchCaller: String? = null

    // The exact set last rendered to the user. The approve/reject decision acts on
    // this snapshot (never the live `pending` list), so a request that races in
    // between render and the user's tap can never be folded into the signed set.
    private var displayed: List<PendingNip55Request> = emptyList()
    // Set once the user approves/rejects; further intents are ignored so the
    // committed decision can only ever apply to what was on screen.
    private var decisionLocked = false

    private class PendingNip55Request(
        val request: Nip55Request,
        val requestId: String?,
        val intentUri: String,
    ) {
        var risk: RiskAssessment? = null
        var notificationRequestId: String? = null
    }

    private class PreApproveFailedException : Exception()

    companion object {
        private const val TAG = "Nip55Activity"
        private val signingDispatcher = Dispatchers.Default.limitedParallelism(1)
        private const val MAX_CONTENT_LENGTH = 1024 * 1024
        private const val MAX_PUBKEY_LENGTH = 128
        private const val MAX_EXTRA_LENGTH = 2048
        // Mirrors keep-mobile MAX_BATCH_SIZE; bounds accumulation against a spammy caller.
        private const val MAX_BATCH_SIZE = 20
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
        if (keepApp?.isSigningKilled() == true) finishWithError("signing_disabled")
    }

    private fun handleIntent(intent: Intent) {
        if (keepApp?.isSigningKilled() == true) return finishWithError("signing_disabled")
        if (pinStore?.requiresAuthentication() == true) return finishWithError("locked")
        // The user has already committed a decision on the displayed set; do not
        // fold a late-arriving request into it. The activity is finishing.
        if (decisionLocked) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Ignoring intent after decision was committed")
            return
        }

        identifyCaller(intent)
        val caller = callerPackage
        if (caller == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from unverified caller")
            return finishWithError("unknown_caller")
        }

        val rawId = intent.getStringExtra("id")
        if (rawId != null && rawId.length > MAX_EXTRA_LENGTH) return finishWithError("Invalid request")
        val uriStr = intent.data?.let { uri ->
            if (uri.scheme != "nostrsigner") return finishWithError("Invalid URI scheme")
            uri.toString()
        }
        if (handler == null) return finishWithError("Handler not initialized")

        val parsed = parseRequest(intent, uriStr) ?: return finishWithError("Invalid request")
        val parsedId = rawId?.takeIf { it.isNotBlank() } ?: parsed.id

        // Accumulate only same-caller operation requests (never get_public_key) up to the cap.
        when (
            batchAccumulationDecision(
                pendingTypes = pending.map { it.request.requestType },
                pendingCaller = batchCaller,
                newType = parsed.requestType,
                newCaller = caller,
                maxBatchSize = MAX_BATCH_SIZE
            )
        ) {
            BatchAccumulation.DROP_OVER_CAP -> {
                if (BuildConfig.DEBUG) Log.w(TAG, "Dropping batch request beyond cap of $MAX_BATCH_SIZE")
                return
            }
            BatchAccumulation.RESET -> {
                cancelAllNotifications()
                pending.clear()
            }
            BatchAccumulation.ACCUMULATE -> {} // keep pending; the new item is appended below
        }

        val item = PendingNip55Request(parsed, parsedId, uriStr ?: "")
        pending.add(item)
        batchCaller = caller

        // Legacy single-request fields drive the single-request path and UI.
        request = parsed
        requestId = parsedId
        intentUri = uriStr

        // One notification per batch: the first request raises it; accumulated
        // requests arrive while the approval UI is already up.
        if (pending.size == 1) showNotificationFor(item)
        calculateRiskAndSetupContent()
    }

    private fun calculateRiskAndSetupContent() {
        val item = pending.lastOrNull() ?: return
        val pkg = callerPackage
        val store = permissionStore

        if (pkg == null || store == null) {
            setupContent()
            return
        }

        lifecycleScope.launch {
            val assessment = runCatching {
                store.riskAssessor.assess(pkg, item.request.eventKind(), item.request.requestType)
            }.getOrElse {
                RiskAssessment(
                    score = 100,
                    factors = listOf(RiskFactor.HIGH_FREQUENCY),
                    requiredAuth = AuthLevel.EXPLICIT
                )
            }
            item.risk = assessment
            riskAssessment = assessment
            // The user may have already decided while this assessment was running;
            // do not resurrect the approval UI.
            if (decisionLocked) return@launch
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

    private fun showNotificationFor(item: PendingNip55Request) {
        if (item.intentUri.isEmpty()) return
        val id = notificationManager?.showSigningRequest(
            requestType = item.request.requestType,
            callerPackage = callerPackage,
            intentUri = item.intentUri,
            requestId = item.requestId
        )
        item.notificationRequestId = id
        notificationRequestId = id
    }

    private fun cancelAllNotifications() {
        notificationManager?.cancelNotification(notificationRequestId)
        pending.forEach { it.notificationRequestId?.let { id -> notificationManager?.cancelNotification(id) } }
    }

    private fun setupContent() {
        // A late async render must not re-display (and re-enable) the approval UI
        // after the user has already committed a decision.
        if (decisionLocked) return
        val items = pending.toList()
        displayed = items
        if (items.size > 1) {
            setupBatchContent(items)
            return
        }

        val current = items.firstOrNull() ?: return
        val currentRequest = current.request
        val currentCallerPackage = callerPackage
        val currentCallerVerified = callerVerified
        val currentPendingFirstUse = callerPendingFirstUse
        val currentSignatureHash = callerSignatureHash
        val currentRisk = current.risk

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
                        onApprove = { duration, bundle, relayScope -> handleApprove(duration, bundle, relayScope) },
                        onReject = { duration, relayScope -> handleReject(duration, relayScope) }
                    )
                }
            }
        }
    }

    private fun setupBatchContent(items: List<PendingNip55Request>) {
        val currentCallerPackage = callerPackage
        val currentCallerVerified = callerVerified
        val currentPendingFirstUse = callerPendingFirstUse
        val currentSignatureHash = callerSignatureHash
        val highestRisk = items.mapNotNull { it.risk }.maxByOrNull { it.score }

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    BatchApprovalScreen(
                        requests = items.map { it.request },
                        callerPackage = currentCallerPackage,
                        callerVerified = currentCallerVerified,
                        showFirstUseWarning = currentPendingFirstUse,
                        callerSignatureFingerprint = if (currentPendingFirstUse) currentSignatureHash else null,
                        riskAssessment = highestRisk,
                        onApprove = { duration -> handleApprove(duration, emptyList()) },
                        onReject = { duration -> handleReject(duration) }
                    )
                }
            }
        }
    }

    private fun parseRequest(intent: Intent, uriStr: String?): Nip55Request? {
        val uri = uriStr ?: return null
        val h = handler ?: return null

        val parsed = runCatching { h.parseIntentUri(uri) }.getOrNull()
            ?: (if (uri.startsWith("nostrsigner:")) parseRequestFromExtras(intent, uri) else null)
            ?: return null

        if (BuildConfig.DEBUG) Log.d(TAG, "Parsed request: type=${parsed.requestType.name}, contentLen=${parsed.content.length}, pubkey=${parsed.pubkey?.take(8)}")
        return parsed
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

    private fun handleApprove(duration: PermissionDuration, declaredBundle: List<Nip55DeclaredPermission>, relayScope: RelayAuthScope? = null) {
        // Re-entry guard: a second tap, or an async render that re-enabled the
        // buttons, must not commit a second decision.
        if (decisionLocked) return
        if (keepApp?.isSigningKilled() == true) {
            return finishWithError("signing_disabled")
        }
        // Lock in the decision and act on exactly the snapshot the user saw.
        decisionLocked = true
        val shown = displayed
        if (shown.size > 1) return handleApproveBatch(duration, shown)
        // Re-bind the single-request fields to the displayed request so a request
        // that raced in after render (overwriting the fields) is never signed.
        shown.firstOrNull()?.let {
            request = it.request
            requestId = it.requestId
            riskAssessment = it.risk
        }

        // decisionLocked is set above, so finish rather than bare-return to avoid
        // soft-locking the screen if there is somehow no displayed request.
        val req = request ?: return finishWithError("Invalid request")
        val nip55Handler = handler ?: return finishWithError("Handler not initialized")
        val keystoreStorage = storage
        val callerId = callerPackage ?: run {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from unknown caller for ${req.requestType.name}")
            return finishWithError("unknown_caller")
        }
        val store = permissionStore
        val eventKind = req.eventKind()

        // Relay-auth allowlist: reject a non-whitelisted 22242 before any biometric/sign.
        if (relayAuthRejected(req)) {
            lifecycleScope.launch {
                store?.logOperation(callerId, req.requestType, eventKind, "deny_relay_whitelist", wasAutomatic = false)
                finishWithRejection()
            }
            return
        }

        val needsBiometric = req.requestType != Nip55RequestType.GET_PUBLIC_KEY ||
            (riskAssessment?.requiredAuth ?: AuthLevel.NONE).atLeast(AuthLevel.PIN)

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
                val signResult = signOneRequest(req, requestId, nip55Handler, callerId, keystoreStorage, currentApp)
                signResult
                    .onSuccess { response ->
                        // Verify a get_public_key response BEFORE persisting any grant
                        // or first-use trust, so a failed connect leaves no persisted
                        // state (#330).
                        val pubkeyError = verifyGetPublicKeyResult(response)
                        if (pubkeyError != null) {
                            store?.logOperation(callerId, req.requestType, eventKind, "pubkey_verification_failed", wasAutomatic = false)
                            finishWithError(pubkeyError)
                            return@onSuccess
                        }
                        recordGrantAndTrust(store, callerId, req, eventKind, duration, relayScopeForGrant(req, relayScope))
                        // On a get_public_key connect, grant the checked pre-declared
                        // permission bundle so the ContentProvider can answer those
                        // methods later (only persists if the user chose a remembered
                        // duration; sensitive kinds stay clamped by the Rust rule).
                        if (declaredBundle.isNotEmpty()) {
                            grantDeclaredBundle(store, callerId, declaredBundle, duration)
                        }
                        finishWithResult(response)
                    }
                    .onFailure { e ->
                        if (e is PreApproveFailedException) {
                            store?.logOperation(callerId, req.requestType, eventKind, "preapprove_failed", wasAutomatic = false)
                            finishWithError("preapprove_failed")
                            return@onFailure
                        }
                        if (BuildConfig.DEBUG) Log.e(TAG, "Request failed: ${e::class.simpleName}: ${e.message}")
                        finishWithError(mapExceptionToError(e))
                    }
            } finally {
                requestId?.let { keystoreStorage?.clearPendingCipher(it) }
            }
        }
    }

    private fun handleApproveBatch(duration: PermissionDuration, items: List<PendingNip55Request>) {
        val nip55Handler = handler ?: return finishWithError("Handler not initialized")
        val keystoreStorage = storage
        val callerId = callerPackage ?: run {
            if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting batch from unknown caller")
            return finishWithError("unknown_caller")
        }
        val store = permissionStore
        val batchAuthId = UUID.randomUUID().toString()

        lifecycleScope.launch {
            val currentApp = application as? KeepMobileApp

            // All batch items are operation requests (never get_public_key).
            if (keystoreStorage != null && currentApp != null) {
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

            // One biometric presence gate covers the whole batch; the live node
            // signs each event without re-consuming the (single-use) cipher.
            if (!authenticateForBatch(keystoreStorage, items, batchAuthId)) return@launch

            try {
                val responses = ArrayList<Nip55Response>(items.size)
                for (item in items) {
                    val req = item.request
                    val eventKind = req.eventKind()
                    // Relay-auth allowlist: a non-whitelisted 22242 event is rejected
                    // rather than signed, without blocking the rest of the batch.
                    if (relayAuthRejected(req)) {
                        store?.logOperation(callerId, req.requestType, eventKind, "deny_relay_whitelist", wasAutomatic = false)
                        responses.add(Nip55Response(result = "", event = null, error = "relay_not_whitelisted", id = item.requestId, rejected = true))
                        continue
                    }
                    val result = signOneRequest(req, item.requestId, nip55Handler, callerId, keystoreStorage, currentApp)
                    result
                        .onSuccess { response ->
                            // Batch has no per-event scope toggle; relay-auth events grant
                            // to their specific relay (the secure default).
                            recordGrantAndTrust(store, callerId, req, eventKind, duration, relayScopeForGrant(req, RelayAuthScope.SPECIFIC))
                            responses.add(response.copy(id = item.requestId))
                        }
                        .onFailure { e ->
                            val action = if (e is PreApproveFailedException) "preapprove_failed" else "deny"
                            store?.logOperation(callerId, req.requestType, eventKind, action, wasAutomatic = false)
                            if (BuildConfig.DEBUG) Log.w(TAG, "Batch item failed: ${e::class.simpleName}")
                            responses.add(Nip55Response(result = "", event = null, error = "request_failed", id = item.requestId, rejected = true))
                        }
                }
                finishWithBatchResults(nip55Handler, responses)
            } finally {
                keystoreStorage?.clearPendingCipher(batchAuthId)
            }
        }
    }

    // Runs preApprove (sign_event only) followed by the Rust handler for one
    // request on the single-threaded signing dispatcher.
    private suspend fun signOneRequest(
        req: Nip55Request,
        reqId: String?,
        nip55Handler: Nip55Handler,
        callerId: String,
        keystoreStorage: AndroidKeystoreStorage?,
        currentApp: KeepMobileApp?
    ): Result<Nip55Response> = withContext(signingDispatcher) {
        reqId?.let { keystoreStorage?.setRequestIdContext(it) }
        try {
            val km = currentApp?.getKeepMobile()
            if (req.requestType == Nip55RequestType.SIGN_EVENT && km != null) {
                val preApprove = runCatching { km.preApproveNostrEvent(req.content) }
                if (preApprove.isFailure) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "preApprove failed: ${preApprove.exceptionOrNull()?.message}")
                    return@withContext Result.failure<Nip55Response>(PreApproveFailedException())
                }
            }
            runCatching { nip55Handler.handleRequest(req, callerId) }
        } finally {
            keystoreStorage?.clearRequestIdContext()
        }
    }

    // Foreground allowlist enforcement (matches the background ContentProvider gate):
    // a kind-22242 request whose relay is not on a non-empty whitelist is rejected
    // without signing, so the whitelist can't be bypassed via the Intent path.
    private fun relayAuthRejected(req: Nip55Request): Boolean {
        if (req.requestType != Nip55RequestType.SIGN_EVENT || req.eventKind() != KIND_NIP42_AUTH) return false
        return evaluateRelayAuthGate(keepApp?.getRelayAuthWhitelistStore(), req.content).first == Nip55RelayAuthGate.AUTO_REJECT
    }

    // Resolves the relay scope to persist for a grant. Only kind-22242 (NIP-42) carries
    // a relay: ALL -> the wildcard; SPECIFIC -> the event's relay host. If the host
    // can't be extracted (missing/empty/multi relay tag) we fall back to RELAY_NONE,
    // NOT the wildcard: extraction fails identically at lookup time, so a RELAY_NONE
    // grant re-matches only the same malformed event (fail-closed) and never grants
    // other relays. Every non-22242 request grants with no relay scope.
    private fun relayScopeForGrant(req: Nip55Request, scope: RelayAuthScope?): String {
        if (req.requestType != Nip55RequestType.SIGN_EVENT || req.eventKind() != KIND_NIP42_AUTH) {
            return RELAY_NONE
        }
        if (scope == RelayAuthScope.ALL) return RELAY_WILDCARD
        return nip55ExtractRelayHost(req.content) ?: RELAY_NONE
    }

    private suspend fun recordGrantAndTrust(
        store: PermissionStore?,
        callerId: String,
        req: Nip55Request,
        eventKind: Int?,
        duration: PermissionDuration,
        relay: String = RELAY_NONE
    ) {
        val permResult = runCatching {
            store?.grantPermission(callerId, req.requestType, eventKind, duration, relay)
            if (eventKind != null && !isSensitiveKind(eventKind) && duration != PermissionDuration.JUST_THIS_TIME) {
                store?.grantPermission(callerId, req.requestType, null, duration)
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
        if (permResult.isFailure && BuildConfig.DEBUG) {
            Log.e(TAG, "Permission/trust write failed: ${permResult.exceptionOrNull()?.message}")
        }
        val auditAction = if (permResult.isFailure) "allow_grant_failed" else "allow"
        store?.logOperation(callerId, req.requestType, eventKind, auditAction, wasAutomatic = false)
    }

    // Grants the user-checked pre-declared permission bundle from a get_public_key
    // connect. The Rust duration clamp is applied per grant; JUST_THIS_TIME grants
    // simply do not persist (matching the reference signer's default).
    private suspend fun grantDeclaredBundle(
        store: PermissionStore?,
        callerId: String,
        declared: List<Nip55DeclaredPermission>,
        duration: PermissionDuration
    ) {
        if (store == null) return
        declared.forEach { perm ->
            val grantResult = runCatching { store.grantPermission(callerId, perm.requestType, perm.kind, duration) }
                .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "Bundle grant failed for ${perm.requestType.name}: ${it.message}") }
            val auditAction = if (grantResult.isFailure) "allow_grant_failed" else "allow"
            store.logOperation(callerId, perm.requestType, perm.kind, auditAction, wasAutomatic = false)
        }
    }

    private suspend fun authenticateForRequest(keystoreStorage: AndroidKeystoreStorage?, req: Nip55Request): Boolean {
        val authedCipher = obtainAuthedCipher(keystoreStorage, req.requestType.displayName(this)) ?: return false
        val reqId = requestId ?: UUID.randomUUID().toString().also { requestId = it }
        keystoreStorage?.setPendingCipher(reqId, authedCipher)
        return true
    }

    private suspend fun authenticateForBatch(
        keystoreStorage: AndroidKeystoreStorage?,
        items: List<PendingNip55Request>,
        batchAuthId: String
    ): Boolean {
        val subtitle = getString(R.string.connections_nip55_batch_auth_subtitle, items.size)
        val authedCipher = obtainAuthedCipher(keystoreStorage, subtitle) ?: return false
        // The share is loaded (and the cipher consumed) only at init, which uses
        // its own cipher; signing runs on the live node. So this authed cipher is
        // purely the biometric presence gate. Register it under the batch id only.
        keystoreStorage?.setPendingCipher(batchAuthId, authedCipher)
        return true
    }

    private suspend fun obtainAuthedCipher(keystoreStorage: AndroidKeystoreStorage?, subtitle: String): Cipher? {
        if (keystoreStorage == null) {
            finishWithError("Storage unavailable")
            return null
        }

        val biometricStatus = biometricHelper.checkBiometricStatus()
        if (biometricStatus != BiometricHelper.BiometricStatus.AVAILABLE) {
            finishWithError("biometric_not_ready", BiometricHelper.getBiometricNotReadyMessage(this, biometricStatus))
            return null
        }

        val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
            .getOrNull()

        if (cipher == null) {
            finishWithError(if (keystoreStorage.hasShare()) "Storage error" else "No share stored")
            return null
        }

        val authedCipher = runCatching {
            biometricHelper.authenticateWithCrypto(
                cipher = cipher,
                title = "Approve Request",
                subtitle = subtitle
            )
        }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Biometric authentication failed: ${it::class.simpleName}") }
            .getOrNull()

        if (authedCipher == null) {
            finishWithError("Authentication failed")
            return null
        }

        return authedCipher
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
        "preapprove_failed" -> "Request failed"
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

    private fun handleReject(duration: PermissionDuration, relayScope: RelayAuthScope? = null) {
        // Re-entry guard: mirrors handleApprove so neither path can run twice or
        // after the other has already committed.
        if (decisionLocked) return
        decisionLocked = true
        val shown = displayed
        if (shown.size > 1) return handleRejectBatch(duration, shown)
        shown.firstOrNull()?.let {
            request = it.request
            requestId = it.requestId
        }

        val req = request ?: return finishWithError("Invalid request")
        val callerId = callerPackage
        val store = permissionStore
        val eventKind = req.eventKind()

        lifecycleScope.launch {
            if (store != null && callerId != null) {
                // Persist the deny at the same relay scope a grant would use (host or "*"
                // for kind-22242), so a remembered reject is consulted by the same lookup
                // and replaces any matching ALLOW row.
                store.denyPermission(callerId, req.requestType, eventKind, duration, relayScopeForGrant(req, relayScope))
                store.logOperation(callerId, req.requestType, eventKind, "deny", wasAutomatic = false)
            }
            finishWithRejection()
        }
    }

    private fun handleRejectBatch(duration: PermissionDuration, items: List<PendingNip55Request>) {
        val callerId = callerPackage
        val store = permissionStore
        val nip55Handler = handler

        lifecycleScope.launch {
            if (store != null && callerId != null) {
                items.forEach { item ->
                    val eventKind = item.request.eventKind()
                    // Mirror the batch grant default (specific relay) so a remembered batch
                    // reject for kind-22242 is scoped like its approve counterpart.
                    store.denyPermission(callerId, item.request.requestType, eventKind, duration, relayScopeForGrant(item.request, RelayAuthScope.SPECIFIC))
                    store.logOperation(callerId, item.request.requestType, eventKind, "deny", wasAutomatic = false)
                }
            }
            if (nip55Handler != null) {
                val rejected = items.map {
                    Nip55Response(result = "", event = null, error = null, id = it.requestId, rejected = true)
                }
                finishWithBatchResults(nip55Handler, rejected)
            } else {
                finishWithRejection()
            }
        }
    }

    // Reads the captured request type and stored group pubkey, then delegates to
    // the pure checkPubkey helper. Used both to gate grant/trust persistence before
    // it happens and to gate returning the result.
    private fun verifyGetPublicKeyResult(response: Nip55Response): String? =
        checkPubkey(request?.requestType, response.result, storage?.getShareMetadata()?.groupPubkey)

    private fun finishWithResult(response: Nip55Response) {
        cancelAllNotifications()
        val req = request

        // Defense-in-depth: the single-request path already verified this before
        // persisting any grant/trust. This re-check intentionally duplicates that
        // gate so other callers of finishWithResult can never return an unverified
        // get_public_key result; do not assume either gate covers the other.
        verifyGetPublicKeyResult(response)?.let { return finishWithError(it) }

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

    private fun finishWithBatchResults(nip55Handler: Nip55Handler, responses: List<Nip55Response>) {
        cancelAllNotifications()
        val json = runCatching { nip55Handler.serializeBatchResults(responses) }
            .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to serialize batch results: ${it::class.simpleName}") }
            .getOrNull() ?: return finishWithError("request_failed")

        if (BuildConfig.DEBUG) Log.d(TAG, "Returning batch results for ${responses.size} requests")
        val resultIntent = Intent().apply {
            putExtra("results", json)
            putExtra("package", packageName)
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    // A user rejection is NOT a signer failure: per NIP-55, return RESULT_OK with
    // rejected=true so the client can tell a declined request from a crash
    // (RESULT_CANCELED). finishWithError stays reserved for actual failures.
    private fun finishWithRejection() {
        cancelAllNotifications()
        if (BuildConfig.DEBUG) Log.d(TAG, "User rejected request (requestId=$requestId)")
        val resultIntent = Intent().apply {
            putExtra("rejected", true)
            putExtra("package", packageName)
            requestId?.let { putExtra("id", it) }
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    private fun finishWithError(error: String, userMessage: String? = null) {
        cancelAllNotifications()
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
