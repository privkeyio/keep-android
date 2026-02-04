package io.privkey.keep.nip46

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import io.privkey.keep.BuildConfig
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.MainActivity
import io.privkey.keep.R
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionDecision
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.uniffi.BunkerApprovalRequest
import io.privkey.keep.uniffi.BunkerCallbacks
import io.privkey.keep.uniffi.BunkerHandler
import io.privkey.keep.uniffi.BunkerLogEvent
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class BunkerService : Service() {

    companion object {
        private const val TAG = "BunkerService"
        private const val CHANNEL_ID = "keep_bunker_service"
        private const val NOTIFICATION_ID = 2

        private const val MAX_PENDING_APPROVALS = 10
        private const val MAX_PENDING_NOSTR_CONNECT_REQUESTS = 10
        private const val MAX_CONCURRENT_PER_CLIENT = 3
        private const val RATE_LIMIT_WINDOW_MS = 60_000L
        private const val MAX_REQUESTS_PER_WINDOW = 30
        private const val BACKOFF_BASE_MS = 1000L
        private const val BACKOFF_MAX_MS = 60_000L
        private const val APPROVAL_TIMEOUT_MS = 60_000L
        private const val GLOBAL_RATE_LIMIT_WINDOW_MS = 60_000L
        private const val GLOBAL_MAX_REQUESTS_PER_WINDOW = 100

        private val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")

        private val _bunkerUrl = MutableStateFlow<String?>(null)
        val bunkerUrl: StateFlow<String?> = _bunkerUrl.asStateFlow()

        private val _status = MutableStateFlow(BunkerStatus.STOPPED)
        val status: StateFlow<BunkerStatus> = _status.asStateFlow()

        private const val GLOBAL_REQUEST_HISTORY_MAX_SIZE = 200

        private val pendingApprovals = ConcurrentHashMap<String, PendingApproval>()
        private val globalPendingCount = AtomicInteger(0)
        private val clientPendingCounts = ConcurrentHashMap<String, AtomicInteger>()
        private val clientRequestHistory = ConcurrentHashMap<String, MutableList<Long>>()
        private val clientBackoffUntil = ConcurrentHashMap<String, Long>()
        private val clientConsecutiveRequests = ConcurrentHashMap<String, AtomicInteger>()
        private val globalRequestHistory = ArrayDeque<Long>(GLOBAL_REQUEST_HISTORY_MAX_SIZE)
        private val globalRequestLock = Any()
        private val serviceInstanceRef = AtomicReference<BunkerService?>(null)
        private val pendingNostrConnectRequests = ConcurrentLinkedQueue<NostrConnectRequest>()

        fun current(): BunkerService? = serviceInstanceRef.get()

        fun queueNostrConnectRequest(request: NostrConnectRequest): Boolean {
            if (pendingNostrConnectRequests.size >= MAX_PENDING_NOSTR_CONNECT_REQUESTS) {
                return false
            }
            pendingNostrConnectRequests.add(request)
            return true
        }

        fun start(context: Context) {
            val intent = Intent(context, BunkerService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, BunkerService::class.java))
        }

        fun respondToApproval(requestId: String, approved: Boolean, clientPubkey: String? = null) {
            pendingApprovals.remove(requestId)?.let { approval ->
                globalPendingCount.decrementAndGet()
                val pubkey = clientPubkey ?: approval.request.appPubkey
                clientPendingCounts[pubkey]?.decrementAndGet()
                if (approved) {
                    clientConsecutiveRequests[pubkey]?.set(0)
                }
                approval.respond(approved)
            }
        }

        internal fun addPendingApproval(requestId: String, approval: PendingApproval): Boolean {
            val newGlobalCount = globalPendingCount.incrementAndGet()
            if (newGlobalCount > MAX_PENDING_APPROVALS) {
                globalPendingCount.decrementAndGet()
                if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request: max pending approvals reached")
                return false
            }

            val clientPubkey = approval.request.appPubkey
            val clientCount = clientPendingCounts.computeIfAbsent(clientPubkey) { AtomicInteger(0) }
            val newClientCount = clientCount.incrementAndGet()
            if (newClientCount > MAX_CONCURRENT_PER_CLIENT) {
                clientCount.decrementAndGet()
                globalPendingCount.decrementAndGet()
                if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from ${truncatePubkey(clientPubkey)}: max concurrent per client reached")
                return false
            }

            pendingApprovals[requestId] = approval
            return true
        }

        fun getPendingApproval(requestId: String): PendingApproval? = pendingApprovals[requestId]

        internal fun isRateLimited(clientPubkey: String): Boolean {
            val now = SystemClock.elapsedRealtime()

            synchronized(globalRequestLock) {
                while (globalRequestHistory.isNotEmpty() && globalRequestHistory.first() < now - GLOBAL_RATE_LIMIT_WINDOW_MS) {
                    globalRequestHistory.removeFirst()
                }
                if (globalRequestHistory.size >= GLOBAL_MAX_REQUESTS_PER_WINDOW) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Global rate limit exceeded")
                    return true
                }
                if (globalRequestHistory.size >= GLOBAL_REQUEST_HISTORY_MAX_SIZE) {
                    globalRequestHistory.removeFirst()
                }
                globalRequestHistory.addLast(now)
            }

            val backoffUntil = clientBackoffUntil[clientPubkey] ?: 0L
            if (now < backoffUntil) {
                if (BuildConfig.DEBUG) Log.w(TAG, "Client ${truncatePubkey(clientPubkey)} in backoff")
                return true
            }

            val history = clientRequestHistory.computeIfAbsent(clientPubkey) { mutableListOf() }
            synchronized(history) {
                history.removeAll { it < now - RATE_LIMIT_WINDOW_MS }

                if (history.size >= MAX_REQUESTS_PER_WINDOW) {
                    val consecutive = clientConsecutiveRequests.computeIfAbsent(clientPubkey) { AtomicInteger(0) }
                    val backoffMs = (BACKOFF_BASE_MS * (1 shl consecutive.getAndIncrement().coerceAtMost(6)))
                        .coerceAtMost(BACKOFF_MAX_MS)
                    clientBackoffUntil[clientPubkey] = now + backoffMs
                    if (BuildConfig.DEBUG) Log.w(TAG, "Rate limit exceeded for ${truncatePubkey(clientPubkey)}")
                    return true
                }

                history.add(now)
            }
            return false
        }

        private fun truncatePubkey(pubkey: String): String =
            if (pubkey.length > 16) "${pubkey.take(8)}..." else pubkey

        internal fun clearRateLimitState() {
            globalPendingCount.set(0)
            clientRequestHistory.clear()
            clientBackoffUntil.clear()
            clientConsecutiveRequests.clear()
            clientPendingCounts.clear()
            synchronized(globalRequestLock) {
                globalRequestHistory.clear()
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var bunkerHandler: BunkerHandler? = null
    private var networkManager: NetworkConnectivityManager? = null
    private var configStore: BunkerConfigStore? = null
    private var permissionStore: PermissionStore? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        clearRateLimitState()
        serviceInstanceRef.set(this)

        configStore = BunkerConfigStore(this)
        if (configStore?.isEnabled() != true) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, createNotification(isActive = false))

        val app = applicationContext as? KeepMobileApp
        val keepMobile = app?.getKeepMobile()
        if (keepMobile == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "KeepMobile not available")
            _status.value = BunkerStatus.ERROR
            stopSelf()
            return START_NOT_STICKY
        }

        permissionStore = PermissionStore(Nip55Database.getInstance(this))

        val relays = configStore?.getRelays() ?: emptyList()
        if (relays.isEmpty()) {
            if (BuildConfig.DEBUG) Log.e(TAG, "No bunker relays configured")
            _status.value = BunkerStatus.ERROR
            stopSelf()
            return START_NOT_STICKY
        }

        serviceScope.launch {
            startBunker(keepMobile, relays)
        }

        networkManager = NetworkConnectivityManager(this) {
            serviceScope.launch {
                val handler = bunkerHandler ?: return@launch
                if (handler.getBunkerStatus() == BunkerStatus.RUNNING) {
                    handler.stopBunker()
                    startBunker(keepMobile, relays)
                }
            }
        }
        networkManager?.register()

        return START_STICKY
    }

    private fun startBunker(keepMobile: io.privkey.keep.uniffi.KeepMobile, relays: List<String>) {
        try {
            _status.value = BunkerStatus.STARTING

            val handler = BunkerHandler(keepMobile)
            bunkerHandler = handler

            val callbacks = object : BunkerCallbacks {
                override fun onLog(event: BunkerLogEvent) {
                    if (BuildConfig.DEBUG) {
                        Log.d(TAG, "Bunker: ${event.app} ${event.action} success=${event.success}")
                    }
                    logBunkerEvent(event)
                }

                override fun requestApproval(request: BunkerApprovalRequest): Boolean {
                    return handleApprovalRequest(request)
                }
            }

            handler.startBunker(relays, callbacks)

            val url = handler.getBunkerUrl()
            _bunkerUrl.value = url
            _status.value = handler.getBunkerStatus()

            updateNotification(isActive = true)

            processQueuedNostrConnectRequests()
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to start bunker: ${e::class.simpleName}")
            _status.value = BunkerStatus.ERROR
        }
    }

    fun processQueuedNostrConnectRequests() {
        val handler = bunkerHandler ?: return
        serviceScope.launch {
            while (true) {
                val request = pendingNostrConnectRequests.poll() ?: break
                runCatching {
                    val method = handler::class.java.getMethod(
                        "sendConnectResponse",
                        String::class.java,
                        List::class.java,
                        String::class.java
                    )
                    method.invoke(handler, request.clientPubkey, request.relays, request.secret)
                    if (BuildConfig.DEBUG) Log.d(TAG, "Sent connect response to ${truncatePubkey(request.clientPubkey)}")
                }.onFailure { e ->
                    val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
                    if (cause is NoSuchMethodException || cause is NoSuchMethodError) {
                        if (BuildConfig.DEBUG) Log.w(TAG, "sendConnectResponse not available in library - client authorized but response not sent")
                    } else {
                        if (BuildConfig.DEBUG) Log.e(TAG, "Failed to send connect response: ${(cause ?: e)::class.simpleName}")
                    }
                }
            }
        }
    }

    private fun logBunkerEvent(event: BunkerLogEvent) {
        val store = permissionStore ?: return
        val requestType = mapMethodToRequestType(event.action) ?: return
        serviceScope.launch {
            runCatching {
                store.logOperation(
                    callerPackage = "nip46:${event.app}",
                    requestType = requestType,
                    eventKind = null,
                    decision = if (event.success) "allow" else "deny",
                    wasAutomatic = false
                )
            }.onFailure {
                if (BuildConfig.DEBUG) Log.w(TAG, "Failed to log bunker event: ${it::class.simpleName}")
            }
        }
    }

    private fun mapMethodToRequestType(method: String): Nip55RequestType? =
        mapMethodToNip55RequestType(method)

    private fun handleApprovalRequest(request: BunkerApprovalRequest): Boolean {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (BuildConfig.DEBUG) Log.e(TAG, "handleApprovalRequest called from main thread - rejecting to avoid ANR")
            return false
        }

        val clientPubkey = request.appPubkey

        if (!HEX_PUBKEY_REGEX.matches(clientPubkey)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Invalid client pubkey format")
            return false
        }

        if (isRateLimited(clientPubkey)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Request from ${truncatePubkey(clientPubkey)} rate limited")
            return false
        }

        val store = configStore
        val isAuthorized = store?.isClientAuthorized(clientPubkey) == true
        val isConnectRequest = request.method == "connect"

        if (!isAuthorized && !isConnectRequest) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Unauthorized client ${truncatePubkey(clientPubkey)} attempted ${request.method}")
            return false
        }

        if (!isConnectRequest) {
            val storedDecision = checkStoredPermission(clientPubkey, request)
            if (storedDecision != null) {
                val allowed = storedDecision == PermissionDecision.ALLOW
                logBunkerEventWithDecision(request, allowed, wasAutomatic = true)
                if (BuildConfig.DEBUG) Log.d(TAG, "Auto-${if (allowed) "approved" else "denied"} request from ${truncatePubkey(clientPubkey)} based on stored permission")
                return allowed
            }
        }

        val requestId = UUID.randomUUID().toString()
        val latch = java.util.concurrent.CountDownLatch(1)
        val approvedRef = AtomicReference<Boolean?>(null)

        val pendingApproval = PendingApproval(
            request,
            isConnectRequest = isConnectRequest
        ) { result ->
            approvedRef.set(result)
            latch.countDown()
        }

        if (!addPendingApproval(requestId, pendingApproval)) {
            return false
        }

        startApprovalActivity(requestId, request, isConnectRequest)

        val completed = latch.await(APPROVAL_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)

        if (!completed) {
            pendingApprovals.remove(requestId)?.let {
                globalPendingCount.decrementAndGet()
                clientPendingCounts[clientPubkey]?.decrementAndGet()
            }
            dismissApprovalActivity(requestId)
            if (BuildConfig.DEBUG) Log.w(TAG, "Approval request $requestId timed out")
            return false
        }

        val result = approvedRef.get() ?: false
        if (result && isConnectRequest && store != null) {
            store.authorizeClient(clientPubkey)
            if (BuildConfig.DEBUG) Log.d(TAG, "Authorized new client: ${truncatePubkey(clientPubkey)}")
        }

        return result
    }

    private fun checkStoredPermission(clientPubkey: String, request: BunkerApprovalRequest): PermissionDecision? {
        val store = permissionStore ?: return null
        val callerPackage = "nip46:$clientPubkey"
        val requestType = mapMethodToRequestType(request.method) ?: return null
        val eventKind = request.eventKind?.toInt()

        return runBlocking(Dispatchers.IO) {
            store.getPermissionDecision(callerPackage, requestType, eventKind)
        }
    }

    private fun logBunkerEventWithDecision(request: BunkerApprovalRequest, allowed: Boolean, wasAutomatic: Boolean) {
        val store = permissionStore ?: return
        val requestType = mapMethodToRequestType(request.method) ?: return
        serviceScope.launch {
            runCatching {
                store.logOperation(
                    callerPackage = "nip46:${request.appPubkey}",
                    requestType = requestType,
                    eventKind = request.eventKind?.toInt(),
                    decision = if (allowed) "allow" else "deny",
                    wasAutomatic = wasAutomatic
                )
            }.onFailure {
                if (BuildConfig.DEBUG) Log.w(TAG, "Failed to log bunker event: ${it::class.simpleName}")
            }
        }
    }

    private fun startApprovalActivity(requestId: String, request: BunkerApprovalRequest, isConnectRequest: Boolean) {
        val intent = Intent(this, Nip46ApprovalActivity::class.java).apply {
            putExtra(Nip46ApprovalActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(Nip46ApprovalActivity.EXTRA_APP_PUBKEY, request.appPubkey)
            putExtra(Nip46ApprovalActivity.EXTRA_APP_NAME, request.appName)
            putExtra(Nip46ApprovalActivity.EXTRA_METHOD, request.method)
            putExtra(Nip46ApprovalActivity.EXTRA_IS_CONNECT, isConnectRequest)
            request.eventKind?.let { putExtra(Nip46ApprovalActivity.EXTRA_EVENT_KIND, it.toInt()) }
            request.eventContent?.let { putExtra(Nip46ApprovalActivity.EXTRA_EVENT_CONTENT, it) }
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        startActivity(intent)
    }

    private fun dismissApprovalActivity(requestId: String) {
        val intent = Intent(this, Nip46ApprovalActivity::class.java).apply {
            putExtra(Nip46ApprovalActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(Nip46ApprovalActivity.EXTRA_TIMEOUT, true)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        startActivity(intent)
    }

    override fun onDestroy() {
        networkManager?.unregister()
        networkManager = null
        bunkerHandler?.stopBunker()
        bunkerHandler = null
        configStore = null
        permissionStore = null
        _bunkerUrl.value = null
        _status.value = BunkerStatus.STOPPED

        pendingApprovals.keys.toList().forEach { reqId ->
            pendingApprovals.remove(reqId)?.respond(false)
        }
        clearRateLimitState()
        serviceInstanceRef.set(null)

        serviceScope.cancel("Service destroyed")

        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.bunker_service_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.bunker_service_channel_description)
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(isActive: Boolean): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val textRes = if (isActive) R.string.bunker_service_text_active else R.string.bunker_service_text_starting

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.bunker_service_title))
            .setContentText(getString(textRes))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun updateNotification(isActive: Boolean) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, createNotification(isActive))
    }
}

class PendingApproval(
    val request: BunkerApprovalRequest,
    val isConnectRequest: Boolean = false,
    private val onResponse: (Boolean) -> Unit
) {
    fun respond(approved: Boolean) = onResponse(approved)
}
