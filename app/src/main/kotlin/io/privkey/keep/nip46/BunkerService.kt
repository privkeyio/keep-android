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
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
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
        private const val MAX_TRACKED_CLIENTS = 1000

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
        private val pendingNostrConnectRequests = ArrayBlockingQueue<NostrConnectRequest>(MAX_PENDING_NOSTR_CONNECT_REQUESTS)

        fun current(): BunkerService? = serviceInstanceRef.get()

        fun queueNostrConnectRequest(request: NostrConnectRequest): Boolean {
            return pendingNostrConnectRequests.offer(request)
        }

        fun dequeueNostrConnectRequest(request: NostrConnectRequest): Boolean {
            return pendingNostrConnectRequests.remove(request)
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

        private val approvalLock = Any()

        internal fun addPendingApproval(requestId: String, approval: PendingApproval): Boolean {
            val clientPubkey = approval.request.appPubkey
            synchronized(approvalLock) {
                if (globalPendingCount.get() >= MAX_PENDING_APPROVALS) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request: max pending approvals reached")
                    return false
                }

                val clientCount = clientPendingCounts.computeIfAbsent(clientPubkey) { AtomicInteger(0) }
                if (clientCount.get() >= MAX_CONCURRENT_PER_CLIENT) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Rejecting request from ${truncatePubkey(clientPubkey)}: max concurrent per client reached")
                    return false
                }

                globalPendingCount.incrementAndGet()
                clientCount.incrementAndGet()
                pendingApprovals[requestId] = approval
                return true
            }
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

            if (clientRequestHistory.size >= MAX_TRACKED_CLIENTS && !clientRequestHistory.containsKey(clientPubkey)) {
                clientRequestHistory.keys.firstOrNull()?.let { evictKey ->
                    clientRequestHistory.remove(evictKey)
                    clientBackoffUntil.remove(evictKey)
                    clientConsecutiveRequests.remove(evictKey)
                }
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
            io.privkey.keep.uniffi.truncateStr(pubkey, 8u, 6u)

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
    private var keepMobileRef: io.privkey.keep.uniffi.KeepMobile? = null
    private var permissionStore: PermissionStore? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        clearRateLimitState()
        serviceInstanceRef.set(this)

        val app = applicationContext as? KeepMobileApp
        val keepMobile = app?.getKeepMobile()
        if (keepMobile == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "KeepMobile not available")
            _status.value = BunkerStatus.ERROR
            stopSelf()
            return START_NOT_STICKY
        }

        keepMobileRef = keepMobile

        val bunkerConfig = runCatching { keepMobile.getBunkerConfig() }.getOrNull()
        if (bunkerConfig?.enabled != true) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, createNotification(isActive = false))

        permissionStore = PermissionStore(Nip55Database.getInstance(this))

        val relays = runCatching { keepMobile.getRelayConfig(null).bunkerRelays }.getOrDefault(emptyList())
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

            val proxy = runCatching { keepMobileRef?.getProxyConfig() }.getOrNull()
            val proxyStarted = proxy != null && proxy.enabled && proxy.port.toInt() in 1..65535 &&
                invokeStartBunkerWithProxy(handler, relays, callbacks, "127.0.0.1", proxy.port)
            if (!proxyStarted) {
                handler.startBunker(relays, callbacks)
            }

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

    private fun invokeStartBunkerWithProxy(
        handler: BunkerHandler,
        relays: List<String>,
        callbacks: BunkerCallbacks,
        proxyHost: String,
        proxyPort: UShort
    ): Boolean = runCatching {
        val method = handler.javaClass.methods.firstOrNull { it.name == "startBunkerWithProxy" }
            ?: return false
        method.invoke(handler, relays, callbacks, proxyHost, proxyPort)
        true
    }.onFailure {
        if (BuildConfig.DEBUG) Log.w(TAG, "startBunkerWithProxy failed: ${it::class.simpleName}")
    }.getOrDefault(false)

    @Volatile
    private var cachedSendConnectMethod: java.lang.reflect.Method? = null

    fun processQueuedNostrConnectRequests() {
        val handler = bunkerHandler ?: return
        serviceScope.launch {
            generateSequence { pendingNostrConnectRequests.poll() }
                .take(MAX_PENDING_NOSTR_CONNECT_REQUESTS)
                .forEach { request -> sendConnectResponse(handler, request) }
        }
    }

    private fun sendConnectResponse(handler: BunkerHandler, request: NostrConnectRequest) {
        runCatching {
            val method = cachedSendConnectMethod ?: handler::class.java.getMethod(
                "sendConnectResponse",
                String::class.java,
                List::class.java,
                String::class.java
            ).also { cachedSendConnectMethod = it }
            method.invoke(handler, request.clientPubkey, request.relays, request.secret)
            if (BuildConfig.DEBUG) Log.d(TAG, "Sent connect response to ${truncatePubkey(request.clientPubkey)}")
        }.onFailure { e ->
            handleSendConnectError(e)
        }
    }

    private fun handleSendConnectError(e: Throwable) {
        val cause = if (e is java.lang.reflect.InvocationTargetException) e.cause else e
        if (cause is NoSuchMethodException || cause is NoSuchMethodError) {
            cachedSendConnectMethod = null
            if (BuildConfig.DEBUG) Log.w(TAG, "sendConnectResponse not available in library")
        } else {
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to send connect response: ${(cause ?: e)::class.simpleName}")
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
            if (BuildConfig.DEBUG) Log.e(TAG, "handleApprovalRequest called from main thread")
            return false
        }

        val clientPubkey = request.appPubkey
        if (!HEX_PUBKEY_REGEX.matches(clientPubkey)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Invalid client pubkey format")
            return false
        }
        if (request.method.isBlank()) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Request method must not be blank")
            return false
        }

        if (isRateLimited(clientPubkey)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Request from ${truncatePubkey(clientPubkey)} rate limited")
            return false
        }

        val mobile = keepMobileRef
        val isAuthorized = mobile != null && runCatching {
            mobile.getBunkerConfig().authorizedClients.any { it.lowercase() == clientPubkey.lowercase() }
        }.getOrDefault(false)
        val isConnectRequest = request.method == "connect"

        if (!isAuthorized && !isConnectRequest) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Unauthorized client ${truncatePubkey(clientPubkey)} attempted ${request.method}")
            return false
        }

        if (!isConnectRequest) {
            val storedDecision = checkStoredPermission(clientPubkey, request)
            if (storedDecision != null) {
                val allowed = storedDecision == PermissionDecision.ALLOW
                if (allowed) {
                    clientConsecutiveRequests[clientPubkey]?.set(0)
                }
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
        if (result && isConnectRequest && mobile != null) {
            runCatching {
                val config = mobile.getBunkerConfig()
                if (!config.authorizedClients.any { it.lowercase() == clientPubkey.lowercase() }) {
                    val updated = config.authorizedClients + clientPubkey.lowercase()
                    mobile.saveBunkerConfig(io.privkey.keep.uniffi.BunkerConfigInfo(config.enabled, updated))
                }
            }
            if (BuildConfig.DEBUG) Log.d(TAG, "Authorized new client: ${truncatePubkey(clientPubkey)}")
        }

        return result
    }

    private fun checkStoredPermission(clientPubkey: String, request: BunkerApprovalRequest): PermissionDecision? {
        require(clientPubkey.isNotBlank()) { "Client pubkey must not be blank" }
        val store = permissionStore ?: return null
        val callerPackage = "nip46:$clientPubkey"
        val requestType = mapMethodToRequestType(request.method) ?: return null
        val eventKind = request.eventKind?.toInt()

        return runCatching {
            runBlocking(Dispatchers.IO) {
                withTimeoutOrNull(5_000L) {
                    store.getPermissionDecision(callerPackage, requestType, eventKind)
                }
            }
        }.getOrNull()
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
        keepMobileRef = null
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
