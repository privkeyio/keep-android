package io.privkey.keep.nip46

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.privkey.keep.BuildConfig
import io.privkey.keep.filterRelaysPreConnection
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.MainActivity
import io.privkey.keep.R
import io.privkey.keep.nip55.EventLogCategory
import io.privkey.keep.nip55.EventLogLevel
import io.privkey.keep.nip55.EventLogStore
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.service.NetworkConnectivityManager
import io.privkey.keep.uniffi.BunkerApprovalRequest
import io.privkey.keep.uniffi.BunkerApprovalResult
import io.privkey.keep.uniffi.BunkerCallbacks
import io.privkey.keep.uniffi.BunkerHandler
import io.privkey.keep.uniffi.BunkerLogEvent
import io.privkey.keep.uniffi.BunkerRememberDuration
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.ConnectAuthorization
import io.privkey.keep.uniffi.Nip46BunkerRateLimiter
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * The clients a revoke covers: [pubkeys], or for Revoke All (null) every client the config,
 * the authorized cache or a connect still being saved knows about. Lowercased, since pubkeys
 * are compared lowercased everywhere else.
 */
internal fun revokedClientSet(
    pubkeys: Collection<String>?,
    configured: Collection<String>,
    cached: Collection<String>,
    pending: Collection<String>,
): Set<String> = (pubkeys ?: (configured + cached + pending)).map { it.lowercase() }.toSet()

class BunkerService : Service() {

    companion object {
        private const val TAG = "BunkerService"
        private const val CHANNEL_ID = "keep_bunker_service"
        private const val NOTIFICATION_ID = 2

        private const val MAX_PENDING_APPROVALS = 10
        private const val MAX_PENDING_NOSTR_CONNECT_REQUESTS = 10
        private const val MAX_CONCURRENT_PER_CLIENT = 3
        private const val MAX_START_RETRIES = 5
        private const val START_RETRY_DELAY_MS = 2_000L
        private const val APPROVAL_CHANNEL_ID = "keep_bunker_approvals"
        private const val APPROVAL_NOTIFICATION_ID_BASE = 0x4E46

        // Kept clearly inside the core's own 60 second backstop on this same wait. With
        // equal deadlines an approval landing at the boundary would be shown to the user
        // as given while the core had already denied it, so this side has to be the one
        // that decides.
        internal const val APPROVAL_TIMEOUT_MS = 55_000L
        private const val MAX_TRACKED_CLIENTS = 1000
        internal const val MAX_AUTHORIZED_CLIENTS = 100
        internal const val BUNKER_MARKERS_PREFS = "keep_bunker_markers"
        internal const val KEY_ROTATED_FOR_EARLIER_REVOKES = "rotated_for_earlier_revokes"
        internal const val KEY_REVOKE_ALL_ON_START = "revoke_all_on_start"

        private val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")

        private val REJECTED = BunkerApprovalResult(
            approved = false,
            remember = BunkerRememberDuration.JUST_THIS_TIME,
        )

        private val _bunkerUrl = MutableStateFlow<String?>(null)
        val bunkerUrl: StateFlow<String?> = _bunkerUrl.asStateFlow()

        private val _status = MutableStateFlow(BunkerStatus.STOPPED)
        val status: StateFlow<BunkerStatus> = _status.asStateFlow()

        private val pendingApprovals = ConcurrentHashMap<String, PendingApproval>()
        private val globalPendingCount = AtomicInteger(0)
        private val clientPendingCounts = ConcurrentHashMap<String, AtomicInteger>()
        // Global + per-client request rate limiting (window + exponential backoff)
        // lives in Rust; the in-flight concurrency cap above stays here (it bounds
        // pending approval UI, not a request rate). The connect limiter is isolated
        // so a connect flood cannot drain the signing budget.
        private val bunkerRateLimiter by lazy { Nip46BunkerRateLimiter() }
        private val connectRateLimiter by lazy { Nip46BunkerRateLimiter() }

        private fun limiterFor(budget: RateLimitBudget): Nip46BunkerRateLimiter =
            when (budget) {
                RateLimitBudget.CONNECT -> connectRateLimiter
                RateLimitBudget.SIGNING -> bunkerRateLimiter
            }

        private val serviceInstanceRef = AtomicReference<BunkerService?>(null)
        private val pendingNostrConnectRequests = ArrayBlockingQueue<NostrConnectRequest>(MAX_PENDING_NOSTR_CONNECT_REQUESTS)

        fun current(): BunkerService? = serviceInstanceRef.get()

        internal fun forgetPendingAuth(pubkey: String) {
            current()?.pendingAuthSaves?.remove(pubkey.lowercase())
        }

        internal fun cacheAuthorizedClient(pubkey: String) {
            current()?.authorizedClientsCache?.add(pubkey.lowercase())
        }

        internal fun uncacheAuthorizedClient(pubkey: String) {
            current()?.authorizedClientsCache?.remove(pubkey.lowercase())
        }

        internal fun revokeClientInEngine(pubkey: String) {
            current()?.authorizedClientsCache?.remove(pubkey.lowercase())
            val handler = current()?.bunkerHandler ?: return
            try {
                handler.revokeClient(pubkey)
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Engine client revoke failed: ${e::class.simpleName}")
                throw e
            }
        }

        internal fun revokeAllClientsInEngine() {
            current()?.authorizedClientsCache?.clear()
            val handler = current()?.bunkerHandler ?: return
            try {
                handler.revokeAllClients()
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Engine revoke-all failed: ${e::class.simpleName}")
                throw e
            }
        }

        /**
         * The one revoke path for NIP-46 clients: [pubkeys], or every client when null.
         * Denylists them, drops them from the app's lists and the engine, then rotates the
         * bunker URL, since the connect secret in it is reusable and a revoked client that
         * kept it could connect again under a new key. Returns the saved bunker config.
         *
         * Stopgap until the core owns revocation: a single core revoke that records the
         * revocation, drops live and persisted grants and invalidates the connect secret
         * replaces this sequence, and the Kotlin denylist with it.
         */
        internal suspend fun revokeClients(
            context: Context,
            keepMobile: io.privkey.keep.uniffi.KeepMobile,
            pubkeys: Collection<String>?,
        ): io.privkey.keep.uniffi.BunkerConfigInfo {
            var revoked = emptySet<String>()
            val saved = BunkerConfigStore.update(keepMobile) { config ->
                val service = current()
                revoked = revokedClientSet(
                    pubkeys,
                    config.authorizedClients,
                    service?.authorizedClientsCache?.let { synchronized(it) { it.toList() } }.orEmpty(),
                    service?.pendingAuthSaves?.let { synchronized(it) { it.toList() } }.orEmpty(),
                )
                // Out of pendingAuthSaves and denylisted before the config drops them, so neither the
                // gate nor a connect still being saved sees them unblocked.
                revoked.forEach { forgetPendingAuth(it) }
                Nip46ClientStore.addAllToDenylist(context, revoked)
                io.privkey.keep.uniffi.BunkerConfigInfo(config.enabled, config.authorizedClients.filter { it.lowercase() !in revoked })
            }
            revoked.forEach { pubkey ->
                runCatching { Nip46ClientStore.removeClient(context, pubkey) }
                    .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to remove NIP-46 client: ${it::class.simpleName}") }
            }
            try {
                if (pubkeys == null) revokeAllClientsInEngine() else revoked.forEach { revokeClientInEngine(it) }
            } finally {
                // The secret must change even if the engine revoke failed; the next start's
                // sweep revokes any grant the engine still holds.
                rotateBunkerCredentials(keepMobile)
            }
            return saved
        }

        /**
         * Called on an account switch. The bunker's URL, its authorized clients and their
         * remembered grants are all device-wide, so without this the clients paired under
         * the previous account would act as the new one: requests reach the user under the
         * new identity and remembered kinds sign with no prompt. Drops the clients, turns
         * the bunker off, rotates the URL, and marks every remembered grant to be revoked
         * on the next start, since revoking needs a running engine. A start that finds the
         * mark rotates again first, so a rotation that failed here is retried and nothing
         * serves the old URL while the old grants are still loaded. Nothing is denylisted,
         * so a client can still be paired to the new account deliberately.
         *
         * Throws when the mark could not be saved, since only it keeps the clients out for good:
         * a start that finds it rotates first and then revokes every remembered grant. A rotated
         * URL alone does not, because the bunker key is public and a restored grant needs no
         * connect. Returns false when another step failed, which the mark still covers, so a
         * reset over an unreadable bunker config does not block every switch and delete.
         *
         * Stopgap. The mark and its start-time revoke go once the pinned core revokes all
         * clients with no running bunker (keep a one-shot revoke for a mark left set by this
         * version). The turn-off, list clear and rotation go once the core keys the bunker
         * config by account. The Nip46ClientStore clear stays until that store is per account.
         */
        internal suspend fun resetForAccountSwitch(context: Context, keepMobile: io.privkey.keep.uniffi.KeepMobile): Boolean {
            // The stop the switch asked for is asynchronous: halt a running instance now, so a
            // start in flight either finishes before the mark exists or serves nothing.
            current()?.haltForAccountSwitch()
            // Every step runs even if an earlier one failed, since each closes part of it. The
            // mark goes first: a reset cut short after it is finished by the next start.
            val failures = mutableListOf<Throwable>()
            suspend fun step(block: suspend () -> Unit): Boolean =
                try {
                    block()
                    true
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    failures += e
                    false
                }
            val marked = step { revokeAllMark(context).set() }
            step {
                BunkerConfigStore.update(keepMobile) {
                    // Inside the lock, so a connect save still queued behind it finds its
                    // client no longer pending and does not write it back (see authorizeClient).
                    current()?.let { service ->
                        service.authorizedClientsCache.clear()
                        service.pendingAuthSaves.clear()
                    }
                    io.privkey.keep.uniffi.BunkerConfigInfo(false, emptyList())
                }
            }
            runCatching { Nip46ClientStore.getClients(context).keys.forEach { Nip46ClientStore.removeClient(context, it) } }
                .onFailure { if (BuildConfig.DEBUG) Log.w(TAG, "Could not clear the NIP-46 client list: ${it::class.simpleName}") }
            // A nostrconnect request approved under the previous account must not be answered
            // under the new one.
            pendingNostrConnectRequests.clear()
            // Standalone: the service is being stopped for the switch and must not restart.
            step { BunkerHandler(keepMobile).use { it.rotateBunkerCredentials() } }
            // Again, now the config is off: a start asked for since the first halt read it on.
            stop(context)
            current()?.haltForAccountSwitch()
            if (!marked) throw failures.first().also { first -> failures.drop(1).forEach(first::addSuppressed) }
            if (BuildConfig.DEBUG) failures.forEach { Log.w(TAG, "Account switch reset step failed: ${it::class.simpleName}") }
            return failures.isEmpty()
        }

        private fun markers(context: Context) = context.getSharedPreferences(BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)

        private var revokeAllMarkInstance: RevokeAllMark? = null

        @Synchronized
        private fun revokeAllMark(context: Context): RevokeAllMark =
            revokeAllMarkInstance ?: RevokeAllMark(markers(context.applicationContext)).also { revokeAllMarkInstance = it }

        /** Saves the revoke-all mark before a store that may replace the active account. */
        internal fun markRevokeAllAhead(context: Context): (switched: Boolean) -> Unit = revokeAllMark(context).setAhead()

        /**
         * Rotate the bunker credentials whether or not the service is running.
         */
        internal suspend fun rotateBunkerCredentials(keepMobile: io.privkey.keep.uniffi.KeepMobile) {
            current()?.takeIf { it.serving }?.let { return it.rotateBunkerUrl() }
            BunkerHandler(keepMobile).use { it.rotateBunkerCredentials() }
            // A service that began starting during the rotation may have loaded the old keys.
            // Remove once the pinned core's rotation stops a bunker started from any handler.
            current()?.takeIf { it.serving }?.rotateBunkerUrl()
        }

        /**
         * Versions before revoke rotated the URL left every revoked client holding a
         * working connect secret, so rotate once if anything was ever revoked.
         * Returns whether it rotated. Lives here only while the denylist does.
         */
        internal fun rotateOnceForEarlierRevokes(context: Context, keepMobile: io.privkey.keep.uniffi.KeepMobile): Boolean {
            val markers = context.getSharedPreferences(BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
            if (markers.getBoolean(KEY_ROTATED_FOR_EARLIER_REVOKES, false)) return false
            val rotate = Nip46ClientStore.getDenylist(context).isNotEmpty()
            if (rotate) BunkerHandler(keepMobile).use { it.rotateBunkerCredentials() }
            markers.edit().putBoolean(KEY_ROTATED_FOR_EARLIER_REVOKES, true).commit()
            return rotate
        }

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

        fun respondToApproval(
            requestId: String,
            approved: Boolean,
            clientPubkey: String? = null,
            remember: BunkerRememberDuration = BunkerRememberDuration.JUST_THIS_TIME,
        ) {
            pendingApprovals.remove(requestId)?.let { approval ->
                globalPendingCount.decrementAndGet()
                val pubkey = clientPubkey ?: approval.request.appPubkey
                clientPendingCounts[pubkey]?.decrementAndGet()
                if (approved) {
                    limiterFor(rateLimitBudgetFor(approval.isConnectRequest)).resetConsecutive(pubkey.lowercase())
                }
                approval.respond(
                    BunkerApprovalResult(
                        approved = approved,
                        remember = remember,
                    )
                )
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

        // Global + per-client window + exponential backoff live in Rust; Android
        // supplies the monotonic clock. Key on the lowercased pubkey so case-variant
        // hex can't mint fresh per-client buckets (matches the authorization path).
        internal fun isRateLimited(clientPubkey: String, budget: RateLimitBudget): Boolean {
            val limited = limiterFor(budget).isRateLimited(clientPubkey.lowercase(), SystemClock.elapsedRealtime().toULong())
            // Bounds the concurrency map (clientPendingCounts); rate-limit state is bounded in Rust.
            if (clientPendingCounts.size > MAX_TRACKED_CLIENTS) {
                evictStaleMaps()
            }
            return limited
        }

        private fun truncatePubkey(pubkey: String): String =
            io.privkey.keep.uniffi.truncateStr(pubkey, 8u, 6u)

        internal fun clearRateLimitState() {
            synchronized(approvalLock) {
                globalPendingCount.set(0)
                clientPendingCounts.clear()
            }
            bunkerRateLimiter.clear()
            connectRateLimiter.clear()
        }

        internal fun evictStaleMaps() {
            synchronized(approvalLock) {
                if (clientPendingCounts.size > MAX_TRACKED_CLIENTS) {
                    clientPendingCounts.entries.removeAll { it.value.get() <= 0 }
                }
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val pendingAuthSaves = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    private val authorizedClientsCache = java.util.Collections.synchronizedSet(mutableSetOf<String>())
    private val startStopMutex = Mutex()
    private val approvalIdCounter = AtomicInteger(0)
    private val approvalIds = ConcurrentHashMap<String, Int>()
    @Volatile private var bunkerHandler: BunkerHandler? = null
    private var networkManager: NetworkConnectivityManager? = null
    @Volatile private var keepMobileRef: io.privkey.keep.uniffi.KeepMobile? = null
    // Set before the first start is launched and cleared first thing in onDestroy.
    @Volatile private var serving = false
    private var permissionStore: PermissionStore? = null
    private var eventLogStore: EventLogStore? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        synchronized(approvalLock) {
            pendingApprovals.keys.toList().forEach { reqId ->
                pendingApprovals.remove(reqId)?.respond(REJECTED)
            }
        }
        clearRateLimitState()
        serviceInstanceRef.set(this)

        val app = applicationContext as? KeepMobileApp
        val keepMobile = app?.getKeepMobile()
        if (keepMobile == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "KeepMobile not available")
            _status.value = BunkerStatus.ERROR
            serving = false
            stopSelf()
            return START_NOT_STICKY
        }

        keepMobileRef = keepMobile

        val bunkerConfig = runCatching { keepMobile.getBunkerConfig() }.getOrNull()
        if (bunkerConfig?.enabled != true) {
            serving = false
            stopSelf()
            return START_NOT_STICKY
        }

        authorizedClientsCache.clear()
        bunkerConfig.authorizedClients.forEach { authorizedClientsCache.add(it.lowercase()) }

        startForeground(NOTIFICATION_ID, createNotification(isActive = false))

        // Stored keys that will not decrypt fail the open rather than being minted over,
        // and this runs on the main thread after startForeground, so an uncaught failure
        // here would take the process down on every launch.
        val db = runCatching { Nip55Database.getInstance(this) }.getOrNull()
        if (db == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Permission database not available")
            _status.value = BunkerStatus.ERROR
            serving = false
            stopSelf()
            return START_NOT_STICKY
        }

        permissionStore = PermissionStore(db)
        eventLogStore = EventLogStore.getInstance(db)

        val relays = runCatching { keepMobile.getRelayConfig(null).bunkerRelays }.getOrDefault(emptyList())
        if (relays.isEmpty()) {
            if (BuildConfig.DEBUG) Log.e(TAG, "No bunker relays configured")
            _status.value = BunkerStatus.ERROR
            serving = false
            stopSelf()
            return START_NOT_STICKY
        }

        serving = true
        serviceScope.launch {
            startBunker(keepMobile, relays)
        }

        networkManager?.unregister()
        networkManager = NetworkConnectivityManager(this) {
            serviceScope.launch {
                val shouldRestart = startStopMutex.withLock {
                    val handler = bunkerHandler ?: return@withLock false
                    if (handler.getBunkerStatus() == BunkerStatus.RUNNING) {
                        handler.stopBunker()
                        true
                    } else {
                        false
                    }
                }
                if (shouldRestart) startBunker(keepMobile, relays)
            }
        }
        networkManager?.register()

        return START_STICKY
    }

    private suspend fun startBunker(keepMobile: io.privkey.keep.uniffi.KeepMobile, relays: List<String>, attempt: Int = 0) {
        val retryAfterInit = startStopMutex.withLock {
            startBunkerLocked(keepMobile, relays, attempt)
        }
        if (retryAfterInit) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Bunker start waiting for init, retry ${attempt + 1}/$MAX_START_RETRIES")
            delay(START_RETRY_DELAY_MS shl attempt)
            startBunker(keepMobile, relays, attempt + 1)
        }
    }

    private suspend fun haltForAccountSwitch() {
        startStopMutex.withLock {
            serving = false
            bunkerHandler?.let { runCatching { it.stopBunker() } }
        }
    }

    /**
     * Rotate the bunker credentials so a previously distributed (possibly leaked)
     * bunker:// URL can no longer pair or sign, then restart the bunker to publish
     * the new URL. Throws if rotation fails; on throw rotation did NOT happen and
     * the old URL is still valid, so callers must not report success.
     */
    suspend fun rotateBunkerUrl() {
        val keepMobile = keepMobileRef
            ?: throw IllegalStateException("Bunker not initialized")
        // Rotate under the start/stop mutex so no concurrent start serves the old
        // keys. rotateBunkerCredentials stops the running handler (if any) and
        // replaces the persisted transport+connect secrets. Clear the displayed
        // URL immediately: it is now invalid and must not linger on screen.
        val restart = startStopMutex.withLock {
            val handler = bunkerHandler ?: BunkerHandler(keepMobile)
            handler.rotateBunkerCredentials()
            _bunkerUrl.value = null
            // A service being destroyed keeps the rotation but must not start again.
            if (serving) _status.value = BunkerStatus.STARTING
            serving
        }
        if (!restart) return
        // Restart so a fresh handler derives and publishes the rotated URL. Run on
        // the service's own scope so publishing completes even if the UI that
        // triggered the rotation is disposed mid-restart.
        val relays = runCatching { keepMobile.getRelayConfig(null).bunkerRelays }
            .getOrDefault(emptyList())
        if (relays.isNotEmpty()) {
            serviceScope.launch { startBunker(keepMobile, relays) }
        } else {
            _status.value = BunkerStatus.STOPPED
        }
    }

    private suspend fun startBunkerLocked(keepMobile: io.privkey.keep.uniffi.KeepMobile, relays: List<String>, attempt: Int): Boolean {
        if (!serving) return false
        try {
            val safeRelays = withContext(Dispatchers.IO) {
                withTimeoutOrNull(10_000L) { filterRelaysPreConnection(relays) }
            }
            if (safeRelays.isNullOrEmpty()) {
                if (attempt < MAX_START_RETRIES) return true
                if (BuildConfig.DEBUG) Log.e(TAG, "All relays failed connection-time DNS validation")
                _status.value = BunkerStatus.ERROR
                stopSelf()
                return false
            }

            _status.value = BunkerStatus.STARTING

            bunkerHandler?.let { runCatching { it.stopBunker() } }
            // After an account switch, before anything serves: retries a rotation the switch
            // could not do, and keeps the old URL dead while the old grants are loaded.
            if (revokeAllMark(this).isSet()) {
                BunkerHandler(keepMobile).use { it.rotateBunkerCredentials() }
            }
            if (rotateOnceForEarlierRevokes(this, keepMobile)) {
                logActivity(EventLogCategory.BUNKER, EventLogLevel.WARN, "bunker", "URL rotated because a client was revoked before this version; pair clients again")
            }
            val handler = BunkerHandler(keepMobile)
            bunkerHandler = handler

            val callbacks = object : BunkerCallbacks {
                override fun onLog(event: BunkerLogEvent) {
                    if (BuildConfig.DEBUG) {
                        Log.d(TAG, "Bunker: ${event.app} ${event.action} success=${event.success}")
                    }
                    logBunkerEvent(event)
                }

                override fun requestApproval(
                    request: BunkerApprovalRequest,
                ): BunkerApprovalResult {
                    return handleApprovalRequest(request)
                }

                override fun onConnect(pubkey: String, name: String, authorization: ConnectAuthorization) {
                    if (BuildConfig.DEBUG) Log.d(TAG, "Bunker: app connected ${pubkey.take(8)}")
                    val safeName = sanitizeDisplayName(name)
                    logActivity(EventLogCategory.BUNKER, EventLogLevel.INFO, safeName.ifBlank { pubkey.take(8) }, "connected")
                    // Persist authorization only when the signer core asserts explicit consent
                    // (a matched connect secret or a user-approved prompt); an auto-approved
                    // connect is not persisted as an authorized client. Authorization is driven
                    // by an explicit assertion rather than the callback merely having fired.
                    if (shouldPersistConnectAuthorization(authorization)) {
                        // A connect the user approved at a prompt lifts an earlier revocation;
                        // a matched secret alone does not.
                        authorizeClient(
                            pubkey,
                            safeName,
                            safeRelays,
                            clearDenylist = authorization == ConnectAuthorization.USER_APPROVED
                        )
                    } else {
                        if (BuildConfig.DEBUG) Log.w(TAG, "Bunker: not persisting auto-approved connect ${pubkey.take(8)}")
                        logActivity(EventLogCategory.BUNKER, EventLogLevel.WARN, safeName.ifBlank { pubkey.take(8) }, "connect not persisted (auto-approved)")
                    }
                }
            }

            val proxy = runCatching { keepMobileRef?.getProxyConfig() }.getOrNull()
            if (proxy != null && proxy.enabled && proxy.port.toInt() in 1..65535) {
                // A proxy is configured. Fail closed if it cannot be started:
                // falling back to a direct connection would leak the user's IP to
                // the relays, defeating the point of the proxy (e.g. Tor).
                if (!invokeStartBunkerWithProxy(handler, safeRelays, callbacks, "127.0.0.1", proxy.port)) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "proxy enabled but startBunkerWithProxy failed; refusing to connect without proxy")
                    }
                    _status.value = BunkerStatus.ERROR
                    stopSelf()
                    return false
                }
            } else {
                handler.startBunker(safeRelays, callbacks)
            }

            // onDestroy cannot stop a handler whose start was still running.
            if (!serving) {
                runCatching { handler.stopBunker() }
                return false
            }

            try {
                // An account switch dropped the previous account's clients; their remembered
                // grants were restored by this start and go here, first, since they are live
                // until then. The revoke is a silent no-op once onDestroy has stopped the
                // handler, and onDestroy clears serving first, so the mark is kept for the next
                // start unless this one is still serving. Ceiling: the pinned core also reports
                // success when it fails to save the emptied grants; a core whose revoke returns
                // a result closes that.
                val mark = revokeAllMark(this)
                val requestsSeen = mark.requestsSoFar()
                if (mark.isSet()) {
                    handler.revokeAllClients()
                    mark.clearIfUnchanged(requestsSeen) { serving }
                }
                // A revoke made while the engine was stopped could not drop the client's
                // persisted grants, and this start has just restored them. Ceiling: one
                // storage write per denylisted client on every start, and grants live until
                // the sweep reaches them. Remove once the pinned core clears persisted grants
                // on a revoke without a running bunker and drops them on rotation.
                Nip46ClientStore.getDenylist(this)
                    .filter { HEX_PUBKEY_REGEX.matches(it) }
                    .forEach { handler.revokeClient(it) }
            } catch (e: Exception) {
                runCatching { handler.stopBunker() }
                throw e
            }

            val url = handler.getBunkerUrl()
            _bunkerUrl.value = url
            _status.value = handler.getBunkerStatus()

            updateNotification(isActive = true)

            processQueuedNostrConnectRequests()
            return false
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            if (e is io.privkey.keep.uniffi.KeepMobileException.NotInitialized && attempt < MAX_START_RETRIES) {
                return true
            }
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to start bunker: ${e::class.simpleName}")
            _status.value = BunkerStatus.ERROR
            stopSelf()
            return false
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

    private fun logActivity(category: EventLogCategory, level: EventLogLevel, source: String, message: String) {
        val activityLog = eventLogStore ?: return
        serviceScope.launch {
            runCatching { activityLog.log(category, level, source, message) }
        }
    }

    private fun logBunkerEvent(event: BunkerLogEvent) {
        val message = buildString {
            append(event.action)
            event.detail?.takeIf { it.isNotBlank() }?.let { append(": "); append(it) }
        }
        logActivity(
            EventLogCategory.BUNKER,
            if (event.success) EventLogLevel.INFO else EventLogLevel.WARN,
            event.app,
            message
        )

        val store = permissionStore ?: return
        val requestType = mapMethodToNip55RequestType(event.action) ?: return
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

    private fun authorizeClient(
        pubkey: String,
        name: String? = null,
        relays: List<String> = emptyList(),
        clearDenylist: Boolean = false
    ) {
        val pk = pubkey.lowercase()
        if (!HEX_PUBKEY_REGEX.matches(pk)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Invalid pubkey in authorizeClient")
            return
        }
        pendingAuthSaves.add(pk)
        serviceScope.launch(Dispatchers.IO) {
            try {
                val mobile = keepMobileRef ?: return@launch
                val evicted = mutableListOf<String>()
                var accepted = false
                runCatching {
                    BunkerConfigStore.update(mobile) { config ->
                        // Decided under the same lock as revokeClients, which drops a client from
                        // pendingAuthSaves when it revokes it, so a revoke that lands while this
                        // connect is being saved is never undone by it.
                        when {
                            pk !in pendingAuthSaves -> return@update config
                            clearDenylist -> Nip46ClientStore.removeFromDenylist(this@BunkerService, pk)
                            runCatching { Nip46ClientStore.isDenylisted(this@BunkerService, pk) }.getOrDefault(true) -> return@update config
                        }
                        accepted = true
                        if (config.authorizedClients.none { it.lowercase() == pk }) {
                            val combined = config.authorizedClients + pk
                            val capped = combined.takeLast(MAX_AUTHORIZED_CLIENTS)
                            evicted.addAll(combined.dropLast(capped.size))
                            io.privkey.keep.uniffi.BunkerConfigInfo(config.enabled, capped)
                        } else {
                            config
                        }
                    }
                }.onSuccess {
                    if (accepted) authorizedClientsCache.add(pk)
                }.onFailure {
                    if (BuildConfig.DEBUG) Log.e(TAG, "Failed to persist authorized client: ${it::class.simpleName}")
                }
                if (!accepted) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "Ignoring connect from revoked client")
                    return@launch
                }
                evicted.forEach {
                    authorizedClientsCache.remove(it.lowercase())
                    runCatching { Nip46ClientStore.removeClient(this@BunkerService, it) }
                }
                if (name != null) {
                    runCatching { Nip46ClientStore.saveClient(this@BunkerService, pk, sanitizeDisplayName(name), relays) }
                }
            } finally {
                pendingAuthSaves.remove(pk)
            }
        }
    }

    private fun handleApprovalRequest(
        request: BunkerApprovalRequest,
    ): BunkerApprovalResult {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            if (BuildConfig.DEBUG) Log.e(TAG, "handleApprovalRequest called from main thread")
            return REJECTED
        }

        val clientPubkey = request.appPubkey
        if (!HEX_PUBKEY_REGEX.matches(clientPubkey)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Invalid client pubkey format")
            return REJECTED
        }
        if (request.method.isBlank()) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Request method must not be blank")
            return REJECTED
        }

        val pk = clientPubkey.lowercase()
        val denylisted = runCatching { Nip46ClientStore.isDenylisted(this, pk) }.getOrDefault(true)
        val isAuthorized = isClientAuthorized(
            denylisted = denylisted,
            inPendingAuth = pendingAuthSaves.contains(pk),
            inCache = authorizedClientsCache.contains(pk)
        )
        val isConnectRequest = request.method == "connect"

        // Gate-then-budget ordering is contract-tested by RateLimitDelegationTest:
        // a null budget means the gate rejected before any limiter is consulted.
        val budget = rateLimitBudgetDecision(isAuthorized, isConnectRequest)
        if (budget == null) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Unauthorized client ${truncatePubkey(clientPubkey)} attempted ${request.method}")
            return REJECTED
        }

        if (isRateLimited(clientPubkey, budget)) {
            if (BuildConfig.DEBUG) Log.w(TAG, "Request from ${truncatePubkey(clientPubkey)} rate limited")
            return REJECTED
        }

        val requestId = UUID.randomUUID().toString()
        val latch = java.util.concurrent.CountDownLatch(1)
        val resultRef = AtomicReference<BunkerApprovalResult?>(null)

        val pendingApproval = PendingApproval(
            request,
            isConnectRequest = isConnectRequest
        ) { result ->
            resultRef.set(result)
            latch.countDown()
        }

        if (!addPendingApproval(requestId, pendingApproval)) {
            return REJECTED
        }

        startApprovalActivity(requestId, request, isConnectRequest)

        val completed = latch.await(APPROVAL_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        cancelApprovalNotification(requestId)

        if (!completed) {
            pendingApprovals.remove(requestId)?.let {
                globalPendingCount.decrementAndGet()
                clientPendingCounts[clientPubkey]?.decrementAndGet()
            }
            dismissApprovalActivity(requestId)
            if (BuildConfig.DEBUG) Log.w(TAG, "Approval request $requestId timed out")
            return REJECTED
        }

        // A connect approval is not persisted here: the core can still refuse the connect
        // after this returns, at its own deadline or on its own checks. onConnect reports
        // the connects it accepted, and persists them.
        val result = resultRef.get() ?: return REJECTED
        // The client may have been revoked while its prompt was open. Stopgap until the core
        // re-checks the client's permission after the prompt, before it signs.
        if (result.approved && !isConnectRequest && runCatching { Nip46ClientStore.isDenylisted(this, pk) }.getOrDefault(true)) {
            return REJECTED
        }
        return result
    }

    private fun startApprovalActivity(requestId: String, request: BunkerApprovalRequest, isConnectRequest: Boolean) {
        val intent = Intent(this, Nip46ApprovalActivity::class.java).apply {
            putExtra(Nip46ApprovalActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(Nip46ApprovalActivity.EXTRA_APP_PUBKEY, request.appPubkey)
            putExtra(Nip46ApprovalActivity.EXTRA_APP_NAME, request.appName)
            putExtra(Nip46ApprovalActivity.EXTRA_IS_CONNECT, isConnectRequest)
            request.eventContent?.let { putExtra(Nip46ApprovalActivity.EXTRA_EVENT_CONTENT, it) }
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        runCatching { startActivity(intent) }
        postApprovalNotification(requestId, request, intent)
    }

    private fun postApprovalNotification(requestId: String, request: BunkerApprovalRequest, intent: Intent) {
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED) return
        val notificationId = approvalNotificationId(requestId)
        val contentIntent = PendingIntent.getActivity(
            this,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val appLabel = sanitizeDisplayName(request.appName).ifBlank { truncatePubkey(request.appPubkey) }
        val body = getString(R.string.bunker_approval_notification_text, appLabel, sanitizeDisplayName(request.method))
        val publicVersion = NotificationCompat.Builder(this, APPROVAL_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.bunker_approval_notification_title))
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .build()
        val notification = NotificationCompat.Builder(this, APPROVAL_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.bunker_approval_notification_title))
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setContentIntent(contentIntent)
            .setFullScreenIntent(contentIntent, true)
            .setAutoCancel(true)
            .setTimeoutAfter(APPROVAL_TIMEOUT_MS)
            .build()
        runCatching {
            NotificationManagerCompat.from(this).notify(notificationId, notification)
        }
    }

    private fun cancelApprovalNotification(requestId: String) {
        val id = approvalIds.remove(requestId) ?: return
        runCatching { NotificationManagerCompat.from(this).cancel(id) }
    }

    private fun approvalNotificationId(requestId: String): Int =
        approvalIds.computeIfAbsent(requestId) {
            APPROVAL_NOTIFICATION_ID_BASE + 1 + approvalIdCounter.getAndIncrement()
        }

    private fun dismissApprovalActivity(requestId: String) {
        val intent = Intent(this, Nip46ApprovalActivity::class.java).apply {
            putExtra(Nip46ApprovalActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(Nip46ApprovalActivity.EXTRA_TIMEOUT, true)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        runCatching { startActivity(intent) }
    }

    override fun onDestroy() {
        serving = false
        networkManager?.unregister()
        networkManager = null
        bunkerHandler?.stopBunker()
        bunkerHandler = null
        keepMobileRef = null
        permissionStore = null
        eventLogStore = null
        _bunkerUrl.value = null
        _status.value = BunkerStatus.STOPPED

        synchronized(approvalLock) {
            pendingApprovals.keys.toList().forEach { reqId ->
                pendingApprovals.remove(reqId)?.respond(REJECTED)
                cancelApprovalNotification(reqId)
            }
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
            val approvalChannel = NotificationChannel(
                APPROVAL_CHANNEL_ID,
                getString(R.string.bunker_approval_channel_name),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = getString(R.string.bunker_approval_channel_description)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
            manager.createNotificationChannel(approvalChannel)
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
    private val onResponse: (BunkerApprovalResult) -> Unit
) {
    fun respond(result: BunkerApprovalResult) = onResponse(result)
}
