package io.privkey.keep.nip46

import android.content.Intent
import android.net.Uri
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
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.BunkerConfigStore
import io.privkey.keep.nip55.PermissionDuration
import io.privkey.keep.storage.KillSwitchStore
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class NostrConnectActivity : FragmentActivity() {

    private lateinit var biometricHelper: BiometricHelper
    private var storage: AndroidKeystoreStorage? = null
    private var killSwitchStore: KillSwitchStore? = null
    private var connectRequest: NostrConnectRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        biometricHelper = BiometricHelper(this)
        val app = application as? KeepMobileApp
        storage = app?.getStorage()
        killSwitchStore = app?.getKillSwitchStore()

        val uri = intent?.data
        if (uri == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "No URI provided")
            finish()
            return
        }

        val parsed = parseNostrConnectUri(uri)
        if (parsed == null) {
            if (BuildConfig.DEBUG) Log.e(TAG, "Failed to parse nostrconnect URI")
            finish()
            return
        }

        connectRequest = parsed

        if (killSwitchStore?.isEnabled() == true) {
            finish()
            return
        }

        setContent {
            KeepAndroidTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    NostrConnectApprovalScreen(
                        request = parsed,
                        onApprove = ::handleApprove,
                        onReject = ::handleReject
                    )
                }
            }
        }
    }

    private fun handleApprove(duration: PermissionDuration, onComplete: (Boolean) -> Unit) {
        val request = connectRequest ?: run {
            onComplete(false)
            return
        }

        val keystoreStorage = storage
        if (keystoreStorage == null || killSwitchStore?.isEnabled() == true) {
            onComplete(false)
            finish()
            return
        }

        lifecycleScope.launch {
            val cipher = runCatching { keystoreStorage.getCipherForDecryption() }
                .onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Failed to get cipher: ${it::class.simpleName}") }
                .getOrNull()

            if (cipher == null) {
                onComplete(false)
                finish()
                return@launch
            }

            val authedCipher = runCatching {
                biometricHelper.authenticateWithCrypto(
                    cipher = cipher,
                    title = "Approve Connection",
                    subtitle = "Authenticate to connect"
                )
            }.onFailure { if (BuildConfig.DEBUG) Log.e(TAG, "Biometric auth failed: ${it::class.simpleName}") }
                .getOrNull()

            if (authedCipher == null) {
                onComplete(false)
                finish()
                return@launch
            }

            val app = application as? KeepMobileApp
            val bunkerConfigStore = app?.getBunkerConfigStore()
            val permissionStore = app?.getPermissionStore()

            var queued = false
            try {
                if (!BunkerService.queueNostrConnectRequest(request)) {
                    if (BuildConfig.DEBUG) Log.w(TAG, "NostrConnect queue full")
                    onComplete(false)
                    finish()
                    return@launch
                }
                queued = true

                withContext(Dispatchers.IO) {
                    bunkerConfigStore?.authorizeClient(request.clientPubkey)

                    Nip46ClientStore.saveClient(
                        this@NostrConnectActivity,
                        request.clientPubkey,
                        request.name,
                        request.relays
                    )

                    if (duration.shouldPersist && request.permissions.isNotEmpty() && permissionStore != null) {
                        val callerPackage = "nip46:${request.clientPubkey}"
                        for (perm in request.permissions) {
                            val requestType = mapPermissionToRequestType(perm.type) ?: continue
                            permissionStore.grantPermission(
                                callerPackage = callerPackage,
                                requestType = requestType,
                                eventKind = perm.kind,
                                duration = duration
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e(TAG, "Persistence failed: ${e::class.simpleName}")
                if (queued) {
                    BunkerService.dequeueNostrConnectRequest(request)
                }
                withContext(Dispatchers.IO) {
                    runCatching { bunkerConfigStore?.revokeClient(request.clientPubkey) }
                    runCatching { Nip46ClientStore.removeClient(this@NostrConnectActivity, request.clientPubkey) }
                    if (permissionStore != null) {
                        val callerPackage = "nip46:${request.clientPubkey}"
                        for (perm in request.permissions) {
                            val requestType = mapPermissionToRequestType(perm.type) ?: continue
                            runCatching { permissionStore.revokePermission(callerPackage, requestType, perm.kind) }
                        }
                    }
                }
                onComplete(false)
                finish()
                return@launch
            }

            BunkerService.current()?.processQueuedNostrConnectRequests()
                ?: BunkerService.start(this@NostrConnectActivity)

            onComplete(true)
            finish()
        }
    }

    private fun handleReject() {
        finish()
    }

    companion object {
        private const val TAG = "NostrConnectActivity"
        private val HEX_PUBKEY_REGEX = Regex("^[a-fA-F0-9]{64}$")
        private val HEX_SECRET_REGEX = Regex("^[a-fA-F0-9]{1,64}$")

        fun parseNostrConnectUri(uri: Uri): NostrConnectRequest? {
            if (uri.scheme != "nostrconnect") return null

            val clientPubkey = uri.host ?: return null
            if (!HEX_PUBKEY_REGEX.matches(clientPubkey)) return null

            val relays = uri.getQueryParameters("relay")
                .filter { url ->
                    url.startsWith("wss://") &&
                    BunkerConfigStore.RELAY_URL_REGEX.matches(url) &&
                    !BunkerConfigStore.isInternalHost(url)
                }
            if (relays.isEmpty()) return null

            val secret = uri.getQueryParameter("secret")
            if (secret.isNullOrBlank() || !HEX_SECRET_REGEX.matches(secret)) return null

            val name = uri.getQueryParameter("name") ?: "Unknown App"
            val permsParam = uri.getQueryParameter("perms")
            val permissions = parsePermissions(permsParam)

            return NostrConnectRequest(
                clientPubkey = clientPubkey.lowercase(),
                relays = relays,
                secret = secret,
                name = sanitizeDisplayName(name),
                permissions = permissions
            )
        }

        private fun parsePermissions(perms: String?): List<RequestedPermission> {
            if (perms.isNullOrBlank()) return emptyList()
            return perms.split(",").mapNotNull { perm ->
                val parts = perm.trim().split(":")
                val type = parts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
                val kind = parts.getOrNull(1)?.toIntOrNull()
                if (kind != null && (kind < 0 || kind > 65535)) return@mapNotNull null
                RequestedPermission(type, kind)
            }
        }

        private fun sanitizeDisplayName(name: String): String {
            return name
                .replace(Regex("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]"), "")
                .replace(Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]"), "")
                .take(50)
                .ifBlank { "Unknown App" }
        }

        private fun mapPermissionToRequestType(type: String): Nip55RequestType? =
            mapMethodToNip55RequestType(type)
    }
}

data class NostrConnectRequest(
    val clientPubkey: String,
    val relays: List<String>,
    val secret: String,
    val name: String,
    val permissions: List<RequestedPermission>
) {
    override fun toString(): String = "NostrConnectRequest(clientPubkey=$clientPubkey, relays=$relays, secret=[REDACTED], name=$name, permissions=$permissions)"
}

data class RequestedPermission(
    val type: String,
    val kind: Int?
)
