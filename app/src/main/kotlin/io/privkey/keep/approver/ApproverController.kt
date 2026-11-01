package io.privkey.keep.approver

import android.content.Context
import android.os.SystemClock
import android.security.keystore.KeyPermanentlyInvalidatedException
import io.privkey.keep.BiometricHelper
import io.privkey.keep.R
import io.privkey.keep.uniffi.ApprovalRequest
import io.privkey.keep.uniffi.ApproverCallbacks
import io.privkey.keep.uniffi.ApproverEvent
import io.privkey.keep.uniffi.ApproverHandler
import io.privkey.keep.uniffi.ApproverStatus
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.KeepMobileException
import io.privkey.keep.uniffi.PairingStart
import java.security.Signature
import java.security.SignatureException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/** A request waiting for the owner, with its deadline on the phone's monotonic clock. */
data class WaitingRequest(val request: ApprovalRequest, val deadlineElapsedMs: Long) {
    fun secondsLeft(nowElapsedMs: Long = SystemClock.elapsedRealtime()): Long =
        ((deadlineElapsedMs - nowElapsedMs) / 1000).coerceAtLeast(0)
}

data class ApproverState(
    val status: ApproverStatus? = null,
    val requests: List<WaitingRequest> = emptyList(),
    /** Why serving the pairing could not start, until a start succeeds. */
    val startError: String? = null,
)

/** Why an approver key signature could not be made. */
class ApproverKeyInvalidatedException : Exception()

/**
 * The app's side of agent approvals: holds the one [ApproverHandler] for the process,
 * turns its events into state for the screen, and posts a notification that only says
 * something is waiting. Every approver key signature goes through [sign].
 */
class ApproverController(private val context: Context, mobile: KeepMobile) {
    private val handler = ApproverHandler(mobile)
    private val notifier = ApproverNotifier(context)

    private val _state = MutableStateFlow(ApproverState())
    val state: StateFlow<ApproverState> = _state.asStateFlow()

    private val _notices = MutableSharedFlow<String>(extraBufferCapacity = 16)
    val notices: SharedFlow<String> = _notices.asSharedFlow()

    private val callbacks = object : ApproverCallbacks {
        override fun onEvent(event: ApproverEvent) = handle(event)
    }

    /**
     * Shows the kept pairing, then starts serving it. Blocking: the start waits on the
     * relays, so the state, freeze included, is published before it.
     */
    fun startIfPaired() {
        reload()
        val status = _state.value.status ?: return
        if (!status.paired && !status.pairing) return
        val error = runCatching { handler.start(callbacks) }.exceptionOrNull()
        _state.update { it.copy(startError = error?.let { e -> errorText(context, e) }) }
        reload()
        if (_state.value.requests.isNotEmpty()) notifier.requestWaiting()
    }

    suspend fun retryStart() = io { startIfPaired() }

    // The core's state is the only truth: every change rereads all of it, and the read and
    // the write happen together, so an older read can never overwrite a newer one.
    private fun reload() = synchronized(this) {
        val now = SystemClock.elapsedRealtime()
        val waiting = handler.waitingRequests().map {
            WaitingRequest(it, now + it.secondsLeft.toLong() * 1000)
        }
        val status = handler.status()
        _state.update { it.copy(status = status, requests = waiting) }
        if (waiting.isEmpty()) notifier.clearRequests()
        if (status.alerts.isEmpty()) notifier.clearAlert()
    }

    private fun handle(event: ApproverEvent) {
        reload()
        when (event) {
            is ApproverEvent.Paired -> notice(R.string.approver_notice_paired)
            is ApproverEvent.PairingRefused -> {
                // Only the key of the pairing that ended goes: a pairing begun since has its own.
                if (event.ended && runCatching { ApproverKey.publicKey() }.getOrNull()?.contentEquals(event.approverKey) == true) {
                    ApproverKey.delete()
                }
                notice(context.getString(R.string.approver_notice_pairing_refused, event.reason))
            }
            is ApproverEvent.Request -> notifier.requestWaiting()
            // The reload above drops it from the waiting list, and a repeat after a restart is nothing new.
            is ApproverEvent.RequestExpired -> Unit
            is ApproverEvent.RequestRefused ->
                notice(context.getString(R.string.approver_notice_request_refused, event.reason))
            is ApproverEvent.Outcome ->
                notice(context.getString(R.string.approver_notice_outcome, event.outcome))
            is ApproverEvent.Anchor -> Unit
            is ApproverEvent.Alert -> notifier.alert()
        }
    }

    private fun notice(resId: Int) = notice(context.getString(resId))

    private fun notice(text: String) {
        _notices.tryEmit(text)
    }

    /**
     * Has the Keystore sign [digest] with the approver key, once [authenticate] has unlocked
     * the Signature with a strong biometric. Returns the DER signature, or null when the
     * owner cancels.
     */
    suspend fun sign(
        digest: ByteArray,
        authenticate: suspend (Signature) -> Signature?,
    ): ByteArray? {
        val signer = withContext(Dispatchers.IO) {
            try {
                ApproverKey.signer()
            } catch (e: KeyPermanentlyInvalidatedException) {
                throw ApproverKeyInvalidatedException()
            }
        }
        val unlocked = authenticate(signer) ?: return null
        return withContext(Dispatchers.IO) {
            unlocked.update(digest)
            unlocked.sign()
        }
    }

    suspend fun beginPairing(uri: String, label: String): PairingStart = io {
        val status = handler.status()
        check(!status.paired && !status.pairing) { "already paired" }
        val challenge = handler.pairingAttestationChallenge(uri)
        ApproverKey.generate(context, challenge)
        handler.beginPairing(uri, ApproverKey.publicKey(), label)
    }

    suspend fun finishPairing(signature: ByteArray) = io {
        try {
            handler.finishPairing(signature, ApproverKey.attestation(), callbacks)
        } finally {
            reload()
        }
    }

    suspend fun decisionDigest(requestId: String, approve: Boolean): ByteArray =
        io { handler.decisionDigest(requestId, approve) }

    suspend fun sendDecision(requestId: String, approve: Boolean, signature: ByteArray) = io {
        handler.sendDecision(requestId, approve, signature)
        reload()
    }

    suspend fun freeze(credential: String?) = io {
        handler.freeze(credential)
        reload()
    }

    suspend fun unfreezeDigest(credential: String?): ByteArray = io { handler.unfreezeDigest(credential) }

    suspend fun sendUnfreeze(credential: String?, signature: ByteArray) = io {
        handler.sendUnfreeze(credential, signature)
        reload()
    }

    suspend fun acknowledgeAlerts(throughSeq: ULong) = io {
        handler.acknowledgeAlerts(throughSeq)
        reload()
    }

    suspend fun forget() = io {
        handler.forget()
        ApproverKey.delete()
        _state.update { it.copy(startError = null) }
        reload()
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    companion object {
        /** The text to show for a failed approver call. */
        fun errorText(context: Context, e: Throwable): String = when (e) {
            is KeepMobileException.InvalidInput -> e.msg
            is KeepMobileException.InvalidRelayUrl -> e.msg
            is ApproverKeyInvalidatedException -> context.getString(R.string.approver_error_key_invalidated)
            // A finger on the sensor before the prompt is shown can authenticate without
            // authorizing this signature; the Keystore then refuses it.
            is SignatureException -> context.getString(R.string.approver_error_try_again)
            is BiometricHelper.BiometricException -> e.message ?: context.getString(R.string.approver_error_generic)
            is KeepMobileException.NetworkException -> context.getString(R.string.approver_error_network, e.msg)
            is KeepMobileException.CertificatePinMismatch -> context.getString(R.string.approver_error_pin_mismatch)
            else -> context.getString(R.string.approver_error_generic)
        }
    }
}
