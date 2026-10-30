package io.privkey.keep.approver

import android.content.Context
import android.os.SystemClock
import android.security.keystore.KeyPermanentlyInvalidatedException
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

    /** Resumes a pairing kept from an earlier run. Blocking. */
    fun startIfPaired() {
        val status = handler.status()
        if (status.paired || status.pairing) {
            runCatching { handler.start(callbacks) }
        }
        reload()
        if (_state.value.requests.isNotEmpty()) notifier.requestWaiting()
    }

    private fun reload() {
        val now = SystemClock.elapsedRealtime()
        val waiting = handler.waitingRequests().map {
            WaitingRequest(it, now + it.secondsLeft.toLong() * 1000)
        }
        _state.value = ApproverState(handler.status(), waiting)
    }

    private fun handle(event: ApproverEvent) {
        when (event) {
            is ApproverEvent.Paired -> notice(R.string.approver_notice_paired)
            is ApproverEvent.PairingRefused -> {
                ApproverKey.delete()
                notice(context.getString(R.string.approver_notice_pairing_refused, event.reason))
            }
            is ApproverEvent.Request -> {
                val deadline = SystemClock.elapsedRealtime() + event.request.secondsLeft.toLong() * 1000
                _state.update { s ->
                    s.copy(
                        requests = s.requests.filterNot { it.request.requestId == event.request.requestId } +
                            WaitingRequest(event.request, deadline)
                    )
                }
                notifier.requestWaiting()
                return
            }
            is ApproverEvent.RequestRefused ->
                notice(context.getString(R.string.approver_notice_request_refused, event.reason))
            is ApproverEvent.Outcome -> {
                removeRequest(event.requestId)
                notice(context.getString(R.string.approver_notice_outcome, event.outcome))
                return
            }
            is ApproverEvent.Anchor -> Unit
            is ApproverEvent.Alert -> notifier.alert()
        }
        reload()
    }

    private fun removeRequest(requestId: String) {
        _state.update { s -> s.copy(requests = s.requests.filterNot { it.request.requestId == requestId }) }
        if (_state.value.requests.isEmpty()) notifier.clearRequests()
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
        check(!handler.status().paired) { "already paired" }
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
        removeRequest(requestId)
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
        notifier.clearRequests()
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
            else -> context.getString(R.string.approver_error_generic)
        }
    }
}
