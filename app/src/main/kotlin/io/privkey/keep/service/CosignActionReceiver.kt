package io.privkey.keep.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.uniffi.SignRequest

/**
 * Handles Approve/Reject taps on the co-sign heads-up notification, so the
 * operator can act without opening the app. Calling `approveRequest` /
 * `rejectRequest` unblocks the waiting `pre_sign` on the FROST node.
 */
/**
 * Approves [requestId] from a notification action only if it is still among [pending] and
 * is not a spend, so an intent left over from an earlier notification cannot approve a
 * spend or a request that has since changed. Returns whether it approved.
 */
internal fun approveFromNotification(
    pending: List<SignRequest>?,
    requestId: String,
    approve: (String) -> Unit,
): Boolean {
    val request = pending?.find { it.id == requestId } ?: return false
    if (!CosignNotifier.approvableFromNotification(request)) return false
    approve(requestId)
    return true
}

class CosignActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val requestId = intent.getStringExtra(CosignNotifier.EXTRA_REQUEST_ID) ?: return
        val app = context.applicationContext as? KeepMobileApp ?: return
        val mobile = app.getKeepMobile() ?: return
        val appContext = context.applicationContext

        // The FFI call may block briefly; do it off the broadcast's main thread.
        val pending = goAsync()
        Thread {
            try {
                val approved = action == CosignNotifier.ACTION_APPROVE
                val result = when (action) {
                    CosignNotifier.ACTION_APPROVE -> runCatching {
                        check(approveFromNotification(app.liveState?.pendingRequests, requestId, mobile::approveRequest)) {
                            "co-sign approve refused outside the app"
                        }
                    }
                    CosignNotifier.ACTION_REJECT -> runCatching { mobile.rejectRequest(requestId) }
                    else -> return@Thread
                }
                if (result.isSuccess) {
                    runCatching { CosignNotifier.confirm(appContext, approved) }
                } else {
                    // Leave the original request notification up so the operator can
                    // retry; do not signal a false "done".
                    Log.w(TAG, "co-sign action failed", result.exceptionOrNull())
                }
            } finally {
                pending.finish()
            }
        }.start()
    }

    private companion object {
        const val TAG = "CosignActionReceiver"
    }
}
