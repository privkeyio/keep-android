package io.privkey.keep.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.privkey.keep.KeepMobileApp

/**
 * Handles Approve/Reject taps on the co-sign heads-up notification, so the
 * operator can act without opening the app. Calling `approveRequest` /
 * `rejectRequest` unblocks the waiting `pre_sign` on the FROST node.
 */
class CosignActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val requestId = intent.getStringExtra(CosignNotifier.EXTRA_REQUEST_ID) ?: return
        val mobile = (context.applicationContext as? KeepMobileApp)?.getKeepMobile() ?: return
        val appContext = context.applicationContext

        // The FFI call may block briefly; do it off the broadcast's main thread.
        val pending = goAsync()
        Thread {
            try {
                val approved = action == CosignNotifier.ACTION_APPROVE
                when (action) {
                    CosignNotifier.ACTION_APPROVE -> runCatching { mobile.approveRequest(requestId) }
                    CosignNotifier.ACTION_REJECT -> runCatching { mobile.rejectRequest(requestId) }
                    else -> return@Thread
                }
                runCatching { CosignNotifier.confirm(appContext, approved) }
            } finally {
                pending.finish()
            }
        }.start()
    }
}
