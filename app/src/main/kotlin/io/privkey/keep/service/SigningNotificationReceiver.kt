package io.privkey.keep.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import io.privkey.keep.KeepMobileApp

class SigningNotificationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val requestId = intent.getStringExtra(SigningNotificationManager.EXTRA_REQUEST_ID) ?: return
        val app = context.applicationContext as? KeepMobileApp ?: return
        val notificationManager = app.getSigningNotificationManager() ?: return

        when (intent.action) {
            SigningNotificationManager.ACTION_OPEN_SIGNING_REQUEST -> {
                val requestInfo = notificationManager.popPendingRequestInfo(requestId) ?: return

                val uri = Uri.parse(requestInfo.intentUri)
                if (uri.scheme != "nostrsigner") return

                val callerVerificationStore = app.getCallerVerificationStore()
                val nonce = requestInfo.callerPackage?.let { callerVerificationStore?.generateNonce(it) }

                val activityIntent = Intent(Intent.ACTION_VIEW, uri).apply {
                    setPackage(context.packageName)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    requestInfo.originalRequestId?.let { putExtra("id", it) }
                    nonce?.let { putExtra("nip55_nonce", it) }
                }

                if (activityIntent.resolveActivity(context.packageManager) != null) {
                    context.startActivity(activityIntent)
                }
            }
            SigningNotificationManager.ACTION_DISMISS_REQUEST -> {
                notificationManager.removeRequest(requestId)
            }
        }
    }
}
