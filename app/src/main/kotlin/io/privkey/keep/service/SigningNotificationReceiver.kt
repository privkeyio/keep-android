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
                val requestInfo = notificationManager.getPendingRequestInfo(requestId) ?: return

                val activityIntent = Intent(Intent.ACTION_VIEW, Uri.parse(requestInfo.intentUri)).apply {
                    setPackage(context.packageName)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    requestInfo.originalRequestId?.let { putExtra("id", it) }
                }

                context.startActivity(activityIntent)
            }
            SigningNotificationManager.ACTION_DISMISS_REQUEST -> {
                notificationManager.removeRequest(requestId)
            }
        }
    }
}
