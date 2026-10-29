package io.privkey.keep.approver

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.privkey.keep.MainActivity
import io.privkey.keep.R

/**
 * Says that a request is waiting or that the gateway needs attention, and nothing more:
 * no request content, and no action that approves or denies. Tapping opens the app.
 */
internal class ApproverNotifier(private val context: Context) {
    private val manager = NotificationManagerCompat.from(context)

    init {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.approver_notification_channel),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = context.getString(R.string.approver_notification_channel_description)
        }
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    fun requestWaiting() = post(REQUEST_ID, R.string.approver_notification_request)

    fun alert() = post(ALERT_ID, R.string.approver_notification_alert)

    fun clearRequests() = manager.cancel(REQUEST_ID)

    @SuppressLint("MissingPermission")
    private fun post(id: Int, textRes: Int) {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) return
        val intent = Intent(context, MainActivity::class.java)
            .setAction(ACTION_SHOW_APPROVER)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val contentIntent = PendingIntent.getActivity(
            context, id, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val text = context.getString(textRes)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(context.getString(R.string.approver_notification_title))
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .build()
        manager.notify(id, notification)
    }

    companion object {
        const val ACTION_SHOW_APPROVER = "io.privkey.keep.action.SHOW_APPROVER"
        private const val CHANNEL_ID = "agent_approvals"
        private const val REQUEST_ID = 0x4B41
        private const val ALERT_ID = 0x4B42
    }
}
