package io.privkey.keep.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import io.privkey.keep.MainActivity
import io.privkey.keep.R
import io.privkey.keep.uniffi.SignRequest

/**
 * Surfaces incoming FROST co-sign requests as a high-priority heads-up
 * notification so the operator sees them immediately — even when the app is
 * backgrounded — and can tap straight through to approve. Mirrors how Amber
 * surfaces signing requests.
 */
object CosignNotifier {
    private const val CHANNEL_ID = "cosign_requests"
    private const val NOTIFICATION_ID = 0x4B50
    private val notified = mutableSetOf<String>()

    fun update(context: Context, pending: List<SignRequest>) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        ensureChannel(nm)

        if (pending.isEmpty()) {
            notified.clear()
            NotificationManagerCompat.from(context).cancel(NOTIFICATION_ID)
            return
        }

        // Only buzz when a genuinely new request arrives; keep the notification
        // up (without re-alerting) while requests remain pending.
        val ids = pending.map { it.id }
        val hasNew = ids.any { it !in notified }
        notified.retainAll(ids.toSet())
        notified.addAll(ids)
        if (!hasNew) return

        val intent = Intent(context, MainActivity::class.java).addFlags(
            Intent.FLAG_ACTIVITY_NEW_TASK or
                Intent.FLAG_ACTIVITY_SINGLE_TOP or
                Intent.FLAG_ACTIVITY_CLEAR_TOP,
        )
        val contentIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val first = pending.first()
        val preview = first.metadata?.contentPreview?.takeIf { it.isNotBlank() }
            ?: first.messagePreview.takeIf { it.isNotBlank() }
            ?: first.messageType
        val title = if (pending.size > 1) {
            context.getString(R.string.cosign_notification_title_multi, pending.size)
        } else {
            context.getString(R.string.cosign_notification_title)
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(preview)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .build()

        runCatching { NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification) }
    }

    private fun ensureChannel(nm: NotificationManager) {
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Co-sign requests",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "FROST co-signing approval requests"
                enableVibration(true)
            },
        )
    }
}
