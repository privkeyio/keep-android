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
 * Surfaces incoming FROST co-sign requests as a high-priority, lock-screen
 * notification so the operator sees them immediately, even when the app is
 * backgrounded or the phone is locked, and can approve/reject inline or tap
 * through to the app.
 */
object CosignNotifier {
    private const val CHANNEL_ID = "cosign_requests"
    const val NOTIFICATION_ID = 0x4B50
    const val ACTION_APPROVE = "io.privkey.keep.COSIGN_APPROVE"
    const val ACTION_REJECT = "io.privkey.keep.COSIGN_REJECT"
    const val EXTRA_REQUEST_ID = "cosign_request_id"
    private val notified = mutableSetOf<String>()

    private fun actionIntent(context: Context, action: String, requestId: String, code: Int) =
        PendingIntent.getBroadcast(
            context,
            code,
            Intent(context, CosignActionReceiver::class.java)
                .setAction(action)
                .putExtra(EXTRA_REQUEST_ID, requestId),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

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
        val body = describe(first)
        val title = if (pending.size > 1) {
            context.getString(R.string.cosign_notification_title_multi, pending.size)
        } else {
            context.getString(R.string.cosign_notification_title)
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(contentIntent)
            .setFullScreenIntent(contentIntent, true)
            .setAutoCancel(true)
            // Approve/reject the (most recent) request straight from the
            // notification, without opening the app.
            .addAction(
                R.drawable.ic_notification,
                context.getString(R.string.cosign_approve),
                actionIntent(context, ACTION_APPROVE, first.id, 1),
            )
            .addAction(
                R.drawable.ic_notification,
                context.getString(R.string.cosign_reject),
                actionIntent(context, ACTION_REJECT, first.id, 2),
            )
            .build()

        runCatching { NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification) }
    }

    /** A short, human-readable summary of what is being signed. */
    private fun describe(req: SignRequest): String {
        val m = req.metadata
        val sats = m?.amountSats
        if (sats != null) {
            val dest = m.destination?.takeIf { it.isNotBlank() }
            return if (dest != null) "$sats sats to $dest" else "$sats sats"
        }
        val content = m?.contentPreview?.takeIf { it.isNotBlank() }
            ?: req.messagePreview.takeIf { it.isNotBlank() }
        val kind = m?.eventKind
        return buildString {
            if (kind != null) append("kind $kind")
            if (content != null) {
                if (isNotEmpty()) append(" · ")
                append(content)
            }
            if (isEmpty()) append(req.messageType)
        }
    }

    /** Brief acknowledgement after the operator acts, so it feels confirmed. */
    fun confirm(context: Context, approved: Boolean) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        ensureChannel(nm)
        val title = context.getString(
            if (approved) R.string.cosign_confirm_approved else R.string.cosign_confirm_rejected,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setAutoCancel(true)
            .setTimeoutAfter(4000L)
            .build()
        notified.clear()
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
