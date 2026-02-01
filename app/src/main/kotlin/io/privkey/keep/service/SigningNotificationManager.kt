package io.privkey.keep.service

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.privkey.keep.R
import io.privkey.keep.nip55.headerTitle
import io.privkey.keep.uniffi.Nip55RequestType
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

class SigningNotificationManager(private val context: Context) {
    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    private val notificationIdCounter = AtomicInteger(NOTIFICATION_ID_START)
    private val requestIdToNotificationId = ConcurrentHashMap<String, Int>()
    private val pendingRequestData = ConcurrentHashMap<String, PendingRequestInfo>()

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_signing_requests),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = context.getString(R.string.notification_channel_signing_requests_description)
            setShowBadge(true)
            enableVibration(true)
            enableLights(true)
        }
        notificationManager.createNotificationChannel(channel)
    }

    @SuppressLint("MissingPermission") // Permission is checked at function entry
    fun showSigningRequest(
        requestType: Nip55RequestType,
        callerPackage: String?,
        intentUri: String,
        requestId: String?
    ): String? {
        if (!hasNotificationPermission()) return null

        // Enforce maximum pending requests to prevent memory exhaustion
        if (pendingRequestData.size >= MAX_PENDING_REQUESTS) {
            cleanupStaleEntries()
            if (pendingRequestData.size >= MAX_PENDING_REQUESTS) {
                return null
            }
        }

        val effectiveRequestId = requestId ?: generateRequestId()
        val notificationId = notificationIdCounter.getAndIncrement()
        requestIdToNotificationId[effectiveRequestId] = notificationId

        pendingRequestData[effectiveRequestId] = PendingRequestInfo(intentUri, requestId)

        val callerLabel = callerPackage?.let { getAppLabel(it) ?: it } ?: "Unknown app"

        val contentIntent = createBroadcastIntent(ACTION_OPEN_SIGNING_REQUEST, effectiveRequestId, notificationId)
        val deleteIntent = createBroadcastIntent(ACTION_DISMISS_REQUEST, effectiveRequestId, notificationId + DISMISS_REQUEST_CODE_OFFSET)

        val publicNotification = buildNotification(
            title = context.getString(R.string.app_name),
            text = context.getString(R.string.notification_signing_request_pending),
            contentIntent = contentIntent
        )

        val notification = buildNotification(
            title = requestType.headerTitle(),
            text = context.getString(R.string.notification_request_from, callerLabel),
            contentIntent = contentIntent,
            deleteIntent = deleteIntent,
            visibility = NotificationCompat.VISIBILITY_SECRET,
            publicVersion = publicNotification
        )

        NotificationManagerCompat.from(context).notify(notificationId, notification)
        return effectiveRequestId
    }

    fun cancelNotification(requestId: String?) {
        val notificationId = requestId?.let { removeRequest(it) } ?: return
        notificationManager.cancel(notificationId)
    }

    fun getPendingRequestInfo(requestId: String): PendingRequestInfo? {
        requestIdToNotificationId.remove(requestId)
        return pendingRequestData.remove(requestId)
    }

    private fun generateRequestId(): String = UUID.randomUUID().toString()

    private fun hasNotificationPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun getAppLabel(packageName: String): String? {
        return try {
            val appInfo = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(appInfo).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    private fun createBroadcastIntent(action: String, requestId: String, requestCode: Int): PendingIntent {
        val intent = Intent(context, SigningNotificationReceiver::class.java).apply {
            this.action = action
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        return PendingIntent.getBroadcast(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun buildNotification(
        title: String,
        text: String,
        contentIntent: PendingIntent,
        deleteIntent: PendingIntent? = null,
        visibility: Int = NotificationCompat.VISIBILITY_SECRET,
        publicVersion: Notification? = null
    ): Notification {
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .apply {
                deleteIntent?.let { setDeleteIntent(it) }
                publicVersion?.let { setPublicVersion(it) }
                setVisibility(visibility)
            }
            .build()
    }

    data class PendingRequestInfo(
        val intentUri: String,
        val originalRequestId: String?,
        val createdAt: Long = System.currentTimeMillis()
    )

    fun removeRequest(requestId: String): Int? {
        pendingRequestData.remove(requestId)
        return requestIdToNotificationId.remove(requestId)
    }

    fun cleanupStaleEntries(maxAgeMillis: Long = DEFAULT_MAX_AGE_MILLIS) {
        val now = System.currentTimeMillis()
        pendingRequestData.entries
            .filter { now - it.value.createdAt > maxAgeMillis }
            .forEach { (requestId, _) ->
                removeRequest(requestId)?.let { notificationManager.cancel(it) }
            }
    }

    companion object {
        const val CHANNEL_ID = "signing_requests"
        const val ACTION_OPEN_SIGNING_REQUEST = "io.privkey.keep.action.OPEN_SIGNING_REQUEST"
        const val ACTION_DISMISS_REQUEST = "io.privkey.keep.action.DISMISS_REQUEST"
        const val EXTRA_REQUEST_ID = "extra_request_id"
        private const val NOTIFICATION_ID_START = 1000
        private const val DISMISS_REQUEST_CODE_OFFSET = 100000
        private const val DEFAULT_MAX_AGE_MILLIS = 24 * 60 * 60 * 1000L // 24 hours
        private const val MAX_PENDING_REQUESTS = 100
    }
}
