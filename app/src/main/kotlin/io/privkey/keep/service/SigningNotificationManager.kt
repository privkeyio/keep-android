package io.privkey.keep.service

import android.annotation.SuppressLint
import android.Manifest
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

        val effectiveRequestId = requestId ?: generateRequestId()
        val notificationId = notificationIdCounter.getAndIncrement()
        requestIdToNotificationId[effectiveRequestId] = notificationId

        pendingRequestData[effectiveRequestId] = PendingRequestInfo(intentUri, requestId)

        val callerLabel = callerPackage?.let { getAppLabel(it) ?: it } ?: "Unknown app"

        val intent = Intent(context, SigningNotificationReceiver::class.java).apply {
            action = ACTION_OPEN_SIGNING_REQUEST
            putExtra(EXTRA_REQUEST_ID, effectiveRequestId)
        }

        val pendingIntent = PendingIntent.getBroadcast(
            context,
            notificationId,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val deleteIntent = Intent(context, SigningNotificationReceiver::class.java).apply {
            action = ACTION_DISMISS_REQUEST
            putExtra(EXTRA_REQUEST_ID, effectiveRequestId)
        }
        val deletePendingIntent = PendingIntent.getBroadcast(
            context,
            notificationId + DISMISS_REQUEST_CODE_OFFSET,
            deleteIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(requestType.headerTitle())
            .setContentText("Request from $callerLabel")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setDeleteIntent(deletePendingIntent)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .build()

        NotificationManagerCompat.from(context).notify(notificationId, notification)
        return effectiveRequestId
    }

    fun cancelNotification(requestId: String?) {
        if (requestId == null) return
        val notificationId = requestIdToNotificationId.remove(requestId) ?: return
        pendingRequestData.remove(requestId)
        notificationManager.cancel(notificationId)
    }

    fun getPendingRequestInfo(requestId: String): PendingRequestInfo? {
        requestIdToNotificationId.remove(requestId)
        return pendingRequestData.remove(requestId)
    }

    private fun generateRequestId(): String {
        return "generated-${System.nanoTime()}"
    }

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

    data class PendingRequestInfo(
        val intentUri: String,
        val originalRequestId: String?,
        val createdAt: Long = System.currentTimeMillis()
    )

    fun removeRequest(requestId: String) {
        requestIdToNotificationId.remove(requestId)
        pendingRequestData.remove(requestId)
    }

    fun cleanupStaleEntries(maxAgeMillis: Long = DEFAULT_MAX_AGE_MILLIS) {
        val now = System.currentTimeMillis()
        val staleRequestIds = pendingRequestData.entries
            .filter { now - it.value.createdAt > maxAgeMillis }
            .map { it.key }

        staleRequestIds.forEach { requestId ->
            val notificationId = requestIdToNotificationId.remove(requestId)
            pendingRequestData.remove(requestId)
            notificationId?.let { notificationManager.cancel(it) }
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
    }
}
