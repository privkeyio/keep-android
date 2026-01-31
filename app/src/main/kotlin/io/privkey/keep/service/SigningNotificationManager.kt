package io.privkey.keep.service

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

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(requestType.notificationTitle())
            .setContentText("Request from $callerLabel")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
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

    private fun Nip55RequestType.notificationTitle(): String = when (this) {
        Nip55RequestType.GET_PUBLIC_KEY -> "Public Key Request"
        Nip55RequestType.SIGN_EVENT -> "Signing Request"
        Nip55RequestType.NIP44_ENCRYPT, Nip55RequestType.NIP04_ENCRYPT -> "Encryption Request"
        Nip55RequestType.NIP44_DECRYPT, Nip55RequestType.NIP04_DECRYPT -> "Decryption Request"
        Nip55RequestType.DECRYPT_ZAP_EVENT -> "Zap Decryption Request"
    }

    data class PendingRequestInfo(
        val intentUri: String,
        val originalRequestId: String?
    )

    companion object {
        const val CHANNEL_ID = "signing_requests"
        const val ACTION_OPEN_SIGNING_REQUEST = "io.privkey.keep.action.OPEN_SIGNING_REQUEST"
        const val EXTRA_REQUEST_ID = "extra_request_id"
        private const val NOTIFICATION_ID_START = 1000
    }
}
