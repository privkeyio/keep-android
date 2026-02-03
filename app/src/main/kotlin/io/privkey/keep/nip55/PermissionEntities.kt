package io.privkey.keep.nip55

import android.os.SystemClock
import android.util.Log
import androidx.annotation.StringRes
import androidx.annotation.VisibleForTesting
import androidx.room.*
import io.privkey.keep.R

object MonotonicClock {
    @Volatile
    @VisibleForTesting
    var testTimeOverride: Long? = null

    fun now(): Long = testTimeOverride ?: SystemClock.elapsedRealtime()
}

enum class PermissionDecision(@StringRes val displayNameRes: Int) {
    ALLOW(R.string.permission_decision_allow),
    DENY(R.string.permission_decision_deny),
    ASK(R.string.permission_decision_ask);

    companion object {
        fun fromString(value: String): PermissionDecision = when (value.lowercase()) {
            "allow" -> ALLOW
            "deny" -> DENY
            "ask" -> ASK
            else -> DENY
        }
    }

    override fun toString(): String = name.lowercase()
}

const val EVENT_KIND_GENERIC = -1

@Entity(
    tableName = "nip55_permissions",
    indices = [Index(value = ["callerPackage", "requestType", "eventKind"], unique = true)]
)
data class Nip55Permission(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val callerPackage: String,
    val requestType: String,
    val eventKind: Int = EVENT_KIND_GENERIC,
    val decision: String,
    val expiresAt: Long?,
    val createdAt: Long
) {
    fun isExpired(): Boolean = isTimestampExpired(expiresAt, createdAt)

    val permissionDecision: PermissionDecision
        get() = PermissionDecision.fromString(decision)

    val eventKindOrNull: Int?
        get() = if (eventKind == EVENT_KIND_GENERIC) null else eventKind
}

@Entity(tableName = "nip55_audit_log")
data class Nip55AuditLog(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val callerPackage: String,
    val requestType: String,
    val eventKind: Int?,
    val decision: String,
    val wasAutomatic: Boolean,
    val previousHash: String? = null,
    val entryHash: String = ""
)

@Entity(
    tableName = "velocity_tracker",
    indices = [Index(value = ["packageName", "timestamp"])]
)
data class VelocityEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val timestamp: Long,
    val eventKind: Int?
)

@Entity(tableName = "nip55_app_settings")
data class Nip55AppSettings(
    @PrimaryKey val callerPackage: String,
    val expiresAt: Long?,
    val signPolicyOverride: Int?,
    val createdAt: Long
) {
    fun isExpired(): Boolean = isTimestampExpired(expiresAt, createdAt)
}

data class VelocityConfig(
    val hourlyLimit: Int = 100,
    val dailyLimit: Int = 500,
    val weeklyLimit: Int = 2000,
    val enabled: Boolean = true
)

sealed class VelocityResult {
    data object Allowed : VelocityResult()
    data class Blocked(val reason: String, val resetAt: Long) : VelocityResult()
}

sealed class ChainVerificationResult {
    data object Valid : ChainVerificationResult()
    data class PartiallyVerified(val legacyEntriesSkipped: Int) : ChainVerificationResult()
    data class Truncated(val entryId: Long) : ChainVerificationResult()
    data class Broken(val entryId: Long) : ChainVerificationResult()
    data class Tampered(val entryId: Long) : ChainVerificationResult()
}

enum class PermissionDuration(val millis: Long?, @StringRes val displayNameRes: Int) {
    JUST_THIS_TIME(null, R.string.permission_duration_just_this_time),
    ONE_MINUTE(60 * 1000L, R.string.permission_duration_one_minute),
    FIVE_MINUTES(5 * 60 * 1000L, R.string.permission_duration_five_minutes),
    TEN_MINUTES(10 * 60 * 1000L, R.string.permission_duration_ten_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.permission_duration_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.permission_duration_one_day),
    FOREVER(null, R.string.permission_duration_forever);

    fun expiresAt(): Long? = millis?.let { MonotonicClock.now() + it }

    val shouldPersist: Boolean
        get() = this != JUST_THIS_TIME
}

enum class AppExpiryDuration(val millis: Long?, @StringRes val displayNameRes: Int) {
    FIVE_MINUTES(5 * 60 * 1000L, R.string.app_expiry_five_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.app_expiry_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.app_expiry_one_day),
    ONE_WEEK(7 * 24 * 60 * 60 * 1000L, R.string.app_expiry_one_week),
    NEVER(null, R.string.app_expiry_never);

    fun expiresAt(): Long? = millis?.let { MonotonicClock.now() + it }
}

data class ConnectedAppInfo(
    val packageName: String,
    val permissionCount: Int,
    val lastUsedTime: Long?,
    val expiresAt: Long?
)

private const val CLOCK_JUMP_THRESHOLD_MS = 60 * 60 * 1000L

internal fun isTimestampExpired(expiresAt: Long?, createdAt: Long): Boolean {
    if (expiresAt == null) return false
    val now = MonotonicClock.now()
    if (now < createdAt) {
        val jumpMs = createdAt - now
        if (jumpMs > CLOCK_JUMP_THRESHOLD_MS) {
            Log.w("PermissionExpiry", "Large clock jump detected: ${jumpMs}ms backward from createdAt")
        }
        return true
    }
    return expiresAt <= now
}
