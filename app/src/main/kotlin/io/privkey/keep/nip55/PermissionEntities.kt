package io.privkey.keep.nip55

import android.os.SystemClock
import androidx.annotation.StringRes
import androidx.room.*
import io.privkey.keep.R

enum class PermissionDecision(@param:StringRes val displayNameRes: Int) {
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
    val createdAt: Long,
    val createdAtElapsed: Long = 0,
    val durationMs: Long? = null
) {
    fun isExpired(): Boolean = isExpired(
        currentElapsed = SystemClock.elapsedRealtime(),
        currentTimeMillis = System.currentTimeMillis()
    )

    fun isExpired(currentElapsed: Long, currentTimeMillis: Long): Boolean =
        isTimestampExpired(expiresAt, createdAt, createdAtElapsed, durationMs, currentElapsed, currentTimeMillis)

    val permissionDecision: PermissionDecision
        get() = PermissionDecision.fromString(decision)

    val eventKindOrNull: Int?
        get() = if (eventKind == EVENT_KIND_GENERIC) null else eventKind
}

@Entity(
    tableName = "nip55_audit_log",
    indices = [
        Index(value = ["callerPackage", "eventKind"]),
        Index(value = ["callerPackage", "timestamp"])
    ]
)
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
    val createdAt: Long,
    val createdAtElapsed: Long = 0,
    val durationMs: Long? = null
) {
    fun isExpired(): Boolean = isExpired(
        currentElapsed = SystemClock.elapsedRealtime(),
        currentTimeMillis = System.currentTimeMillis()
    )

    fun isExpired(currentElapsed: Long, currentTimeMillis: Long): Boolean =
        isTimestampExpired(expiresAt, createdAt, createdAtElapsed, durationMs, currentElapsed, currentTimeMillis)
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

enum class PermissionDuration(val millis: Long?, @param:StringRes val displayNameRes: Int) {
    JUST_THIS_TIME(null, R.string.permission_duration_just_this_time),
    ONE_MINUTE(60 * 1000L, R.string.permission_duration_one_minute),
    FIVE_MINUTES(5 * 60 * 1000L, R.string.permission_duration_five_minutes),
    TEN_MINUTES(10 * 60 * 1000L, R.string.permission_duration_ten_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.permission_duration_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.permission_duration_one_day),
    FOREVER(null, R.string.permission_duration_forever);

    @Deprecated("Use monotonic time via durationMs field instead")
    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }

    val shouldPersist: Boolean
        get() = this != JUST_THIS_TIME
}

enum class AppExpiryDuration(val millis: Long?, @param:StringRes val displayNameRes: Int) {
    FIVE_MINUTES(5 * 60 * 1000L, R.string.app_expiry_five_minutes),
    ONE_HOUR(60 * 60 * 1000L, R.string.app_expiry_one_hour),
    ONE_DAY(24 * 60 * 60 * 1000L, R.string.app_expiry_one_day),
    ONE_WEEK(7 * 24 * 60 * 60 * 1000L, R.string.app_expiry_one_week),
    NEVER(null, R.string.app_expiry_never);

    @Deprecated("Use monotonic time via durationMs field instead")
    fun expiresAt(): Long? = millis?.let { System.currentTimeMillis() + it }
}

data class ConnectedAppInfo(
    val packageName: String,
    val permissionCount: Int,
    val lastUsedTime: Long?,
    val expiresAt: Long?
)

internal fun isTimestampExpired(
    expiresAt: Long?,
    createdAt: Long,
    createdAtElapsed: Long,
    durationMs: Long?,
    currentElapsed: Long,
    currentTimeMillis: Long
): Boolean {
    if (expiresAt == null && durationMs == null) return false

    if (durationMs != null) {
        if (createdAtElapsed > 0) {
            if (currentElapsed < createdAtElapsed) return true
            val elapsed = currentElapsed - createdAtElapsed
            if (elapsed >= durationMs) return true
        } else {
            val wallClockExpiry = createdAt + durationMs
            if (currentTimeMillis >= wallClockExpiry) return true
        }
    }

    if (expiresAt != null) {
        val clockManipulated = currentTimeMillis < createdAt
        if (clockManipulated || expiresAt <= currentTimeMillis) return true
    }

    return false
}
