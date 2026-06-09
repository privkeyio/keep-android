package io.privkey.keep.nip55

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

enum class EventLogCategory { RELAY, BUNKER, PEER }

enum class EventLogLevel { INFO, WARN, ERROR }

@Entity(
    tableName = "event_log",
    indices = [
        Index(value = ["timestamp"]),
        Index(value = ["category", "timestamp"])
    ]
)
data class EventLogEntry(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val category: String,
    val level: String,
    val source: String = "",
    val message: String = ""
)
