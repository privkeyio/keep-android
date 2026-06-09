package io.privkey.keep.nip55

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface EventLogDao {
    @Insert
    suspend fun insert(entry: EventLogEntry): Long

    @Query("SELECT * FROM event_log ORDER BY id DESC LIMIT :limit OFFSET :offset")
    suspend fun getPage(limit: Int, offset: Int): List<EventLogEntry>

    @Query("SELECT * FROM event_log ORDER BY id DESC LIMIT :limit")
    suspend fun getRecent(limit: Int): List<EventLogEntry>

    @Query("SELECT COUNT(*) FROM event_log")
    suspend fun getCount(): Int

    @Query("DELETE FROM event_log WHERE timestamp < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM event_log")
    suspend fun deleteAll()

    @Query("DELETE FROM event_log WHERE id < (SELECT MIN(id) FROM (SELECT id FROM event_log ORDER BY id DESC LIMIT :cap))")
    suspend fun trimToMostRecent(cap: Int)
}
