package io.privkey.keep.nip55

import java.util.concurrent.atomic.AtomicInteger

class EventLogStore(database: Nip55Database) {
    private val dao = database.eventLogDao()
    private val insertCounter = AtomicInteger(0)

    suspend fun log(category: EventLogCategory, level: EventLogLevel, source: String, message: String) {
        dao.insert(
            EventLogEntry(
                timestamp = System.currentTimeMillis(),
                category = category.name,
                level = level.name,
                source = source.take(MAX_SOURCE_LEN),
                message = message.take(MAX_MESSAGE_LEN)
            )
        )
        if (insertCounter.incrementAndGet() % TRIM_EVERY == 0) {
            dao.trimToMostRecent(RING_CAP)
        }
    }

    suspend fun getPage(limit: Int, offset: Int): List<EventLogEntry> =
        dao.getPage(limit.coerceIn(1, 100), offset.coerceAtLeast(0))

    suspend fun getRecent(limit: Int): List<EventLogEntry> =
        dao.getRecent(limit.coerceAtLeast(0))

    suspend fun getCount(): Int = dao.getCount()

    suspend fun clear() = dao.deleteAll()

    suspend fun cleanupOld(before: Long) = dao.deleteOlderThan(before)

    companion object {
        const val RING_CAP = 2000
        private const val TRIM_EVERY = 64
        private const val MAX_SOURCE_LEN = 256
        private const val MAX_MESSAGE_LEN = 1024
    }
}
