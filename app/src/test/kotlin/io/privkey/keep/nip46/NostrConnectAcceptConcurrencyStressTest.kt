package io.privkey.keep.nip46

import io.privkey.keep.uniffi.KeepMobileException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * Real-thread stress of [acceptAndAdmit] against a model of BunkerService's revoke path:
 * the generation moves and clientRevokedAt is set under the config lock before the engine
 * revoke runs, which drops the client from the core's listing and the cache. An accept takes
 * the same lock twice: to hold its key and read the generation, and to admit.
 */
class NostrConnectAcceptConcurrencyStressTest {

    private val pk = "ab".repeat(32)
    private val other = "cd".repeat(32)

    private class Model {
        val lock = Mutex()
        val generation = AtomicLong()
        val everyClientRevokedAt = AtomicLong()
        val clientRevokedAt = ConcurrentHashMap<String, Long>()
        val holds = ConcurrentHashMap<String, Any>()
        val cache: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())
        val listed: MutableSet<String> = ConcurrentHashMap.newKeySet()
        val named: MutableSet<String> = ConcurrentHashMap.newKeySet()
        @Volatile var serving = true
        // Accept lock sections asked for, counted before the lock is taken.
        val lockRequests = AtomicInteger()
        // Completed when an accept's second lock section, the admission's, finds the lock held.
        val admissionLockContended = CompletableDeferred<Unit>()

        val revokes = NostrconnectRevokeState(generation::get, everyClientRevokedAt::get) { clientRevokedAt[it] }

        suspend fun revoke(client: String?, beforeEngine: suspend () -> Unit = {}) = lock.withLock {
            val g = generation.incrementAndGet()
            val revoked = client?.let(::setOf) ?: (listed + synchronized(cache) { cache.toList() } + holds.keys)
            revoked.forEach {
                clientRevokedAt[it] = g
                holds.remove(it)
            }
            beforeEngine()
            if (client == null) {
                cache.clear()
                listed.clear()
                everyClientRevokedAt.accumulateAndGet(g, ::maxOf)
            } else {
                cache.remove(client)
                listed.remove(client)
            }
            serving = false
        }

        fun restart() {
            serving = true
        }

        suspend fun accept(
            client: String,
            core: suspend () -> Unit = {},
            readClients: suspend () -> List<String> = { listed.toList() },
            saveName: suspend () -> Unit = { named += client },
        ): NostrconnectOutcome {
            var locks = 0
            return acceptAndAdmit(
                pk = client,
                holds = holds,
                cache = cache,
                revokes = revokes,
                withLock = { block ->
                    lockRequests.incrementAndGet()
                    val section = ++locks
                    if (!lock.tryLock()) {
                        if (section == 2) admissionLockContended.complete(Unit)
                        lock.lock()
                    }
                    try {
                        block()
                    } finally {
                        lock.unlock()
                    }
                },
                accept = {
                    core()
                    if (!serving) throw KeepMobileException.BunkerNotRunning()
                    listed += client
                },
                readClients = readClients,
                saveName = saveName,
            )
        }
    }

    @Test
    fun manyThreadsRacingOneKeyGetExactlyOneRealAcceptPerRound() {
        val threads = 16
        val pool = Executors.newFixedThreadPool(threads)
        try {
            repeat(300) { round ->
                val m = Model()
                val barrier = CyclicBarrier(threads)
                val inCore = AtomicInteger()
                val maxInCore = AtomicInteger()
                val outcomes = (0 until threads).map {
                    pool.submit<NostrconnectOutcome> {
                        barrier.await(5, TimeUnit.SECONDS)
                        runBlocking {
                            m.accept(pk, core = {
                                maxInCore.accumulateAndGet(inCore.incrementAndGet(), ::maxOf)
                                Thread.sleep(1)
                                inCore.decrementAndGet()
                            })
                        }
                    }
                }.map { it.get(10, TimeUnit.SECONDS) }
                // Several can be real accepts in turn, but never two core calls at once.
                assertEquals("round $round", 1, maxInCore.get())
                assertTrue("round $round: $outcomes", outcomes.all { it == NostrconnectOutcome.CONNECTED || it == NostrconnectOutcome.ALREADY_ACCEPTING })
                assertTrue(outcomes.contains(NostrconnectOutcome.CONNECTED))
                assertTrue("round $round", m.holds.isEmpty())
                assertEquals(setOf(pk), m.cache)
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun interleavedRevokesNeverLeaveAnUnlistedClientAdmitted() {
        val pool = Executors.newFixedThreadPool(8)
        val dispatcher = pool.asCoroutineDispatcher()
        try {
            val rnd = Random(645)
            repeat(400) { round ->
                val m = Model()
                val keys = listOf(pk, other)
                runBlocking(dispatcher) {
                    try {
                        withTimeout(DEADLINE_MS) {
                            val jobs = (0 until 12).map { i ->
                                val seed = rnd.nextInt()
                                async {
                                    val r = Random(seed)
                                    when (r.nextInt(4)) {
                                        0 -> m.revoke(if (r.nextBoolean()) null else keys[r.nextInt(2)])
                                        1 -> m.restart()
                                        else -> runCatching {
                                            m.accept(keys[i % 2], core = { if (r.nextBoolean()) yield() })
                                        }.exceptionOrNull()?.let { if (it !is KeepMobileException.BunkerNotRunning) throw it }
                                    }
                                }
                            }
                            jobs.awaitAll()
                        }
                    } catch (_: TimeoutCancellationException) {
                        fail("round $round: did not finish within $DEADLINE_MS ms")
                    }
                }
                val cached = synchronized(m.cache) { m.cache.toSet() }
                assertTrue("round $round: cache $cached listed ${m.listed}", m.listed.containsAll(cached))
                assertTrue("round $round", m.holds.isEmpty())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun cancellingAtEachPhaseDropsTheHoldAndAdmitsOnlyOnceTheLockSectionRan() = runBlocking {
        for (phase in listOf("core", "lock", "read", "name")) {
            val m = Model()
            val parked = CompletableDeferred<Unit>()
            val never = CompletableDeferred<Unit>()
            val lockTaken = CompletableDeferred<Unit>()
            val outer = this
            val job = launch(Dispatchers.Default) {
                m.accept(
                    pk,
                    core = {
                        if (phase == "core") { parked.complete(Unit); never.await() }
                        // Taken once the hold is, so the accept parks on the admission's lock.
                        if (phase == "lock") {
                            outer.launch { m.lock.withLock { lockTaken.complete(Unit); never.await() } }
                            lockTaken.await()
                        }
                    },
                    readClients = { if (phase == "read") { parked.complete(Unit); never.await() }; m.listed.toList() },
                    saveName = { if (phase == "name") { parked.complete(Unit); never.await() } },
                )
            }
            try {
                withTimeout(DEADLINE_MS) { if (phase == "lock") m.admissionLockContended.await() else parked.await() }
                // Still held, so the cancel lands while the accept waits for the admission's lock.
                if (phase == "lock") assertTrue(phase, m.lock.isLocked && m.listed.contains(pk))
                withTimeout(DEADLINE_MS) { job.cancelAndJoin() }
            } finally {
                never.complete(Unit)
                job.cancel()
            }
            assertTrue(phase, m.holds.isEmpty())
            // Only a cancel inside saveName finds the client already admitted, unnamed.
            assertEquals(phase, phase == "name", m.cache.contains(pk))
            assertTrue(phase, m.named.isEmpty())
        }
    }

    @Test
    fun aThrowableThatIsNotAnExceptionStillDropsTheHold() = runBlocking {
        val m = Model()
        try {
            m.accept(pk, core = { throw StackOverflowError() })
            fail()
        } catch (_: StackOverflowError) {
        }
        assertTrue(m.holds.isEmpty())
        assertTrue(m.cache.isEmpty())
    }

    @Test
    fun aCancellationExceptionFromTheReadIsNotTakenForAnUnreadableConfig() = runBlocking {
        val m = Model()
        try {
            m.accept(pk, readClients = { throw CancellationException("not ours") })
            fail()
        } catch (_: CancellationException) {
        }
        assertTrue(m.holds.isEmpty())
        assertFalse(m.cache.contains(pk))
    }

    @Test
    fun aNameSaveFailureLeavesTheClientAdmittedButReportsNoOutcome() = runBlocking {
        val m = Model()
        try {
            m.accept(pk, saveName = { throw IllegalStateException("prefs") })
            fail()
        } catch (_: IllegalStateException) {
        }
        assertTrue(m.cache.contains(pk))
        assertTrue(m.holds.isEmpty())
    }

    @Test
    fun aRevokeDuringTheAcceptLetsASecondAcceptHoldTheKeyAndTheFirstLeavesItAlone() = runBlocking {
        val m = Model()
        val inCore = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val secondRelease = CompletableDeferred<Unit>()
        try {
            val first = async(Dispatchers.Default) { m.accept(pk, core = { inCore.complete(Unit); release.await() }) }
            withTimeout(DEADLINE_MS) { inCore.await() }
            m.revoke(pk)
            m.restart()
            val secondInCore = CompletableDeferred<Unit>()
            val second = async(Dispatchers.Default) { m.accept(pk, core = { secondInCore.complete(Unit); secondRelease.await() }) }
            withTimeout(DEADLINE_MS) { secondInCore.await() }
            release.complete(Unit)
            assertEquals(NostrconnectOutcome.REVOKED, withTimeout(DEADLINE_MS) { first.await() })
            assertTrue("the second accept is still held", m.holds.containsKey(pk))
            secondRelease.complete(Unit)
            assertEquals(NostrconnectOutcome.CONNECTED, withTimeout(DEADLINE_MS) { second.await() })
        } finally {
            release.complete(Unit)
            secondRelease.complete(Unit)
        }
        assertTrue(m.holds.isEmpty())
        assertEquals(setOf(pk), m.cache)
    }

    // A revoke bumps the generation under the lock before its engine revoke. An accept started
    // in that window waits on the lock for its hold and generation read, so it reaches the core
    // only once the engine revoke ran, and then meets the bunker the revoke stopped: the handler
    // it captured stays stopped while the service restarts on a new one, unless [restarted].
    private suspend fun acceptInsideRevokeWindow(
        m: Model,
        readClients: suspend () -> List<String>,
        restarted: Boolean = false,
    ): Result<NostrconnectOutcome> {
        var outcome: Deferred<Result<NostrconnectOutcome>>? = null
        val engineRan = AtomicInteger()
        m.revoke(pk) {
            outcome = CoroutineScope(Dispatchers.Default).async {
                runCatching {
                    m.accept(
                        pk,
                        core = {
                            assertEquals("the core ran inside the revoke window", 1, engineRan.get())
                            if (restarted) m.restart()
                        },
                        readClients = readClients,
                    )
                }
            }
            withTimeout(DEADLINE_MS) { while (m.lockRequests.get() == 0) yield() }
            repeat(100) { yield() }
            assertTrue(m.holds.isEmpty())
            assertFalse(m.listed.contains(pk))
            engineRan.set(1)
        }
        return withTimeout(DEADLINE_MS) { outcome!!.await() }
    }

    @Test
    fun aRevokeWindowAcceptWithAReadableConfigIsNotAdmitted() = runBlocking {
        val m = Model()
        val reads = AtomicInteger()
        val result = acceptInsideRevokeWindow(m, readClients = { reads.incrementAndGet(); m.listed.toList() })
        // The core failure comes before the admission, which so never rereads the config.
        assertEquals(0, reads.get())
        // The revoke had bumped the generation before this accept read it, so its failure on the
        // stopped bunker reads as "not running"; the user is told to check the bunker and try again.
        assertTrue("$result", result.exceptionOrNull() is KeepMobileException.BunkerNotRunning)
        assertFalse(m.listed.contains(pk))
        assertFalse(m.cache.contains(pk))
        assertTrue(m.holds.isEmpty())
    }

    // Its generation was read after the revoke's bump, so on a bunker serving again the fallback
    // for an unreadable config admits it: that revoke came before this accept, not during it.
    @Test
    fun aRevokeWindowAcceptOnARestartedBunkerWithAnUnreadableConfigFallsBackAndIsAdmitted() = runBlocking {
        val m = Model()
        val reads = AtomicInteger()
        val result = acceptInsideRevokeWindow(
            m,
            readClients = { reads.incrementAndGet(); throw KeepMobileException.StorageException("unreadable") },
            restarted = true,
        )
        assertEquals("the unreadable config was read", 1, reads.get())
        assertEquals(NostrconnectOutcome.CONNECTED, result.getOrThrow())
        assertTrue(m.listed.contains(pk))
        assertTrue(m.cache.contains(pk))
        assertTrue(m.holds.isEmpty())
    }

    // The accept read the generation under the lock first, so the whole revoke, bump and engine
    // stop alike, comes after it and the stopped bunker's failure is reported as the revoke.
    @Test
    fun aRevokeWindowAcceptTheStoppedBunkerFailsIsReportedAsARevoke() = runBlocking {
        val m = Model()
        val inCore = CompletableDeferred<Unit>()
        val gate = CompletableDeferred<Unit>()
        val deferred = CoroutineScope(Dispatchers.Default).async {
            runCatching {
                m.accept(
                    pk,
                    core = { inCore.complete(Unit); gate.await() },
                    readClients = { throw KeepMobileException.StorageException("unreadable") },
                )
            }
        }
        try {
            withTimeout(DEADLINE_MS) { inCore.await() }
            m.revoke(pk)
        } finally {
            gate.complete(Unit)
        }
        assertEquals(NostrconnectOutcome.REVOKED, withTimeout(DEADLINE_MS) { deferred.await() }.getOrThrow())
        assertFalse(m.cache.contains(pk))
        assertTrue(m.holds.isEmpty())
    }

    @Test
    fun aCoreRefusalDuringAnUnrelatedRevokeKeepsItsOwnError() = runBlocking {
        val m = Model()
        try {
            m.accept(pk, core = {
                m.revoke(other)
                throw KeepMobileException.TooManyAuthorizedClients(10u)
            })
            fail("expected the core refusal")
        } catch (_: KeepMobileException.TooManyAuthorizedClients) {
        }
    }

    private companion object {
        const val DEADLINE_MS = 5_000L
    }
}
