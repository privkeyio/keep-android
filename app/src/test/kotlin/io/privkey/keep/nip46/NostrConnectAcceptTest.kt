package io.privkey.keep.nip46

import io.privkey.keep.R
import io.privkey.keep.uniffi.KeepMobileException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

class NostrConnectAcceptTest {

    private val pk = "ab".repeat(32)
    private val other = "cd".repeat(32)

    private class Fixture(val pk: String) {
        val holds = ConcurrentHashMap<String, Any>()
        val cache = mutableSetOf<String>()
        val named = mutableListOf<String>()
        var generation = 0L
        var everyClientRevokedAt = 0L
        val clientRevokedAt = mutableMapOf<String, Long>()

        /** A revoke of [client], or of every client (Revoke All, an account switch) when null. */
        fun revoke(client: String?) {
            generation++
            if (client == null) everyClientRevokedAt = generation else clientRevokedAt[client] = generation
            if (client == null) {
                holds.clear()
                cache.clear()
            } else {
                holds.remove(client)
                cache.remove(client)
            }
        }

        /** [beforeLock] runs before the admission's lock, the second one an accept takes. */
        suspend fun accept(
            accept: suspend () -> Unit = {},
            beforeLock: () -> Unit = {},
            readClients: suspend () -> List<String> = { listOf(pk) },
            saveName: suspend () -> Unit = { named += pk },
        ): NostrconnectOutcome {
            var locks = 0
            return acceptAndAdmit(
                pk = pk,
                holds = holds,
                cache = cache,
                revokes = NostrconnectRevokeState({ generation }, { everyClientRevokedAt }) { clientRevokedAt[it] },
                withLock = { block -> if (++locks == 2) beforeLock(); block() },
                accept = accept,
                readClients = readClients,
                saveName = saveName,
            )
        }
    }

    @Test
    fun aSuccessfulAcceptAdmitsAndNamesTheClient() = runBlocking {
        val f = Fixture(pk)
        assertEquals(NostrconnectOutcome.CONNECTED, f.accept())
        assertEquals(setOf(pk), f.cache)
        assertEquals(listOf(pk), f.named)
        assertTrue(f.holds.isEmpty())
    }

    @Test
    fun aRevokeOfThisClientDuringTheAcceptIsReportedAndNotAdmitted() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(accept = { f.revoke(pk); throw KeepMobileException.BunkerNotRunning() })
        assertEquals(NostrconnectOutcome.REVOKED, outcome)
        assertTrue(f.cache.isEmpty())
        assertTrue(f.named.isEmpty())
    }

    @Test
    fun aRevokeOfThisClientDuringAnAcceptTheCoreCompletedIsNotAdmitted() = runBlocking {
        val f = Fixture(pk)
        assertEquals(NostrconnectOutcome.REVOKED, f.accept(accept = { f.revoke(pk) }))
        assertTrue(f.cache.isEmpty())
        assertTrue(f.named.isEmpty())
    }

    @Test
    fun aRevokeOfAnotherClientDuringTheAcceptIsARestart() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(accept = { f.revoke(other); throw KeepMobileException.BunkerNotRunning() })
        assertEquals(NostrconnectOutcome.RESTARTED, outcome)
        assertTrue(f.cache.isEmpty())
        assertTrue(f.holds.isEmpty())
    }

    @Test
    fun aCoreRefusalDuringARevokeOfAnotherClientKeepsItsOwnError() = runBlocking {
        for (refusal in listOf(KeepMobileException.PolicyViolation("killed"), KeepMobileException.TooManyAuthorizedClients(10u))) {
            val f = Fixture(pk)
            try {
                f.accept(accept = { f.revoke(other); throw refusal })
                fail("rethrown")
            } catch (e: KeepMobileException) {
                assertSame(refusal, e)
            }
            assertTrue(f.holds.isEmpty())
        }
    }

    @Test
    fun aRevokeOfAnUnheldClientKeepsOtherClientsHolds() = runBlocking {
        val f = Fixture(pk)
        val otherHold = Any()
        f.holds[other] = otherHold
        var heldAfterRevoke = false
        val outcome = f.accept(accept = { f.revoke("ef".repeat(32)); heldAfterRevoke = f.holds.containsKey(pk) })
        assertEquals(NostrconnectOutcome.CONNECTED, outcome)
        assertTrue(heldAfterRevoke)
        assertSame(otherHold, f.holds[other])
    }

    @Test
    fun aRevokeOfEveryClientDuringTheAcceptIsARevoke() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(accept = { f.revoke(null); throw KeepMobileException.BunkerNotRunning() })
        assertEquals(NostrconnectOutcome.REVOKED, outcome)
    }

    @Test
    fun aRevokeAfterTheAcceptButBeforeTheAdmissionWins() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(beforeLock = { f.revoke(pk) }, readClients = { emptyList() })
        assertEquals(NostrconnectOutcome.REVOKED, outcome)
        assertTrue(f.cache.isEmpty())
        assertTrue(f.named.isEmpty())
    }

    @Test
    fun aRevokeBeforeTheAdmissionWinsEvenWhileTheConfigStillListsTheClient() = runBlocking {
        val f = Fixture(pk)
        assertEquals(NostrconnectOutcome.REVOKED, f.accept(beforeLock = { f.revoke(pk) }))
        assertTrue(f.cache.isEmpty())
    }

    @Test
    fun anUnreadableConfigWithNoRevokeAdmits() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(readClients = { throw KeepMobileException.StorageException("unreadable") })
        assertEquals(NostrconnectOutcome.CONNECTED, outcome)
        assertEquals(setOf(pk), f.cache)
    }

    @Test
    fun anUnreadableConfigAfterARevokeDoesNotAdmit() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(
            accept = { f.revoke(pk) },
            readClients = { throw KeepMobileException.StorageException("unreadable") },
        )
        assertEquals(NostrconnectOutcome.REVOKED, outcome)
        assertTrue(f.cache.isEmpty())
    }

    @Test
    fun anUnreadableConfigAfterARevokeOfAnotherClientAdmits() = runBlocking {
        val f = Fixture(pk)
        val outcome = f.accept(
            accept = { f.revoke(other) },
            readClients = { throw KeepMobileException.StorageException("unreadable") },
        )
        assertEquals(NostrconnectOutcome.CONNECTED, outcome)
    }

    @Test
    fun aSecondConcurrentAcceptIsRefusedAndKeepsTheFirstHold() = runBlocking {
        val f = Fixture(pk)
        val release = CompletableDeferred<Unit>()
        val first = async { f.accept(accept = { release.await() }) }
        withTimeout(DEADLINE_MS) { while (!f.holds.containsKey(pk)) yield() }
        val firstHold = f.holds[pk]

        assertEquals(NostrconnectOutcome.ALREADY_ACCEPTING, f.accept())
        assertSame(firstHold, f.holds[pk])

        release.complete(Unit)
        assertEquals(NostrconnectOutcome.CONNECTED, withTimeout(DEADLINE_MS) { first.await() })
        assertTrue(f.holds.isEmpty())
    }

    @Test
    fun anAcceptDoesNotDropAHoldItDidNotAdd() = runBlocking {
        val f = Fixture(pk)
        val release = CompletableDeferred<Unit>()
        val first = async { f.accept(accept = { release.await() }) }
        withTimeout(DEADLINE_MS) { while (!f.holds.containsKey(pk)) yield() }
        // A revoke drops the first hold; a later accept for the key then holds it.
        f.revoke(pk)
        val laterHold = Any()
        f.holds[pk] = laterHold

        release.complete(Unit)
        assertEquals(NostrconnectOutcome.REVOKED, withTimeout(DEADLINE_MS) { first.await() })
        assertSame(laterHold, f.holds[pk])
    }

    @Test
    fun theHoldIsSetForTheWholeAccept() = runBlocking {
        val f = Fixture(pk)
        var heldDuringAccept = false
        var heldDuringAdmission = false
        f.accept(
            accept = { heldDuringAccept = f.holds.containsKey(pk) },
            readClients = { heldDuringAdmission = f.holds.containsKey(pk); listOf(pk) },
        )
        assertTrue(heldDuringAccept)
        assertTrue(heldDuringAdmission)
    }

    @Test
    fun theHoldIsRemovedOnEveryExitPath() = runBlocking {
        val coreFailure = Fixture(pk)
        try {
            coreFailure.accept(accept = { throw KeepMobileException.Timeout() })
            fail("the core failure is rethrown")
        } catch (_: KeepMobileException.Timeout) {
        }
        assertTrue(coreFailure.holds.isEmpty())

        val nameFailure = Fixture(pk)
        try {
            nameFailure.accept(saveName = { throw IllegalStateException("store") })
            fail("the name failure is rethrown")
        } catch (_: IllegalStateException) {
        }
        assertTrue(nameFailure.holds.isEmpty())

        for (outcomeOf in listOf<suspend (Fixture) -> NostrconnectOutcome>(
            { it.accept() },
            { it.accept(accept = { it.revoke(pk); throw KeepMobileException.BunkerNotRunning() }) },
            { it.accept(accept = { it.revoke(other); throw KeepMobileException.BunkerNotRunning() }) },
            { it.accept(beforeLock = { it.revoke(pk) }) },
        )) {
            val f = Fixture(pk)
            outcomeOf(f)
            assertTrue(f.holds.isEmpty())
        }

        val cancelled = Fixture(pk)
        val job = launch { cancelled.accept(accept = { CompletableDeferred<Unit>().await() }) }
        withTimeout(DEADLINE_MS) { while (!cancelled.holds.containsKey(pk)) yield() }
        withTimeout(DEADLINE_MS) { job.cancelAndJoin() }
        assertTrue(cancelled.holds.isEmpty())
        assertTrue(cancelled.cache.isEmpty())
    }

    @Test
    fun aCoreFailureWithNoRevokeIsRethrown() = runBlocking {
        val f = Fixture(pk)
        try {
            f.accept(accept = { throw KeepMobileException.InvalidInput("This client is already connected; revoke it to connect it again") })
            fail("rethrown")
        } catch (e: KeepMobileException.InvalidInput) {
            assertEquals(R.string.connections_nostrconnect_error_already_connected, acceptErrorMessage(e))
        }
        assertTrue(f.cache.isEmpty())
    }

    @Test
    fun anAcceptRunsOnlyOnTheBunkerTheUserTappedConnectOn() {
        val service = Any()
        val handler = Any()
        assertTrue(isSameServingBunker(service, handler, service, handler))
        assertFalse("a restart installs a new handler", isSameServingBunker(service, handler, service, Any()))
        assertFalse("a new service", isSameServingBunker(service, handler, Any(), handler))
        assertFalse("stopped since", isSameServingBunker(service, handler, null, null))
        assertFalse("none was serving", isSameServingBunker(null, null, null, null))
        assertFalse("serving without a handler", isSameServingBunker(service, null, service, null))
    }

    @Test
    fun acceptErrorsMapToTheirMessages() {
        assertEquals(
            R.string.connections_nostrconnect_error_already_connected,
            acceptErrorMessage(KeepMobileException.InvalidInput("This client is already connected; revoke it to connect it again")),
        )
        assertEquals(R.string.connections_nostrconnect_error_failed, acceptErrorMessage(KeepMobileException.InvalidInput("Invalid client pubkey")))
        assertEquals(R.string.connections_nostrconnect_error_not_running, acceptErrorMessage(KeepMobileException.BunkerNotRunning()))
        assertEquals(R.string.nip46_client_limit_toast, acceptErrorMessage(KeepMobileException.TooManyAuthorizedClients(10u)))
        assertEquals(R.string.kill_switch_active_toast, acceptErrorMessage(KeepMobileException.PolicyViolation("killed")))
        assertEquals(R.string.connections_nostrconnect_error_timeout, acceptErrorMessage(KeepMobileException.Timeout()))
        assertEquals(R.string.connections_nostrconnect_error_network, acceptErrorMessage(KeepMobileException.NetworkException("down")))
        assertEquals(R.string.connections_nostrconnect_error_failed, acceptErrorMessage(KeepMobileException.StorageException("disk")))
        assertEquals(R.string.connections_nostrconnect_error_failed, acceptErrorMessage(IllegalStateException()))
    }

    @Test
    fun everyOutcomeHasItsOwnMessage() {
        val messages = NostrconnectOutcome.entries.map(::nostrconnectOutcomeMessage)
        assertEquals(messages.size, messages.toSet().size)
        assertEquals(R.string.connections_nostrconnect_error_restarted, nostrconnectOutcomeMessage(NostrconnectOutcome.RESTARTED))
        assertEquals(R.string.connections_nostrconnect_already_connecting, nostrconnectOutcomeMessage(NostrconnectOutcome.ALREADY_ACCEPTING))
    }

    @Test
    fun aClientWithNoNameToShowIsListedUnderTheCoresFallback() {
        assertEquals("App abababab", nostrconnectClientName(null, pk))
        assertEquals("App abababab", nostrconnectClientName("   ", pk.uppercase()))
        assertEquals("App abababab", nostrconnectClientName("\u200B", pk))
        assertEquals("Damus", nostrconnectClientName("Damus", pk))
    }

    @Test
    fun formatCharactersAreNotShown() {
        val tag = { cp: Int -> String(Character.toChars(cp)) }
        assertEquals("Damus", nostrconnectDisplayName("Damus" + tag(0xE0041)))
        assertEquals("Damus", nostrconnectDisplayName("Damus" + tag(0xE0001) + tag(0xE0020) + tag(0xE007F) + tag(0xE0000)))
        assertEquals("Damus", nostrconnectDisplayName("Da\u00ADmus"))
        assertEquals("Damus", nostrconnectDisplayName("Da\u180Emus"))
        assertEquals("Damus", nostrconnectDisplayName("\u2066Damus\u2069\u061C"))
        assertEquals("Damus", nostrconnectDisplayName("Da\u200Dmus\uFEFF"))
    }

    @Test
    fun aNameOfOnlyFormatCharactersFallsBack() {
        val tags = (0xE0000..0xE007F).joinToString("") { String(Character.toChars(it)) }
        assertNull(nostrconnectDisplayName(tags))
        assertNull(nostrconnectDisplayName("\u00AD\u180E\u200B\u2060\uFEFF"))
        assertEquals("App abababab", nostrconnectClientName("\u00AD" + tags, pk))
    }

    @Test
    fun formatCharactersDoNotCountTowardsTheCap() {
        val name = "a".repeat(50)
        val padded = name.map { "$it\u00AD" }.joinToString("")
        assertEquals(name, nostrconnectDisplayName(padded))
        assertFalse(nostrconnectDisplayName(padded)!!.contains('\u00AD'))
    }

    private companion object {
        const val DEADLINE_MS = 5_000L
    }
}
