package io.privkey.keep.nip46

import androidx.annotation.StringRes
import io.privkey.keep.R
import io.privkey.keep.uniffi.KeepMobileException
import kotlinx.coroutines.CancellationException
import java.util.concurrent.ConcurrentMap

/** How a `nostrconnect://` accept the user approved ended, short of a core failure it throws. */
internal enum class NostrconnectOutcome {
    /** Accepted by the core and admitted past the request gate. */
    CONNECTED,

    /** A revoke covering this client landed during the accept, so it is not connected. */
    REVOKED,

    /** Another accept for this client is in flight and reports its own result. */
    ALREADY_ACCEPTING,

    /** A revoke of other clients or an account switch stopped the bunker during the accept. */
    RESTARTED,
}

/** What [acceptAndAdmit] reads of the revokes, as [BunkerService] keeps them. */
internal class NostrconnectRevokeState(
    val generation: () -> Long,
    val everyClientRevokedAt: () -> Long,
    val clientRevokedAt: (String) -> Long?,
)

/**
 * The race logic of [BunkerService.acceptNostrconnect]. Under [withLock] (the lock revokes hold)
 * holds [pk] in [holds] and reads the revoke generation, failing fast with
 * [NostrconnectOutcome.ALREADY_ACCEPTING] when another call holds it. Under that lock the read
 * comes before a revoke starts, which then counts, or after it finished, engine revoke included.
 * Runs [accept] (the core call), then under [withLock] again reads the listed clients with
 * [readClients] and admits [pk] into [cache] and names it with [saveName] only while no revoke
 * covering it came since the read. An unreadable config falls back to the generation, which
 * every revoke moves. Drops only the hold it added.
 *
 * A failed core call is judged against the generation read before the lock as well, since one
 * that waited behind a revoke reads its generation after it, yet runs on the bunker that revoke
 * stopped. That earlier read only words the failure; admission keeps the read under the lock.
 * One that arrived after the revoke's bump still fails as BunkerNotRunning, which is safe.
 */
internal suspend fun acceptAndAdmit(
    pk: String,
    holds: ConcurrentMap<String, Any>,
    cache: MutableSet<String>,
    revokes: NostrconnectRevokeState,
    withLock: suspend (suspend () -> Unit) -> Unit,
    accept: suspend () -> Unit,
    readClients: suspend () -> List<String>,
    saveName: suspend () -> Unit,
): NostrconnectOutcome {
    val hold = Any()
    try {
        val beforeLock = revokes.generation()
        var started: Long? = null
        withLock { if (holds.putIfAbsent(pk, hold) == null) started = revokes.generation() }
        val generation = started ?: return NostrconnectOutcome.ALREADY_ACCEPTING
        try {
            accept()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // A revoke stops the bunker, which the accept then fails on.
            if (revokedSince(beforeLock, revokes.everyClientRevokedAt(), revokes.clientRevokedAt(pk))) return NostrconnectOutcome.REVOKED
            if (e is KeepMobileException.BunkerNotRunning && revokes.generation() != beforeLock) return NostrconnectOutcome.RESTARTED
            throw e
        }
        var outcome = NostrconnectOutcome.REVOKED
        withLock {
            // The core listed it when it returned. The re-read only catches a revoke since,
            // which also moves the generation, so an unreadable config falls back to that.
            val clients = try {
                readClients()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                listOf(pk)
            }
            if (admitsNostrconnectClient(clients, pk, generation, revokes.everyClientRevokedAt(), revokes.clientRevokedAt(pk))) {
                cache.add(pk)
                // Under the lock, so a revoke cannot land between the admission and the name.
                saveName()
                outcome = NostrconnectOutcome.CONNECTED
            }
        }
        return outcome
    } finally {
        holds.remove(pk, hold)
    }
}

/**
 * The name Android lists a nostrconnect client under: its own when it has one to show, else
 * "App" and the first 8 hex digits of its key. That is the core's fallback (keep-mobile nip46.rs
 * nostrconnect_name), but the core falls back only for a name that is empty after Rust's trim,
 * so a name made only of invisible characters is listed here under the fallback while the core
 * keeps it as parsed.
 */
internal fun nostrconnectClientName(name: String?, pubkey: String): String =
    nostrconnectDisplayName(name) ?: "App ${pubkey.lowercase().take(8)}"

@StringRes
internal fun nostrconnectOutcomeMessage(outcome: NostrconnectOutcome): Int = when (outcome) {
    NostrconnectOutcome.CONNECTED -> R.string.connections_nostrconnect_connected
    NostrconnectOutcome.REVOKED -> R.string.connections_nostrconnect_error_revoked
    NostrconnectOutcome.ALREADY_ACCEPTING -> R.string.connections_nostrconnect_already_connecting
    NostrconnectOutcome.RESTARTED -> R.string.connections_nostrconnect_error_restarted
}

@StringRes
internal fun acceptErrorMessage(e: Throwable): Int = when (e) {
    is KeepMobileException.BunkerNotRunning -> R.string.connections_nostrconnect_error_not_running
    is KeepMobileException.TooManyAuthorizedClients -> R.string.nip46_client_limit_toast
    is KeepMobileException.PolicyViolation -> R.string.kill_switch_active_toast
    is KeepMobileException.Timeout -> R.string.connections_nostrconnect_error_timeout
    is KeepMobileException.NetworkException -> R.string.connections_nostrconnect_error_network
    is KeepMobileException.CertificatePinMismatch -> R.string.certificate_pin_mismatch_error
    // The request already parsed, so an input error here is not a bad request. The core
    // refuses a client it already lists with one (keep-mobile nip46.rs refuse_to_register),
    // told apart only by its message until the core reports it as ClientAlreadyConnected
    // (privkeyio/keep follow-up).
    is KeepMobileException.InvalidInput ->
        if (e.msg.contains("already connected")) R.string.connections_nostrconnect_error_already_connected
        else R.string.connections_nostrconnect_error_failed
    else -> R.string.connections_nostrconnect_error_failed
}
