package io.privkey.keep.nip55

import io.privkey.keep.storage.PrefRead
import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.uniffi.Nip55RelayAuthGate
import io.privkey.keep.uniffi.nip55ExtractRelayHost
import io.privkey.keep.uniffi.nip55RelayAuthGate

/**
 * The whitelist as the two inputs the gate is decided from: the hosts to match against,
 * and whether the read failed.
 *
 * One place, because the foreground gate below and the background path through the core
 * must not disagree about the same stored list. It replaced two copies of this fold that
 * had already drifted on which throwables they caught.
 *
 * A fault answers no hosts and a raised flag, which is what makes both paths reject
 * rather than fall through to per-app resolution. The catch is wider than a storage
 * fault on purpose: [RelayAuthWhitelistStore.readHosts] is already total, so anything
 * reaching it is unexpected, and for a gate the safe reading of unexpected is a
 * rejection. The [PrefRead.Absent] arm is
 * unreachable today, since [RelayAuthWhitelistStore.readHosts] folds a never-configured
 * list into an empty one; it answers "no gating" rather than riding the reject leg, so
 * unfolding it later cannot turn an absence into a denial.
 */
internal fun relayWhitelistInputs(store: RelayAuthWhitelistStore?): Pair<List<String>, Boolean> {
    if (store == null) return emptyList<String>() to false
    return when (val read = runCatching { store.readHosts() }.getOrDefault(PrefRead.Unreadable)) {
        is PrefRead.Found -> read.value to false
        PrefRead.Unreadable -> emptyList<String>() to true
        PrefRead.Absent -> emptyList<String>() to false
    }
}

/**
 * Single source of truth for the NIP-42 (kind 22242) relay-auth whitelist gate, shared
 * by the background ContentProvider and the foreground Activity. Returns the gate outcome
 * plus the relay host resolved from [rawContent].
 *
 * - No store -> DEFER (no gating).
 * - Store present but the list could not be read -> AUTO_REJECT (fail closed; a configured
 *   whitelist must never silently degrade to normal resolution on a read error).
 * - Store present and deliberately empty -> DEFER (no gating).
 *
 * The fail-closed leg used to be a `catch`, which covered only the fault that raises. A
 * value that would not decrypt returned an empty set instead, so it took the DEFER leg
 * and the gate came off without anything raising or being logged. Reading three-way is
 * what makes the documented behavior above the actual behavior for both fault kinds.
 *
 * AUTO_REJECT rather than a prompt, matching what the core decides from the same input:
 * `relay_whitelist_read_failed` maps to AutoReject there, and the background path routes
 * through the core, so answering anything else here would make the foreground and
 * background gates disagree about the same stored list.
 */
fun evaluateRelayAuthGate(
    store: RelayAuthWhitelistStore?,
    rawContent: String
): Pair<Nip55RelayAuthGate, String?> {
    val relayHost = nip55ExtractRelayHost(rawContent)
    val (hosts, readFailed) = relayWhitelistInputs(store)
    if (readFailed) return Nip55RelayAuthGate.AUTO_REJECT to relayHost
    if (hosts.isEmpty()) return Nip55RelayAuthGate.DEFER to relayHost
    return nip55RelayAuthGate(relayHost, hosts) to relayHost
}
