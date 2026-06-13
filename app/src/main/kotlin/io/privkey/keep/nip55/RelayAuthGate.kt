package io.privkey.keep.nip55

import io.privkey.keep.storage.RelayAuthWhitelistStore
import io.privkey.keep.uniffi.Nip55RelayAuthGate
import io.privkey.keep.uniffi.nip55ExtractRelayHost
import io.privkey.keep.uniffi.nip55RelayAuthGate

/**
 * Single source of truth for the NIP-42 (kind 22242) relay-auth whitelist gate, shared
 * by the background ContentProvider and the foreground Activity. Returns the gate outcome
 * plus the relay host resolved from [rawContent].
 *
 * - No store -> DEFER (no gating).
 * - Store present but the read throws -> AUTO_REJECT (fail closed; a configured whitelist
 *   must never silently degrade to normal resolution on a read error).
 * - Store present and deliberately empty -> DEFER (no gating).
 */
fun evaluateRelayAuthGate(
    store: RelayAuthWhitelistStore?,
    rawContent: String
): Pair<Nip55RelayAuthGate, String?> {
    val relayHost = nip55ExtractRelayHost(rawContent)
    if (store == null) return Nip55RelayAuthGate.DEFER to relayHost
    val hosts = try {
        store.getHosts()
    } catch (_: Exception) {
        return Nip55RelayAuthGate.AUTO_REJECT to relayHost
    }
    if (hosts.isEmpty()) return Nip55RelayAuthGate.DEFER to relayHost
    return nip55RelayAuthGate(relayHost, hosts) to relayHost
}
