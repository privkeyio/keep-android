package io.privkey.keep.nip55

import android.content.Context
import android.util.Log
import io.privkey.keep.BuildConfig
import io.privkey.keep.KeepMobileApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Record a self-initiated key-management operation (see [PermissionStore.logKeyExport])
 * in the tamper-evident activity log after a successful export.
 *
 * Best-effort: a logging failure must never fail the export, so it is swallowed, but it is
 * surfaced in debug builds so a violation of the "always audited" contract is diagnosable.
 * A [CancellationException] is rethrown so structured concurrency is not broken.
 */
suspend fun auditKeyExport(context: Context, operation: String) {
    withContext(Dispatchers.IO) {
        try {
            (context.applicationContext as? KeepMobileApp)
                ?.getPermissionStore()
                ?.logKeyExport(operation)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (BuildConfig.DEBUG) {
                Log.w("KeyExportAudit", "Failed to audit key export: ${e::class.simpleName}")
            }
        }
    }
}
