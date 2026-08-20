package io.privkey.keep

import android.content.Context
import android.os.Handler
import android.os.Looper
import java.util.concurrent.atomic.AtomicBoolean
import android.util.Log
import android.widget.Toast
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.DkgConfig
import io.privkey.keep.uniffi.DkgProgressCallback
import io.privkey.keep.uniffi.DkgProgressUpdate
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.PendingShareInfo
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.Arrays
import java.util.UUID
import javax.crypto.Cipher

private val EMPTY_RELAY_CONFIG = RelayConfigInfo(emptyList(), emptyList(), emptyList())

internal const val MAX_ACCOUNT_NAME_LENGTH = 64

// Per-round timeout for the DKG. The ceremony has three blocking network rounds
// (Round1, Round2, Confirming), so the whole run can approach 3x this before the
// share is persisted.
private const val DKG_ROUND_TIMEOUT_SECS = 180L
// The biometric cipher is consumed only at the final persist step, so it must
// outlive the whole ceremony. Cover all three rounds plus relay/biometric slack;
// the run is deterministically cleared in the finally below regardless.
private const val DKG_CIPHER_TIMEOUT_MS = DKG_ROUND_TIMEOUT_SECS * 4 * 1000L

sealed class CreateGroupState {
    object Idle : CreateGroupState()
    data class Running(val update: DkgProgressUpdate) : CreateGroupState()
    data class Success(val name: String, val groupPubkey: String) : CreateGroupState()
    data class Error(val message: String) : CreateGroupState()
}

internal class AccountActions(
    private val keepMobile: KeepMobile,
    private val storage: AndroidKeystoreStorage,
    private val coroutineScope: CoroutineScope,
    private val appContext: Context,
    private val onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    private val onAccountSwitched: suspend () -> Unit,
    private val onAccountDeleted: suspend () -> Unit,
    private val onStateChanged: (AccountState) -> Unit
) {
    data class AccountState(
        val hasShare: Boolean,
        val shareInfo: ShareInfo?,
        val activeAccountKey: String?,
        val allAccounts: List<AccountInfo>,
        val relays: List<String>,
        val profileRelays: List<String>,
        val activeDidBackup: Boolean?
    )

    private val accountMutex = Mutex()

    // Single-flight guard for the DKG. frostCancelDkg sets one process-wide flag
    // with no run identity, so a second ceremony queued behind accountMutex (e.g.
    // a double-tap on Start before the button hides) would let a cancel abort the
    // run actually on the wire while the queued one proceeds. Reject duplicates
    // synchronously so only ever one run is in flight for cancel to target.
    private val dkgInProgress = AtomicBoolean(false)

    @Volatile
    private var currentRelays: List<String> = emptyList()

    fun setCurrentRelays(relays: List<String>) {
        currentRelays = relays
    }

    private suspend fun activateShare(authedCipher: Cipher, groupPubkeyHex: String) {
        val switchId = UUID.randomUUID().toString()
        storage.setPendingCipher(switchId, authedCipher)
        try {
            withContext(Dispatchers.IO) {
                storage.setRequestIdContext(switchId)
                try {
                    keepMobile.setActiveShare(groupPubkeyHex)
                } finally {
                    storage.clearRequestIdContext()
                }
            }
        } finally {
            storage.clearPendingCipher(switchId)
        }
    }

    private suspend fun refreshAccountState() {
        val result = withContext(Dispatchers.IO) {
            val hasShare = keepMobile.hasShare()
            val shareInfo = keepMobile.getShareInfo()
            val activeKey = storage.getActiveShareKey()
            val accounts = storage.listAllShares().map { it.toAccountInfo() }
            val config = runCatching { keepMobile.getRelayConfig(activeKey) }.getOrNull()
                ?: EMPTY_RELAY_CONFIG
            val activeDidBackup = runCatching { keepMobile.getActiveShareMetadata()?.didBackup }
                .onFailure { Log.w("AccountActions", "getActiveShareMetadata failed: ${it::class.simpleName}") }
                .getOrNull()
            AccountState(hasShare, shareInfo, activeKey, accounts, config.frostRelays, config.profileRelays, activeDidBackup)
        }
        onStateChanged(result)
    }

    private fun withBiometricAuth(
        accountKey: String,
        title: String,
        subtitle: String,
        onDismiss: () -> Unit,
        action: suspend (Cipher) -> Unit
    ) {
        coroutineScope.launch {
            val cipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(accountKey) }.getOrNull()
            }
            if (cipher == null) {
                onDismiss()
                return@launch
            }
            onBiometricRequest(title, subtitle, cipher) { authedCipher ->
                if (authedCipher != null) {
                    coroutineScope.launch { action(authedCipher) }
                } else {
                    onDismiss()
                }
            }
        }
    }

    private fun logAndToast(tag: String, message: String, e: Exception) {
        if (BuildConfig.DEBUG) Log.e("AccountActions", "$tag: ${e::class.simpleName}")
        coroutineScope.launch(Dispatchers.Main) {
            Toast.makeText(appContext, message, Toast.LENGTH_SHORT).show()
        }
    }

    fun switchAccount(account: AccountInfo, onDismiss: () -> Unit) {
        withBiometricAuth(
            account.groupPubkeyHex,
            appContext.getString(R.string.account_switch_title),
            appContext.getString(R.string.account_switch_subtitle),
            onDismiss
        ) { authedCipher ->
            accountMutex.withLock {
                try {
                    withContext(Dispatchers.IO) {
                        val currentKey = storage.getActiveShareKey()
                        if (currentKey != null) {
                            val existing = runCatching { keepMobile.getRelayConfig(currentKey) }.getOrNull()
                                ?: EMPTY_RELAY_CONFIG
                            keepMobile.saveRelayConfig(currentKey, RelayConfigInfo(currentRelays, existing.profileRelays, existing.bunkerRelays))
                        }
                    }
                    // Clear the previous account's permissions/state BEFORE
                    // activating the new signing key. The NIP-55 ContentProvider
                    // signing path does not take accountMutex, so if activation
                    // happened first a request racing this switch could resolve an
                    // old grant against the newly-active key. Revoking first makes
                    // the transition window fail-safe (no grants + old key -> the
                    // request re-prompts). onAccountSwitched clears state account-
                    // agnostically and does not depend on the new active share.
                    onAccountSwitched()
                    activateShare(authedCipher, account.groupPubkeyHex)
                    refreshAccountState()
                } catch (e: Exception) {
                    logAndToast("Switch failed", appContext.getString(R.string.account_switch_failed), e)
                } finally {
                    onDismiss()
                }
            }
        }
    }

    fun deleteAccount(account: AccountInfo, onDismiss: () -> Unit) {
        withBiometricAuth(
            account.groupPubkeyHex,
            appContext.getString(R.string.account_delete_title),
            appContext.getString(R.string.account_delete_subtitle),
            onDismiss
        ) {
            accountMutex.withLock {
                val activeAccountKey = withContext(Dispatchers.IO) { storage.getActiveShareKey() }
                val wasActive = account.groupPubkeyHex == activeAccountKey
                try {
                    withContext(Dispatchers.IO) {
                        keepMobile.deleteShareByKey(account.groupPubkeyHex)
                        runCatching { keepMobile.deleteRelayConfig(account.groupPubkeyHex) }
                            .onFailure { if (BuildConfig.DEBUG) Log.e("AccountActions", "Relay config cleanup failed: ${it::class.simpleName}") }
                        // Audit the deletion in the current chain. Deleting the active
                        // account then switches to another (whose fresh chain records the
                        // switch), so this entry persists for non-active deletes.
                        onAccountDeleted()
                    }
                } catch (e: Exception) {
                    logAndToast("Delete failed", appContext.getString(R.string.account_delete_failed), e)
                    onDismiss()
                    return@withLock
                }
                try {
                    postDeleteCleanup(wasActive, onDismiss)
                } catch (e: Exception) {
                    logAndToast("Post-delete refresh failed", appContext.getString(R.string.account_delete_refresh_failed), e)
                    onDismiss()
                }
            }
        }
    }

    private suspend fun postDeleteCleanup(wasActive: Boolean, onDismiss: () -> Unit) {
        val remainingAccounts = withContext(Dispatchers.IO) {
            storage.listAllShares().map { it.toAccountInfo() }
        }

        if (wasActive && remainingAccounts.isNotEmpty()) {
            switchToNextAccountAfterDelete(remainingAccounts.first(), onDismiss)
        } else if (wasActive) {
            try {
                onAccountSwitched()
            } finally {
                refreshAccountState()
                onDismiss()
            }
        } else {
            refreshAccountState()
            onDismiss()
        }
    }

    private suspend fun switchToNextAccountAfterDelete(nextAccount: AccountInfo, onDismiss: () -> Unit) {
        val switchCipher = withContext(Dispatchers.IO) {
            runCatching { storage.getCipherForShareDecryption(nextAccount.groupPubkeyHex) }.getOrNull()
        }
        if (switchCipher != null) {
            onBiometricRequest(
                appContext.getString(R.string.account_switch_title),
                appContext.getString(R.string.account_switch_remaining_subtitle),
                switchCipher
            ) { switchAuthed ->
                coroutineScope.launch {
                    accountMutex.withLock {
                        try {
                            // Clear the deleted account's permissions/state before
                            // activating the next account's key, so a signing request
                            // racing this switch cannot resolve an old grant against
                            // the new key (revoke-before-activate; see switchAccount).
                            onAccountSwitched()
                            if (switchAuthed != null) {
                                try {
                                    activateShare(switchAuthed, nextAccount.groupPubkeyHex)
                                } catch (e: Exception) {
                                    if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-delete switch failed: ${e::class.simpleName}")
                                }
                            }
                            refreshAccountState()
                        } finally {
                            onDismiss()
                        }
                    }
                }
            }
        } else {
            try {
                onAccountSwitched()
                refreshAccountState()
            } finally {
                onDismiss()
            }
        }
    }

    fun renameAccount(account: AccountInfo, newName: String) {
        val trimmedName = newName.trim()
        if (trimmedName.isBlank() || trimmedName.length > MAX_ACCOUNT_NAME_LENGTH) {
            logAndToast("Rename failed", appContext.getString(R.string.account_rename_failed), IllegalArgumentException("invalid name"))
            return
        }
        coroutineScope.launch {
            val decryptCipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(account.groupPubkeyHex) }.getOrNull()
            }
            if (decryptCipher == null) {
                logAndToast("Rename failed", appContext.getString(R.string.account_rename_failed), IllegalStateException("no cipher"))
                return@launch
            }
            onBiometricRequest(
                appContext.getString(R.string.account_rename_title),
                appContext.getString(R.string.account_rename_subtitle),
                decryptCipher
            ) { authedDecrypt ->
                if (authedDecrypt == null) return@onBiometricRequest
                requestEncryptCipherAndFinishRename(account, trimmedName, authedDecrypt)
            }
        }
    }

    private fun requestEncryptCipherAndFinishRename(
        account: AccountInfo,
        newName: String,
        authedDecrypt: Cipher
    ) {
        coroutineScope.launch {
            val encryptCipher = accountMutex.withLock {
                withContext(Dispatchers.IO) {
                    if (!shareExists(account.groupPubkeyHex)) null
                    else runCatching { storage.getCipherForShareEncryption(account.groupPubkeyHex) }.getOrNull()
                }
            }
            if (encryptCipher == null) {
                logAndToast("Rename failed", appContext.getString(R.string.account_rename_failed), IllegalStateException("no cipher"))
                return@launch
            }
            onBiometricRequest(
                appContext.getString(R.string.account_rename_title),
                appContext.getString(R.string.account_rename_save_subtitle),
                encryptCipher
            ) { authedEncrypt ->
                if (authedEncrypt == null) return@onBiometricRequest
                finishRename(account, newName, authedDecrypt, authedEncrypt)
            }
        }
    }

    private fun finishRename(
        account: AccountInfo,
        newName: String,
        authedDecrypt: Cipher,
        authedEncrypt: Cipher
    ) {
        coroutineScope.launch {
            accountMutex.withLock {
                val stillExists = withContext(Dispatchers.IO) { shareExists(account.groupPubkeyHex) }
                if (!stillExists) {
                    logAndToast("Rename failed", appContext.getString(R.string.account_rename_failed), IllegalStateException("share removed"))
                    return@withLock
                }
                val requestId = UUID.randomUUID().toString()
                var pendingSet = false
                try {
                    storage.setPendingCipher(requestId, authedDecrypt, AndroidKeystoreStorage.CipherRole.DECRYPT)
                    pendingSet = true
                    storage.setPendingCipher(requestId, authedEncrypt, AndroidKeystoreStorage.CipherRole.ENCRYPT)
                    withContext(Dispatchers.IO) {
                        storage.setRequestIdContext(requestId)
                        try {
                            keepMobile.renameShare(account.groupPubkeyHex, newName)
                        } finally {
                            storage.clearRequestIdContext()
                        }
                    }
                    coroutineScope.launch(Dispatchers.Main) {
                        Toast.makeText(appContext, appContext.getString(R.string.account_rename_success), Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    logAndToast("Rename failed", appContext.getString(R.string.account_rename_failed), e)
                } finally {
                    if (pendingSet) storage.clearPendingCipher(requestId)
                    runCatching { refreshAccountState() }
                }
            }
        }
    }

    fun importShare(
        data: String,
        passphrase: String,
        name: String,
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit
    ) {
        onImportStateChanged(ImportState.Importing)
        if (!isValidKshareFormat(data)) {
            onImportStateChanged(ImportState.Error(appContext.getString(R.string.account_import_invalid_share)))
            return
        }
        executeImport(cipher, onImportStateChanged) { keepMobile.importShare(data, passphrase, name) }
    }

    fun importNsec(
        nsec: ByteArray,
        name: String,
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit
    ) {
        onImportStateChanged(ImportState.Importing)
        // The nsec crosses the FFI as a wipeable ByteArray; keep-mobile decodes the
        // bech32 and derives the key in-crate, so no plaintext key String lives on the
        // JVM heap. The bytes are copied into the Rust buffer synchronously by
        // importNsec, then zeroed unconditionally via executeImport's cleanup (which
        // runs even if the coroutine is cancelled before the call dispatches).
        executeImport(cipher, onImportStateChanged, cleanup = { nsec.fill(0.toByte()) }) {
            keepMobile.importNsec(nsec, name)
        }
    }

    fun createAccountFromMnemonic(
        mnemonic: ByteArray,
        passphrase: String,
        name: String,
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit
    ) {
        onImportStateChanged(ImportState.Importing)
        // The mnemonic crosses the FFI as a wipeable ByteArray; keep-mobile derives the
        // key in-crate. Zero the bytes unconditionally once the async call has run.
        executeImport(cipher, onImportStateChanged, cleanup = { mnemonic.fill(0.toByte()) }) {
            keepMobile.createAccountFromMnemonic(mnemonic, passphrase, name)
        }
    }

    /**
     * Mint (or re-mint) this device's per-group DKG signing subkey and return its
     * pubkey hex. The secret stays in Rust memory keyed by [groupName]; each
     * participant runs this, exchanges pubkeys out of band, and the coordinator
     * assembles them into the roster that [createGroup] consumes. Must be called
     * with the same [groupName] later passed as config.groupName.
     */
    fun dkgBegin(groupName: String): String = keepMobile.frostDkgBegin(groupName)

    /** Signal a cancel to an in-flight [createGroup] DKG run. */
    fun cancelDkg() = keepMobile.frostCancelDkg()

    fun createGroup(
        config: DkgConfig,
        name: String,
        cipher: Cipher,
        onState: (CreateGroupState) -> Unit
    ) {
        val mainHandler = Handler(Looper.getMainLooper())
        // The DKG completes inside frost_run_dkg (share already persisted) before
        // this coroutine resumes to post Success. Progress updates arrive on the
        // main Handler while the coroutine resumes on the Compose dispatcher, and
        // the two are not FIFO-ordered: a late Running(Finalizing) could otherwise
        // overwrite the terminal state and freeze the UI on "Finalizing…". Route
        // every state change through this one Handler and drop progress once
        // terminal, so Success/Error always win.
        val finished = AtomicBoolean(false)
        fun postState(state: CreateGroupState) = mainHandler.post { onState(state) }
        // Reject a duplicate ceremony (e.g. a double-tap, or a retry while a run
        // left running in the background is still finishing) before posting any
        // Running state, so nothing queues behind the in-flight run and cancel
        // can only target the one on the wire. Cleared when the run finishes.
        if (!dkgInProgress.compareAndSet(false, true)) {
            postState(CreateGroupState.Error(appContext.getString(R.string.create_group_in_progress)))
            return
        }
        val callback = object : DkgProgressCallback {
            override fun onProgress(update: DkgProgressUpdate) {
                mainHandler.post { if (!finished.get()) onState(CreateGroupState.Running(update)) }
            }
        }
        val passphraseChars = CharArray(64)
        val random = ByteArray(32)
        SecureRandom().nextBytes(random)
        val hex = "0123456789abcdef"
        for (i in random.indices) {
            val b = random[i].toInt() and 0xFF
            passphraseChars[i * 2] = hex[b ushr 4]
            passphraseChars[i * 2 + 1] = hex[b and 0x0F]
        }
        Arrays.fill(random, 0.toByte())
        // frostRunDkg takes a String, so this copies the passphrase into an
        // immutable JVM object that cannot be wiped and lives until GC. The value
        // is a freshly generated ephemeral key, not user-derived; the char array
        // and entropy bytes above are still zeroed to limit their lifetime.
        val passphrase = String(passphraseChars)
        // Wipe synchronously here rather than in a finally inside the launch:
        // the coroutine body (and its finally) never runs if the scope is
        // already cancelled, stranding the passphrase bytes in the array until
        // GC. The ceremony only needs the immutable `passphrase` copy above.
        Arrays.fill(passphraseChars, '\u0000')

        postState(CreateGroupState.Running(DkgProgressUpdate.Connecting))
        val job = coroutineScope.launch {
            accountMutex.withLock {
                val requestId = UUID.randomUUID().toString()
                var pendingSet = false
                try {
                    storage.setPendingCipher(requestId, cipher, timeoutMs = DKG_CIPHER_TIMEOUT_MS)
                    pendingSet = true
                    val result = withContext(Dispatchers.IO) {
                        storage.setRequestIdContext(requestId)
                        try {
                            keepMobile.frostRunDkg(config, name, passphrase, DKG_ROUND_TIMEOUT_SECS.toULong(), callback)
                        } finally {
                            storage.clearRequestIdContext()
                        }
                    }
                    finished.set(true)
                    postState(CreateGroupState.Success(result.name, result.groupPubkey))
                    try {
                        refreshAccountState()
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-DKG refresh failed: ${e::class.simpleName}")
                    }
                } catch (c: CancellationException) {
                    throw c
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.e("AccountActions", "DKG failed: ${e::class.simpleName}")
                    finished.set(true)
                    postState(CreateGroupState.Error(appContext.getString(R.string.create_group_failed)))
                } finally {
                    if (pendingSet) storage.clearPendingCipher(requestId)
                }
            }
        }
        // Release the single-flight guard via completion rather than a finally in
        // the body: a coroutine launched into an already-cancelled scope never runs
        // its body, but invokeOnCompletion still fires (synchronously here), so the
        // guard cannot be stranded true and permanently block later ceremonies.
        job.invokeOnCompletion { dkgInProgress.set(false) }
    }

    /**
     * The DKG share (if any) that completed its ceremony but whose import into
     * share storage was never confirmed, e.g. after a storage failure or a crash
     * mid-import. Reads only the non-auth marker, so it needs no biometric.
     * `null` when nothing is pending.
     */
    /**
     * `Ok(null)` means nothing is pending; a failure means the stash could not be
     * read and must not be rendered as absence. The Rust draws the same
     * distinction deliberately (`pending_dkg_share`), because a marker that reads
     * as absent while `frost_run_dkg` still fail-closes on it strands the user
     * with no way to reach the discard escape hatch.
     */
    suspend fun pendingDkgShare(): Result<PendingShareInfo?> = withContext(Dispatchers.IO) {
        runCatching { keepMobile.pendingDkgShare() }
    }

    /**
     * Permanently abandon a pending DKG share, re-enabling group creation when a
     * stash can't be recovered (its record is corrupt, or the vault won't unlock).
     * Destructive: the caller must gate this behind an explicit confirmation.
     */
    suspend fun discardPendingDkgShare() = withContext(Dispatchers.IO) {
        keepMobile.discardPendingDkgShare()
        runCatching { refreshAccountState() }
        Unit
    }

    /**
     * Finish importing a vault-protected pending DKG share. Two authorized ciphers
     * are needed and gathered in one biometric chain (like [renameShare]): an RSA
     * decrypt cipher to unwrap the auth-gated secret, then an AES encrypt cipher to
     * store the recovered share. The ephemeral ceremony passphrase rides inside the
     * secret, so no passphrase is asked of the user. [onResult] receives the stored
     * share, or null on any failure/cancel.
     */
    fun recoverPendingDkgShare(
        title: String,
        subtitle: String,
        onResult: (ShareInfo?) -> Unit,
        // Null reason means the user cancelled and needs no message. Any other stop
        // must carry one: Recover sits in an undismissable dialog whose only other
        // button destroys the share, so a silent no-op reads as a dead button.
        onDismiss: (String?) -> Unit
    ) {
        coroutineScope.launch {
            val pendingResult = pendingDkgShare()
            val pending = pendingResult.getOrNull()
            if (pending == null) {
                // Genuinely absent -> no exception -> nothing to say. A read failure
                // here carries a message and must not look like a dead button.
                onDismiss(pendingResult.exceptionOrNull()?.message)
                return@launch
            }
            if (!pending.vaultProtected) {
                onDismiss(appContext.getString(R.string.main_pending_dkg_recover_passphrase_required))
                return@launch
            }
            // A re-enrolled fingerprint invalidates the alias, and the exception
            // carries the only actionable text ("please re-import your share").
            val decryptAttempt = withContext(Dispatchers.IO) {
                runCatching { storage.getDkgSecretDecryptCipher() }
            }
            val decryptCipher = decryptAttempt.getOrNull()
            if (decryptCipher == null) {
                onDismiss(
                    decryptAttempt.exceptionOrNull()?.message
                        ?: appContext.getString(R.string.main_pending_dkg_recover_unavailable)
                )
                return@launch
            }
            onBiometricRequest(title, subtitle, decryptCipher) { authedDecrypt ->
                if (authedDecrypt == null) {
                    onDismiss(null)
                    return@onBiometricRequest
                }
                requestEncryptCipherAndRecover(pending.groupPubkey, title, subtitle, authedDecrypt, onResult, onDismiss)
            }
        }
    }

    private fun requestEncryptCipherAndRecover(
        groupPubkeyHex: String,
        title: String,
        subtitle: String,
        authedDecrypt: Cipher,
        onResult: (ShareInfo?) -> Unit,
        onDismiss: (String?) -> Unit
    ) {
        coroutineScope.launch {
            val encryptAttempt = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareEncryption(groupPubkeyHex) }
            }
            val encryptCipher = encryptAttempt.getOrNull()
            if (encryptCipher == null) {
                onDismiss(
                    encryptAttempt.exceptionOrNull()?.message
                        ?: appContext.getString(R.string.main_pending_dkg_recover_unavailable)
                )
                return@launch
            }
            onBiometricRequest(title, subtitle, encryptCipher) { authedEncrypt ->
                if (authedEncrypt == null) {
                    onDismiss(null)
                    return@onBiometricRequest
                }
                finishRecoverDkgShare(authedDecrypt, authedEncrypt, onResult)
            }
        }
    }

    private fun finishRecoverDkgShare(
        authedDecrypt: Cipher,
        authedEncrypt: Cipher,
        onResult: (ShareInfo?) -> Unit
    ) {
        coroutineScope.launch {
            accountMutex.withLock {
                val requestId = UUID.randomUUID().toString()
                var pendingSet = false
                try {
                    storage.setPendingCipher(requestId, authedDecrypt, AndroidKeystoreStorage.CipherRole.DECRYPT)
                    pendingSet = true
                    storage.setPendingCipher(requestId, authedEncrypt, AndroidKeystoreStorage.CipherRole.ENCRYPT)
                    val info = withContext(Dispatchers.IO) {
                        storage.setRequestIdContext(requestId)
                        try {
                            // Vault-protected: the passphrase is stashed in the secret.
                            keepMobile.recoverDkgShare(null)
                        } finally {
                            storage.clearRequestIdContext()
                        }
                    }
                    runCatching { refreshAccountState() }
                    onResult(info)
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.e("AccountActions", "DKG recovery failed: ${e::class.simpleName}")
                    onResult(null)
                } finally {
                    if (pendingSet) storage.clearPendingCipher(requestId)
                }
            }
        }
    }

    // The Rust FFI returns the seed as a wipeable ByteArray; it is delivered to onResult
    // (which decodes it into a wipeable buffer) and then zeroed unconditionally in the
    // finally below, so no seed String lives on the JVM heap.
    fun viewSeedWords(
        account: AccountInfo,
        onResult: (ByteArray?) -> Unit,
        onDismiss: (Boolean) -> Unit
    ) {
        withBiometricAuth(
            account.groupPubkeyHex,
            appContext.getString(R.string.account_view_seed_title),
            appContext.getString(R.string.account_view_seed_subtitle),
            { onDismiss(false) }
        ) { authedCipher ->
            accountMutex.withLock {
                val requestId = UUID.randomUUID().toString()
                var pendingSet = false
                var success = false
                var delivered = false
                var seedWords: ByteArray? = null
                try {
                    val activeNow = withContext(Dispatchers.IO) { storage.getActiveShareKey() }
                    if (activeNow != account.groupPubkeyHex) {
                        delivered = true
                        onResult(null)
                        return@withLock
                    }
                    storage.setPendingCipher(requestId, authedCipher)
                    pendingSet = true
                    seedWords = withContext(Dispatchers.IO) {
                        storage.setRequestIdContext(requestId)
                        try {
                            keepMobile.getSeedWords(account.groupPubkeyHex)
                        } finally {
                            storage.clearRequestIdContext()
                        }
                    }
                    if (seedWords == null) {
                        coroutineScope.launch(Dispatchers.Main) {
                            Toast.makeText(appContext, appContext.getString(R.string.account_view_seed_none), Toast.LENGTH_SHORT).show()
                        }
                    }
                    delivered = true
                    onResult(seedWords)
                    success = seedWords != null
                } catch (e: Exception) {
                    logAndToast("View seed words failed", appContext.getString(R.string.account_view_seed_failed), e)
                    if (!delivered) onResult(null)
                } finally {
                    seedWords?.fill(0.toByte())
                    if (pendingSet) storage.clearPendingCipher(requestId)
                    onDismiss(success)
                }
            }
        }
    }

    fun markBackedUp(
        account: AccountInfo,
        onComplete: (Boolean) -> Unit
    ) {
        coroutineScope.launch {
            val decryptCipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(account.groupPubkeyHex) }.getOrNull()
            }
            if (decryptCipher == null) {
                onComplete(false)
                return@launch
            }
            onBiometricRequest(
                appContext.getString(R.string.account_confirm_backup_title),
                appContext.getString(R.string.account_confirm_backup_subtitle),
                decryptCipher
            ) { authedDecrypt ->
                if (authedDecrypt == null) {
                    onComplete(false)
                    return@onBiometricRequest
                }
                requestEncryptCipherAndFinishBackup(account, authedDecrypt, onComplete)
            }
        }
    }

    private fun requestEncryptCipherAndFinishBackup(
        account: AccountInfo,
        authedDecrypt: Cipher,
        onComplete: (Boolean) -> Unit
    ) {
        coroutineScope.launch {
            val encryptCipher = accountMutex.withLock {
                withContext(Dispatchers.IO) {
                    if (!shareExists(account.groupPubkeyHex)) null
                    else runCatching { storage.getCipherForShareEncryption(account.groupPubkeyHex) }.getOrNull()
                }
            }
            if (encryptCipher == null) {
                onComplete(false)
                return@launch
            }
            onBiometricRequest(
                appContext.getString(R.string.account_confirm_backup_title),
                appContext.getString(R.string.account_confirm_backup_save_subtitle),
                encryptCipher
            ) { authedEncrypt ->
                if (authedEncrypt == null) {
                    onComplete(false)
                    return@onBiometricRequest
                }
                finishMarkBackedUp(account, authedDecrypt, authedEncrypt, onComplete)
            }
        }
    }

    private fun finishMarkBackedUp(
        account: AccountInfo,
        authedDecrypt: Cipher,
        authedEncrypt: Cipher,
        onComplete: (Boolean) -> Unit
    ) {
        coroutineScope.launch {
            accountMutex.withLock {
                val stillExists = withContext(Dispatchers.IO) { shareExists(account.groupPubkeyHex) }
                if (!stillExists) {
                    onComplete(false)
                    return@withLock
                }
                val requestId = UUID.randomUUID().toString()
                var pendingSet = false
                try {
                    storage.setPendingCipher(requestId, authedDecrypt, AndroidKeystoreStorage.CipherRole.DECRYPT)
                    pendingSet = true
                    storage.setPendingCipher(requestId, authedEncrypt, AndroidKeystoreStorage.CipherRole.ENCRYPT)
                    withContext(Dispatchers.IO) {
                        storage.setRequestIdContext(requestId)
                        try {
                            keepMobile.markShareBackedUp(account.groupPubkeyHex)
                        } finally {
                            storage.clearRequestIdContext()
                        }
                    }
                    try {
                        refreshAccountState()
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-mark refresh failed: ${e::class.simpleName}")
                    }
                    onComplete(true)
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.e("AccountActions", "Mark backed up failed", e)
                    onComplete(false)
                } finally {
                    if (pendingSet) storage.clearPendingCipher(requestId)
                }
            }
        }
    }

    private fun shareExists(groupPubkeyHex: String): Boolean =
        storage.listAllShares().any { it.toAccountInfo().groupPubkeyHex == groupPubkeyHex }

    private fun executeImport(
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit,
        cleanup: (() -> Unit)? = null,
        apiCall: suspend () -> ShareInfo
    ) {
        coroutineScope.launch {
            try {
                accountMutex.withLock {
                    val importId = UUID.randomUUID().toString()
                    var pendingSet = false
                    try {
                        storage.setPendingCipher(importId, cipher)
                        pendingSet = true
                        val result = withContext(Dispatchers.IO) {
                            storage.setRequestIdContext(importId)
                            try {
                                apiCall()
                            } finally {
                                storage.clearRequestIdContext()
                            }
                        }
                        onImportStateChanged(ImportState.Success(result.name, result.groupPubkey))
                        try {
                            refreshAccountState()
                        } catch (e: Exception) {
                            if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-import refresh failed: ${e::class.simpleName}")
                        }
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("AccountActions", "Import failed: ${e::class.simpleName}")
                        onImportStateChanged(ImportState.Error(appContext.getString(R.string.account_import_failed)))
                    } finally {
                        if (pendingSet) storage.clearPendingCipher(importId)
                    }
                }
            } finally {
                // Runs on success, failure, AND coroutine cancellation (including a
                // cancel while suspended on the lock, before apiCall ran), so a secret
                // captured by apiCall is wiped unconditionally.
                cleanup?.invoke()
            }
        }
    }
}
