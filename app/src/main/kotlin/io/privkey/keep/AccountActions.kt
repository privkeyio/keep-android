package io.privkey.keep

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Toast
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.DkgConfig
import io.privkey.keep.uniffi.DkgProgressCallback
import io.privkey.keep.uniffi.DkgProgressUpdate
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.ShareInfo
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
        val callback = object : DkgProgressCallback {
            override fun onProgress(update: DkgProgressUpdate) {
                mainHandler.post { onState(CreateGroupState.Running(update)) }
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
        val passphrase = String(passphraseChars)

        onState(CreateGroupState.Running(DkgProgressUpdate.Connecting))
        coroutineScope.launch {
            try {
                accountMutex.withLock {
                    val requestId = UUID.randomUUID().toString()
                    var pendingSet = false
                    try {
                        storage.setPendingCipher(requestId, cipher)
                        pendingSet = true
                        val result = withContext(Dispatchers.IO) {
                            storage.setRequestIdContext(requestId)
                            try {
                                keepMobile.frostRunDkg(config, name, passphrase, 180uL, callback)
                            } finally {
                                storage.clearRequestIdContext()
                            }
                        }
                        onState(CreateGroupState.Success(result.name, result.groupPubkey))
                        try {
                            refreshAccountState()
                        } catch (e: Exception) {
                            if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-DKG refresh failed: ${e::class.simpleName}")
                        }
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("AccountActions", "DKG failed: ${e::class.simpleName}")
                        onState(CreateGroupState.Error(appContext.getString(R.string.create_group_failed)))
                    } finally {
                        if (pendingSet) storage.clearPendingCipher(requestId)
                    }
                }
            } finally {
                Arrays.fill(passphraseChars, ' ')
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
