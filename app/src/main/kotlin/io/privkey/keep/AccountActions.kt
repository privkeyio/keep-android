package io.privkey.keep

import android.content.Context
import android.util.Log
import android.widget.Toast
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.nsecToHex
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.Cipher

private val EMPTY_RELAY_CONFIG = RelayConfigInfo(emptyList(), emptyList(), emptyList())

internal class AccountActions(
    private val keepMobile: KeepMobile,
    private val storage: AndroidKeystoreStorage,
    private val coroutineScope: CoroutineScope,
    private val appContext: Context,
    private val onBiometricRequest: (String, String, Cipher, (Cipher?) -> Unit) -> Unit,
    private val onAccountSwitched: suspend () -> Unit,
    private val onStateChanged: (AccountState) -> Unit
) {
    data class AccountState(
        val hasShare: Boolean,
        val shareInfo: ShareInfo?,
        val activeAccountKey: String?,
        val allAccounts: List<AccountInfo>,
        val relays: List<String>,
        val profileRelays: List<String>
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
            AccountState(hasShare, shareInfo, activeKey, accounts, config.frostRelays, config.profileRelays)
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
        withBiometricAuth(account.groupPubkeyHex, "Switch Account", "Authenticate to switch", onDismiss) { authedCipher ->
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
                    activateShare(authedCipher, account.groupPubkeyHex)
                    onAccountSwitched()
                    refreshAccountState()
                } catch (e: Exception) {
                    logAndToast("Switch failed", "Failed to switch account", e)
                } finally {
                    onDismiss()
                }
            }
        }
    }

    fun deleteAccount(account: AccountInfo, onDismiss: () -> Unit) {
        withBiometricAuth(account.groupPubkeyHex, "Delete Account", "Authenticate to delete account", onDismiss) {
            accountMutex.withLock {
                try {
                    performDelete(account, onDismiss)
                } catch (e: Exception) {
                    logAndToast("Delete failed", "Failed to delete account", e)
                    onDismiss()
                }
            }
        }
    }

    private suspend fun performDelete(account: AccountInfo, onDismiss: () -> Unit) {
        val activeAccountKey = withContext(Dispatchers.IO) { storage.getActiveShareKey() }
        val wasActive = account.groupPubkeyHex == activeAccountKey
        withContext(Dispatchers.IO) {
            keepMobile.deleteShareByKey(account.groupPubkeyHex)
            runCatching { keepMobile.deleteRelayConfig(account.groupPubkeyHex) }
                .onFailure { if (BuildConfig.DEBUG) Log.e("AccountActions", "Relay config cleanup failed: ${it::class.simpleName}") }
        }
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
            onBiometricRequest("Switch Account", "Authenticate to switch to remaining account", switchCipher) { switchAuthed ->
                coroutineScope.launch {
                    accountMutex.withLock {
                        try {
                            if (switchAuthed != null) {
                                try {
                                    activateShare(switchAuthed, nextAccount.groupPubkeyHex)
                                } catch (e: Exception) {
                                    if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-delete switch failed: ${e::class.simpleName}")
                                }
                            }
                            onAccountSwitched()
                            refreshAccountState()
                        } finally {
                            onDismiss()
                        }
                    }
                }
            }
        } else {
            onAccountSwitched()
            refreshAccountState()
            onDismiss()
        }
    }

    fun renameAccount(account: AccountInfo, newName: String) {
        coroutineScope.launch {
            accountMutex.withLock {
                try {
                    withContext(Dispatchers.IO) {
                        storage.renameShare(account.groupPubkeyHex, newName)
                    }
                } catch (e: Exception) {
                    logAndToast("Rename failed", "Failed to rename account", e)
                } finally {
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
            onImportStateChanged(ImportState.Error("Invalid share format"))
            return
        }
        executeImport(cipher, onImportStateChanged) { keepMobile.importShare(data, passphrase, name) }
    }

    fun importNsec(
        nsec: String,
        name: String,
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit
    ) {
        onImportStateChanged(ImportState.Importing)
        val hexKey = nsecToHex(nsec) ?: run {
            onImportStateChanged(ImportState.Error("Invalid nsec format"))
            return
        }
        executeImport(cipher, onImportStateChanged) {
            keepMobile.importNsec(hexKey, name)
        }
    }

    fun createAccountFromMnemonic(
        mnemonic: String,
        passphrase: String,
        name: String,
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit
    ) {
        onImportStateChanged(ImportState.Importing)
        executeImport(cipher, onImportStateChanged) {
            keepMobile.createAccountFromMnemonic(mnemonic, passphrase, name)
        }
    }

    private fun executeImport(
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit,
        apiCall: suspend () -> ShareInfo
    ) {
        coroutineScope.launch {
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
                    onImportStateChanged(ImportState.Success(result.name))
                    try {
                        refreshAccountState()
                    } catch (e: Exception) {
                        if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-import refresh failed: ${e::class.simpleName}")
                    }
                } catch (e: Exception) {
                    if (BuildConfig.DEBUG) Log.e("AccountActions", "Import failed: ${e::class.simpleName}")
                    onImportStateChanged(ImportState.Error("Import failed. Please try again."))
                } finally {
                    if (pendingSet) storage.clearPendingCipher(importId)
                }
            }
        }
    }
}
