package io.privkey.keep

import android.content.Context
import android.util.Log
import android.widget.Toast
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.storage.RelayConfigStore
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays
import java.util.UUID
import javax.crypto.Cipher

internal class AccountActions(
    private val keepMobile: KeepMobile,
    private val storage: AndroidKeystoreStorage,
    private val relayConfigStore: RelayConfigStore,
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
        val relays: List<String>
    )

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
            val h = keepMobile.hasShare()
            val s = keepMobile.getShareInfo()
            val k = storage.getActiveShareKey()
            val a = storage.listAllShares().map { it.toAccountInfo() }
            val r = if (k != null) relayConfigStore.getRelaysForAccount(k) else relayConfigStore.getRelays()
            AccountState(h, s, k, a, r)
        }
        onStateChanged(result)
    }

    fun switchAccount(account: AccountInfo, onDismiss: () -> Unit) {
        coroutineScope.launch {
            val cipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(account.groupPubkeyHex) }.getOrNull()
            }
            if (cipher == null) {
                onDismiss()
                return@launch
            }
            onBiometricRequest("Switch Account", "Authenticate to switch", cipher) { authedCipher ->
                if (authedCipher != null) {
                    coroutineScope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                val currentKey = storage.getActiveShareKey()
                                if (currentKey != null) {
                                    relayConfigStore.setRelaysForAccount(currentKey, currentRelays)
                                }
                            }
                            activateShare(authedCipher, account.groupPubkeyHex)
                            onAccountSwitched()
                            refreshAccountState()
                            onDismiss()
                        } catch (e: Exception) {
                            if (BuildConfig.DEBUG) Log.e("AccountActions", "Switch failed: ${e::class.simpleName}")
                            withContext(Dispatchers.Main) {
                                Toast.makeText(appContext, "Failed to switch account", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        }
    }

    fun deleteAccount(account: AccountInfo, onDismiss: () -> Unit) {
        coroutineScope.launch {
            val cipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(account.groupPubkeyHex) }.getOrNull()
            }
            if (cipher == null) {
                onDismiss()
                return@launch
            }
            onBiometricRequest("Delete Account", "Authenticate to delete account", cipher) { authedCipher ->
                if (authedCipher != null) {
                    coroutineScope.launch {
                        try {
                            performDelete(account, onDismiss)
                        } catch (e: Exception) {
                            if (BuildConfig.DEBUG) Log.e("AccountActions", "Delete failed: ${e::class.simpleName}")
                            withContext(Dispatchers.Main) {
                                Toast.makeText(appContext, "Failed to delete account", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun performDelete(account: AccountInfo, onDismiss: () -> Unit) {
        val activeAccountKey = withContext(Dispatchers.IO) { storage.getActiveShareKey() }
        val wasActive = account.groupPubkeyHex == activeAccountKey
        withContext(Dispatchers.IO) {
            keepMobile.deleteShareByKey(account.groupPubkeyHex)
            relayConfigStore.deleteRelaysForAccount(account.groupPubkeyHex)
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
        }
    }

    private fun switchToNextAccountAfterDelete(nextAccount: AccountInfo, onDismiss: () -> Unit) {
        coroutineScope.launch {
            val switchCipher = withContext(Dispatchers.IO) {
                runCatching { storage.getCipherForShareDecryption(nextAccount.groupPubkeyHex) }.getOrNull()
            }
            if (switchCipher != null) {
                onBiometricRequest("Switch Account", "Authenticate to switch to remaining account", switchCipher) { switchAuthed ->
                    coroutineScope.launch {
                        if (switchAuthed != null) {
                            try {
                                activateShare(switchAuthed, nextAccount.groupPubkeyHex)
                            } catch (e: Exception) {
                                if (BuildConfig.DEBUG) Log.e("AccountActions", "Post-delete switch failed: ${e::class.simpleName}")
                            }
                        }
                        onAccountSwitched()
                        refreshAccountState()
                        onDismiss()
                    }
                }
            } else {
                onAccountSwitched()
                refreshAccountState()
                onDismiss()
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
        val keyBytes = nsecToBytes(nsec) ?: run {
            onImportStateChanged(ImportState.Error("Invalid nsec format"))
            return
        }
        executeImport(cipher, onImportStateChanged) {
            try {
                val hexKey = keyBytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                keepMobile.importNsec(hexKey, name)
            } finally {
                Arrays.fill(keyBytes, 0.toByte())
            }
        }
    }

    private fun executeImport(
        cipher: Cipher,
        onImportStateChanged: (ImportState) -> Unit,
        apiCall: suspend () -> ShareInfo
    ) {
        coroutineScope.launch {
            val importId = UUID.randomUUID().toString()
            storage.setPendingCipher(importId, cipher)
            try {
                val result = withContext(Dispatchers.IO) {
                    storage.setRequestIdContext(importId)
                    try {
                        apiCall()
                    } finally {
                        storage.clearRequestIdContext()
                    }
                }
                onImportStateChanged(ImportState.Success(result.name))
                refreshAccountState()
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) Log.e("AccountActions", "Import failed: ${e::class.simpleName}")
                onImportStateChanged(ImportState.Error("Import failed. Please try again."))
            } finally {
                storage.clearPendingCipher(importId)
            }
        }
    }
}
