package io.privkey.keep

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.core.app.ActivityOptionsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.KeepMobile
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Drives the backup screen over real storage and the core, with the biometric prompt
 * answered in place. Every account of a vault takes its own numbered prompt, and a
 * refused one ends the backup or restore.
 */
@RunWith(AndroidJUnit4::class)
class BackupRestorePromptsTest {

    // createComposeRule() is deprecated in favor of the v2 API; the classic rule
    // is intentional here, and the project builds with -Werror.
    @Suppress("DEPRECATION")
    @get:Rule
    val compose = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var storage: AndroidKeystoreStorage
    private lateinit var mobile: KeepMobile
    private val created = mutableListOf<String>()
    private val prompts = Collections.synchronizedList(mutableListOf<Pair<Int, Int>>())
    private val backupFile = File(context.cacheDir, "backup-prompts-test.kbak")

    // Stands in for the system pickers: a request to save is recorded, and a request to
    // open a file is answered with the backup written for the test.
    private val saveRequested = AtomicBoolean(false)
    private val registryOwner = object : ActivityResultRegistryOwner {
        override val activityResultRegistry: ActivityResultRegistry = object : ActivityResultRegistry() {
            override fun <I, O> onLaunch(
                requestCode: Int,
                contract: ActivityResultContract<I, O>,
                input: I,
                options: ActivityOptionsCompat?
            ) {
                if (contract is ActivityResultContracts.OpenDocument) {
                    val result = Intent().setData(Uri.fromFile(backupFile))
                    Handler(Looper.getMainLooper()).post { dispatchResult(requestCode, Activity.RESULT_OK, result) }
                } else {
                    saveRequested.set(true)
                }
            }
        }
    }

    @Before
    fun setup() {
        storage = AndroidKeystoreStorage(context, requireUserAuth = false, keystoreAlias = ALIAS, prefsSuffix = SUFFIX)
        mobile = KeepMobile(storage)
        repeat(ACCOUNTS) { importNewGroup(it) }
    }

    @After
    fun teardown() {
        backupFile.delete()
        created.forEach { runCatching { mobile.deleteShareByKey(it) } }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(ALIAS) }.forEach { keyStore.deleteEntry(it) }
    }

    private fun <T> inRequest(stage: (String) -> Unit, block: () -> T): T {
        val requestId = "backup-prompts-${System.nanoTime()}"
        stage(requestId)
        storage.setRequestIdContext(requestId)
        try {
            return block()
        } finally {
            storage.clearRequestIdContext()
            storage.clearPendingCipher(requestId)
            storage.clearCipherProvider(requestId)
        }
    }

    private fun importNewGroup(i: Int) {
        val export = mobile.frostGenerate(2u.toUShort(), 2u.toUShort(), "screen-$i", "screen-$i")
            .shares.first().exportData
        created += inRequest({ storage.setPendingCipher(it, storage.getCipherForEncryption()) }) {
            mobile.importShare(export, "screen-$i", "screen-$i")
        }.groupPubkey
    }

    private fun storedGroups(): Set<String> =
        storage.listAllShares().map { meta -> meta.groupPubkey.joinToString("") { "%02x".format(it) } }.toSet()

    // A backup of every account, written to the file the open picker hands back, then the
    // accounts removed so the restore has them to write.
    private fun backUpAndClear() {
        val data = inRequest({ id ->
            storage.setCipherProvider(id) { key, _ -> storage.getCipherForShareDecryption(key) }
        }) { mobile.createBackup(PASSPHRASE) }
        backupFile.writeBytes(data)
        created.forEach { mobile.deleteShareByKey(it) }
        assertTrue(storedGroups().isEmpty())
    }

    private fun render(refuseAt: Int?) {
        compose.setContent {
            CompositionLocalProvider(LocalActivityResultRegistryOwner provides registryOwner) {
                KeepAndroidTheme {
                    BackupRestoreScreen(
                        keepMobile = mobile,
                        storage = storage,
                        onGetBackupCipher = { key -> storage.getCipherForShareDecryption(key) },
                        onGetRestoreCipher = { storage.getCipherForEncryption() },
                        onBiometricAuth = { cipher, step, total, callback ->
                            prompts += step to total
                            callback(if (step == refuseAt) null else cipher)
                        },
                        onDismiss = {}
                    )
                }
            }
        }
    }

    private fun startBackup(refuseAt: Int?) {
        render(refuseAt)
        compose.onNodeWithText(context.getString(R.string.backup_restore_passphrase_label))
            .performTextInput(PASSPHRASE)
        compose.onNodeWithText(context.getString(R.string.backup_restore_confirm_passphrase_label))
            .performTextInput(PASSPHRASE)
        compose.onNode(hasText(context.getString(R.string.backup_restore_create_button)) and hasClickAction())
            .performClick()
    }

    private fun startRestore(refuseAt: Int?) {
        render(refuseAt)
        compose.onNodeWithText(context.getString(R.string.backup_restore_select_file)).performClick()
        val passphraseField = hasText(context.getString(R.string.backup_restore_backup_passphrase_label))
        compose.waitUntil(TIMEOUT_MS) { compose.onAllNodes(passphraseField).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(passphraseField).performTextInput(PASSPHRASE)
        compose.onNodeWithText(context.getString(R.string.backup_restore_verify)).performClick()
        val restore = hasText(context.getString(R.string.backup_restore_restore_button)) and hasClickAction()
        compose.waitUntil(TIMEOUT_MS) { compose.onAllNodes(restore).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(restore).performClick()
        compose.waitUntil(TIMEOUT_MS) { compose.onAllNodes(restore).fetchSemanticsNodes().size == 2 }
        compose.onAllNodes(restore)[1].performClick()
    }

    private fun shown(id: Int) = compose.onAllNodes(hasText(context.getString(id))).fetchSemanticsNodes().isNotEmpty()

    @Test
    fun everyAccountTakesItsOwnNumberedPromptToBackUp() {
        startBackup(refuseAt = null)

        compose.waitUntil(TIMEOUT_MS) { saveRequested.get() || shown(R.string.backup_restore_backup_failed) }
        assertEquals((1..ACCOUNTS).map { it to ACCOUNTS }, prompts.toList())
        assertEquals("the backup must be made", true, saveRequested.get())
    }

    @Test
    fun aRefusedPromptEndsTheBackup() {
        startBackup(refuseAt = 2)

        compose.waitUntil(TIMEOUT_MS) { shown(R.string.backup_restore_backup_failed) }
        assertEquals(listOf(1 to ACCOUNTS, 2 to ACCOUNTS), prompts.toList())
        assertEquals("no backup is offered for saving", false, saveRequested.get())
    }

    @Test
    fun everyAccountTakesItsOwnNumberedPromptToRestore() {
        backUpAndClear()
        startRestore(refuseAt = null)

        compose.waitUntil(TIMEOUT_MS) {
            shown(R.string.backup_restore_restore_complete) || shown(R.string.backup_restore_failed)
        }
        assertEquals((1..ACCOUNTS).map { it to ACCOUNTS }, prompts.toList())
        assertEquals(created.toSet(), storedGroups())
    }

    // The first account is written before the second prompt is refused, so the restore
    // says it stopped partway rather than that nothing happened.
    @Test
    fun aRefusedPromptPartwayThroughARestoreSaysWhatWasKept() {
        backUpAndClear()
        startRestore(refuseAt = 2)

        compose.waitUntil(TIMEOUT_MS) {
            shown(R.string.backup_restore_partial) || shown(R.string.backup_restore_failed)
        }
        assertEquals(listOf(1 to ACCOUNTS, 2 to ACCOUNTS), prompts.toList())
        assertTrue("the partial message is shown", shown(R.string.backup_restore_partial))
        assertEquals(1, storedGroups().size)
    }

    private companion object {
        const val ACCOUNTS = 3
        const val TIMEOUT_MS = 30_000L
        const val SUFFIX = "_backup_prompts_test"
        const val ALIAS = "keep_frost_share$SUFFIX"
        const val PASSPHRASE = "backup-prompts-test-passphrase"
    }
}
