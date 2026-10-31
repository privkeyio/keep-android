package io.privkey.keep.nip46

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.printToString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import io.privkey.keep.AccountActions
import io.privkey.keep.ImportState
import io.privkey.keep.KeepMobileApp
import io.privkey.keep.toAccountInfo
import io.privkey.keep.nip55.AppPermissionsScreen
import io.privkey.keep.nip55.EventLogCategory
import io.privkey.keep.nip55.EventLogLevel
import io.privkey.keep.nip55.EventLogStore
import io.privkey.keep.nip55.FrostSignFixture
import io.privkey.keep.nip55.FrostSignTestSupport
import io.privkey.keep.nip55.FrostSignTestSupport.withCipher
import io.privkey.keep.nip55.Nip55Database
import io.privkey.keep.nip55.PermissionStore
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.ui.theme.KeepAndroidTheme
import io.privkey.keep.uniffi.BunkerConfigInfo
import io.privkey.keep.uniffi.BunkerRememberDuration
import io.privkey.keep.uniffi.BunkerStatus
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.RelayConfigInfo
import io.privkey.keep.uniffi.parseBunkerUrl
import io.privkey.keep.uniffi.truncateStr
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.SecureRandom

/**
 * End-to-end: a real NIP-46 client on the host (testharness/nip46probe) talks to the
 * real BunkerService over a public relay, and each revoke path is driven through its
 * real screen. Manual-only; run it with testharness/nip46probe/run-revoke-e2e.sh,
 * which serves the probe requests this test writes.
 *
 * It imports a throwaway nsec as a temporary account (the fixture share is 2-of-3
 * and cannot sign alone). The device's own state is saved to a file before anything
 * changes and restored after the run, or at the start of the next one if this run
 * was killed. Every run, and every recovery, ends with a fresh bunker key, under which
 * the core restores no grant made before it, so no test client keeps a way in.
 */
@RunWith(AndroidJUnit4::class)
class BunkerRevokeE2ETest {

    @get:Rule
    val compose = createComposeRule()

    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val app: KeepMobileApp get() = context.applicationContext as KeepMobileApp
    private val dir by lazy { File(context.filesDir, "bunker-e2e") }
    private val savedFile by lazy { File(context.filesDir, "bunker-e2e-saved.json") }
    private val clientsFile by lazy { File(context.filesDir, "bunker-e2e-clients.txt") }
    private val testAccounts = mutableSetOf<String>()
    private var requests = 0
    private var screen by mutableStateOf<Screen>(Screen.None)

    private sealed interface Screen {
        data object None : Screen
        data class Bunker(val generation: Int) : Screen
        data class Disconnect(val pubkey: String) : Screen
    }

    private class Client(val secret: String, val pubkey: String)

    @Test(timeout = 20 * 60_000L)
    fun aRevokedClientCannotConnectOrSignOnAnyRevokePath() {
        assumeTrue("manual-only; run testharness/nip46probe/run-revoke-e2e.sh", InstrumentationRegistry.getArguments().getString(MANUAL_ARG) == "1")
        val mobile = requireNotNull(app.getKeepMobile())
        val storage = requireNotNull(app.getStorage())
        recoverFromInterruptedRun(mobile, storage)
        assumeTrue("the bunker service must not be running", BunkerService.current() == null)
        val saved = SavedState.capture(context, mobile, storage)
        saved.writeTo(savedFile)
        var passed = false
        try {
            val secondAccount = importSecondAccount(mobile, storage)
            importThrowawayAccount(mobile, storage)
            val bunkerRelay = InstrumentationRegistry.getArguments().getString(RELAY_ARG) ?: FrostSignFixture.RELAY
            mobile.saveRelayConfig(null, RelayConfigInfo(saved.relays.frostRelays, saved.relays.profileRelays, listOf(bunkerRelay)))
            mobile.saveBunkerConfig(BunkerConfigInfo(true, emptyList()))
            markers().edit().putBoolean(BunkerService.KEY_ROTATED_FOR_EARLIER_REVOKES, true).commit()
            // Fresh keys, so requests an earlier run left on the relay never reach this bunker.
            runBlocking { BunkerService.rotateBunkerCredentials(mobile) }
            compose.setContent { KeepAndroidTheme { Host(mobile) } }

            // A secret-matched connect, and a sign the user approves with "always".
            BunkerService.start(context)
            val url1 = awaitRunning(previous = null)
            val c1 = newClient()
            assertOk(settled("connect", c1.secret, url1))
            awaitAuthorized(mobile, c1)
            val signed = probeAsync("sign", c1.secret, url1, "1", "90")
            approve(c1.pubkey)
            assertOk(awaitProbe(signed))
            // Another client with a remembered grant, which no revoke of a single client touches.
            val c2 = newClient()
            assertOk(settled("connect", c2.secret, url1))
            awaitAuthorized(mobile, c2)
            val signed2 = probeAsync("sign", c2.secret, url1, "1", "90")
            approve(c2.pubkey)
            assertOk(awaitProbe(signed2))

            // Control: after a plain restart the remembered grant signs with no connect and no prompt.
            stopService()
            BunkerService.start(context)
            assertEquals(url1, awaitRunning(previous = null))
            assertOk(settled("sign", c1.secret, url1, "1", "30"))

            // At the client cap, a connect that holds the bunker secret is refused and granted nothing.
            val listed = mobile.getBunkerConfig().authorizedClients
            val full = listed + probe("pubkeys", (BunkerService.MAX_AUTHORIZED_CLIENTS - listed.size).toString()).split(" ")
            mobile.saveBunkerConfig(BunkerConfigInfo(true, full))
            val stranger = newClient()
            val capped = System.currentTimeMillis()
            assertEquals("ERR Capacity exceeded", settled("connect", stranger.secret, url1))
            assertRefused(
                "a client refused at the cap must not sign",
                settled("sign", stranger.secret, url1, "1", "15"), stranger.pubkey, capped, reason = "Permission denied",
            )
            assertNull("a client refused at the cap must not be asked about", resumedApproval(stranger.pubkey))
            assertEquals("a client refused at the cap must not be listed", full, mobile.getBunkerConfig().authorizedClients)
            assertNull("a client refused at the cap must not be stored", Nip46ClientStore.getClient(context, stranger.pubkey))
            mobile.saveBunkerConfig(BunkerConfigInfo(true, listed))

            // Revoke from the Bunker screen while the bunker is stopped.
            stopService()
            screen = Screen.Bunker(1)
            revokeListedClient(c1.pubkey)
            BunkerService.start(context)
            val url2 = awaitRunning(previous = null)
            assertSecretReplaced(url1, url2)
            val restarted = System.currentTimeMillis()
            assertRefused("a grant revoked while the bunker was stopped must not come back on a start", settled("sign", c1.secret, url2, "1", "15"), c1.pubkey, restarted)
            assertOk(settled("sign", c2.secret, url2, "1", "15"))
            assertDead(url1, url2)

            // Revoke from the Bunker screen while the bunker is running.
            val c3 = newClient()
            assertOk(settled("connect", c3.secret, url2))
            awaitAuthorized(mobile, c3)
            screen = Screen.Bunker(2)
            revokeListedClient(c3.pubkey)
            val url3 = awaitRunning(previous = url2)
            assertSecretReplaced(url2, url3)
            assertOk(settled("sign", c2.secret, url3, "1", "15"))
            assertDead(url2, url3)

            // A prompt answered after its client was revoked is refused.
            val c5 = newClient()
            assertOk(settled("connect", c5.secret, url3))
            awaitAuthorized(mobile, c5)
            val asked = System.currentTimeMillis()
            val late = probeAsync("sign", c5.secret, url3, "1", "90")
            val requestId = awaitApprovalPrompt(c5.pubkey)
            runBlocking { BunkerService.revokeClients(context, mobile, listOf(c5.pubkey)) }
            respond(requestId, c5.pubkey)
            assertNotSigned("an approval given after the revoke must not sign", awaitProbe(late), c5.pubkey, asked)
            val url3b = awaitRunning(previous = url3)
            val revoked5 = System.currentTimeMillis()
            assertRefused("the revoked client must not sign after the restart", settled("sign", c5.secret, url3b, "1", "15"), c5.pubkey, revoked5)

            // Disconnect from App Permissions while the bunker is running.
            val c6 = newClient()
            assertOk(settled("connect", c6.secret, url3b))
            awaitAuthorized(mobile, c6)
            awaitStored(c6)
            screen = Screen.Disconnect(c6.pubkey)
            compose.waitUntil(30_000) { compose.onAllNodesWithText("Disconnect Client").fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText("Disconnect Client").performScrollTo().performClick()
            compose.onNodeWithText("Disconnect").performClick()
            val url4 = awaitRunning(previous = url3b)
            assertSecretReplaced(url3b, url4)
            assertFalse(c6.pubkey in mobile.getBunkerConfig().authorizedClients)
            assertNull("the client's stored entry must go", Nip46ClientStore.getClient(context, c6.pubkey))
            assertDead(url3b, url4)

            // Revoke All from the Bunker screen while the bunker is running.
            val c7 = newClient()
            val c8 = newClient()
            for (c in listOf(c7, c8)) {
                assertOk(settled("connect", c.secret, url4))
                awaitAuthorized(mobile, c)
                awaitStored(c)
            }
            screen = Screen.Bunker(3)
            compose.waitUntil(30_000) { compose.onAllNodesWithText(truncateStr(c8.pubkey, 8u, 6u)).fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText("Revoke All").performScrollTo().performClick()
            compose.onNode(hasText("Revoke All") and hasAnyAncestor(isDialog())).performClick()
            val url5 = awaitRunning(previous = url4)
            assertSecretReplaced(url4, url5)
            val revokedAll = System.currentTimeMillis()
            assertRefused("Revoke All must take every remembered grant", settled("sign", c2.secret, url5, "1", "15"), c2.pubkey, revokedAll)
            for (c in listOf(c7, c8)) {
                assertFalse(c.pubkey in mobile.getBunkerConfig().authorizedClients)
                assertNull("the client's stored entry must go", Nip46ClientStore.getClient(context, c.pubkey))
            }
            assertDead(url4, url5)

            // Account switch: the previous account's clients, and their remembered grants,
            // must not act as the new account.
            run {
                val c9 = newClient()
                assertOk(settled("connect", c9.secret, url5))
                awaitAuthorized(mobile, c9)
                val remembered = probeAsync("sign", c9.secret, url5, "1", "90")
                approve(c9.pubkey)
                assertOk(awaitProbe(remembered))
                // The app's own stop: a reset that fails wipes nothing. It also stops the
                // bunker, which then serves again so the switch below has one to halt.
                assertStoppedSwitchWipesNothing()
                BunkerService.start(context)
                assertEquals(url5, awaitRunning(previous = null))
                val throwaway = THROWAWAY_GROUP
                // The delete below must only ever be tried on the test's own account.
                check(storage.getActiveShareKey() == throwaway) { "the throwaway account is not the active one" }
                var resetAsked = false
                val failingReset: suspend (Boolean) -> Boolean = { stop -> resetAsked = resetAsked || stop; false }
                // A delete or a switch must stop when the bunker cannot be reset, wiping nothing.
                withAccountActions(mobile, storage, failingReset) { actions, done -> actions.deleteAccount(account(storage, throwaway), done) }
                assertTrue("the delete must ask to stop on a failed bunker reset", resetAsked)
                assertTrue("a failed bunker reset must stop the delete", storage.listAllShares().any { it.toAccountInfo().groupPubkeyHex == throwaway })
                assertEquals(throwaway, storage.getActiveShareKey())
                resetAsked = false
                withAccountActions(mobile, storage, failingReset) { actions, done -> actions.switchAccount(account(storage, secondAccount), done) }
                assertTrue("the switch must ask to stop on a failed bunker reset", resetAsked)
                assertEquals("a failed bunker reset must stop the switch", throwaway, storage.getActiveShareKey())
                // The app's own switch, in its own order: reset, wipe, then activate.
                withAccountActions(mobile, storage, { stop -> app.onAccountSwitched(stop) }) { actions, done ->
                    actions.switchAccount(account(storage, secondAccount), done)
                }
                assertEquals("the switch must activate the new account", secondAccount, storage.getActiveShareKey())
                FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "bunker-e2e-switch-init")
                val afterSwitch = mobile.getBunkerConfig()
                assertFalse("the switch turns the bunker off", afterSwitch.enabled)
                assertTrue("the switch drops the previous account's clients", afterSwitch.authorizedClients.isEmpty())
                assertNull(Nip46ClientStore.getClient(context, c9.pubkey))
                // The user turns the bunker back on under the new account.
                mobile.saveBunkerConfig(BunkerConfigInfo(true, emptyList()))
                BunkerService.start(context)
                val url6 = awaitRunning(previous = null)
                assertRotated(url5, url6)
                val switched = System.currentTimeMillis()
                assertRefused(
                    "a grant remembered under the previous account must not sign as the new one",
                    settled("sign", c9.secret, url6, "1", "15"), c9.pubkey, switched, reason = "Permission denied",
                )
                assertFalse("the mark is cleared once the grants are revoked", markers().getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false))
                // And it stays revoked: a later start must not restore it.
                stopService()
                BunkerService.start(context)
                assertEquals(url6, awaitRunning(previous = null))
                val restarted = System.currentTimeMillis()
                assertRefused(
                    "a revoked grant must stay revoked across restarts",
                    settled("sign", c9.secret, url6, "1", "15"), c9.pubkey, restarted, reason = "Permission denied",
                )
                assertDead(url5, url6)

                // Import over the active account: the core switches as it stores, so the mark
                // that revokes the previous account's grants is saved before the store runs.
                val c10 = newClient()
                assertOk(settled("connect", c10.secret, url6))
                awaitAuthorized(mobile, c10)
                val rememberedHere = probeAsync("sign", c10.secret, url6, "1", "90")
                approve(c10.pubkey)
                assertOk(awaitProbe(rememberedHere))
                val active = storage.getActiveShareKey()
                val (thirdNsec, thirdAccount) = newTestAccount()
                val realReset: suspend (Boolean) -> Boolean = { stop -> app.onAccountSwitched(stop) }
                importThroughActions(mobile, storage, thirdNsec, realReset) { throw IllegalStateException("bunker-e2e: the mark fails") }
                assertFalse(
                    "an import must not run when the mark cannot be saved",
                    storage.listAllShares().any { it.toAccountInfo().groupPubkeyHex == thirdAccount },
                )
                assertEquals(active, storage.getActiveShareKey())
                // An import that stores nothing withdraws its mark, and the grants stay.
                var savedAhead = false
                importThroughActions(mobile, storage, "nsec1bunkere2einvalid", realReset) {
                    BunkerService.markRevokeAllAhead(context).also { savedAhead = markers().getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false) }
                }
                assertTrue("the import must save the mark before it runs", savedAhead)
                assertFalse("an import that changed nothing must withdraw its mark", markers().getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false))
                stopService()
                BunkerService.start(context)
                assertEquals("an import that changed nothing must not rotate the bunker", url6, awaitRunning(previous = null))
                assertOk(settled("sign", c10.secret, url6, "1", "15"))
                // A switching import whose reset then fails still revokes at the next start.
                importThroughActions(mobile, storage, thirdNsec, onAccountSwitched = { false })
                assertEquals("the import must activate the new account", thirdAccount, storage.getActiveShareKey())
                assertTrue("the mark must be saved before the import switches", markers().getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false))
                FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "bunker-e2e-import-init")
                stopService()
                BunkerService.start(context)
                val url7 = awaitRunning(previous = null)
                assertRotated(url6, url7)
                val imported = System.currentTimeMillis()
                assertRefused(
                    "a grant remembered under the account an import replaced must not sign as the new one",
                    settled("sign", c10.secret, url7, "1", "15"), c10.pubkey, imported, reason = "Permission denied",
                )
                assertFalse("the mark is cleared once the grants are revoked", markers().getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false))
            }
            passed = true
        } finally {
            screen = Screen.None
            val failures = cleanUp(mobile, storage, saved)
            // A failed cleanup fails a passing run, but never hides the failure of a failing one.
            if (passed && failures.isNotEmpty()) throw AssertionError("cleanup failed: ${failures.joinToString()}")
        }
    }

    @androidx.compose.runtime.Composable
    private fun Host(mobile: KeepMobile) {
        val url by BunkerService.bunkerUrl.collectAsState()
        val status by BunkerService.status.collectAsState()
        when (val current = screen) {
            Screen.None -> Unit
            is Screen.Bunker -> androidx.compose.runtime.key(current.generation) {
                BunkerScreen(mobile, url, status, onToggleBunker = {}, onDismiss = {})
            }
            is Screen.Disconnect -> AppPermissionsScreen(
                packageName = "nip46:${current.pubkey}",
                permissionStore = PermissionStore(Nip55Database.getInstance(context)),
                onDismiss = {}
            )
        }
    }

    /**
     * Leaves no test client a way in: a fresh bunker key, under which the core restores no
     * grant made before it, and the request files
     * (which hold client secrets and URLs) deleted. Each step runs whatever happened before it.
     */
    private fun cleanUp(mobile: KeepMobile, storage: AndroidKeystoreStorage, saved: SavedState): List<String> {
        val failures = mutableListOf<String>()
        fun step(name: String, block: () -> Unit) = runCatching(block).onFailure {
            Log.e(TAG, "cleanup step '$name' failed", it)
            failures += "$name: $it"
        }
        step("stop the bunker") { stopService() }
        step("rotate the bunker URL") { runBlocking { BunkerService.rotateBunkerCredentials(mobile) } }
        failures += saved.restore(context, mobile, storage, testAccounts)
        step("delete the request files") { check(!dir.exists() || dir.deleteRecursively()) }
        if (failures.isEmpty()) step("delete the saved state") { check(savedFile.delete() && (!clientsFile.exists() || clientsFile.delete())) }
        return failures
    }

    // A run killed mid-way (a crash, the timeout) leaves its saved state and the throwaway
    // account behind; put the device back before saving its state again.
    private fun recoverFromInterruptedRun(mobile: KeepMobile, storage: AndroidKeystoreStorage) {
        if (savedFile.exists()) {
            val failures = mutableListOf<String>()
            fun step(name: String, block: () -> Unit) = runCatching(block).onFailure {
                Log.e(TAG, "recovery step '$name' failed", it)
                failures += "$name: $it"
            }
            // The killed run left the bunker enabled, so the app may have started it again.
            step("stop the bunker") { stopService() }
            step("rotate the bunker URL") { runBlocking { BunkerService.rotateBunkerCredentials(mobile) } }
            val recorded = if (clientsFile.exists()) clientsFile.readLines().mapNotNull { line -> line.split(" ").takeIf { it.size == 2 } } else emptyList()
            failures += SavedState.readFrom(savedFile).restore(
                context, mobile, storage,
                testAccounts = recorded.filter { it[0] == ACCOUNT }.map { it[1] }.toSet(),
            )
            check(failures.isEmpty()) {
                "could not restore the state an interrupted run saved (see README): ${failures.joinToString()}"
            }
            dir.deleteRecursively()
            check(savedFile.delete() && (!clientsFile.exists() || clientsFile.delete()))
        }
        clientsFile.delete()
        dropThrowawayAccount(mobile, storage)
    }

    // The list rows have no semantics of their own, so every row's label and Revoke button
    // are siblings; the button for a client is the one on the same line as its label.
    private fun revokeListedClient(pubkey: String) {
        val label = truncateStr(pubkey, 8u, 6u)
        try {
            compose.waitUntil(30_000) { compose.onAllNodesWithText(label).fetchSemanticsNodes().size == 1 }
        } catch (e: ComposeTimeoutException) {
            throw AssertionError("expected ${pubkey.take(8)} listed once:\n" + compose.onRoot().printToString(), e)
        }
        compose.onNodeWithText(label).performScrollTo()
        val row = compose.onNodeWithText(label).fetchSemanticsNode().boundsInRoot
        val buttons = compose.onAllNodesWithContentDescription("Revoke")
        val index = buttons.fetchSemanticsNodes().indexOfFirst { it.boundsInRoot.center.y in row.top..row.bottom }
        check(index >= 0) { "no Revoke button beside ${pubkey.take(8)}:\n" + compose.onRoot().printToString() }
        buttons[index].performClick()
        compose.onNodeWithText("Revoke").performClick()
        // The row goes only after the revoke and its rotation both complete.
        compose.waitUntil(60_000) { compose.onAllNodesWithText(label).fetchSemanticsNodes().isEmpty() }
    }

    private fun assertStoppedSwitchWipesNothing() {
        val log = EventLogStore.getInstance(Nip55Database.getInstance(context))
        val sentinel = "bunker-e2e sentinel ${System.nanoTime()}"
        runBlocking { log.log(EventLogCategory.BUNKER, EventLogLevel.INFO, "bunker-e2e", sentinel) }
        val realReset = app.resetBunkerForSwitch
        app.resetBunkerForSwitch = { _, _ -> throw IllegalStateException("bunker-e2e: the reset fails") }
        val result = try {
            runBlocking { app.onAccountSwitched(true) }
        } finally {
            app.resetBunkerForSwitch = realReset
        }
        assertFalse("a reset that fails must be reported", result)
        val entries = runBlocking { log.getRecent(200) }
        assertTrue("a stopped switch must wipe nothing", entries.any { it.message == sentinel })
        assertTrue(
            "a stopped switch must say so",
            entries.any { it.level == EventLogLevel.ERROR.name && it.message.startsWith("The bunker was stopped and could not be reset") },
        )
    }

    private fun account(storage: AndroidKeystoreStorage, key: String) =
        storage.listAllShares().map { it.toAccountInfo() }.single { it.groupPubkeyHex == key }

    // Runs one of the app's account actions, the biometric prompt answered with the cipher it
    // was given, and waits for the action to dismiss.
    private fun withAccountActions(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        onAccountSwitched: suspend (Boolean) -> Boolean,
        markBunkerRevokeAhead: () -> (Boolean) -> Unit = { BunkerService.markRevokeAllAhead(context) },
        action: (AccountActions, () -> Unit) -> Unit,
    ) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val dismissed = CompletableDeferred<Unit>()
        try {
            val actions = AccountActions(
                keepMobile = mobile,
                storage = storage,
                coroutineScope = scope,
                appContext = context,
                onBiometricRequest = { _, _, cipher, onResult -> onResult(cipher) },
                onAccountSwitched = onAccountSwitched,
                onAccountDeleted = {},
                onLiveNodeDropped = {},
                onStateChanged = {},
                markBunkerRevokeAhead = markBunkerRevokeAhead,
            )
            storage.getActiveShareKey()?.let { actions.setCurrentRelays(mobile.getRelayConfig(it).frostRelays) }
            action(actions) { dismissed.complete(Unit) }
            runBlocking { withTimeout(60_000) { dismissed.await() } }
        } finally {
            scope.cancel()
        }
    }

    // Runs the app's own import, waiting for it to finish either way.
    private fun importThroughActions(
        mobile: KeepMobile,
        storage: AndroidKeystoreStorage,
        nsec: String,
        onAccountSwitched: suspend (Boolean) -> Boolean,
        markBunkerRevokeAhead: () -> (Boolean) -> Unit = { BunkerService.markRevokeAllAhead(context) },
    ) = withAccountActions(mobile, storage, onAccountSwitched, markBunkerRevokeAhead) { actions, done ->
        actions.importNsec(nsec.toByteArray(), "bunker-e2e-import", storage.getCipherForEncryption()) { state ->
            if (state is ImportState.Success || state is ImportState.Error) done()
        }
    }

    // An account the test owns, as its nsec and group key. Random, so it is never one of the
    // device's own; recorded before use so cleanup and recovery delete it.
    private fun newTestAccount(): Pair<String, String> {
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val nsec = probe("nsec", secret)
        check(nsec.startsWith("nsec1")) { "probe returned no nsec: $nsec" }
        // An nsec account's group key is the key's own pubkey, so it can be recorded first.
        val expected = probe("pubkey", secret)
        clientsFile.appendText("$ACCOUNT $expected\n")
        testAccounts += expected
        return nsec to expected
    }

    // A second account, for the account switch.
    private fun importSecondAccount(mobile: KeepMobile, storage: AndroidKeystoreStorage): String {
        val (nsec, expected) = newTestAccount()
        val group = withCipher(storage, "bunker-e2e-import-second", storage.getCipherForEncryption()) {
            mobile.importNsec(nsec.toByteArray(), "bunker-e2e-second")
        }.groupPubkey
        check(group == expected) { "unexpected group key $group for the second account" }
        return group
    }

    private fun importThrowawayAccount(mobile: KeepMobile, storage: AndroidKeystoreStorage) {
        val info = withCipher(storage, "bunker-e2e-import", storage.getCipherForEncryption()) {
            mobile.importNsec(THROWAWAY_NSEC.toByteArray(), "bunker-e2e")
        }
        check(info.groupPubkey == THROWAWAY_GROUP) { "unexpected throwaway key ${info.groupPubkey}" }
        if (storage.getActiveShareKey() != THROWAWAY_GROUP) switchAccount(mobile, storage, THROWAWAY_GROUP)
        FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "bunker-e2e-init")
    }

    private fun stopService() {
        BunkerService.stop(context)
        awaitTrue("the service stops") { BunkerService.current() == null && BunkerService.status.value != BunkerStatus.RUNNING }
    }

    private fun awaitRunning(previous: String?): String {
        var url: String? = null
        awaitTrue("the bunker runs with a new URL", 120_000) {
            url = BunkerService.bunkerUrl.value
            BunkerService.status.value == BunkerStatus.RUNNING && url != null && url != previous
        }
        return url!!
    }

    private fun awaitStored(client: Client) =
        awaitTrue("the client ${client.pubkey.take(8)} is stored") { Nip46ClientStore.getClient(context, client.pubkey) != null }

    private fun awaitAuthorized(mobile: KeepMobile, client: Client) =
        awaitTrue("the connect from ${client.pubkey.take(8)} is authorized") { client.pubkey in mobile.getBunkerConfig().authorizedClients }

    private fun assertRotated(old: String, new: String) {
        val before = parseBunkerUrl(old)
        val after = parseBunkerUrl(new)
        assertNotEquals("the bunker key must change", before.pubkey, after.pubkey)
        assertNotEquals("the connect secret must change", before.secret, after.secret)
    }

    // A revoke replaces only the connect secret, so other clients keep their grants.
    private fun assertSecretReplaced(old: String, new: String) {
        val before = parseBunkerUrl(old)
        val after = parseBunkerUrl(new)
        assertEquals("the bunker key must stay", before.pubkey, after.pubkey)
        assertNotEquals("the connect secret must change", before.secret, after.secret)
    }

    // A refusal can reach the probe as an error or, from a bunker that does not answer, a
    // TIMEOUT, which proves nothing on its own, so the same relay must answer a connect to
    // the new URL right after. The probe reports UNSENT rather than TIMEOUT when no relay
    // took the request, so a request that never left cannot pass for a dead URL.
    private fun assertDead(old: String, new: String) {
        var result = probe("connect", newClient().secret, old, "15")
        repeat(2) { if (result.startsWith("UNSENT")) result = probe("connect", newClient().secret, old, "15") }
        assertTrue("the old URL must be dead, got: $result", result == "TIMEOUT" || result.startsWith("ERR "))
        assertOk(settled("connect", newClient().secret, new))
    }

    // The revoke stops the bunker under the open prompt, so the answer can be lost on the way;
    // the bunker's own log is what shows nothing was signed.
    private fun assertNotSigned(message: String, result: String, pubkey: String, since: Long) {
        assertFalse("$message; got: $result", result.startsWith("OK "))
        assertFalse("$message; the request never left: $result", result.startsWith("UNSENT"))
        val log = EventLogStore.getInstance(Nip55Database.getInstance(context))
        assertFalse(message, runBlocking { log.getRecent(200) }.any {
            it.timestamp >= since && it.category == EventLogCategory.BUNKER.name && it.level == EventLogLevel.INFO.name &&
                it.source == pubkey.take(8) && it.message.startsWith("sign_event")
        })
    }

    private fun awaitApprovalPrompt(pubkey: String): String {
        var requestId: String? = null
        awaitTrue("the approval prompt opens", 60_000) {
            requestId = resumedApproval(pubkey)?.intent?.getStringExtra(Nip46ApprovalActivity.EXTRA_REQUEST_ID)
            requestId != null
        }
        return requestId!!
    }

    private fun resumedApproval(pubkey: String): Activity? {
        var found: Activity? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            found = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                .firstOrNull { it is Nip46ApprovalActivity && it.intent.getStringExtra(Nip46ApprovalActivity.EXTRA_APP_PUBKEY) == pubkey }
        }
        return found
    }

    // Answers the way the prompt's Approve button does after its biometric check, which
    // is the one step this test cannot drive.
    private fun respond(requestId: String, pubkey: String) {
        BunkerService.respondToApproval(requestId, approved = true, clientPubkey = pubkey, remember = BunkerRememberDuration.FOREVER)
        val prompt = resumedApproval(pubkey) ?: return
        InstrumentationRegistry.getInstrumentation().runOnMainSync { prompt.finish() }
    }

    private fun approve(pubkey: String) = respond(awaitApprovalPrompt(pubkey), pubkey)

    private fun newClient(): Client {
        val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val pubkey = probe("pubkey", secret)
        check(pubkey.matches(Regex("[0-9a-f]{64}"))) { "probe returned no pubkey: $pubkey" }
        return Client(secret, pubkey)
    }

    private fun probe(vararg args: String): String = awaitProbe(probeAsync(*args))

    // A bunker reports RUNNING a moment before its relay subscription is live, and a relay
    // can drop a request, so a positive check retries an unanswered one. Retrying only ever
    // turns a lost request into an answer; checks that expect a TIMEOUT use probe().
    private fun settled(vararg args: String): String {
        repeat(2) { probe(*args).let { if (it != "TIMEOUT" && !it.startsWith("UNSENT")) return it } }
        return probe(*args)
    }

    private fun probeAsync(vararg args: String): Int {
        dir.mkdirs()
        val n = ++requests
        val tmp = File(dir, "req-$n.tmp")
        tmp.writeText(args.joinToString(" "))
        check(tmp.renameTo(File(dir, "req-$n")))
        return n
    }

    private fun awaitProbe(n: Int): String {
        val res = File(dir, "res-$n")
        awaitTrue("the host answers request $n", 180_000) { res.exists() }
        return res.readText().trim()
    }

    private fun awaitTrue(what: String, timeoutMs: Long = 60_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting until $what" }
            Thread.sleep(250)
        }
    }

    private fun assertOk(result: String) = assertTrue("expected OK, got: $result", result.startsWith("OK "))

    // The core does not answer a client that holds no permission, so a refusal can reach the
    // probe as a TIMEOUT. The bunker's own log entry is what proves the request arrived and failed.
    private fun assertRefused(message: String, result: String, pubkey: String, since: Long, reason: String? = null) {
        assertFalse("$message; got: $result", result.startsWith("OK "))
        val log = EventLogStore.getInstance(Nip55Database.getInstance(context))
        awaitTrue("the bunker logs the refused sign from ${pubkey.take(8)}") {
            runBlocking { log.getRecent(200) }.any {
                it.timestamp >= since && it.category == EventLogCategory.BUNKER.name && it.level == EventLogLevel.WARN.name &&
                    it.source == pubkey.take(8) && it.message.startsWith("sign_event") && (reason == null || reason in it.message)
            }
        }
    }

    private fun markers() = context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)

    private class SavedState(
        val activeKey: String?,
        val relays: RelayConfigInfo,
        val bunker: BunkerConfigInfo,
        val denylist: Set<String>,
        val marker: Boolean,
        val revokeAllMark: Boolean,
    ) {
        /** Restores each part on its own, so one failure does not skip the rest. Returns the failures. */
        fun restore(
            context: Context,
            mobile: KeepMobile,
            storage: AndroidKeystoreStorage,
            testAccounts: Set<String>,
        ): List<String> {
            val failures = mutableListOf<String>()
            fun step(name: String, block: () -> Unit) = runCatching(block).onFailure {
                Log.e(TAG, "restore step '$name' failed", it)
                failures += "$name: $it"
            }
            step("relay config") { mobile.saveRelayConfig(null, relays) }
            step("bunker config") { mobile.saveBunkerConfig(bunker) }
            step("denylist") { Nip46ClientStore.setDenylistForTest(context, denylist) }
            step("bunker markers") {
                check(context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean(BunkerService.KEY_ROTATED_FOR_EARLIER_REVOKES, marker)
                    .putBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, revokeAllMark)
                    .commit())
            }
            step("active account") { activeKey?.takeIf { it != THROWAWAY_GROUP && it !in testAccounts }?.let { switchAccount(mobile, storage, it) } }
            step("throwaway account") { dropThrowawayAccount(mobile, storage, testAccounts) }
            testAccounts.forEach { key ->
                step("test account ${key.take(8)}") { if (mobile.listShares().any { it.groupPubkey == key }) mobile.deleteShareByKey(key) }
            }
            return failures
        }

        fun writeTo(file: File) {
            val json = JSONObject()
                .put("activeKey", activeKey ?: JSONObject.NULL)
                .put("frostRelays", JSONArray(relays.frostRelays))
                .put("profileRelays", JSONArray(relays.profileRelays))
                .put("bunkerRelays", JSONArray(relays.bunkerRelays))
                .put("bunkerEnabled", bunker.enabled)
                .put("authorizedClients", JSONArray(bunker.authorizedClients))
                .put("denylist", JSONArray(denylist.toList()))
                .put("marker", marker)
                .put("revokeAllMark", revokeAllMark)
            val tmp = File(file.path + ".tmp")
            tmp.writeText(json.toString())
            check(tmp.renameTo(file))
        }

        companion object {
            fun capture(context: Context, mobile: KeepMobile, storage: AndroidKeystoreStorage) = SavedState(
                activeKey = storage.getActiveShareKey(),
                relays = mobile.getRelayConfig(null),
                bunker = mobile.getBunkerConfig(),
                denylist = Nip46ClientStore.getDenylist(context),
                marker = context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
                    .getBoolean(BunkerService.KEY_ROTATED_FOR_EARLIER_REVOKES, false),
                revokeAllMark = context.getSharedPreferences(BunkerService.BUNKER_MARKERS_PREFS, Context.MODE_PRIVATE)
                    .getBoolean(BunkerService.KEY_REVOKE_ALL_ON_START, false),
            )

            fun readFrom(file: File): SavedState {
                val json = JSONObject(file.readText())
                fun list(name: String) = json.getJSONArray(name).let { a -> List(a.length()) { a.getString(it) } }
                return SavedState(
                    activeKey = if (json.isNull("activeKey")) null else json.getString("activeKey"),
                    relays = RelayConfigInfo(list("frostRelays"), list("profileRelays"), list("bunkerRelays")),
                    bunker = BunkerConfigInfo(json.getBoolean("bunkerEnabled"), list("authorizedClients")),
                    denylist = list("denylist").toSet(),
                    marker = json.getBoolean("marker"),
                    revokeAllMark = json.optBoolean("revokeAllMark", false),
                )
            }
        }
    }

    private companion object {
        const val TAG = "BunkerRevokeE2ETest"
        const val MANUAL_ARG = "bunkerRevokeE2e"
        const val RELAY_ARG = "bunkerRelay"
        // The NIP-19 test vector key: public, used only for this temporary account.
        const val ACCOUNT = "account"
        const val THROWAWAY_NSEC = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
        const val THROWAWAY_GROUP = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"

        fun switchAccount(mobile: KeepMobile, storage: AndroidKeystoreStorage, key: String) =
            withCipher(storage, "bunker-e2e-switch", requireNotNull(storage.getCipherForShareDecryption(key)) { "no cipher for $key" }) {
                mobile.setActiveShare(key)
            }

        // Matched by its key, so no account of the device's own is ever deleted.
        fun dropThrowawayAccount(mobile: KeepMobile, storage: AndroidKeystoreStorage, testAccounts: Set<String> = emptySet()) {
            val shares = mobile.listShares()
            if (shares.none { it.groupPubkey == THROWAWAY_GROUP }) return
            if (storage.getActiveShareKey() == THROWAWAY_GROUP) {
                shares.firstOrNull { it.groupPubkey != THROWAWAY_GROUP && it.groupPubkey !in testAccounts }
                    ?.let { switchAccount(mobile, storage, it.groupPubkey) }
            }
            mobile.deleteShareByKey(THROWAWAY_GROUP)
        }
    }
}
