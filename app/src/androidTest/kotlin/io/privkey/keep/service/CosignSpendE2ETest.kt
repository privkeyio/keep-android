package io.privkey.keep.service

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.privkey.keep.R
import io.privkey.keep.describe
import io.privkey.keep.nip55.FrostSignFixture
import io.privkey.keep.nip55.FrostSignTestSupport
import io.privkey.keep.spendOverview
import io.privkey.keep.storage.AndroidKeystoreStorage
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.ShareMetadataInfo
import io.privkey.keep.uniffi.SignRequest
import io.privkey.keep.uniffi.SpendOutput
import io.privkey.keep.uniffi.SpendSummary
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Locale
import kotlin.random.Random

/**
 * A spend co-signed over the network: a peer on the host holding the fixture's other share
 * asks this device to sign a taproot spend, and the request the device is shown is checked
 * against the transaction the peer built. The prompt lists every output with its exact
 * amount, the fee and the total. The notification counts the outputs, says the rest is in
 * the app, and offers no Approve, and an approve sent from a notification is refused. A
 * key-path spend of the group's own taproot output is shown the same way and signs under
 * the tweaked output key. A Nostr note signs from the notification, while a contact list,
 * which the core marks as needing a fresh authentication, signs only when approved in the app.
 *
 * Manual only: run testharness/cosignpeer/run-spend-e2e.sh, which serves the peer.
 */
@RunWith(AndroidJUnit4::class)
class CosignSpendE2ETest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dir = File(context.filesDir, "cosign-e2e")
    private var requests = 0
    private val salt = Random.nextInt(1, 1_000)
    private lateinit var storage: AndroidKeystoreStorage
    private var mobile: KeepMobile? = null
    private var plantedDescriptor: String? = null

    @After
    fun tearDown() {
        plantedDescriptor?.let { runCatching { storage.deleteShareByKey(it) } }
        context.getSystemService(NotificationManager::class.java).cancel(CosignNotifier.NOTIFICATION_ID)
        mobile?.destroy()
    }

    @Test(timeout = 15 * 60_000L)
    fun aSpendIsShownInFullAndIsNotApprovedFromTheNotification() {
        assumeTrue(
            "manual-only; run testharness/cosignpeer/run-spend-e2e.sh",
            InstrumentationRegistry.getArguments().getString(MANUAL_ARG) == "1",
        )
        InstrumentationRegistry.getInstrumentation().uiAutomation
            .grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        storage = FrostSignTestSupport.noAuthStorage()
        val mobile = KeepMobile(storage).also { this.mobile = it }
        FrostSignTestSupport.importShareNoAuth(mobile, storage, FrostSignFixture.SHARE1_EXPORT_DATA, "cosign-e2e-import")
        FrostSignTestSupport.initializeWithDecryptContext(mobile, storage, "cosign-e2e-connect")
        val group = FrostSignTestSupport.assertFixtureShareLoaded(mobile)
        assertFalse("the kill switch must be off to co-sign", mobile.getKillSwitch())
        assumeTrue(
            "the device already holds a wallet descriptor for the fixture group",
            mobile.walletDescriptorList().none { it.groupPubkey == group },
        )

        // No descriptor, so no network: neither output has an address, and each shows its script.
        val since = System.currentTimeMillis() / 1000
        val two = askPeer("two")
        val expectedTwo = SpendSummary(
            listOf(SpendOutput(90_000uL - salt.toULong(), null, P2WPKH_SCRIPT), SpendOutput(8_500uL, null, OP_RETURN_SCRIPT)),
            100_000uL,
            1_500uL + salt.toULong(),
        )
        val unaddressed = awaitSpend(mobile, since, expectedTwo)
        assertEquals(
            listOf(
                "bitcoin-sighash",
                "${sats(90_000 - salt)} to unrecognized script $P2WPKH_SCRIPT",
                "8,500 sats to unrecognized script $OP_RETURN_SCRIPT",
                "Fee: ${sats(1_500 + salt)}",
                "Total from inputs: 100,000 sats",
            ).joinToString("\n"),
            unaddressed.describe(),
        )

        var approved = false
        assertFalse(approveFromNotification(mobile.getPendingRequests(), unaddressed.id) { approved = true })
        assertFalse("an approve from the notification must not reach the core", approved)
        assertTrue("the spend is still waiting", mobile.getPendingRequests().any { it.id == unaddressed.id })

        // Answered before the slower notification checks, since the peer waits only a short round.
        val declined = answerUntilPeerReplies(mobile, since, two, expectedTwo, mobile::rejectRequest)
        assertTrue("a declined spend is not signed: $declined", declined.startsWith("ERR") && "rejected" in declined.lowercase())

        // Posting is asynchronous, and the app's own state callback can clear the
        // notification in between, so it is posted again until it shows.
        var posted: Notification? = null
        awaitTrue("the co-sign notification is posted", 15_000) {
            CosignNotifier.update(context, emptyList())
            CosignNotifier.update(context, listOf(unaddressed))
            Thread.sleep(500)
            posted = postedNotification()
            posted != null
        }
        val shown = requireNotNull(posted)
        assertEquals(
            "bitcoin-sighash\n2 outputs · fee ${sats(1_500 + salt)} · total from inputs 100,000 sats\nOpen Keep to review every output and approve.",
            shown.extras.getCharSequence(Notification.EXTRA_BIG_TEXT).toString(),
        )
        assertEquals(unaddressed.spendOverview(), shown.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertEquals(
            "a spend offers only Reject on the notification",
            listOf(context.getString(R.string.cosign_reject)),
            shown.actions?.map { it.title.toString() },
        )

        // With a descriptor naming testnet, the P2WPKH output shows as its address, and the
        // spend the device approves verifies on the peer under the group key.
        plantDescriptor(group)
        val since2 = System.currentTimeMillis() / 1000
        val one = askPeer("one")
        val expectedOne = SpendSummary(
            listOf(SpendOutput(99_000uL - salt.toULong(), TESTNET_ADDRESS, P2WPKH_SCRIPT)),
            100_000uL,
            1_000uL + salt.toULong(),
        )
        val addressed = awaitSpend(mobile, since2, expectedOne)
        assertEquals(
            "bitcoin-sighash\n${sats(99_000 - salt)} to $TESTNET_ADDRESS\nFee: ${sats(1_000 + salt)}\nTotal from inputs: 100,000 sats",
            addressed.describe(),
        )
        val signed = answerUntilPeerReplies(mobile, since2, one, expectedOne, mobile::approveRequest)
        assertTrue("the approved spend is signed: $signed", signed.startsWith("SIGNED "))
        assertNull(mobile.getPendingRequests().firstOrNull { it.id == addressed.id })

        // A payment spending the group's own BIP-86 output on the key path, with its own
        // amount so a redelivered request of the previous case cannot stand in for it. The
        // peer checks the signature under the tweaked key.
        val since3 = System.currentTimeMillis() / 1000
        val keyPath = askPeer("keypath")
        val expectedKeyPath = SpendSummary(
            listOf(SpendOutput(98_000uL - salt.toULong(), TESTNET_ADDRESS, P2WPKH_SCRIPT)),
            100_000uL,
            2_000uL + salt.toULong(),
        )
        val keyPathShown = awaitSpend(mobile, since3, expectedKeyPath)
        assertEquals(
            "bitcoin-sighash\n${sats(98_000 - salt)} to $TESTNET_ADDRESS\nFee: ${sats(2_000 + salt)}\nTotal from inputs: 100,000 sats",
            keyPathShown.describe(),
        )
        val keyPathSigned = answerUntilPeerReplies(mobile, since3, keyPath, expectedKeyPath, mobile::approveRequest)
        assertTrue("the approved key-path spend is signed: $keyPathSigned", keyPathSigned.startsWith("SIGNED "))

        // A contact list is a verified Nostr event, but the core asks for a fresh
        // authentication for it, so a notification approve is refused. Approved in the
        // app, which asks for that authentication first, it still signs.
        val since4 = System.currentTimeMillis() / 1000
        val contacts = askPeer("contacts")
        val isContacts = isThisEvent(3u, since4)
        val contactList = awaitRequest(mobile, "the peer's contact list reaches this device", isContacts)
        assertTrue(contactList.typeVerified)
        assertTrue("the core marks a contact list for fresh authentication", contactList.needsFreshAuth)
        assertFalse(CosignNotifier.approvableFromNotification(contactList))
        approved = false
        assertFalse(approveFromNotification(mobile.getPendingRequests(), contactList.id) { approved = true })
        assertFalse("an approve from the notification must not reach the core", approved)
        val contactsSigned = answerUntilPeerReplies(mobile, contacts, isContacts, mobile::approveRequest)
        assertTrue("the contact list approved in the app is signed: $contactsSigned", contactsSigned.startsWith("SIGNED "))

        // A note keeps the usual approval and signs from the notification.
        val since5 = System.currentTimeMillis() / 1000
        val note = askPeer("note")
        val isNote = isThisEvent(1u, since5)
        val noteShown = awaitRequest(mobile, "the peer's note reaches this device", isNote)
        assertFalse("the core clears a note for the usual approval", noteShown.needsFreshAuth)
        assertTrue(CosignNotifier.approvableFromNotification(noteShown))
        val noteSigned = answerUntilPeerReplies(mobile, note, isNote) { id ->
            check(approveFromNotification(mobile.getPendingRequests(), id, mobile::approveRequest))
        }
        assertTrue("the note approved from the notification is signed: $noteSigned", noteSigned.startsWith("SIGNED "))
    }

    private fun isThisEvent(kind: UInt, since: Long): (SignRequest) -> Boolean = {
        it.messageType == "nostr-event" && it.timestamp.toLong() >= since &&
            it.metadata?.eventKind == kind && it.metadata?.contentPreview?.startsWith("cosign-e2e $salt ") == true
    }

    // The record the core reads the account's network from, as a descriptor session stores it.
    private fun plantDescriptor(group: String) {
        val key = "__keep_descriptor_$group"
        val record = JSONObject()
            .put("group_pubkey", group)
            .put("external_descriptor", "tr(cosign-e2e/0/*)")
            .put("internal_descriptor", "tr(cosign-e2e/1/*)")
            .put("network", "testnet")
            .put("created_at", 1_700_000_000)
        storage.storeShareByKey(key, record.toString().toByteArray(), ShareMetadataInfo("descriptor", 0u, 0u, 0u, ByteArray(0), false))
        plantedDescriptor = key
    }

    private fun postedNotification(): Notification? =
        context.getSystemService(NotificationManager::class.java).activeNotifications
            .firstOrNull { it.id == CosignNotifier.NOTIFICATION_ID }?.notification

    private fun sats(n: Int) = String.format(Locale.US, "%,d sats", n)

    // On connecting, the device fetches recent relay history and can raise an earlier run's
    // request again. Only this run's exact spend counts, and any other is declined, since the
    // device takes the next message only once the request in front of it is answered.
    private fun awaitSpend(mobile: KeepMobile, since: Long, expected: SpendSummary): SignRequest =
        awaitRequest(mobile, "the peer's spend reaches this device") { isThisSpend(it, since, expected) }

    private fun awaitRequest(mobile: KeepMobile, what: String, matches: (SignRequest) -> Boolean): SignRequest {
        var found: SignRequest? = null
        awaitTrue(what, 180_000) {
            declineOthers(mobile, matches)
            found = mobile.getPendingRequests().firstOrNull(matches)
            found != null
        }
        return requireNotNull(found)
    }

    private fun declineOthers(mobile: KeepMobile, matches: (SignRequest) -> Boolean) =
        mobile.getPendingRequests().filterNot(matches).forEach { mobile.rejectRequest(it.id) }

    private fun isThisSpend(request: SignRequest, since: Long, expected: SpendSummary) =
        request.messageType == "bitcoin-sighash" && request.timestamp.toLong() >= since && request.metadata?.spend == expected

    // The peer waits one short round per request and then asks again as a new request, so
    // every request for this spend is answered until the peer reports the outcome.
    private fun answerUntilPeerReplies(mobile: KeepMobile, since: Long, n: Int, expected: SpendSummary, answer: (String) -> Unit): String =
        answerUntilPeerReplies(mobile, n, { isThisSpend(it, since, expected) }, answer)

    private fun answerUntilPeerReplies(mobile: KeepMobile, n: Int, matches: (SignRequest) -> Boolean, answer: (String) -> Unit): String {
        val res = File(dir, "res-$n")
        val answered = mutableSetOf<String>()
        awaitTrue("the peer answers request $n", 300_000) {
            declineOthers(mobile, matches)
            mobile.getPendingRequests()
                .filter { matches(it) && it.id !in answered }
                .forEach {
                    answered += it.id
                    answer(it.id)
                }
            res.exists()
        }
        return res.readText().trim()
    }

    private fun askPeer(case: String): Int {
        val relay = InstrumentationRegistry.getArguments().getString(RELAY_ARG) ?: FrostSignFixture.RELAY
        dir.mkdirs()
        val n = ++requests
        val tmp = File(dir, "req-$n.tmp")
        tmp.writeText(listOf(case, salt.toString(), relay, FrostSignFixture.PASSPHRASE, FrostSignFixture.SHARE2_EXPORT_DATA).joinToString(" "))
        check(tmp.renameTo(File(dir, "req-$n")))
        return n
    }

    private fun awaitTrue(what: String, timeoutMs: Long, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { "timed out waiting until $what" }
            Thread.sleep(250)
        }
    }

    private companion object {
        const val MANUAL_ARG = "cosignSpendE2e"
        const val RELAY_ARG = "cosignRelay"
        const val P2WPKH_SCRIPT = "00140303030303030303030303030303030303030303"
        const val OP_RETURN_SCRIPT = "6a0402020202"
        const val TESTNET_ADDRESS = "tb1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcr7mrzn4"
    }
}
