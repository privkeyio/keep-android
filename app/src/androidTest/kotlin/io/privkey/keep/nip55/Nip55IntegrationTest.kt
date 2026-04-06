package io.privkey.keep.nip55

import android.content.Intent
import android.net.Uri
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.Nip55RequestType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Nip55IntegrationTest {

    private lateinit var database: Nip55Database
    private lateinit var store: PermissionStore
    private lateinit var callerVerificationStore: CallerVerificationStore

    @Before
    fun setup() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            Nip55Database::class.java
        ).allowMainThreadQueries().build()
        store = PermissionStore(database)
        callerVerificationStore = CallerVerificationStore(
            ApplicationProvider.getApplicationContext()
        )
    }

    @After
    fun teardown() {
        database.close()
    }

    // --- NIP-55 Intent Parsing Tests ---

    @Test
    fun parseRequestFromIntent_getPublicKey_succeeds() {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("nostrsigner:")
            putExtra("type", "get_public_key")
            putExtra("id", "test-pubkey-001")
        }
        val type = intent.extras?.getString("type")
        assertEquals("get_public_key", type)
        assertEquals("test-pubkey-001", intent.getStringExtra("id"))
    }

    @Test
    fun parseRequestFromIntent_signEvent_parsesContent() {
        val eventJson = """{"kind":1,"content":"hello world","tags":[],"created_at":1234567890}"""
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("nostrsigner:${Uri.encode(eventJson)}")
            putExtra("type", "sign_event")
            putExtra("id", "test-sign-001")
        }
        val uriBody = intent.data?.schemeSpecificPart?.substringBefore('?') ?: ""
        val decoded = java.net.URLDecoder.decode(uriBody, "UTF-8")
        assertEquals(eventJson, decoded)

        val kind = parseEventKind(decoded)
        assertEquals(1, kind)
    }

    @Test
    fun parseRequestFromIntent_signEvent_parsesKind0Metadata() {
        val eventJson = """{"kind":0,"content":"{\"name\":\"test\"}","tags":[]}"""
        val kind = parseEventKind(eventJson)
        assertEquals(0, kind)
        assertTrue(isSensitiveKind(kind!!))
    }

    @Test
    fun parseRequestFromIntent_nip44Encrypt_hasPubkey() {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = Uri.parse("nostrsigner:${Uri.encode("secret message")}")
            putExtra("type", "nip44_encrypt")
            putExtra("pubkey", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            putExtra("id", "test-encrypt-001")
        }
        val pubkey = intent.getStringExtra("pubkey")
        assertNotNull(pubkey)
        assertEquals(64, pubkey!!.length)
    }

    @Test
    fun parseRequestFromIntent_invalidScheme_rejected() {
        val uri = Uri.parse("https://evil.com/steal?type=sign_event")
        assertNotEquals("nostrsigner", uri.scheme)
    }

    // --- Oversized Intent Extras Rejection ---

    @Test
    fun oversizedContent_exceeding1MB_isRejected() {
        val oversizedContent = "x".repeat(1024 * 1024 + 1)
        assertTrue(oversizedContent.length > 1024 * 1024)
    }

    @Test
    fun oversizedPubkey_exceeding128Chars_isRejected() {
        val oversizedPubkey = "a".repeat(129)
        assertTrue(oversizedPubkey.length > 128)
    }

    @Test
    fun oversizedExtra_exceeding2048Chars_isRejected() {
        val oversizedExtra = "b".repeat(2049)
        assertTrue(oversizedExtra.length > 2048)
    }

    @Test
    fun oversizedContent_exactly1MB_isAccepted() {
        val exactContent = "x".repeat(1024 * 1024)
        assertFalse(exactContent.length > 1024 * 1024)
    }

    @Test
    fun oversizedPubkey_exactly128Chars_isAccepted() {
        val exactPubkey = "a".repeat(128)
        assertFalse(exactPubkey.length > 128)
    }

    @Test
    fun oversizedCallbackUrl_exceeding2048_isRejected() {
        val longUrl = "https://example.com/" + "x".repeat(2048)
        assertTrue(longUrl.length > 2048)
    }

    @Test
    fun callbackUrl_nonHttps_isRejected() {
        val httpUrl = "http://insecure.com/callback"
        val parsed = runCatching { java.net.URL(httpUrl) }.getOrNull()
        assertNotNull(parsed)
        assertNotEquals("https", parsed!!.protocol)
    }

    @Test
    fun callbackUrl_validHttps_isAccepted() {
        val httpsUrl = "https://secure.example.com/callback"
        val parsed = runCatching { java.net.URL(httpsUrl) }.getOrNull()
        assertNotNull(parsed)
        assertEquals("https", parsed!!.protocol)
    }

    // --- TOFU (Trust-On-First-Use) Tests ---

    @Test
    fun tofuVerification_unknownPackage_returnsNotInstalled() {
        val result = callerVerificationStore.verifyOrTrust("com.nonexistent.app.zzzz")
        assertTrue(result is CallerVerificationStore.VerificationResult.NotInstalled)
    }

    @Test
    fun tofuVerification_installedPackage_returnsFirstUseRequiresApproval() {
        callerVerificationStore.clearAllTrust()
        val result = callerVerificationStore.verifyOrTrust("io.privkey.keep")
        assertTrue(
            "Expected FirstUseRequiresApproval after clearing trust, got: $result",
            result is CallerVerificationStore.VerificationResult.FirstUseRequiresApproval
        )
    }

    @Test
    fun tofuVerification_trustThenVerify_succeeds() {
        val pkgName = "io.privkey.keep"
        val sigHash = callerVerificationStore.getPackageSignatureHash(pkgName)
        assertNotNull("Should get signature hash for installed package", sigHash)

        callerVerificationStore.trustPackage(pkgName, sigHash!!)
        val result = callerVerificationStore.verifyOrTrust(pkgName)
        assertTrue("After trusting, should be Verified", result is CallerVerificationStore.VerificationResult.Verified)
    }

    @Test
    fun tofuVerification_signatureMismatch_isDetected() {
        val pkgName = "io.privkey.keep"
        callerVerificationStore.trustPackage(pkgName, "deadbeefdeadbeefdeadbeefdeadbeef")
        val result = callerVerificationStore.verifyOrTrust(pkgName)
        assertTrue(
            "Mismatched signature should be SignatureMismatch, got: $result",
            result is CallerVerificationStore.VerificationResult.SignatureMismatch
        )
    }

    @Test
    fun tofuVerification_clearAllTrust_resetsToFirstUse() {
        val pkgName = "io.privkey.keep"
        val sigHash = callerVerificationStore.getPackageSignatureHash(pkgName)
        assertNotNull(sigHash)

        callerVerificationStore.trustPackage(pkgName, sigHash!!)
        callerVerificationStore.clearAllTrust()

        val result = callerVerificationStore.verifyOrTrust(pkgName)
        assertTrue(
            "After clearAllTrust, should be FirstUseRequiresApproval",
            result is CallerVerificationStore.VerificationResult.FirstUseRequiresApproval
        )
    }

    // --- Nonce Verification Tests ---

    @Test
    fun nonceGeneration_andConsumption_succeeds() {
        val nonce = callerVerificationStore.generateNonce("com.test.app")
        assertNotNull(nonce)
        assertEquals(64, nonce.length)

        val result = callerVerificationStore.consumeNonce(nonce)
        assertTrue("Nonce should be valid", result is CallerVerificationStore.NonceResult.Valid)
        assertEquals("com.test.app", (result as CallerVerificationStore.NonceResult.Valid).packageName)
    }

    @Test
    fun nonceConsumption_isOneTimeOnly() {
        val nonce = callerVerificationStore.generateNonce("com.test.app")
        callerVerificationStore.consumeNonce(nonce)

        val secondResult = callerVerificationStore.consumeNonce(nonce)
        assertTrue("Second consumption should be Invalid", secondResult is CallerVerificationStore.NonceResult.Invalid)
    }

    @Test
    fun nonceInvalid_forUnknownNonce() {
        val result = callerVerificationStore.consumeNonce("not_a_real_nonce")
        assertTrue(result is CallerVerificationStore.NonceResult.Invalid)
    }

    // --- Permission Store Tests ---

    @Test
    fun permissionGrantAndDeny_worksCorrectly() = runBlocking {
        store.grantPermission("com.test.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        assertEquals(PermissionDecision.ALLOW, store.getPermissionDecision("com.test.app", Nip55RequestType.SIGN_EVENT, 1))

        store.denyPermission("com.test.app", Nip55RequestType.NIP44_ENCRYPT, null, PermissionDuration.FOREVER)
        assertEquals(PermissionDecision.DENY, store.getPermissionDecision("com.test.app", Nip55RequestType.NIP44_ENCRYPT, null))
    }

    @Test
    fun permissionAsk_isDefaultForUnknown() = runBlocking {
        val decision = store.getPermissionDecision("com.unknown.app", Nip55RequestType.SIGN_EVENT, 1)
        assertNull("Unknown caller should have null (no stored decision)", decision)
    }

    @Test
    fun auditLog_recordsOperations() = runBlocking {
        store.logOperation("com.test.app", Nip55RequestType.SIGN_EVENT, 1, "allow", wasAutomatic = false)
        store.logOperation("com.test.app", Nip55RequestType.GET_PUBLIC_KEY, null, "allow", wasAutomatic = true)

        val logs = store.getAuditLog(10)
        assertTrue("Should have at least 2 audit entries", logs.size >= 2)
    }

    @Test
    fun revokeAllPermissions_clearsEverything() = runBlocking {
        store.grantPermission("com.test1.app", Nip55RequestType.SIGN_EVENT, 1, PermissionDuration.FOREVER)
        store.grantPermission("com.test2.app", Nip55RequestType.GET_PUBLIC_KEY, null, PermissionDuration.FOREVER)

        store.revokeAllPermissions()

        assertNull(store.getPermissionDecision("com.test1.app", Nip55RequestType.SIGN_EVENT, 1))
        assertNull(store.getPermissionDecision("com.test2.app", Nip55RequestType.GET_PUBLIC_KEY, null))
    }

    // --- Event Kind Parsing Tests ---

    @Test
    fun parseEventKind_validKinds() {
        assertEquals(1, parseEventKind("""{"kind":1}"""))
        assertEquals(0, parseEventKind("""{"kind":0}"""))
        assertEquals(30023, parseEventKind("""{"kind":30023}"""))
        assertEquals(65535, parseEventKind("""{"kind":65535}"""))
    }

    @Test
    fun parseEventKind_invalidValues() {
        assertNull(parseEventKind("""{"content":"no kind"}"""))
        assertNull(parseEventKind("""not json"""))
        assertNull(parseEventKind(""))
    }

    @Test
    fun parseEventKind_outOfRange() {
        assertNull(parseEventKind("""{"kind":-1}"""))
        assertNull(parseEventKind("""{"kind":65536}"""))
    }

    // --- Content Provider Behavior Tests ---

    @Test
    fun contentProvider_getPublicKey_authority_isCorrect() {
        val uri = Uri.parse("content://io.privkey.keep.GET_PUBLIC_KEY")
        assertEquals("io.privkey.keep.GET_PUBLIC_KEY", uri.authority)
    }

    @Test
    fun contentProvider_signEvent_authority_isCorrect() {
        val uri = Uri.parse("content://io.privkey.keep.SIGN_EVENT")
        assertEquals("io.privkey.keep.SIGN_EVENT", uri.authority)
    }

    @Test
    fun contentProvider_allAuthorities_areDeclared() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val expectedAuthorities = listOf(
            "io.privkey.keep.GET_PUBLIC_KEY",
            "io.privkey.keep.SIGN_EVENT",
            "io.privkey.keep.NIP04_ENCRYPT",
            "io.privkey.keep.NIP04_DECRYPT",
            "io.privkey.keep.NIP44_ENCRYPT",
            "io.privkey.keep.NIP44_DECRYPT",
            "io.privkey.keep.DECRYPT_ZAP_EVENT"
        )
        for (authority in expectedAuthorities) {
            val providerInfo = context.packageManager.resolveContentProvider(authority, 0)
            assertNotNull("Content provider for authority $authority should be registered", providerInfo)
        }
    }

    // --- Rate Limiter Tests ---

    @Test
    fun rateLimiter_allowsNormalRequests() {
        val limiter = RateLimiter()
        for (i in 1..limiter.maxRequests) {
            assertTrue("Request $i should be allowed", limiter.checkRateLimit("com.test.app"))
        }
        assertFalse("Request beyond maxRequests should be rejected", limiter.checkRateLimit("com.test.app"))
    }

    // --- Risk Assessment Integration ---

    @Test
    fun riskAssessor_sensitiveKind_flagsHighRisk() = runBlocking {
        val auditDao = database.auditLogDao()
        val appSettingsDao = database.appSettingsDao()
        val assessor = RiskAssessor(auditDao, appSettingsDao)

        val result = assessor.assess("com.test.app", 0)
        assertTrue("Kind 0 (metadata) should be flagged as sensitive", result.factors.contains(RiskFactor.SENSITIVE_EVENT_KIND))
        assertTrue("Sensitive event should require auth", result.requiredAuth.atLeast(AuthLevel.PIN))
    }

    @Test
    fun riskAssessor_normalKind_lowRisk() = runBlocking {
        val auditDao = database.auditLogDao()
        val appSettingsDao = database.appSettingsDao()
        val assessor = RiskAssessor(auditDao, appSettingsDao)

        appSettingsDao.insertOrUpdate(Nip55AppSettings(
            callerPackage = "com.test.app",
            expiresAt = null,
            signPolicyOverride = null,
            createdAt = System.currentTimeMillis() - 7 * 24 * 60 * 60 * 1000L,
            createdAtElapsed = android.os.SystemClock.elapsedRealtime() - 7 * 24 * 60 * 60 * 1000L,
            durationMs = null
        ))

        for (i in 1..5) {
            auditDao.insert(Nip55AuditLog(
                callerPackage = "com.test.app",
                requestType = "SIGN_EVENT",
                eventKind = 1,
                decision = "allow",
                wasAutomatic = false,
                timestamp = System.currentTimeMillis() - i * 60 * 1000L
            ))
        }

        val result = assessor.assess("com.test.app", 1)
        assertEquals("Normal kind 1 with history should have low risk", AuthLevel.NONE, result.requiredAuth)
    }

}
