package io.privkey.keep.nip55

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.privkey.keep.uniffi.KeepMobile
import io.privkey.keep.uniffi.Nip55Handler
import io.privkey.keep.uniffi.Nip55Response
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Round-trip coverage for the batch result serialization seam (gh #323 item 5):
 * the JSON that [Nip55Activity.finishWithBatchResults] returns to the client must
 * parse back to one object per request with the expected shape. Serialization is
 * owned by the Rust handler (keep-mobile/src/nip55.rs, serialize_batch_results_json),
 * so this exercises the real FFI method rather than re-deriving the format in Kotlin.
 *
 * A share is never loaded: serialization does not touch signing, so a bare
 * [KeepMobile] is sufficient and the test needs no online co-signer.
 */
@RunWith(AndroidJUnit4::class)
class SerializeBatchResultsTest {

    private var mobile: KeepMobile? = null
    private lateinit var handler: Nip55Handler

    @Before
    fun setup() {
        val storage = FrostSignTestSupport.noAuthStorage()
        val m = KeepMobile(storage).also { mobile = it }
        handler = Nip55Handler(m)
    }

    @After
    fun tearDown() {
        handler.destroy()
        mobile?.destroy()
        mobile = null
    }

    private fun success(id: String, result: String) =
        Nip55Response(result = result, event = null, error = null, id = id, rejected = false)

    private fun rejected(id: String) =
        Nip55Response(result = "", event = null, error = null, id = id, rejected = true)

    private fun failed(id: String, error: String) =
        Nip55Response(result = "", event = null, error = error, id = id, rejected = false)

    @Test
    fun successResponseRoundTripsWithSignatureAndResult() {
        val json = handler.serializeBatchResults(listOf(success("req-1", "deadbeef")))
        val arr = JSONArray(json)
        assertEquals(1, arr.length())

        val obj = arr.getJSONObject(0)
        assertEquals("req-1", obj.getString("id"))
        // Rust always emits a package key set to null; the Activity fills the caller
        // package on the Intent, not in the per-request JSON.
        assertTrue(obj.isNull("package"))
        assertEquals("deadbeef", obj.getString("signature"))
        assertEquals("deadbeef", obj.getString("result"))
        // A successful entry carries no rejected marker.
        assertFalse(obj.has("rejected"))
    }

    @Test
    fun rejectedResponseRoundTripsWithNullsAndRejectedTrue() {
        val json = handler.serializeBatchResults(listOf(rejected("req-2")))
        val obj = JSONArray(json).getJSONObject(0)

        assertEquals("req-2", obj.getString("id"))
        assertTrue(obj.isNull("package"))
        assertTrue(obj.isNull("signature"))
        assertTrue(obj.isNull("result"))
        assertTrue(obj.getBoolean("rejected"))
    }

    @Test
    fun erroredResponseSerializesAsRejected() {
        // An entry whose sign attempt failed (error set, rejected=false) must still
        // serialize as rejected=true with null signature/result, so the client can
        // never mistake a failed request for a signature.
        val json = handler.serializeBatchResults(listOf(failed("req-3", "request_failed")))
        val obj = JSONArray(json).getJSONObject(0)

        assertEquals("req-3", obj.getString("id"))
        assertTrue(obj.isNull("signature"))
        assertTrue(obj.isNull("result"))
        assertTrue(obj.getBoolean("rejected"))
    }

    @Test
    fun mixedBatchPreservesPerRequestOrderAndMapping() {
        val responses = listOf(
            success("a", "aa"),
            rejected("b"),
            failed("c", "request_failed"),
            success("d", "dd")
        )
        val arr = JSONArray(handler.serializeBatchResults(responses))
        assertEquals(4, arr.length())

        assertEquals("a", arr.getJSONObject(0).getString("id"))
        assertEquals("aa", arr.getJSONObject(0).getString("signature"))
        assertFalse(arr.getJSONObject(0).has("rejected"))

        assertEquals("b", arr.getJSONObject(1).getString("id"))
        assertTrue(arr.getJSONObject(1).getBoolean("rejected"))

        assertEquals("c", arr.getJSONObject(2).getString("id"))
        assertTrue(arr.getJSONObject(2).getBoolean("rejected"))

        assertEquals("d", arr.getJSONObject(3).getString("id"))
        assertEquals("dd", arr.getJSONObject(3).getString("signature"))
        assertFalse(arr.getJSONObject(3).has("rejected"))
    }

    @Test
    fun emptyBatchSerializesToEmptyArray() {
        assertEquals(0, JSONArray(handler.serializeBatchResults(emptyList())).length())
    }
}
