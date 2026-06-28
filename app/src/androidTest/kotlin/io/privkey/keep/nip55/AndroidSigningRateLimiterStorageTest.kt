package io.privkey.keep.nip55

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSigningRateLimiterStorageTest {

    private lateinit var context: Context
    private lateinit var storage: AndroidSigningRateLimiterStorage

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        storage = AndroidSigningRateLimiterStorage(context)
        storage.clear()
    }

    @After
    fun teardown() {
        storage.clear()
    }

    @Test
    fun saveThenLoadReturnsStoredValue() {
        storage.save("com.example.app", "counter=3;cooloff=0")
        assertEquals("counter=3;cooloff=0", storage.load("com.example.app"))
    }

    @Test
    fun saveOverwritesExistingValue() {
        storage.save("com.example.app", "counter=3")
        storage.save("com.example.app", "counter=4")
        assertEquals("counter=4", storage.load("com.example.app"))
    }

    @Test
    fun distinctKeysRoundTripIndependently() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")

        assertEquals("counter=1", storage.load("com.example.a"))
        assertEquals("counter=2", storage.load("com.example.b"))
    }

    @Test
    fun loadOfAbsentKeyReturnsNull() {
        assertNull(storage.load("com.example.missing"))
    }

    @Test
    fun removeThenLoadReturnsNull() {
        storage.save("com.example.app", "counter=1")
        storage.remove("com.example.app")
        assertNull(storage.load("com.example.app"))
    }

    @Test
    fun removeLeavesOtherKeysIntact() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")

        storage.remove("com.example.a")

        assertNull(storage.load("com.example.a"))
        assertEquals("counter=2", storage.load("com.example.b"))
    }

    @Test
    fun removeOfAbsentKeyIsNoOp() {
        storage.save("com.example.a", "counter=1")
        storage.remove("com.example.missing")
        assertEquals("counter=1", storage.load("com.example.a"))
    }

    @Test
    fun clearWipesAllEntries() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")
        assertEquals("counter=1", storage.load("com.example.a"))
        assertEquals("counter=2", storage.load("com.example.b"))

        storage.clear()

        assertNull(storage.load("com.example.a"))
        assertNull(storage.load("com.example.b"))
    }

    @Test
    fun savedValueSurvivesFreshAdapterInstance() {
        storage.save("com.example.app", "counter=7")

        val reopened = AndroidSigningRateLimiterStorage(context)
        assertEquals("counter=7", reopened.load("com.example.app"))
    }
}
