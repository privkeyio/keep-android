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
    fun clearWipesAllEntries() {
        storage.save("com.example.a", "counter=1")
        storage.save("com.example.b", "counter=2")

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
