package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OnboardingStoreIntegrationTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        clear()
    }

    @After
    fun teardown() {
        clear()
    }

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
    }

    @Test
    fun defaultsToNotCompletedOnFreshInstall() {
        assertFalse(OnboardingStore(context).isCompleted())
    }

    @Test
    fun persistsCompletionAcrossInstances() {
        OnboardingStore(context).setCompleted(true)

        // A new instance reads the committed value, so onboarding is not shown again.
        assertTrue(OnboardingStore(context).isCompleted())
    }

    @Test
    fun completionCanBeReset() {
        val store = OnboardingStore(context)
        store.setCompleted(true)
        store.setCompleted(false)

        assertFalse(OnboardingStore(context).isCompleted())
    }

    private companion object {
        const val PREFS_NAME = "keep_onboarding"
    }
}
