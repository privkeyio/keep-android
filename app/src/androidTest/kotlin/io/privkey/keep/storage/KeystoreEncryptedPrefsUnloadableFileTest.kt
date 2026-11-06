package io.privkey.keep.storage

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore

/**
 * SharedPreferences loads a file it cannot parse as an empty map. A store opened over
 * such a file must not write its own key over it, which would replace whatever the
 * file held, while a file left empty still opens, since it holds nothing to lose.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreEncryptedPrefsUnloadableFileTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val file get() = File(context.dataDir, "shared_prefs/$PREFS_NAME.xml")

    @Before
    fun setup() = clear()

    @After
    fun teardown() = clear()

    private fun clear() {
        context.deleteSharedPreferences(PREFS_NAME)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KeystoreEncryptedPrefs.keyAliasFor(PREFS_NAME))
    }

    private fun stage(content: String) {
        file.parentFile!!.mkdirs()
        file.writeText(content)
    }

    @Test
    fun aFileThatWillNotParseIsNotWrittenOver() {
        stage("<map><string name=")
        val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

        assertEquals(PrefRead.Unreadable, prefs.readString("k"))
        assertEquals("<map><string name=", file.readText())
    }

    @Test
    fun anEmptyFileStillOpens() {
        stage("")
        val prefs = KeystoreEncryptedPrefs.create(context, PREFS_NAME)

        assertTrue(prefs.edit().putString("k", "v").commit())
        assertEquals(PrefRead.Found("v"), prefs.readString("k"))
    }

    private companion object {
        const val PREFS_NAME = "keep_unloadable_file_test"
    }
}
