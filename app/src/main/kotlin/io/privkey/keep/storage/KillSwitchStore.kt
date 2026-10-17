package io.privkey.keep.storage

import android.content.Context
import androidx.annotation.VisibleForTesting

/**
 * Whether the startup carry should engage the core kill switch.
 *
 * Kept as a rule of its own because the dangerous case reads like the harmless
 * one: a value that could not be read is not a value, and answering such a read
 * with a default says the switch was confirmed disengaged when nothing of the
 * sort was established, which resumes signing on a restriction never seen.
 *
 * So an unreadable state carries as engaged. That is the record being cleared to
 * the restriction it holds rather than to an absence, which is the only direction
 * that is safe for a record whose content is a refusal: a switch missing from the
 * core reads as disengaged there too.
 */
internal fun carryEngagesKillSwitch(legacy: PrefRead<Boolean>): Boolean = when (legacy) {
    is PrefRead.Found -> legacy.value
    PrefRead.Absent -> false
    PrefRead.Unreadable -> true
}

/**
 * Applies the carry, given [engage] and [retire] as the effects.
 *
 * The effects are parameters so the decision order is exercised without a core
 * instance or a device, which is what the one-off nature of the carry demands:
 * it runs once per install, before any signing gate, and is not repeatable.
 *
 * [retire] reports whether the store could establish that the legacy value is
 * gone. An uncertified retire means it could not see the value, so an absence it
 * reported a moment earlier was an absence it could not see rather than one it
 * confirmed, and the restriction is applied instead of resumed. Engaging twice
 * is harmless; the alternative is resuming on an unproven absence.
 *
 * The carry is always retired. It is deliberately not left open for a later
 * launch to retry: the core switch now holds the restriction, where the user can
 * see it and clear it behind an authenticated factor, whereas an un-retired carry
 * would re-apply itself on every launch and, if the fault never lifted, leave no
 * route back at all.
 */
internal fun carryKillSwitch(
    legacy: PrefRead<Boolean>,
    engage: () -> Unit,
    retire: () -> Boolean,
) {
    val engaged = carryEngagesKillSwitch(legacy)
    if (engaged) engage()
    if (!retire() && !engaged) engage()
}

/**
 * [prefsName] is parameterized only for tests, which must not drive the file the
 * running app keeps its kill switch in: the retire step deletes from it.
 */
class KillSwitchStore @VisibleForTesting internal constructor(
    private val context: Context,
    private val prefsName: String,
) {

    constructor(context: Context) : this(context, PREFS_NAME)

    companion object {
        internal const val PREFS_NAME = "keep_kill_switch"
        internal const val KEY_ENABLED = "kill_switch_enabled"
        private const val KEY_MIGRATED = "migrated_to_core"
    }

    private val prefs = KeystoreEncryptedPrefs.create(context, prefsName)

    /**
     * Whether the carry has already run.
     *
     * On the collapsing getter deliberately. An unreadable marker resolves to
     * false, which runs the carry again, and running it again is the safe
     * direction: it can only re-apply a restriction, never lift one.
     */
    fun hasMigrated(): Boolean = prefs.getBoolean(KEY_MIGRATED, false)

    /**
     * The legacy state, with "could not be read" kept apart from "disengaged".
     *
     * Those two were the same answer here, and conflating them does not lose a
     * setting so much as invert it: the carry is what puts the restriction into
     * the core, so a switch read as disengaged is one the core is never told
     * about, and signing resumes.
     */
    fun legacyState(): PrefRead<Boolean> = LegacyPrefsMigration.readBooleanForMigration(
        context, prefsName, KEY_ENABLED, prefs
    )

    /**
     * Records the carry as done and drops this store's copy of the legacy value.
     *
     * Returns what the commit reported. False does not mean nothing was written:
     * the marker lands, and what failed is the certification of the removal, so
     * the value is still on disk and the store is saying it could not establish
     * otherwise. A caller that concluded there was nothing to carry has to treat
     * that as grounds to doubt the conclusion, since a store that cannot see the
     * value well enough to delete it cannot see it well enough to call it absent.
     *
     * Only this store's copy is dropped. The legacy store names its entries
     * differently in the same file and nothing deletes those, which is what lets
     * [legacyState] answer from the legacy copy when this one cannot be read.
     */
    fun markMigrated(): Boolean =
        prefs.edit().putBoolean(KEY_MIGRATED, true).remove(KEY_ENABLED).commit()
}
