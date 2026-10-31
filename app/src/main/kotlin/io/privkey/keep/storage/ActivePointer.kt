package io.privkey.keep.storage

/** What the active-share getter should answer. */
internal sealed interface ActivePointer {
    /** Use this group's key as the active account. */
    data class Use(val key: String) : ActivePointer

    /** Report no active account, leaving the choice to an explicit selection. */
    data object None : ActivePointer
}

/**
 * Resolve the active account from the registry and the stored pointer, without
 * writing anything.
 *
 * Nothing here persists, which is the point. The core removed the same
 * inference-and-write from its own layer (`keep-mobile`'s `resolve_active_share`)
 * because `list_all_shares` has no error channel, so a storage fault that leaves
 * one readable share is indistinguishable from owning one share, and persisting
 * the guess turned a transient fault into a permanent repoint of the active
 * account that outlived the fault and was never surfaced. That doc names this
 * getter as the place the write still happened, one layer down.
 *
 * Two rules carry the safety:
 *
 * An unreadable pointer answers [ActivePointer.None] rather than falling through
 * to the registry. A pointer that is present and cannot be read is not the same
 * as no pointer, and scanning past it would sign as whichever account sorts
 * first.
 *
 * Inference only answers when exactly one registry entry holds share data, and
 * a share that cannot be read counts as holding it. One leaves nothing to choose,
 * so answering it keeps a single-account device working. Several means answering
 * any of them is a choice the user did not make, so this reports none and lets
 * the core's "Multiple shares found, please select one" arm be what happens. A
 * fault never drops a share from the count: a two-account device with one
 * unreadable share would otherwise look like a one-account device and be pinned
 * to the readable share, which keep-mobile's resolver refuses for the same
 * reason. A lone unreadable share is still answered, so the load that follows
 * reports its fault rather than "no active account".
 *
 * @param holdsShareData whether that group's own file holds share data, answering
 *   `true` when the file cannot be read.
 */
internal fun activePointer(
    registry: Set<String>,
    pointer: PrefRead<String>,
    holdsShareData: (key: String) -> Boolean,
): ActivePointer {
    if (registry.isEmpty()) return ActivePointer.None
    when (pointer) {
        is PrefRead.Found ->
            if (registry.contains(pointer.value) && holdsShareData(pointer.value)) {
                return ActivePointer.Use(pointer.value)
            }
        // Present and unreadable: never scan past it.
        PrefRead.Unreadable -> return ActivePointer.None
        // No pointer written yet, so inference below is the honest reading.
        PrefRead.Absent -> Unit
    }
    // Reached when there is no pointer, or the pointer is stale: it names a group
    // the registry no longer lists, or one whose share data is gone.
    val candidates = registry.filter(holdsShareData)
    return if (candidates.size == 1) ActivePointer.Use(candidates.single()) else ActivePointer.None
}
