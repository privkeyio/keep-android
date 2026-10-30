package io.privkey.keep.approver

sealed interface ApproverReset<out T> {
    /** The state read on the retry, so the pairing was kept. */
    data class Kept<T>(val approver: T) : ApproverReset<T>
    data class Cleared<T>(val approver: T) : ApproverReset<T>
    data object NotReset : ApproverReset<Nothing>
}

/**
 * Clears the approver state only when one more [open] still fails and [unreadable]
 * says the stored state is damaged for good, so a fault that has cleared, or one
 * that may yet clear, keeps the pairing.
 */
internal fun <T : Any> resetUnreadableApprover(
    open: () -> T?,
    unreadable: () -> Boolean,
    clear: () -> Unit,
): ApproverReset<T> {
    open()?.let { return ApproverReset.Kept(it) }
    if (!unreadable()) return ApproverReset.NotReset
    clear()
    return open()?.let { ApproverReset.Cleared(it) } ?: ApproverReset.NotReset
}
