package io.privkey.keep.approver

import io.privkey.keep.storage.ApproverStateFile
import io.privkey.keep.uniffi.KeepMobileException

sealed interface ApproverReset<out T> {
    /** The state read on the retry, so the pairing was kept. */
    data class Kept<T>(val approver: T) : ApproverReset<T>
    data class Cleared<T>(val approver: T) : ApproverReset<T>
    data object NotReset : ApproverReset<Nothing>
}

/**
 * Whether an approver that would not open has state that is damaged for good, judged
 * by what the core's own load found. Bytes that loaded count too, since the core then
 * refused them, but only behind a storage error, and a fault that may clear does not.
 */
internal fun approverDamaged(error: Throwable?, load: ApproverStateFile.LoadResult?): Boolean =
    error is KeepMobileException.StorageException &&
        (load == ApproverStateFile.LoadResult.DAMAGED || load == ApproverStateFile.LoadResult.READABLE)

/**
 * Clears the approver state only when two more tries to [open] fail and each finds it
 * [damaged], so a fault that has cleared, or one that crossed a single load, keeps
 * the pairing.
 */
internal fun <T : Any> resetUnreadableApprover(
    open: () -> T?,
    damaged: () -> Boolean,
    clear: () -> Unit,
): ApproverReset<T> {
    repeat(2) {
        open()?.let { return ApproverReset.Kept(it) }
        if (!damaged()) return ApproverReset.NotReset
    }
    clear()
    return open()?.let { ApproverReset.Cleared(it) } ?: ApproverReset.NotReset
}
