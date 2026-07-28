package io.privkey.keep.storage

import androidx.annotation.StringRes
import io.privkey.keep.R
import io.privkey.keep.uniffi.SignPolicySelection

/**
 * The UI-facing sign policy. Mirrors the core's [SignPolicySelection] but carries the
 * display strings the FFI enum cannot. The core owns the persisted selection; this
 * type only exists to render it.
 */
enum class SignPolicy(@param:StringRes val displayNameRes: Int, @param:StringRes val descriptionRes: Int) {
    MANUAL(R.string.sign_policy_manual, R.string.sign_policy_manual_description),
    BASIC(R.string.sign_policy_basic, R.string.sign_policy_basic_description),
    AUTO(R.string.sign_policy_auto, R.string.sign_policy_auto_description);

    companion object {
        fun fromOrdinal(ordinal: Int): SignPolicy = entries.getOrElse(ordinal) { MANUAL }
    }
}

// Exhaustive on purpose: a new variant on either side must become a compile error
// rather than a silent mis-map onto a looser policy.

fun SignPolicy.toSelection(): SignPolicySelection = when (this) {
    SignPolicy.MANUAL -> SignPolicySelection.MANUAL
    SignPolicy.BASIC -> SignPolicySelection.BASIC
    SignPolicy.AUTO -> SignPolicySelection.AUTO
}

fun SignPolicySelection.toSignPolicy(): SignPolicy = when (this) {
    SignPolicySelection.MANUAL -> SignPolicy.MANUAL
    SignPolicySelection.BASIC -> SignPolicy.BASIC
    SignPolicySelection.AUTO -> SignPolicy.AUTO
}
