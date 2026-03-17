package io.privkey.keep.nip55

import io.privkey.keep.uniffi.isSensitiveKind as rustIsSensitiveKind
import io.privkey.keep.uniffi.sensitiveKindWarning as rustSensitiveKindWarning

fun isSensitiveKind(kind: Int): Boolean =
    if (kind < 0) true else rustIsSensitiveKind(kind.toUInt())

fun sensitiveKindWarning(kind: Int): String? =
    if (kind < 0) "Invalid event kind" else rustSensitiveKindWarning(kind.toUInt())
