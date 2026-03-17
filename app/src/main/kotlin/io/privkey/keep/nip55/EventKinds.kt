package io.privkey.keep.nip55

import io.privkey.keep.uniffi.isSensitiveKind as rustIsSensitiveKind
import io.privkey.keep.uniffi.sensitiveKindWarning as rustSensitiveKindWarning

fun isSensitiveKind(kind: Int): Boolean =
    rustIsSensitiveKind(kind.toUInt())

fun sensitiveKindWarning(kind: Int): String? =
    rustSensitiveKindWarning(kind.toUInt())
