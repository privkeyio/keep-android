package io.privkey.keep.storage

/**
 * What a metadata record's two prefs entries say about it, kept apart from the
 * Keystore plumbing so the decision is directly testable.
 *
 * The core acts on the difference between absence and a fault, so collapsing
 * them is not a lost log line. `keep-mobile`'s persistence maps
 * `StorageNotFound` to a default and propagates every other error, which is how
 * its fail-closed reads are built: an unreadable kill switch is meant to read as
 * engaged (`lib.rs`: `load_kill_switch(..).unwrap_or(true)`), an unreadable
 * descriptor index is meant to stop a rewrite that would drop the entries it
 * could not see, and the sign-policy store says the same thing in its own FFI
 * type, whose `Unavailable` arm is documented as "callers must fail closed".
 * Reporting a blob this layer merely cannot decrypt as "nothing was ever
 * written" turns each of those into its permissive default.
 */
internal enum class MetadataRead {
    /** Both entries are present and readable. */
    Stored,

    /**
     * Neither entry is present, so a first use is the honest reading.
     *
     * Honest as far as this layer can see, which is not the same as "nothing is
     * on disk". [KeystoreEncryptedPrefs]'s lookup refuses a value sitting at a
     * derivable name when that value predates the AAD binding and the store's
     * index does not list its key, and it refuses by answering null, which
     * `readTyped` turns into [PrefRead.Absent]. A present but unauthenticated
     * record therefore still arrives here as an absence, and for the records the
     * core defaults permissively that is the same hole in a narrower form.
     * Closing it means reporting such a refusal as unreadable, which is a change
     * in the prefs lookup rather than anything reachable from here.
     */
    NotStored,

    /**
     * Something is stored that this layer cannot produce.
     *
     * Covers an unreadable entry, and also one entry present with the other
     * missing: a record is written as a pair, so half of one is a torn write or
     * a partial removal, which is a fault rather than proof nothing was stored.
     */
    Faulted,
}

/**
 * Classify a record from the entries it is written as: two for a metadata
 * record (its data and IV), three for the DKG secret (wrapped key, IV, data).
 *
 * Absence is reported only when every entry is [PrefRead.Absent]. That rules
 * out every fault this layer is told about; see [MetadataRead.NotStored] for
 * the one the prefs lookup still reports as an absence.
 */
internal fun metadataRead(
    first: PrefRead<String>,
    vararg rest: PrefRead<String>,
): MetadataRead {
    // Taking the first entry separately rather than one vararg: an empty call
    // would make `all {}` vacuously true and classify a record with no entries
    // as `Stored`, and a signature that cannot express it beats a runtime guard
    // that has to be remembered.
    val entries = sequenceOf(first) + rest.asSequence()
    return when {
        entries.all { it is PrefRead.Found } -> MetadataRead.Stored
        entries.all { it is PrefRead.Absent } -> MetadataRead.NotStored
        else -> MetadataRead.Faulted
    }
}
