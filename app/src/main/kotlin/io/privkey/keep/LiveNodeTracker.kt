package io.privkey.keep

import java.util.concurrent.atomic.AtomicLong

/**
 * Whether the core's live node is still the one the app last initialized.
 *
 * The core drops its node on an account switch, a share delete, an import or DKG that
 * stores a share, and a certificate pin edit, and reports none of them through the state
 * callback. A callback the dropped node had already queued can also land after the drop.
 * So the last state delivered cannot say whether a node is up. This counts drops
 * instead: a node is live only if no drop has happened since the initialize that built
 * it began. An initialize that a drop overlapped therefore reads as not live, which costs
 * a re-initialize rather than skipping one.
 */
internal class LiveNodeTracker {

    private val drops = AtomicLong()

    @Volatile
    private var builtAt = NEVER

    fun dropped() {
        drops.incrementAndGet()
    }

    /** Taken before an initialize starts, and handed to [built] once it succeeds. */
    fun beginInit(): Long = drops.get()

    fun built(startedAt: Long) {
        builtAt = startedAt
    }

    fun isLive(): Boolean = builtAt == drops.get()

    private companion object {
        const val NEVER = -1L
    }
}
