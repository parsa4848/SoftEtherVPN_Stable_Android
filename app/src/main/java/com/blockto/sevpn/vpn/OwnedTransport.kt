package com.blockto.sevpn.vpn

import com.blockto.sevpn.protocol.SoftEtherTransport
import java.util.concurrent.atomic.AtomicBoolean

/** Closing a secondary removes its resources from the attempt, bounding retries. */
internal class OwnedTransport(private val delegate: SoftEtherTransport,
    private val child: AttemptResources, private val parent: AttemptResources) : SoftEtherTransport by delegate {
    private val closed = AtomicBoolean()
    override fun close() {
        if (closed.compareAndSet(false, true)) { child.close(); parent.release(child) }
    }
}
