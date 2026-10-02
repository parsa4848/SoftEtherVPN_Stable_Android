package com.blockto.sevpn.vpn

import java.io.Closeable

/** Synchronized publication makes close race safely with in-progress setup. */
class AttemptResources : Closeable {
    private val owned = mutableListOf<Closeable>()
    private var closed = false
    fun <T : Closeable> own(value: T): T {
        val accepted = synchronized(this) { if (closed) false else { owned += value; true } }
        if (!accepted) { runCatching { value.close() }; throw java.io.IOException("Connection attempt cancelled") }
        return value
    }
    @Synchronized fun release(value: Closeable) { owned.remove(value) }
    // Raw socket is registered first: abort TCP before TLS close-notify can block.
    override fun close() {
        val snapshot = synchronized(this) { if (closed) return; closed = true; owned.toList().also { owned.clear() } }
        snapshot.forEach { runCatching { it.close() } }
    }
}
