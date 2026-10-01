package com.blockto.sevpn.vpn

import java.io.Closeable

/** Synchronized publication makes close race safely with in-progress setup. */
class AttemptResources : Closeable {
    private val owned = mutableListOf<Closeable>()
    private var closed = false
    @Synchronized fun <T : Closeable> own(value: T): T {
        if (closed) { value.close(); throw java.io.IOException("Connection attempt cancelled") }
        owned += value; return value
    }
    // Raw socket is registered first: abort TCP before TLS close-notify can block.
    @Synchronized override fun close() { if (!closed) { closed = true; owned.forEach { runCatching { it.close() } }; owned.clear() } }
}
