package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.*
import java.io.Closeable
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

enum class ConnectionState { CONNECTING, HANDSHAKING, ACTIVE, FAILED, CLOSED }
class AdditionalConnection(val transport: SoftEtherTransport, val direction: Int) : Closeable {
    val channel = SoftEtherDataChannel(transport)
    @Volatile var state = ConnectionState.CONNECTING; internal set
    override fun close() { state = ConnectionState.CLOSED; transport.close() }
}

/** One replenishment job, bounded writers. Selection is at Connection.c's
 * block boundary, based on queue pressure. No pool lock encloses I/O. */
@OptIn(ExperimentalCoroutinesApi::class)
class SoftEtherConnectionPool(
    private val session: SoftEtherSession, private val scope: CoroutineScope,
    private val connectAdditional: (suspend () -> AdditionalConnection)?,
    val inbound: Channel<ByteArray> = Channel(128),
    private val keepAliveBody: () -> ByteArray = { byteArrayOf() },
    private val receivedKeepAlive: (ByteArray) -> Unit = {}
) : Closeable {
    private class Entry(val id: Int, val connection: AdditionalConnection) {
        val outgoing = Channel<ByteArray>(16)
        val pending = AtomicLong(0)
        val writeStarted = AtomicLong(0)
        var job: Job? = null
    }
    private val lock = Any()
    private val entries = linkedMapOf<Int, Entry>()
    private val capacity = Channel<Unit>(Channel.CONFLATED)
    private val random = SecureRandom()
    private var nextId = 0
    private var cursor = 0
    private var closed = false
    private var manager: Job? = null
    private var watchdog: Job? = null
    val activeCount get() = synchronized(lock) { entries.size }
    val activeTcpConnections get() = if (session.primaryTransport.type == TransportType.TCP) activeCount else 0
    fun start() {
        check(manager == null)
        activate(AdditionalConnection(session.primaryTransport, 0))
        watchdog = scope.launch {
            while (isActive) {
                val now = monotonic()
                val stalled = synchronized(lock) { entries.values.filter {
                    val started = it.writeStarted.get()
                    started != 0L && now - started >= session.timeoutMs
                } }
                stalled.forEach { failed(it) }
                delay(100)
            }
        }
        manager = scope.launch {
            var attempts = 0; var retryAt = 0L
            try { while (isActive) {
                val now = monotonic()
                if (connectAdditional != null && activeCount < session.negotiatedMaxConnections && now >= retryAt) {
                    try {
                        activate(connectAdditional())
                        attempts = 0; retryAt = monotonic() + 250
                    } catch (e: CancellationException) { throw e }
                    catch (e: Exception) {
                        if (e is SoftEtherServerException && e.code in setOf(13, 14)) throw e
                        if (e is javax.net.ssl.SSLException) throw e
                        attempts++
                        val delay = minOf(30_000L, 1000L shl minOf(attempts - 1, 5))
                        retryAt = monotonic() + delay + random.nextInt((delay / 4).toInt())
                    }
                }
                delay(100)
            } } finally { close() } // Interrupt blocking readers before the scope waits for them.
        }
    }
    private fun activate(connection: AdditionalConnection) {
        val entry = synchronized(lock) {
            if (closed) null else Entry(nextId++, connection).also { entries[it.id] = it; connection.state = ConnectionState.ACTIVE }
        }
        if (entry == null) { connection.close(); return }
        connection.channel.onKeepAlive = receivedKeepAlive
        entry.job = scope.launch(Dispatchers.IO) {
            try {
                coroutineScope {
                    launch {
                        try { while (isActive) inbound.send(connection.channel.readFrame()) }
                        catch (e: CancellationException) { throw e }
                        catch (_: IOException) { failed(entry) }
                    }
                    launch {
                        try {
                            while (isActive) {
                                select<Unit> {
                                    entry.outgoing.onReceive { frame ->
                                        entry.writeStarted.set(monotonic())
                                        try { connection.channel.sendFrame(frame) }
                                        finally { entry.writeStarted.set(0); entry.pending.addAndGet(-frame.size.toLong()); capacity.trySend(Unit) }
                                    }
                                    onTimeout((session.timeoutMs / 3).toLong()) {
                                        entry.writeStarted.set(monotonic())
                                        try { connection.channel.keepAlive(keepAliveBody()) } finally { entry.writeStarted.set(0) }
                                    }
                                }
                            }
                        } catch (e: CancellationException) { throw e }
                        catch (_: IOException) { failed(entry) }
                    }
                }
            } finally { failed(entry) }
        }
        capacity.trySend(Unit)
    }
    private fun failed(entry: Entry) {
        val removed = synchronized(lock) { if (entries[entry.id] !== entry) false else { entries.remove(entry.id); entry.connection.state = ConnectionState.FAILED; true } }
        if (!removed) return
        entry.outgoing.cancel(); runCatching { entry.connection.close() }; entry.job?.cancel(); capacity.trySend(Unit)
        if (!synchronized(lock) { closed } && activeCount == 0) inbound.close(IOException("All session transports disconnected"))
    }
    suspend fun sendFrame(frame: ByteArray) {
        require(frame.size in 14..1600)
        while (true) {
            currentCoroutineContext().ensureActive()
            val sent = synchronized(lock) {
                if (closed) throw IOException("Connection pool closed")
                if (entries.isEmpty()) throw IOException("No outbound session transport")
                val start = (cursor++ and Int.MAX_VALUE) % entries.size
                var first: Entry? = null; var bestPressure = Long.MAX_VALUE; var bestDistance = Int.MAX_VALUE
                var index = 0
                for (entry in entries.values) {
                    val distance = (index++ - start + entries.size) % entries.size
                    if (entry.connection.direction == 1) continue
                    val pressure = entry.pending.get()
                    if (pressure < bestPressure || pressure == bestPressure && distance < bestDistance) {
                        first = entry; bestPressure = pressure; bestDistance = distance
                    }
                }
                val selected = first ?: throw IOException("No outbound session transport")
                fun offer(entry: Entry): Boolean {
                    entry.pending.addAndGet(frame.size.toLong())
                    return if (entry.outgoing.trySend(frame).isSuccess) true
                    else { entry.pending.addAndGet(-frame.size.toLong()); false }
                }
                offer(selected) || entries.values.any { it !== selected && it.connection.direction != 1 && offer(it) }
            }
            if (sent) return
            capacity.receive()
        }
    }
    override fun close() {
        val all = synchronized(lock) { if (closed) return; closed = true; entries.values.toList().also { entries.clear() } }
        manager?.cancel(); watchdog?.cancel(); capacity.cancel(); inbound.cancel()
        all.forEach { it.outgoing.cancel(); runCatching { it.connection.close() }; it.job?.cancel() }
    }
    companion object { private fun monotonic() = System.nanoTime() / 1_000_000 }
}
