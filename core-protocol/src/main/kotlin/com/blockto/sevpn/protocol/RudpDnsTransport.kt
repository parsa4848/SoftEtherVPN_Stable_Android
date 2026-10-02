package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import java.io.*
import java.net.*
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Protected socket supplied by Android; a single child owns reliability/timers.
 * Blocking stream adapters use bounded queues, with no coroutine per packet. */
class RudpDnsTransport(private val socket: DatagramSocket, private val server: InetSocketAddress,
    private val scope: CoroutineScope) : SoftEtherTransport {
    override val type = TransportType.RUDP_DNS_53
    override val localAddress get() = socket.localSocketAddress as? InetSocketAddress
    override val remoteAddress get() = server
    private val closed = AtomicBoolean()
    private val incoming = ArrayBlockingQueue<ByteArray>(128)
    private val outgoing = ArrayBlockingQueue<ByteArray>(128)
    private val connected = CompletableDeferred<Unit>()
    private var worker: Job? = null
    @Volatile private var failure: IOException? = null
    @Volatile private var timeout = 15000
    val packetsSent = AtomicLong(); val packetsReceived = AtomicLong(); val retransmissions = AtomicLong()
    override fun setReadTimeout(milliseconds: Int) { require(milliseconds > 0); timeout = milliseconds }
    override val input = object : InputStream() {
        private var current = byteArrayOf(); private var offset = 0
        private val single = ByteArray(1)
        override fun read(): Int = if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 255
        override fun read(bytes: ByteArray, start: Int, length: Int): Int {
            require(start >= 0 && length >= 0 && start <= bytes.size - length)
            if (length == 0) return 0
            val deadline = monotonic() + timeout
            while (offset == current.size) {
                failure?.let { throw it }
                if (closed.get()) throw EOFException("R-UDP stream closed")
                val wait = minOf(50, deadline - monotonic())
                if (wait <= 0) throw SocketTimeoutException("R-UDP stream read timed out")
                current = incoming.poll(wait, TimeUnit.MILLISECONDS) ?: continue
                offset = 0
            }
            val n = minOf(length, current.size - offset)
            current.copyInto(bytes, start, offset, offset + n); offset += n; return n
        }
    }
    override val output = object : OutputStream() {
        override fun write(value: Int) { write(byteArrayOf(value.toByte())) }
        @Synchronized override fun write(bytes: ByteArray, start: Int, length: Int) {
            require(start >= 0 && length >= 0 && start <= bytes.size - length)
            var i = start
            val deadline = monotonic() + timeout
            while (i < start + length) {
                failure?.let { throw it }
                if (closed.get()) throw EOFException("R-UDP stream closed")
                val end = minOf(start + length, i + 512)
                val chunk = bytes.copyOfRange(i, end)
                while (!outgoing.offer(chunk, 50, TimeUnit.MILLISECONDS)) {
                    failure?.let { throw it }; if (closed.get()) throw EOFException("R-UDP stream closed")
                    if (monotonic() >= deadline) throw SocketTimeoutException("R-UDP send queue stalled")
                }
                i = end
            }
        }
    }
    suspend fun establish() {
        require(server.address is Inet4Address && server.port == 53)
        check(worker == null)
        worker = scope.launch(Dispatchers.IO) {
            val session = RudpSession(monotonic())
            var lastBad: RudpException? = null
            var staged: ByteArray? = null
            val bytes = ByteArray(1398); val packet = DatagramPacket(bytes, bytes.size)
            try {
                socket.connect(server); socket.soTimeout = 10
                while (isActive && !closed.get()) {
                    while (session.established && session.canEnqueue) {
                        val chunk = outgoing.poll() ?: break
                        check(session.enqueue(chunk)); chunk.fill(0)
                    }
                    val pending = staged
                    if (pending != null && incoming.offer(pending)) staged = null
                    while (staged == null) {
                        val chunk = session.readSegment() ?: break
                        if (!incoming.offer(chunk)) staged = chunk
                    }
                    val sends = try { session.poll(monotonic()) }
                    catch (e: RudpException) { if (e.failure == RudpFailure.HANDSHAKE_TIMEOUT && lastBad != null) throw lastBad; throw e }
                    for (payload in sends) {
                        val wire = RudpDnsCodec.query(payload)
                        socket.send(DatagramPacket(wire, wire.size, server)); packetsSent.incrementAndGet()
                    }
                    retransmissions.set(session.retransmissions)
                    packet.length = bytes.size
                    try { socket.receive(packet) } catch (_: SocketTimeoutException) { continue }
                    packetsReceived.incrementAndGet()
                    try {
                        val payload = RudpDnsCodec.responsePayload(bytes.copyOf(packet.length))
                        session.receive(payload, monotonic())
                        if (session.established && !connected.isCompleted) connected.complete(Unit)
                    } catch (e: RudpException) {
                        if (e.failure == RudpFailure.DISCONNECTED) throw e
                        lastBad = e
                    }
                }
            } catch (e: CancellationException) { throw e }
            catch (_: PortUnreachableException) { failure = RudpException(RudpFailure.UNREACHABLE) }
            catch (e: IOException) { failure = e }
            finally {
                if (!socket.isClosed) runCatching {
                    for (payload in session.disconnectPackets(monotonic())) {
                        val wire = RudpDnsCodec.query(payload); socket.send(DatagramPacket(wire, wire.size, server))
                    }
                }
                session.close(); staged?.fill(0); socket.close(); closed.set(true)
                if (!connected.isCompleted) connected.completeExceptionally(failure ?: EOFException("R-UDP cancelled"))
            }
        }
        try { connected.await() } catch (e: Throwable) { close(); throw e }
    }
    override fun close() {
        if (closed.compareAndSet(false, true)) { socket.close(); worker?.cancel(); incoming.clear(); outgoing.clear() }
    }
    companion object { private fun monotonic() = System.nanoTime() / 1_000_000 }
}
