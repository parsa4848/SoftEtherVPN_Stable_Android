package com.blockto.sevpn.protocol

import java.io.Closeable
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.TreeMap
import java.util.TreeSet

/** Actor-owned client subset of Network.c RUDPInterruptProc/RecvProc.
 * 64-segment windows, 512-byte segments, 64 KiB FIFO; no bulk negotiation. */
class RudpSession(private val createdAt: Long, initialKey: ByteArray = ByteArray(20).also { SecureRandom().nextBytes(it) }) : Closeable {
    private val random = SecureRandom()
    private val initial = initialKey.copyOf()
    internal val keys = RudpKeys(initial)
    private var nextIv = ByteArray(20).also { random.nextBytes(it) }
    val disconnectMagic = -0x100000000L or (random.nextInt().toLong() and 0xffffffffL)
    private class Segment(val data: ByteArray, var nextSend: Long = 0, var sent: Int = 0)
    private val sending = TreeMap<Long, Segment>()
    private val receiving = TreeMap<Long, ByteArray>()
    private val pending = ArrayDeque<ByteArray>()
    private val delivered = ArrayDeque<ByteArray>()
    private val replyAcks = TreeSet<Long>()
    private var queuedBytes = 0
    private var deliveredBytes = 0
    var nextSendSequence = 1L; private set
    var receivedSequence = 0L; private set
    var established = false; private set
    private var remoteTick = 0L
    private var latestEcho = createdAt
    private var rtt = 0L
    private var lastSent = 0L
    private var keepaliveInterval = 2500L + random.nextInt(2292)
    var retransmissions = 0L; private set
    val outstandingSegments get() = sending.size
    val reassemblySegments get() = receiving.size
    val canEnqueue get() = queuedBytes <= 65536 - 512
    init { pending.add(ByteBuffer.allocate(8).putLong(disconnectMagic).array()); queuedBytes = 8 }
    fun enqueue(bytes: ByteArray): Boolean {
        require(bytes.size in 1..512)
        if (queuedBytes + bytes.size > 65536) return false
        pending.addLast(bytes.copyOf()); queuedBytes += bytes.size; return true
    }
    fun receive(bytes: ByteArray, now: Long): Boolean {
        val p = RudpPacketCodec.decode(keys.server, bytes)
        if (p.echoedTick > now || p.cumulativeAck >= nextSendSequence || p.acknowledgements.any { it >= nextSendSequence })
            throw RudpException(RudpFailure.INVALID_RESPONSE)
        if (p.sequence == disconnectMagic) throw RudpException(RudpFailure.DISCONNECTED)
        if (p.sequence < 0) throw RudpException(RudpFailure.INVALID_RESPONSE)
        val acked = sending.keys.filter { it <= p.cumulativeAck || it in p.acknowledgements }
        acked.forEach { sending.remove(it)?.data?.fill(0) }
        remoteTick = maxOf(remoteTick, if (p.tick >= 2) p.tick - 1 else p.tick)
        if (p.echoedTick > latestEcho) { latestEcho = p.echoedTick; rtt = now - latestEcho }
        established = true
        if (p.sequence != 0L && p.payload.isNotEmpty() && p.sequence <= receivedSequence + 64) {
            if (p.sequence > receivedSequence && !receiving.containsKey(p.sequence)) receiving[p.sequence] = p.payload
            if (replyAcks.size < 64) replyAcks.add(p.sequence)
        }
        drainReceive()
        return true
    }
    private fun drainReceive() {
        while (deliveredBytes <= 65536 - 512) {
            val data = receiving.remove(receivedSequence + 1) ?: break
            receivedSequence++
            when {
                data.contentEquals(keys.keepAliveRequest) -> if (sending.isEmpty() && pending.isEmpty()) enqueue(keys.keepAliveResponse)
                data.contentEquals(keys.keepAliveResponse) -> {}
                else -> { delivered.addLast(data); deliveredBytes += data.size }
            }
        }
    }
    fun readSegment(): ByteArray? {
        val data = delivered.removeFirstOrNull() ?: return null
        deliveredBytes -= data.size; drainReceive(); return data
    }
    fun poll(now: Long): List<ByteArray> {
        if (!established) {
            if (now - createdAt >= 5000) throw RudpException(RudpFailure.HANDSHAKE_TIMEOUT)
            if (lastSent == 0L || now - lastSent >= 200) {
                lastSent = now
                return listOf(initial + ByteArray(19).also { random.nextBytes(it) })
            }
            return emptyList()
        }
        if (now - latestEcho >= 12000) throw RudpException(RudpFailure.TIMEOUT)
        while (pending.isNotEmpty() && (sending.isEmpty() || nextSendSequence <= sending.firstKey() + 63)) {
            val data = pending.removeFirst(); queuedBytes -= data.size
            sending[nextSendSequence++] = Segment(data)
        }
        if (sending.isEmpty() && pending.isEmpty() && (lastSent == 0L || now - lastSent >= keepaliveInterval)) {
            sending[nextSendSequence++] = Segment(keys.keepAliveRequest.copyOf())
            keepaliveInterval = 2500L + random.nextInt(2292)
        }
        val result = ArrayList<ByteArray>(65)
        for ((seq, segment) in sending) if (now >= segment.nextSend) {
            result += packet(seq, segment.data, now)
            if (segment.sent != 0) retransmissions++
            val interval = minOf(4792L, (if (rtt != 0L) maxOf(1, rtt * 120 / 100) else 200) shl minOf(segment.sent, 10))
            segment.sent++; segment.nextSend = now + interval; lastSent = now
        }
        if (replyAcks.isNotEmpty()) result += packet(nextSendSequence, byteArrayOf(), now)
        return result
    }
    private fun packet(seq: Long, payload: ByteArray, now: Long): ByteArray {
        val ack = replyAcks.take(64).toLongArray(); ack.forEach { replyAcks.remove(it) }
        val p = RudpPacket(now, remoteTick, receivedSequence, ack, seq, payload)
        val bytes = RudpPacketCodec.encode(keys.client, p, nextIv, maxOf(1, random.nextInt(256)))
        val pos = random.nextInt(bytes.size - 20)
        bytes.copyInto(nextIv, 0, pos, pos + 20)
        return bytes
    }
    fun disconnectPackets(now: Long): List<ByteArray> = if (established) List(5) { packet(disconnectMagic, byteArrayOf(), now) } else emptyList()
    override fun close() {
        initial.fill(0); nextIv.fill(0); keys.close()
        sending.values.forEach { it.data.fill(0) }; receiving.values.forEach { it.fill(0) }
        pending.forEach { it.fill(0) }; delivered.forEach { it.fill(0) }
        sending.clear(); receiving.clear(); pending.clear(); delivered.clear(); replyAcks.clear()
    }
}
