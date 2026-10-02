package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import java.net.*
import java.nio.ByteBuffer
import java.util.TreeMap

/** Scripted peer exercises the stream on actual UDP destination port 53.
 * Wire-format authority is the independent C vectors, not this peer. */
class RudpStreamTest {
    @Test fun reliableStreamUsesUdp53AndSurvivesDroppedSegment() = runBlocking {
        val server = DatagramSocket(InetSocketAddress("127.0.0.1", 53)).apply { soTimeout = 20 }
        val client = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
        val transport = RudpDnsTransport(client, InetSocketAddress("127.0.0.1", 53), this)
        val echo = launch(Dispatchers.IO) {
            val received = TreeMap<Long, ByteArray>(); var complete = 0L; var next = 2L; var magic = 0L
            var keys: RudpKeys? = null; var lost = false
            val buf = ByteArray(1393)
            fun response(payload: ByteArray, id: ByteArray): ByteArray {
                val header = transportVector("dns_response").copyOf(42)
                id.copyInto(header); ByteBuffer.wrap(header, 36, 2).putShort((payload.size + 4).toShort())
                return header + payload
            }
            try {
                while (isActive) {
                    val d = DatagramPacket(buf, buf.size)
                    try { server.receive(d) } catch (_: SocketTimeoutException) { continue } catch (_: SocketException) { break }
                    val payload = buf.copyOfRange(37, d.length); val id = buf.copyOf(2)
                    val k = keys
                    if (payload.size == 39) {
                        if (keys == null) keys = RudpKeys(payload.copyOf(20))
                        val active = keys!!
                        val hello = RudpPacketCodec.encode(active.server, RudpPacket(System.nanoTime() / 1_000_000, 0, complete, longArrayOf(), 1, active.keepAliveRequest), ByteArray(20), 1)
                        val wire = response(hello, id); server.send(DatagramPacket(wire, wire.size, d.socketAddress)); continue
                    }
                    if (k == null) continue
                    val p = try { RudpPacketCodec.decode(k.client, payload) } catch (_: RudpException) { continue }
                    if (p.sequence == magic && magic != 0L) break
                    if (p.sequence == 2L && p.payload.isNotEmpty() && !lost) { lost = true; continue }
                    if (p.payload.isNotEmpty() && p.sequence > complete) received[p.sequence] = p.payload
                    var output = byteArrayOf()
                    while (true) {
                        val b = received.remove(complete + 1) ?: break
                        complete++
                        if (complete == 1L) magic = ByteBuffer.wrap(b).long
                        else if (!b.contentEquals(k.keepAliveRequest) && !b.contentEquals(k.keepAliveResponse)) output += b
                    }
                    if (output.isEmpty()) {
                        val ack = RudpPacketCodec.encode(k.server, RudpPacket(System.nanoTime() / 1_000_000, p.tick, complete, longArrayOf(), next, byteArrayOf()), ByteArray(20), 1)
                        val wire = response(ack, id); server.send(DatagramPacket(wire, wire.size, d.socketAddress))
                    } else {
                        var start = 0
                        while (start < output.size) {
                            val end = minOf(start + 512, output.size)
                            val reply = RudpPacketCodec.encode(k.server, RudpPacket(System.nanoTime() / 1_000_000, p.tick, complete, longArrayOf(), next++, output.copyOfRange(start, end)), ByteArray(20), 1)
                            val wire = response(reply, id); server.send(DatagramPacket(wire, wire.size, d.socketAddress)); start = end
                        }
                    }
                }
            } catch (e: SocketException) { if (!server.isClosed) throw e }
            finally { keys?.close() }
        }
        try {
            withTimeout(3000) { transport.establish() }
            assertEquals(TransportType.RUDP_DNS_53, transport.type); assertEquals(53, transport.remoteAddress.port)
            val bytes = ByteArray(6000) { it.toByte() }
            withContext(Dispatchers.IO) {
                transport.output.write(bytes)
                val received = ByteArray(bytes.size); java.io.DataInputStream(transport.input).readFully(received)
                assertArrayEquals(bytes, received)
            }
            assertTrue(transport.packetsSent.get() > 0); assertTrue(transport.packetsReceived.get() > 0)
            assertTrue(transport.retransmissions.get() > 0)
        } finally { transport.close(); server.close(); echo.cancelAndJoin() }
        assertTrue(client.isClosed)
    }
}
