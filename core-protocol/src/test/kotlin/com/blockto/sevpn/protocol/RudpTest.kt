package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.util.Properties

internal fun transportVector(key: String): ByteArray {
    val p = Properties().apply { RudpTest::class.java.getResourceAsStream("/transport-vectors.properties")!!.use { load(it) } }
    val h = p.getProperty(key); return ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

class RudpTest {
    private val seed = ByteArray(20) { it.toByte() }
    private fun server(s: RudpSession, seq: Long, data: ByteArray = byteArrayOf(), ack: Long = 0, selective: LongArray = longArrayOf(), echo: Long = 100000) =
        RudpPacketCodec.encode(s.keys.server, RudpPacket(200000, echo, ack, selective, seq, data), ByteArray(20), 1)
    @Test fun keyDerivationAndPacketSignatureMatchExecutedC() {
        RudpKeys(seed).use { keys ->
            assertArrayEquals(transportVector("rudp_server_key"), keys.server)
            assertArrayEquals(transportVector("rudp_client_key"), keys.client)
            assertArrayEquals(transportVector("rudp_keep_request"), keys.keepAliveRequest)
            assertArrayEquals(transportVector("rudp_keep_response"), keys.keepAliveResponse)
            val p = RudpPacket(100000, 90000, 3, longArrayOf(), 7, ByteArray(60) { (it + 7).toByte() })
            assertArrayEquals(transportVector("rudp_segment"), RudpPacketCodec.encode(keys.client, p, ByteArray(20) { (it + 32).toByte() }, 1))
            assertArrayEquals(p.payload, RudpPacketCodec.decode(keys.client, transportVector("rudp_segment")).payload)
        }
    }
    @Test fun establishmentDisconnectPrefixRetransmissionAndAcks() {
        RudpSession(100000, seed).use { s ->
            assertArrayEquals(seed, s.poll(100000).single().copyOf(20)); assertTrue(s.poll(100199).isEmpty())
            assertEquals(39, s.poll(100200).single().size)
            s.receive(server(s, 1, s.keys.keepAliveRequest), 100200)
            assertTrue(s.established); assertNull(s.readSegment())
            val first = s.poll(100200).map { RudpPacketCodec.decode(s.keys.client, it) }
            assertArrayEquals(ByteBuffer.allocate(8).putLong(s.disconnectMagic).array(), first[0].payload)
            assertTrue(s.poll(100399).isEmpty())
            assertTrue(s.poll(100400).isNotEmpty()); assertEquals(1, s.retransmissions)
            s.receive(server(s, 2, ack = 1, echo = 100400), 100410)
            assertEquals(0, s.outstandingSegments)
            assertTrue(s.enqueue(byteArrayOf(9))); s.poll(100411)
            s.receive(server(s, 2, selective = longArrayOf(2), echo = 100411), 100412)
            assertEquals(0, s.outstandingSegments)
        }
    }
    @Test fun orderedReassemblyDuplicatesAndBoundedWindows() {
        RudpSession(100000, seed).use { s ->
            s.receive(server(s, 2, byteArrayOf(2)), 100010); assertNull(s.readSegment())
            s.receive(server(s, 2, byteArrayOf(2)), 100010); assertEquals(1, s.reassemblySegments)
            s.receive(server(s, 1, byteArrayOf(1)), 100010)
            assertArrayEquals(byteArrayOf(1), s.readSegment()); assertArrayEquals(byteArrayOf(2), s.readSegment())
            s.receive(server(s, 1, byteArrayOf(1)), 100010); assertNull(s.readSegment())
            s.receive(server(s, 100, byteArrayOf(3)), 100010); assertEquals(0, s.reassemblySegments)
            repeat(127) { assertTrue(s.enqueue(ByteArray(512))) }; assertTrue(s.enqueue(ByteArray(504))); assertFalse(s.enqueue(byteArrayOf(1)))
            s.poll(100010); assertEquals(64, s.outstandingSegments)
        }
    }
    @Test fun malformedCorruptAndTimeouts() {
        RudpSession(100000, seed).use { s ->
            try { s.poll(105000); fail() } catch (e: RudpException) { assertEquals(RudpFailure.HANDSHAKE_TIMEOUT, e.failure) }
            val bytes = server(s, 1, byteArrayOf(1))
            for (i in bytes.indices) try { s.receive(bytes.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }, 100100); fail() } catch (_: RudpException) {}
            s.receive(bytes, 100100)
            try { s.poll(112001); fail() } catch (e: RudpException) { assertEquals(RudpFailure.TIMEOUT, e.failure) }
            try { s.receive(server(s, s.disconnectMagic), 100100); fail() } catch (e: RudpException) { assertEquals(RudpFailure.DISCONNECTED, e.failure) }
        }
    }
    @Test fun largestPacketAndOversizedBounds() {
        RudpKeys(seed).use { k ->
            val p = RudpPacket(1, 0, 0, LongArray(64) { it.toLong() }, 1, ByteArray(512))
            val b = RudpPacketCodec.encode(k.client, p, ByteArray(20), 255)
            assertEquals(1355, b.size); assertEquals(512, RudpPacketCodec.decode(k.client, b).payload.size)
            try { RudpPacketCodec.decode(k.client, ByteArray(1356)); fail() } catch (_: RudpException) {}
        }
    }
}
