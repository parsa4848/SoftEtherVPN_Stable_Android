package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.*

class ChannelTest {
    class Streams(bytes: ByteArray) : SoftEtherTransport {
        override val input = ByteArrayInputStream(bytes)
        override val output = ByteArrayOutputStream()
        override fun setReadTimeout(milliseconds: Int) {}
        override fun close() {}
    }
    @Test fun batchesKeepalivesAndExactFraming() {
        val frame = ByteArray(42) { it.toByte() }
        val data = ByteArrayOutputStream()
        DataOutputStream(data).apply { writeInt(-1); writeInt(2); writeShort(77); writeInt(2); writeInt(frame.size); write(frame); writeInt(frame.size); write(frame) }
        val t = Streams(data.toByteArray()); val c = SoftEtherDataChannel(t)
        assertArrayEquals(frame, c.readFrame()); assertArrayEquals(frame, c.readFrame())
        c.sendFrame(frame); c.keepAlive()
        val out = DataInputStream(ByteArrayInputStream(t.output.toByteArray()))
        assertEquals(1, out.readInt()); assertEquals(42, out.readInt())
        val f = ByteArray(42).also { out.readFully(it) }; assertArrayEquals(frame, f)
        assertEquals(-1, out.readInt()); assertEquals(0, out.readInt())
    }
    @Test fun rejectsUnboundedCountsFramesKeepalives() {
        listOf(intArrayOf(4097), intArrayOf(1, 1601), intArrayOf(-1, 513), intArrayOf(1, -1)).forEach { v ->
            val b = ByteArrayOutputStream(); DataOutputStream(b).apply { v.forEach { writeInt(it) } }
            try { SoftEtherDataChannel(Streams(b.toByteArray())).readFrame(); fail() } catch (_: ProtocolException) {}
        }
    }
    @Test fun httpDoesNotConsumeNextRecord() {
        val p = SoftEtherPackCodec.encode(Pack().uint("version", 444))
        val header = "HTTP/1.1 200 OK\r\nContent-Length: ${p.size}\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray()
        val t = Streams(header + p + byteArrayOf(99))
        assertEquals(444L, SoftEtherHttp(t, "example.org").receivePack().int("version")); assertEquals(99, t.input.read())
    }
    @Test fun rejectsAmbiguousHttpBodyLength() {
        val t = Streams("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 9\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray())
        try { SoftEtherHttp(t, "example.org").receivePack(); fail() } catch (_: ProtocolException) {}
    }
}
