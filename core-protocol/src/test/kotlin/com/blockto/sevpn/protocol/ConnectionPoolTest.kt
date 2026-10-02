package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import java.io.*
import java.util.concurrent.atomic.AtomicInteger

class ConnectionPoolTest {
    private fun http(p: Pack): ByteArray {
        val b = SoftEtherPackCodec.encode(p)
        return "HTTP/1.1 200 OK\r\nContent-Length: ${b.size}\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray() + b
    }
    private class Fixture(prefix: ByteArray) : SoftEtherTransport {
        private val pipe = PipedInputStream(32768)
        val peer = PipedOutputStream(pipe)
        override val input: InputStream = SequenceInputStream(ByteArrayInputStream(prefix), pipe)
        override val output = ByteArrayOutputStream()
        @Volatile var closed = false
        override fun setReadTimeout(milliseconds: Int) {}
        override fun close() { closed = true; peer.close(); pipe.close() }
    }
    private fun hello() = http(Pack().str("hello", "stock").data("random", ByteArray(20)))
    private fun primary(n: Int) = Fixture(hello() + http(Pack().str("session_name", "test").str("connection_name", "test")
        .uint("max_connection", n.toLong()).bool("use_encrypt", true).uint("timeout", 5000).data("session_key", ByteArray(20) { it.toByte() })))
    private fun session(p: Fixture, n: Int) = SoftEtherSession.connect(p, "server", "hub", "user", null, ByteArray(20), SessionOptions(n))
    @Test fun additionalPackJoinsTheSameSessionWithVersionAndDirection() {
        val p = primary(2); val s = session(p, 2)
        val t = Fixture(hello() + http(Pack().uint("error", 0).uint("direction", 1)))
        val additional = s.attachAdditional(t, "server")
        assertEquals(1, additional.direction)
        val out = t.output.toByteArray(); val text = String(out, Charsets.ISO_8859_1)
        val start = text.indexOf("\r\n\r\n", text.indexOf("POST /vpnsvc/vpn.cgi")) + 4
        val pack = SoftEtherPackCodec.decode(out.copyOfRange(start, out.size))
        assertEquals("additional_connect", pack.str("method")); assertArrayEquals(ByteArray(20) { it.toByte() }, pack.data("session_key"))
        assertEquals(444L, pack.int("client_ver")); assertEquals(9807L, pack.int("client_build"))
        assertNull(pack.str("username")); assertNull(pack.data("secure_password"))
        additional.close(); s.close()
    }
    @Test fun secondaryLossRestoresPoolAndWholeRecordsContinue() = runBlocking {
        val p = primary(2); val s = session(p, 2); val peers = java.util.Collections.synchronizedList(mutableListOf<Fixture>())
        val connections = AtomicInteger()
        val pool = SoftEtherConnectionPool(s, this, {
            val t = Fixture(hello() + http(Pack().uint("direction", 0)))
            peers += t; connections.incrementAndGet(); s.attachAdditional(t, "server")
        })
        try {
            pool.start()
            withTimeout(4000) { while (pool.activeCount != 2) delay(10) }
            val frame = ByteArray(60) { (it + 7).toByte() }
            repeat(10) { pool.sendFrame(frame) }
            val second = peers[0]; second.close()
            withTimeout(4000) { while (connections.get() < 2 || pool.activeCount != 2) delay(10) }
            assertFalse(p.closed)
            DataOutputStream(p.peer).apply { writeInt(1); writeInt(frame.size); write(frame); flush() }
            assertArrayEquals(frame, withTimeout(1000) { pool.inbound.receive() })
            repeat(10) { pool.sendFrame(frame) }; delay(100)
            // Every transport starts with HTTP, then complete count/length/frame records.
            val bytes = p.output.toByteArray(); val text = String(bytes, Charsets.ISO_8859_1)
            val body = text.indexOf("\r\n\r\n", text.indexOf("POST /vpnsvc/vpn.cgi")) + 4
            val header = text.substring(text.indexOf("POST /vpnsvc/vpn.cgi"), body)
            val authSize = Regex("Content-Length: (\\d+)").find(header)!!.groupValues[1].toInt()
            val records = DataInputStream(ByteArrayInputStream(bytes, body + authSize, bytes.size - body - authSize))
            while (records.available() > 0) { assertEquals(1, records.readInt()); assertEquals(60, records.readInt()); assertArrayEquals(frame, ByteArray(60).also { records.readFully(it) }) }
        } finally { pool.close(); s.close() }
        assertTrue(p.closed); assertTrue(peers.all { it.closed })
    }
    @Test fun closeRacesSafelyWithAnAdditionalHandshake() = runBlocking {
        val p = primary(2); val s = session(p, 2); val started = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val t = Fixture(hello() + http(Pack().uint("direction", 0)))
        val pool = SoftEtherConnectionPool(s, this, { started.complete(Unit); release.await(); s.attachAdditional(t, "server") })
        pool.start(); started.await(); pool.close(); release.complete(Unit); s.close()
        assertEquals(0, pool.activeCount); t.close()
    }
    @Test fun receiveOnlySecondaryNeverCarriesOutboundFrames() = runBlocking {
        val p = primary(2); val s = session(p, 2)
        val secondary = Fixture(hello() + http(Pack().uint("direction", 1)))
        val pool = SoftEtherConnectionPool(s, this, { s.attachAdditional(secondary, "server") })
        try {
            pool.start(); withTimeout(3000) { while (pool.activeCount != 2) delay(10) }
            val initialBytes = secondary.output.size()
            repeat(20) { pool.sendFrame(ByteArray(60) { it.toByte() }) }; delay(100)
            assertEquals(initialBytes, secondary.output.size())
            DataOutputStream(secondary.peer).apply { writeInt(1); writeInt(60); write(ByteArray(60)); flush() }
            assertEquals(60, withTimeout(1000) { pool.inbound.receive() }.size)
        } finally { pool.close(); s.close(); secondary.close() }
    }
    @Test fun expiredSessionDuringAdditionalConnectTerminatesTheLogicalSession() = runBlocking {
        for (code in listOf(13, 14)) {
            val p = primary(2); val s = session(p, 2); var pool: SoftEtherConnectionPool? = null
            try {
                coroutineScope {
                    pool = SoftEtherConnectionPool(s, this, { throw SoftEtherServerException(code) }).also { it.start() }
                    awaitCancellation()
                }
                fail("Expired session must fail its scope")
            } catch (e: SoftEtherServerException) { assertEquals(code, e.code) }
            finally { pool?.close(); s.close() }
            assertTrue(p.closed)
        }
    }
}
