package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.*
import java.net.InetSocketAddress

class HandshakeTest {
    private fun http(p: Pack): ByteArray {
        val b = SoftEtherPackCodec.encode(p)
        return "HTTP/1.1 200 OK\r\nContent-Length: ${b.size}\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray() + b
    }
    private fun welcome() = Pack().str("session_name", "SID-TEST").str("connection_name", "CID-TEST")
        .uint("max_connection", 1).bool("use_encrypt", true).uint("timeout", 30_000).data("session_key", ByteArray(20)).uint("session_key_32", 77)
    private class Fixture(inputBytes: ByteArray) : SoftEtherTransport {
        override val input = ByteArrayInputStream(inputBytes)
        override val output = ByteArrayOutputStream()
        override val localAddress = InetSocketAddress("192.168.1.2", 12345)
        override val remoteAddress = InetSocketAddress("192.168.1.1", 443)
        var closed = false
        var timeout = 0
        override fun setReadTimeout(milliseconds: Int) { timeout = milliseconds }
        override fun close() { closed = true }
    }
    private fun fixture(welcome: Pack) = Fixture(http(Pack().str("hello", "SoftEther VPN Server").uint("version", 444).uint("build", 9807).data("random", ByteArray(20) { it.toByte() })) + http(welcome))
    @Test fun exactSignatureChallengeLoginMetadataAndTlsNegotiation() {
        val t = fixture(welcome())
        val s = SoftEtherSession.connect(t, "vpn.example.org", "TEST", "user", "synthetic-password".toCharArray(), ByteArray(20))
        assertEquals("SID-TEST", s.sessionName); assertEquals(30_000, t.timeout)
        val output = t.output.toByteArray()
        val text = String(output, Charsets.ISO_8859_1)
        assertTrue(text.startsWith("POST /vpnsvc/connect.cgi HTTP/1.1\r\n")); assertTrue(text.contains("VPNCONNECT"))
        val authStart = text.indexOf("POST /vpnsvc/vpn.cgi")
        val body = text.indexOf("\r\n\r\n", authStart) + 4
        val p = SoftEtherPackCodec.decode(output.copyOfRange(body, output.size))
        assertEquals("login", p.str("method")); assertEquals("TEST", p.str("hubname")); assertEquals(1L, p.int("max_connection"))
        assertEquals(0L, p.int("protocol")); assertTrue(p.bool("use_encrypt")); assertFalse(p.bool("use_udp_acceleration"))
        assertEquals(0xbc010000L, p.int("ClientProductVer")) // LittleEndian32(Endian32(444)).
        assertEquals(0x0201a8c0L, p.int("ClientIpAddress")) // PackAddIp32: octets reversed within uint32.
        assertEquals(20, p.data("secure_password")!!.size)
        assertFalse(text.contains("synthetic-password")); assertNull(p.str("plain_password"))
        s.close(); assertTrue(t.closed)
    }
    @Test fun serverErrorsAndUnsafeNegotiationCloseTransport() {
        val error = fixture(Pack().uint("error", 9))
        try { SoftEtherSession.connect(error, "server", "hub", "user", charArrayOf(), ByteArray(20)); fail() }
        catch (e: SoftEtherServerException) { assertEquals(9, e.code) }
        assertTrue(error.closed)
        for (w in listOf(welcome().bool("use_encrypt", false), welcome().bool("use_compress", true), welcome().uint("max_connection", 33))) {
            val t = fixture(w)
            try { SoftEtherSession.connect(t, "server", "hub", "user", charArrayOf(), ByteArray(20)); fail() } catch (_: ProtocolException) {}
            assertTrue(t.closed)
        }
    }
    @Test fun requestedAndNegotiatedCountsAreSeparate() {
        for (n in listOf(1, 2, 4, 8, 32)) {
            val t = fixture(welcome().uint("max_connection", n.toLong()))
            val s = SoftEtherSession.connect(t, "server", "hub", "user", charArrayOf(), ByteArray(20), SessionOptions(n))
            assertEquals(n, s.requestedTcpConnections); assertEquals(n, s.negotiatedMaxConnections)
            val bytes = t.output.toByteArray(); val str = String(bytes, Charsets.ISO_8859_1)
            val offset = str.indexOf("\r\n\r\n", str.indexOf("POST /vpnsvc/vpn.cgi")) + 4
            assertEquals(n.toLong(), SoftEtherPackCodec.decode(bytes.copyOfRange(offset, bytes.size)).int("max_connection"))
            s.close()
        }
        val s = SoftEtherSession.connect(fixture(welcome().uint("max_connection", 4)), "server", "hub", "user", charArrayOf(), ByteArray(20), SessionOptions(8))
        assertEquals(8, s.requestedTcpConnections); assertEquals(4, s.negotiatedMaxConnections); s.close()
    }
    @Test fun boundedMutationalPackFuzz() {
        val random = java.util.Random(7)
        val valid = SoftEtherPackCodec.encode(Pack().str("hello", "server").data("random", ByteArray(20)))
        repeat(5000) {
            val bytes = if (it % 2 == 0) ByteArray(random.nextInt(2048)).also { a -> random.nextBytes(a) }
                else valid.copyOf().also { a -> a[random.nextInt(a.size)] = random.nextInt(256).toByte() }
            try { SoftEtherPackCodec.decode(bytes) } catch (_: ProtocolException) {}
        }
    }
    @Test fun cleanupFailureDoesNotMaskTheHandshakeFailure() {
        val transport = object : SoftEtherTransport {
            override val input = ByteArrayInputStream(byteArrayOf())
            override val output = ByteArrayOutputStream()
            override fun setReadTimeout(milliseconds: Int) { }
            override fun close() { throw IOException("synthetic cleanup failure") }
        }
        try { SoftEtherSession.connect(transport, "server", "hub", "user", charArrayOf(), ByteArray(20)); fail() }
        catch (_: EOFException) { }
    }
}
