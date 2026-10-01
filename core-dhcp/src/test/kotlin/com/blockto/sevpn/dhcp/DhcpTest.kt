package com.blockto.sevpn.dhcp

import com.blockto.sevpn.l2.*
import com.blockto.sevpn.network.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream

class DhcpTest {
    private val mac = Mac(0x020102030405)
    private val server = Ipv4.parse("192.168.30.1")
    private val offered = Ipv4.parse("192.168.30.10")
    private fun reply(xid: Int, type: Int, extra: ByteArray = byteArrayOf()): ByteArray {
        val b = ByteArray(240)
        b[0] = 2; b[1] = 1; b[2] = 6; Wire.put32(b, 4, xid); Wire.put32(b, 16, offered.bits); mac.write(b, 28); Wire.put32(b, 236, 0x63825363)
        val o = ByteArrayOutputStream()
        fun opt(id: Int, data: ByteArray) { o.write(id); o.write(data.size); o.write(data) }
        opt(53, byteArrayOf(type.toByte())); opt(54, server.bytes()); opt(1, Ipv4.parse("255.255.255.0").bytes())
        opt(3, server.bytes()); opt(6, server.bytes()); opt(51, byteArrayOf(0, 0, 14, 16))
        o.write(extra); o.write(255)
        return EthernetFrame.write(Mac.BROADCAST, Mac(0x020000000001), EthernetFrame.IPV4, Ipv4Packet.udp(server, Ipv4.BROADCAST, 67, 68, b + o.toByteArray()))
    }
    @Test fun messagesAndLeaseOptions() {
        val packet = DhcpCodec.request(mac, 12345, 1)
        val p = Ipv4Packet.parse(packet, 14, packet.size - 14)
        val payload = p.udpPayload(68, 67)
        assertEquals(12345, Wire.i32(payload, 4)); assertEquals(mac, Mac.read(payload, 28))
        assertEquals(0x63825363, Wire.i32(payload, 236)); assertEquals(Ipv4.ZERO, p.source)
        val r = DhcpCodec.parse(reply(12345, 5), mac, 12345)!!
        val lease = DhcpCodec.lease(r, 100)
        assertEquals(offered, lease.address); assertEquals(24, lease.prefix); assertEquals(server, lease.gateway)
        assertEquals(listOf(server), lease.dns); assertEquals(3600L, lease.seconds)
        assertNull(DhcpCodec.parse(reply(12345, 5), mac, 999))
        assertNull(DhcpCodec.parse(reply(12345, 5), Mac(0x020000000099), 12345))
    }
    @Test fun classlessRoutesRespectDefaultAndRejectTruncation() {
        val r = DhcpCodec.classlessRoutes(byteArrayOf(8, 10) + server.bytes() + byteArrayOf(0) + server.bytes())
        assertEquals(2, r.size); assertEquals(8, r[0].prefix); assertEquals(Ipv4.parse("10.0.0.0"), r[0].network)
        for (b in listOf(byteArrayOf(33), byteArrayOf(24, 10, 0))) try { DhcpCodec.classlessRoutes(b); fail() } catch (_: PacketException) {}
        // RFC3442: option 121 without default route overrides option 3.
        val routes = byteArrayOf(121, 6, 8, 10) + server.bytes()
        try { DhcpCodec.lease(DhcpCodec.parse(reply(1, 5, routes), mac)!!, 0); fail() } catch (_: PacketException) {}
    }
    @Test fun malformedOptionsAndNoDnsAreErrors() {
        try { DhcpCodec.parse(reply(1, 5, byteArrayOf(99, 100, 1)), mac); fail() } catch (_: PacketException) {}
        val r = DhcpCodec.parse(reply(1, 5), mac)!!
        try { DhcpCodec.lease(r.copy(options = r.options - 6), 0); fail() } catch (_: PacketException) {}
        val badMask = r.copy(options = r.options + (1 to Ipv4.parse("255.0.255.0").bytes()))
        try { DhcpCodec.lease(badMask, 0); fail() } catch (_: PacketException) {}
    }
    @Test fun discoverRequestAckStateMachine() = runBlocking {
        val incoming = Channel<ByteArray>(8)
        val requests = mutableListOf<Int>()
        val client = DhcpClient(mac, { frame ->
            val b = Ipv4Packet.parse(frame, 14, frame.size - 14).udpPayload(68, 67)
            val xid = Wire.i32(b, 4)
            val type = b[242].toInt()
            requests += type
            incoming.send(reply(xid, if (type == 1) 2 else 5))
        }, incoming)
        val lease = client.acquire()
        assertEquals(listOf(1, 3), requests); assertEquals(offered, lease.address)
        assertNotNull(client.renew(lease)); incoming.close(); Unit
    }
    @Test fun boundedRandomInputDoesNotEscapeParserExceptions() {
        val random = java.util.Random(42) // deterministic parser fuzzing, no protocol randomness.
        repeat(2000) {
            val b = ByteArray(random.nextInt(1700)).also { random.nextBytes(it) }
            try { DhcpCodec.parse(b, mac) } catch (_: PacketException) { }
        }
    }
}
