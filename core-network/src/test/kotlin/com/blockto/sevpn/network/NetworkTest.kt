package com.blockto.sevpn.network
import org.junit.Assert.*
import org.junit.Test

class NetworkTest {
    @Test fun contiguousMasksAndRoutes() {
        for (n in 0..32) assertEquals(n, Ipv4.prefix(Ipv4.mask(n)))
        try { Ipv4.prefix(0xff00ff00.toInt()); fail() } catch (_: IllegalArgumentException) {}
        val a = Ipv4.parse("192.168.30.10"); val g = Ipv4.parse("192.168.30.1")
        val r = Ipv4RoutingEngine(a, 24, g, listOf(Route(Ipv4.parse("10.0.0.0"), 8, Ipv4.parse("192.168.30.2"))))
        assertEquals(Ipv4.parse("192.168.30.12"), r.nextHop(Ipv4.parse("192.168.30.12")))
        assertEquals(g, r.nextHop(Ipv4.parse("8.8.8.8")))
        assertEquals(Ipv4.parse("192.168.30.2"), r.nextHop(Ipv4.parse("10.1.2.3")))
    }
    @Test fun udpChecksumsAndMalformedPackets() {
        val b = Ipv4Packet.udp(Ipv4.parse("192.168.30.10"), Ipv4.parse("192.168.30.1"), 1234, 53, byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), Ipv4Packet.parse(b).udpPayload(1234, 53))
        val bad = b.copyOf().also { it[30] = 99 }
        try { Ipv4Packet.parse(bad).udpPayload(); fail() } catch (_: PacketException) {}
        for (size in 0 until b.size) try { Ipv4Packet.parse(b.copyOf(size)); fail() } catch (_: PacketException) {}
        try { Ipv4Packet.parse(b, mtu = 28); fail() } catch (_: PacketException) {}
    }
}
