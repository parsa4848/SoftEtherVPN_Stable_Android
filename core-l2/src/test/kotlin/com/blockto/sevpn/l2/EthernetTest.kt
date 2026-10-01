package com.blockto.sevpn.l2
import com.blockto.sevpn.network.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class EthernetTest {
    @Test fun ethernetArpAndMac() {
        val mac = Mac(0x020102030405); val ip = Ipv4.parse("192.168.30.10")
        val b = ArpPacket.frame(1, mac, ip, Mac.ZERO, Ipv4.parse("192.168.30.1"))
        val eth = EthernetFrame.parse(b); val a = ArpPacket.parse(b)
        assertEquals(mac, eth.source); assertEquals(Mac.BROADCAST, eth.destination)
        assertEquals(1, a.operation); assertEquals(ip, a.senderIp)
        assertTrue(Mac.generate().isUnicast())
        assertEquals(2L, Mac.generate().bits ushr 40 and 3)
        try { EthernetFrame.parse(ByteArray(13)); fail() } catch (_: PacketException) {}
        b[18] = 5
        try { ArpPacket.parse(b); fail() } catch (_: PacketException) {}
    }
    @Test fun cacheExpiresAndIsBounded() {
        var now = 0L; val cache = ArpCache({ now }, 2, 50)
        val mac = Mac(0x020102030405)
        for (i in 1..3) cache.put(Ipv4(0xc0a80100.toInt() or i), mac)
        assertNull(cache.get(Ipv4(0xc0a80101.toInt())))
        assertEquals(mac, cache.get(Ipv4(0xc0a80103.toInt())))
        now = 50; assertNull(cache.get(Ipv4(0xc0a80103.toInt())))
    }
    @Test fun outboundWaitsForArpAndInboundStripsEthernet() = runBlocking {
        val mac = Mac(0x020102030405); val gatewayMac = Mac(0x020607080901)
        val ip = Ipv4.parse("192.168.30.10"); val gw = Ipv4.parse("192.168.30.1")
        val sent = mutableListOf<ByteArray>()
        val e = VirtualEthernetEndpoint(mac, Ipv4RoutingEngine(ip, 24, gw, emptyList()), 1500, { sent += it })
        val packet = Ipv4Packet.udp(ip, Ipv4.parse("1.1.1.1"), 1234, 53, byteArrayOf(1))
        e.sendIp(packet); assertEquals(EthernetFrame.ARP, EthernetFrame.parse(sent.single()).type)
        e.receive(ArpPacket.frame(2, gatewayMac, gw, mac, ip))
        assertEquals(gatewayMac, EthernetFrame.parse(sent.last()).destination)
        val incoming = Ipv4Packet.udp(Ipv4.parse("1.1.1.1"), ip, 53, 1234, byteArrayOf(2))
        assertArrayEquals(incoming, e.receive(EthernetFrame.write(mac, gatewayMac, EthernetFrame.IPV4, incoming)))
        assertNull(e.receive(EthernetFrame.write(Mac(0x020000000099), gatewayMac, EthernetFrame.IPV4, incoming)))
    }
}
