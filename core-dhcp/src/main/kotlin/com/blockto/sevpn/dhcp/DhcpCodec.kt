package com.blockto.sevpn.dhcp

import com.blockto.sevpn.l2.*
import com.blockto.sevpn.network.*
import java.io.ByteArrayOutputStream

data class DhcpReply(val transaction: Int, val type: Int, val address: Ipv4, val options: Map<Int, ByteArray>)
data class DhcpLease(val address: Ipv4, val prefix: Int, val gateway: Ipv4, val dns: List<Ipv4>,
                     val server: Ipv4, val seconds: Long, val renewSeconds: Long, val rebindSeconds: Long,
                     val routes: List<Route>, val acquiredMs: Long) {
    val expiresMs get() = acquiredMs + seconds * 1000
    fun sameConfiguration(other: DhcpLease) = address == other.address && prefix == other.prefix && gateway == other.gateway && dns == other.dns && routes == other.routes
}

object DhcpCodec {
    private val parameters = byteArrayOf(1, 3, 6, 51, 58, 59, 121, 249.toByte())
    fun request(mac: Mac, xid: Int, type: Int, requested: Ipv4? = null, server: Ipv4? = null, current: Ipv4 = Ipv4.ZERO): ByteArray {
        require(type == 1 || type == 3 || type == 7)
        val b = ByteArray(240)
        b[0] = 1; b[1] = 1; b[2] = 6; Wire.put32(b, 4, xid)
        Wire.put16(b, 10, if (current == Ipv4.ZERO) 0x8000 else 0)
        Wire.put32(b, 12, current.bits); mac.write(b, 28); Wire.put32(b, 236, 0x63825363)
        val options = ByteArrayOutputStream()
        fun option(code: Int, value: ByteArray) { require(value.size <= 255); options.write(code); options.write(value.size); options.write(value) }
        option(53, byteArrayOf(type.toByte()))
        option(61, byteArrayOf(1) + mac.bytes())
        option(55, parameters)
        option(57, byteArrayOf(5, -64)) // Maximum DHCP payload 1472 within IPv4 MTU 1500.
        option(12, "android-sevpn".toByteArray(Charsets.US_ASCII))
        requested?.let { option(50, it.bytes()) }
        server?.let { option(54, it.bytes()) }
        options.write(255)
        val payload = (b + options.toByteArray()).let { if (it.size < 300) it.copyOf(300) else it }
        val ip = Ipv4Packet.udp(current, Ipv4.BROADCAST, 68, 67, payload)
        return EthernetFrame.write(Mac.BROADCAST, mac, EthernetFrame.IPV4, ip)
    }
    fun parse(frameBytes: ByteArray, mac: Mac, xid: Int? = null): DhcpReply? {
        val frame = EthernetFrame.parse(frameBytes)
        if (frame.type != EthernetFrame.IPV4 || (frame.destination != mac && frame.destination != Mac.BROADCAST)) return null
        val ip = Ipv4Packet.parse(frameBytes, 14, frameBytes.size - 14)
        if (ip.protocol != 17 || ip.fragmented || ip.totalLength < ip.headerLength + 8) return null
        val u = 14 + ip.headerLength
        if (Wire.u16(frameBytes, u) != 67 || Wire.u16(frameBytes, u + 2) != 68) return null
        val b = ip.udpPayload(67, 68)
        if (b.size !in 240..1472 || b[0] != 2.toByte() || b[1] != 1.toByte() || b[2] != 6.toByte() || Wire.i32(b, 236) != 0x63825363) throw PacketException("Invalid DHCP header")
        if (Mac.read(b, 28) != mac) return null
        val transaction = Wire.i32(b, 4)
        if (xid != null && xid != transaction) return null
        val options = linkedMapOf<Int, ByteArray>()
        fun parseOptions(start: Int, length: Int) {
            var i = start; val end = start + length; var ended = false
            while (i < end) {
                val code = b[i++].toInt() and 255
                if (code == 255) { ended = true; break }
                if (code == 0) continue
                if (i >= end) throw PacketException("Truncated DHCP option")
                val size = b[i++].toInt() and 255
                if (size > end - i) throw PacketException("DHCP option exceeds packet")
                val old = options[code] ?: byteArrayOf()
                if (old.size + size > 1472) throw PacketException("DHCP concatenation exceeds bounds")
                options[code] = old + b.copyOfRange(i, i + size); i += size
            }
            if (!ended) throw PacketException("Missing DHCP option terminator")
        }
        parseOptions(240, b.size - 240)
        val overload = options[52]?.let { if (it.size != 1 || (it[0].toInt() and 255) !in 1..3) throw PacketException("Invalid DHCP option overload"); it[0].toInt() } ?: 0
        if (overload and 1 != 0) parseOptions(108, 128)
        if (overload and 2 != 0) parseOptions(44, 64)
        val type = options[53] ?: throw PacketException("Missing DHCP type")
        if (type.size != 1 || type[0].toInt() !in setOf(2, 5, 6)) throw PacketException("Unexpected DHCP type")
        return DhcpReply(transaction, type[0].toInt(), Ipv4(Wire.i32(b, 16)), options)
    }
    fun server(reply: DhcpReply): Ipv4 {
        val b = reply.options[54] ?: throw PacketException("DHCP server identifier missing")
        if (b.size != 4) throw PacketException("Invalid DHCP server identifier")
        return Ipv4(Wire.i32(b, 0)).also { if (!it.isUnicast()) throw PacketException("Invalid DHCP server address") }
    }
    fun lease(reply: DhcpReply, now: Long, fallbackDns: List<Ipv4> = emptyList(), previous: DhcpLease? = null): DhcpLease {
        if (reply.type != 5) throw PacketException("DHCP ACK required")
        fun scalar(code: Int, default: Long? = null): Long {
            val b = reply.options[code] ?: return default ?: throw PacketException("DHCP option $code missing")
            if (b.size != 4) throw PacketException("Invalid DHCP scalar $code")
            return Wire.i32(b, 0).toLong() and 0xffffffffL
        }
        fun addresses(code: Int): List<Ipv4> {
            val b = reply.options[code] ?: return emptyList()
            if (b.isEmpty() || b.size % 4 != 0 || b.size > 32) throw PacketException("Invalid DHCP address list $code")
            return (b.indices step 4).map { Ipv4(Wire.i32(b, it)) }.also { if (it.any { a -> !a.isUnicast() }) throw PacketException("Invalid DHCP address") }
        }
        val address = if (reply.address == Ipv4.ZERO && previous != null) previous.address else reply.address
        if (!address.isUnicast()) throw PacketException("Invalid leased IPv4 address")
        val prefix = try { Ipv4.prefix(scalar(1, previous?.let { Ipv4.mask(it.prefix).toLong() and 0xffffffffL }).toInt()) }
            catch (_: IllegalArgumentException) { throw PacketException("DHCP subnet mask is not contiguous") }
        if (prefix !in 1..30) throw PacketException("DHCP subnet must support an Ethernet gateway")
        val net = address.bits and Ipv4.mask(prefix); val broadcast = net or Ipv4.mask(prefix).inv()
        if (address.bits == net || address.bits == broadcast) throw PacketException("DHCP offered a network or broadcast address")
        val routeOption = reply.options[121] ?: reply.options[249]
        val routes = routeOption?.let { classlessRoutes(it) } ?: previous?.routes ?: emptyList()
        val gateway = if (routeOption != null) routes.firstOrNull { it.prefix == 0 }?.gateway ?: Ipv4.ZERO
            else addresses(3).firstOrNull() ?: previous?.gateway ?: Ipv4.ZERO
        fun validHop(a: Ipv4) = a.isUnicast() && a.bits and Ipv4.mask(prefix) == net && a.bits != broadcast && a != address && a.bits != net
        if (!validHop(gateway)) throw PacketException("DHCP supplied no usable default gateway for full tunnel")
        if (routes.any { it.gateway != Ipv4.ZERO && !validHop(it.gateway) }) throw PacketException("DHCP route gateway is off-link")
        val dns = fallbackDns.ifEmpty { addresses(6).ifEmpty { previous?.dns ?: emptyList() } }
        if (dns.isEmpty() || dns.any { !it.isUnicast() }) throw PacketException("DHCP supplied no usable DNS; configure an explicit override")
        val seconds = scalar(51, previous?.seconds ?: 3600L)
        if (seconds < 5) throw PacketException("DHCP lease too short")
        val t1 = scalar(58, maxOf(1, seconds / 2))
        val t2 = scalar(59, maxOf(t1 + 1, seconds * 7 / 8))
        if (t1 < 1 || t1 >= t2 || t2 >= seconds) throw PacketException("Invalid DHCP renewal times")
        return DhcpLease(address, prefix, gateway, dns, server(reply), seconds, t1, t2, routes, now)
    }
    fun classlessRoutes(b: ByteArray): List<Route> {
        var i = 0; val routes = mutableListOf<Route>()
        while (i < b.size) {
            val prefix = b[i++].toInt() and 255
            if (prefix > 32 || routes.size >= 64) throw PacketException("Invalid classless route prefix/count")
            val count = (prefix + 7) / 8
            if (count + 4 > b.size - i) throw PacketException("Truncated classless route")
            var address = 0
            for (j in 0 until count) address = address or ((b[i++].toInt() and 255) shl (24 - 8 * j))
            address = address and Ipv4.mask(prefix)
            val gateway = Ipv4(Wire.i32(b, i)); i += 4
            routes += Route(Ipv4(address), prefix, gateway)
        }
        return routes
    }
}
