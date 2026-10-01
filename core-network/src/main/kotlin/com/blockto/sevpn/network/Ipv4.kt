package com.blockto.sevpn.network

class PacketException(message: String) : IllegalArgumentException(message)

object Wire {
    fun u16(b: ByteArray, p: Int) = ((b[p].toInt() and 255) shl 8) or (b[p + 1].toInt() and 255)
    fun i32(b: ByteArray, p: Int): Int = ((b[p].toInt() and 255) shl 24) or ((b[p + 1].toInt() and 255) shl 16) or ((b[p + 2].toInt() and 255) shl 8) or (b[p + 3].toInt() and 255)
    fun put16(b: ByteArray, p: Int, v: Int) { b[p] = (v ushr 8).toByte(); b[p + 1] = v.toByte() }
    fun put32(b: ByteArray, p: Int, v: Int) { for (i in 0..3) b[p + i] = (v ushr (24 - 8 * i)).toByte() }
    fun checksum(b: ByteArray, offset: Int = 0, length: Int = b.size - offset, initial: Long = 0): Int {
        require(offset >= 0 && length >= 0 && offset <= b.size - length)
        var sum = initial; var i = offset; val end = offset + length
        while (i + 1 < end) { sum += u16(b, i); i += 2 }
        if (i < end) sum += (b[i].toInt() and 255) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }
}

@JvmInline value class Ipv4(val bits: Int) {
    override fun toString() = (0..3).joinToString(".") { ((bits ushr (24 - it * 8)) and 255).toString() }
    fun bytes() = ByteArray(4).also { Wire.put32(it, 0, bits) }
    fun isUnicast(): Boolean { val first = bits ushr 24; return first in 1..223 && first != 127 && bits != -1 }
    fun isMulticast() = bits ushr 28 == 14
    companion object {
        val ZERO = Ipv4(0); val BROADCAST = Ipv4(-1)
        fun parse(s: String): Ipv4 {
            val parts = s.split('.')
            require(parts.size == 4)
            var v = 0
            for (part in parts) { require(part.isNotEmpty() && part.all { it in '0'..'9' }); val n = part.toInt(); require(n in 0..255); v = (v shl 8) or n }
            return Ipv4(v)
        }
        fun mask(prefix: Int): Int { require(prefix in 0..32); return if (prefix == 0) 0 else -1 shl (32 - prefix) }
        fun prefix(mask: Int): Int {
            val n = Integer.bitCount(mask)
            require(mask == mask(n)) { "DHCP supplied a non-contiguous subnet mask" }
            return n
        }
    }
}

data class Route(val network: Ipv4, val prefix: Int, val gateway: Ipv4) {
    init { require(prefix in 0..32 && network.bits and Ipv4.mask(prefix) == network.bits) }
    fun contains(ip: Ipv4) = ip.bits and Ipv4.mask(prefix) == network.bits
}

class Ipv4RoutingEngine(val address: Ipv4, val prefix: Int, val gateway: Ipv4, routes: List<Route>) {
    private val subnet = address.bits and Ipv4.mask(prefix)
    val broadcast = Ipv4(subnet or Ipv4.mask(prefix).inv())
    private val table = (routes + Route(Ipv4(subnet), prefix, Ipv4.ZERO)).sortedByDescending { it.prefix }
    fun onLink(ip: Ipv4) = ip.bits and Ipv4.mask(prefix) == subnet
    fun nextHop(ip: Ipv4): Ipv4 {
        if (ip == Ipv4.BROADCAST || ip == broadcast || ip.isMulticast()) return ip
        val best = table.firstOrNull { it.contains(ip) }
        return if (best != null) { if (best.gateway == Ipv4.ZERO) ip else best.gateway } else gateway
    }
}

class Ipv4Packet private constructor(val bytes: ByteArray, val offset: Int, val headerLength: Int, val totalLength: Int) {
    val source get() = Ipv4(Wire.i32(bytes, offset + 12))
    val destination get() = Ipv4(Wire.i32(bytes, offset + 16))
    val protocol get() = bytes[offset + 9].toInt() and 255
    val fragmented get() = Wire.u16(bytes, offset + 6) and 0x3fff != 0
    fun copyPacket() = bytes.copyOfRange(offset, offset + totalLength)
    companion object {
        fun parse(b: ByteArray, offset: Int = 0, available: Int = b.size - offset, mtu: Int = 1500): Ipv4Packet {
            if (offset < 0 || available < 20 || offset > b.size - available) throw PacketException("Truncated IPv4 packet")
            val version = b[offset].toInt() and 255
            val ihl = (version and 15) * 4
            val len = Wire.u16(b, offset + 2)
            if (version ushr 4 != 4 || ihl !in 20..60 || len < ihl || len > available || len > mtu) throw PacketException("Invalid IPv4 length or MTU")
            if (Wire.checksum(b, offset, ihl) != 0) throw PacketException("Invalid IPv4 checksum")
            if (Wire.u16(b, offset + 6) and 0x8000 != 0) throw PacketException("Reserved IPv4 fragment flag")
            return Ipv4Packet(b, offset, ihl, len)
        }
        fun udp(source: Ipv4, dest: Ipv4, sourcePort: Int, destPort: Int, data: ByteArray): ByteArray {
            require(data.size <= 1472)
            val b = ByteArray(28 + data.size)
            b[0] = 0x45; Wire.put16(b, 2, b.size); b[8] = 64; b[9] = 17
            Wire.put32(b, 12, source.bits); Wire.put32(b, 16, dest.bits)
            Wire.put16(b, 20, sourcePort); Wire.put16(b, 22, destPort); Wire.put16(b, 24, 8 + data.size)
            data.copyInto(b, 28)
            Wire.put16(b, 26, udpChecksum(b, 20, 8 + data.size, source, dest).let { if (it == 0) 0xffff else it })
            Wire.put16(b, 10, Wire.checksum(b, 0, 20))
            return b
        }
        fun udpChecksum(b: ByteArray, offset: Int, length: Int, source: Ipv4, dest: Ipv4): Int {
            val initial = ((source.bits ushr 16).toLong() + (source.bits and 0xffff) + (dest.bits ushr 16) + (dest.bits and 0xffff) + 17 + length)
            return Wire.checksum(b, offset, length, initial)
        }
    }
    fun udpPayload(expectedSourcePort: Int? = null, expectedDestPort: Int? = null): ByteArray {
        if (protocol != 17 || fragmented || totalLength < headerLength + 8) throw PacketException("Invalid UDP packet")
        val u = offset + headerLength
        val size = Wire.u16(bytes, u + 4)
        if (size < 8 || size != totalLength - headerLength) throw PacketException("Invalid UDP length")
        if (expectedSourcePort != null && Wire.u16(bytes, u) != expectedSourcePort) throw PacketException("Unexpected UDP source port")
        if (expectedDestPort != null && Wire.u16(bytes, u + 2) != expectedDestPort) throw PacketException("Unexpected UDP destination port")
        if (Wire.u16(bytes, u + 6) != 0 && udpChecksum(bytes, u, size, source, destination) != 0) throw PacketException("Invalid UDP checksum")
        return bytes.copyOfRange(u + 8, u + size)
    }
}
