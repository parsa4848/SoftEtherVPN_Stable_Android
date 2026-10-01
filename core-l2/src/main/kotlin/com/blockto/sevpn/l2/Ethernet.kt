package com.blockto.sevpn.l2

import com.blockto.sevpn.network.*
import java.security.SecureRandom

@JvmInline value class Mac(val bits: Long) {
    init { require(bits in 0..0xffffffffffffL) }
    fun bytes() = ByteArray(6).also { write(it, 0) }
    fun write(b: ByteArray, offset: Int) { for (i in 0..5) b[offset + i] = (bits ushr (40 - 8 * i)).toByte() }
    fun isUnicast() = bits != 0L && bits ushr 40 and 1L == 0L
    override fun toString() = bytes().joinToString(":") { "%02x".format(it) }
    companion object {
        val BROADCAST = Mac(0xffffffffffffL)
        val ZERO = Mac(0)
        fun read(b: ByteArray, offset: Int): Mac {
            var v = 0L
            for (i in 0..5) v = (v shl 8) or (b[offset + i].toLong() and 255)
            return Mac(v)
        }
        fun generate(): Mac = ByteArray(6).also { SecureRandom().nextBytes(it); it[0] = ((it[0].toInt() or 2) and 254).toByte() }.let { read(it, 0) }
        fun multicast(ip: Ipv4) = Mac(0x01005e000000L or (ip.bits.toLong() and 0x7fffff))
    }
}

class EthernetFrame private constructor(val bytes: ByteArray, val destination: Mac, val source: Mac, val type: Int) {
    companion object {
        const val IPV4 = 0x0800; const val ARP = 0x0806
        fun parse(b: ByteArray): EthernetFrame {
            if (b.size !in 14..1600) throw PacketException("Invalid Ethernet frame length")
            return EthernetFrame(b, Mac.read(b, 0), Mac.read(b, 6), Wire.u16(b, 12))
        }
        fun write(destination: Mac, source: Mac, type: Int, payload: ByteArray, offset: Int = 0, size: Int = payload.size - offset): ByteArray {
            require(size in 0..1500 && offset >= 0 && offset <= payload.size - size)
            return ByteArray(maxOf(60, 14 + size)).also {
                destination.write(it, 0); source.write(it, 6); Wire.put16(it, 12, type); payload.copyInto(it, 14, offset, offset + size)
            }
        }
    }
}

data class ArpPacket(val operation: Int, val senderMac: Mac, val senderIp: Ipv4, val targetMac: Mac, val targetIp: Ipv4) {
    companion object {
        fun parse(b: ByteArray, offset: Int = 14): ArpPacket {
            if (offset < 0 || b.size - offset < 28) throw PacketException("Truncated ARP")
            if (Wire.u16(b, offset) != 1 || Wire.u16(b, offset + 2) != EthernetFrame.IPV4 || b[offset + 4] != 6.toByte() || b[offset + 5] != 4.toByte()) throw PacketException("Unsupported ARP type")
            val op = Wire.u16(b, offset + 6)
            if (op !in 1..2) throw PacketException("Invalid ARP operation")
            return ArpPacket(op, Mac.read(b, offset + 8), Ipv4(Wire.i32(b, offset + 14)), Mac.read(b, offset + 18), Ipv4(Wire.i32(b, offset + 24)))
        }
        fun frame(op: Int, ourMac: Mac, ourIp: Ipv4, targetMac: Mac, targetIp: Ipv4): ByteArray {
            require(op in 1..2)
            val b = ByteArray(28)
            Wire.put16(b, 0, 1); Wire.put16(b, 2, EthernetFrame.IPV4); b[4] = 6; b[5] = 4; Wire.put16(b, 6, op)
            ourMac.write(b, 8); Wire.put32(b, 14, ourIp.bits); targetMac.write(b, 18); Wire.put32(b, 24, targetIp.bits)
            return EthernetFrame.write(if (op == 1) Mac.BROADCAST else targetMac, ourMac, EthernetFrame.ARP, b)
        }
    }
}

class ArpCache(private val now: () -> Long = { System.nanoTime() / 1_000_000 }, private val maxEntries: Int = 256, private val lifetime: Long = 180_000) {
    private data class Entry(val mac: Mac, val until: Long)
    private val entries = LinkedHashMap<Ipv4, Entry>()
    fun put(ip: Ipv4, mac: Mac) {
        if (!ip.isUnicast() || !mac.isUnicast()) return
        if (entries.size >= maxEntries && ip !in entries) entries.remove(entries.keys.first())
        entries[ip] = Entry(mac, now() + lifetime)
    }
    fun get(ip: Ipv4): Mac? {
        val e = entries[ip] ?: return null
        if (now() >= e.until) { entries.remove(ip); return null }
        return e.mac
    }
    fun clear() = entries.clear()
}
