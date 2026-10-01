package com.blockto.sevpn.l2

import com.blockto.sevpn.network.*

/** Actor-owned. Call receive/sendIp/tick from the same packet coroutine. */
class VirtualEthernetEndpoint(
    val mac: Mac, val routing: Ipv4RoutingEngine, private val mtu: Int,
    private val send: suspend (ByteArray) -> Unit,
    private val now: () -> Long = { System.nanoTime() / 1_000_000 }
) {
    val arp = ArpCache(now)
    private data class Pending(val packets: ArrayDeque<ByteArray>, val since: Long, var last: Long, var tries: Int)
    private val pending = LinkedHashMap<Ipv4, Pending>()
    private var pendingPackets = 0
    var transmittedBytes = 0L; private set
    var receivedBytes = 0L; private set
    var droppedPackets = 0L; private set

    suspend fun sendIp(bytes: ByteArray) {
        val p = try { Ipv4Packet.parse(bytes, mtu = mtu) } catch (_: PacketException) { droppedPackets++; return }
        if (p.source != routing.address || p.destination == Ipv4.ZERO || p.destination == routing.address) { droppedPackets++; return }
        val hop = routing.nextHop(p.destination)
        val target = when {
            p.destination == routing.broadcast || p.destination == Ipv4.BROADCAST -> Mac.BROADCAST
            p.destination.isMulticast() -> Mac.multicast(p.destination)
            else -> arp.get(hop)
        }
        if (target != null) { emit(target, bytes, p.totalLength); return }
        if (!hop.isUnicast() || !routing.onLink(hop)) { droppedPackets++; return }
        val waiting = pending[hop]
        if (pendingPackets >= 128 || (waiting?.packets?.size ?: 0) >= 8 || (waiting == null && pending.size >= 64)) { droppedPackets++; return }
        val q = waiting ?: Pending(ArrayDeque(), now(), now(), 1).also {
            pending[hop] = it
            send(ArpPacket.frame(1, mac, routing.address, Mac.ZERO, hop))
        }
        q.packets.addLast(if (bytes.size == p.totalLength) bytes else p.copyPacket()); pendingPackets++
    }
    private suspend fun emit(target: Mac, ip: ByteArray, size: Int) {
        send(EthernetFrame.write(target, mac, EthernetFrame.IPV4, ip, size = size)); transmittedBytes += size
    }
    suspend fun receive(bytes: ByteArray): ByteArray? {
        val frame = try { EthernetFrame.parse(bytes) } catch (_: PacketException) { droppedPackets++; return null }
        if (frame.destination != mac && frame.destination != Mac.BROADCAST) return null
        if (!frame.source.isUnicast() || frame.source == mac) return null
        when (frame.type) {
            EthernetFrame.ARP -> {
                val a = try { ArpPacket.parse(bytes) } catch (_: PacketException) { droppedPackets++; return null }
                if (a.senderMac != frame.source || a.targetIp != routing.address) return null
                if (a.operation == 2 && (a.targetMac != mac || frame.destination != mac)) return null
                if (a.senderIp == routing.address) throw java.io.IOException("VPN IPv4 address conflict detected")
                if (a.senderIp.isUnicast() && routing.onLink(a.senderIp) && a.senderIp != routing.broadcast) {
                    // Only replies for outstanding requests or requests addressed to us update cache.
                    if (a.operation == 1 || pending.containsKey(a.senderIp)) arp.put(a.senderIp, a.senderMac)
                    val q = pending.remove(a.senderIp)
                    if (q != null) {
                        pendingPackets -= q.packets.size
                        for (p in q.packets) emit(a.senderMac, p, p.size)
                    }
                }
                if (a.operation == 1) send(ArpPacket.frame(2, mac, routing.address, a.senderMac, a.senderIp))
            }
            EthernetFrame.IPV4 -> {
                val p = try { Ipv4Packet.parse(bytes, 14, bytes.size - 14, mtu) } catch (_: PacketException) { droppedPackets++; return null }
                if (p.destination != routing.address || !p.source.isUnicast()) return null
                receivedBytes += p.totalLength
                return p.copyPacket()
            }
        }
        return null
    }
    suspend fun announce() { send(ArpPacket.frame(1, mac, routing.address, Mac.ZERO, routing.address)) }
    suspend fun tick() {
        val time = now()
        val i = pending.iterator()
        while (i.hasNext()) {
            val (ip, p) = i.next()
            if (time - p.since >= 5000) { pendingPackets -= p.packets.size; droppedPackets += p.packets.size; i.remove() }
            else if (time - p.last >= 1000 && p.tries < 3) { p.tries++; p.last = time; send(ArpPacket.frame(1, mac, routing.address, Mac.ZERO, ip)) }
        }
    }
}
