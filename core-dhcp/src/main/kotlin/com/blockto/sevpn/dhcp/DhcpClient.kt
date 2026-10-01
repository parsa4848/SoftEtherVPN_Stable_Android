package com.blockto.sevpn.dhcp

import com.blockto.sevpn.l2.Mac
import com.blockto.sevpn.network.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import java.io.IOException
import java.security.SecureRandom

class DhcpException(message: String) : IOException(message)

class DhcpClient(private val mac: Mac, private val send: suspend (ByteArray) -> Unit,
                 private val incoming: ReceiveChannel<ByteArray>, private val dnsOverride: List<Ipv4> = emptyList(),
                 private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    private val random = SecureRandom()
    suspend fun acquire(): DhcpLease {
        repeat(3) {
            val xid = random.nextInt()
            val offer = exchange(xid, DhcpCodec.request(mac, xid, 1), 2) ?: return@repeat
            val server = try { DhcpCodec.server(offer) } catch (_: PacketException) { return@repeat }
            if (!offer.address.isUnicast()) return@repeat
            val ack = exchange(xid, DhcpCodec.request(mac, xid, 3, offer.address, server), 5, server) ?: return@repeat
            if (ack.address != offer.address) throw DhcpException("DHCP ACK address differs from selected offer")
            return try { DhcpCodec.lease(ack, now(), dnsOverride) } catch (e: PacketException) { throw DhcpException(e.message ?: "Invalid DHCP configuration") }
        }
        throw DhcpException("DHCP unavailable on this Virtual Hub (DISCOVER/REQUEST timed out)")
    }
    suspend fun renew(lease: DhcpLease): DhcpLease? {
        val xid = random.nextInt()
        // Broadcast ciaddr REQUEST supports rebinding without depending on gateway ARP.
        val ack = exchange(xid, DhcpCodec.request(mac, xid, 3, current = lease.address), 5) ?: return null
        return try { DhcpCodec.lease(ack, now(), dnsOverride, lease) } catch (e: PacketException) { throw DhcpException(e.message ?: "Invalid DHCP renewal") }
    }
    private suspend fun exchange(xid: Int, frame: ByteArray, expected: Int, selectedServer: Ipv4? = null): DhcpReply? {
        for (wait in listOf(1000L, 2000L, 4000L)) {
            send(frame)
            val reply = withTimeoutOrNull(wait + random.nextInt(200)) {
                var result: DhcpReply? = null
                while (result == null) {
                    currentCoroutineContext().ensureActive()
                    val bytes = incoming.receive()
                    val p = try { DhcpCodec.parse(bytes, mac, xid) } catch (_: PacketException) { null } ?: continue
                    if (selectedServer != null && runCatching { DhcpCodec.server(p) }.getOrNull() != selectedServer) continue
                    if (p.type == 6) throw DhcpException("DHCP server rejected the requested address")
                    if (p.type == expected) result = p
                }
                result
            }
            if (reply != null) return reply
        }
        return null
    }
}
