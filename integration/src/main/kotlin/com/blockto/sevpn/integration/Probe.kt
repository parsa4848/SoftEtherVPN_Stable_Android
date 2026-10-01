package com.blockto.sevpn.integration

import com.blockto.sevpn.dhcp.*
import com.blockto.sevpn.l2.*
import com.blockto.sevpn.network.*
import com.blockto.sevpn.protocol.*
import com.blockto.sevpn.security.TlsPolicy
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.*
import java.io.Closeable
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.net.ssl.SSLSocket

/** Real stock-server host probe, shares production protocol/ARP/DHCP code.
 * No kernel tunnel or Android acceptance is claimed by this host test. */
@OptIn(ExperimentalCoroutinesApi::class)
fun main(args: Array<String>) = runBlocking {
    require(args.size >= 4) { "Usage: host port hub user [sha256-pin|-] [traffic|login|no-dhcp|error:9|error:8|tls-error]" }
    val host = args[0]; val port = args[1].toInt(); val hub = args[2]; val user = args[3]
    val pin = args.getOrNull(4)?.takeUnless { it == "-" }
    val mode = args.getOrNull(5) ?: "traffic"
    val password = System.getenv("SEVPN_TEST_PASSWORD")?.toCharArray()
        ?: System.console()?.readPassword("Test server password: ") ?: error("Set SEVPN_TEST_PASSWORD or run from an interactive console; never pass passwords as arguments")
    val raw = Socket()
    val closer = launch(start = CoroutineStart.UNDISPATCHED) { try { awaitCancellation() } finally { raw.close() } }
    var session: SoftEtherSession? = null
    try {
        raw.connect(InetSocketAddress(host, port), 10_000)
        val policy = TlsPolicy(pin)
        val tls = policy.socketFactory().createSocket(raw, host, port, true) as SSLSocket
        policy.configure(tls); tls.soTimeout = 15_000
        withContext(Dispatchers.IO) { tls.startHandshake() }
        println("PASS TLS (${if (policy.isPinned) "explicit certificate pin" else "trusted CA and hostname"})")
        session = withContext(Dispatchers.IO) { SoftEtherSession.connect(SocketTransport(tls), host, hub, user, password, ByteArray(20).also { SecureRandom().nextBytes(it) }) }
        password.fill('\u0000')
        check(!mode.startsWith("error:") && mode != "tls-error") { "Expected failure but authentication succeeded" }
        println("PASS native authentication and session")
        if (mode == "login") return@runBlocking
        val activeSession = session
        coroutineScope {
            val incoming = Channel<ByteArray>(128); val outgoing = Channel<ByteArray?>(128)
            val reader = launch(Dispatchers.IO) { while (isActive) incoming.send(activeSession.channel.readFrame()) }
            val writer = launch(Dispatchers.IO) { for (f in outgoing) if (f == null) activeSession.channel.keepAlive() else activeSession.channel.sendFrame(f) }
            val keepalive = launch { while (isActive) { delay((activeSession.timeoutMs / 3).toLong()); outgoing.send(null) } }
            try {
                val mac = Mac.generate()
                val lease = try { DhcpClient(mac, { outgoing.send(it) }, incoming).acquire() }
                    catch (e: DhcpException) { if (mode == "no-dhcp") { println("PASS DHCP unavailable produces an error"); return@coroutineScope }; throw e }
                check(mode != "no-dhcp") { "Expected missing DHCP but obtained a lease" }
                println("PASS DHCP ${lease.address}/${lease.prefix}, gateway ${lease.gateway}, DNS ${lease.dns.joinToString()}")
                val ipIn = Channel<ByteArray>(64); val ipOut = Channel<ByteArray>(64)
                val endpoint = VirtualEthernetEndpoint(mac, Ipv4RoutingEngine(lease.address, lease.prefix, lease.gateway, lease.routes), 1400, { outgoing.send(it) })
                val bridge = launch {
                    endpoint.announce()
                    while (isActive) {
                        select<Unit> {
                            incoming.onReceive { endpoint.receive(it)?.let { b -> ipIn.send(b) } }
                            ipOut.onReceive { endpoint.sendIp(it) }
                            onTimeout(250) { }
                        }
                        endpoint.tick()
                    }
                }
                try {
                    val destination = dnsProbe(lease, ipOut, ipIn)
                    tcpProbe(lease.address, destination, ipOut, ipIn)
                    println("PASS forwarded bytes tx=${endpoint.transmittedBytes} rx=${endpoint.receivedBytes}")
                } finally { bridge.cancelAndJoin() }
            } finally { raw.close(); reader.cancelAndJoin(); writer.cancelAndJoin(); keepalive.cancelAndJoin() }
        }
    } catch (e: SoftEtherServerException) {
        check(mode == "error:${e.code}") { "Native server rejected connection, code ${e.code}" }
        println("PASS expected server error ${e.code}")
    } catch (e: javax.net.ssl.SSLException) {
        if (mode != "tls-error") throw e
        println("PASS expected TLS validation failure")
    } finally { password.fill('\u0000'); raw.close(); session?.close(); closer.cancelAndJoin() }
}

private suspend fun dnsProbe(lease: DhcpLease, send: Channel<ByteArray>, receive: Channel<ByteArray>): Ipv4 {
    val random = SecureRandom(); val xid = random.nextInt(65536); val port = 49152 + random.nextInt(10000)
    val q = ByteArrayOutputStream()
    q.write(ByteBuffer.allocate(12).putShort(xid.toShort()).putShort(0x0100).putShort(1).putShort(0).putShort(0).putShort(0).array())
    "example.com".split('.').forEach { q.write(it.length); q.write(it.toByteArray()) }; q.write(byteArrayOf(0, 0, 1, 0, 1))
    repeat(3) {
        send.send(Ipv4Packet.udp(lease.address, lease.dns[0], port, 53, q.toByteArray()))
        val result = withTimeoutOrNull(5000) {
            while (true) {
                val p = Ipv4Packet.parse(receive.receive(), mtu = 1400)
                if (p.source != lease.dns[0] || p.protocol != 17) continue
                val b = try { p.udpPayload(53, port) } catch (_: PacketException) { continue }
                if (b.size < 12 || Wire.u16(b, 0) != xid || Wire.u16(b, 2) and 0x800f != 0x8000) continue
                fun skipName(start: Int): Int {
                    var i = start
                    while (true) {
                        check(i < b.size) { "Truncated DNS name" }
                        val size = b[i++].toInt() and 255
                        if (size == 0) return i
                        if (size and 0xc0 == 0xc0) { check(i < b.size); return i + 1 }
                        check(size <= 63 && size <= b.size - i); i += size
                    }
                }
                check(Wire.u16(b, 4) <= 16 && Wire.u16(b, 6) <= 128)
                var i = 12
                repeat(Wire.u16(b, 4)) { i = skipName(i); check(i <= b.size - 4); i += 4 }
                var a: Ipv4? = null
                repeat(Wire.u16(b, 6)) {
                    i = skipName(i); check(i <= b.size - 10)
                    val type = Wire.u16(b, i); val klass = Wire.u16(b, i + 2); val size = Wire.u16(b, i + 8); i += 10
                    check(size <= b.size - i)
                    if (type == 1 && klass == 1 && size == 4) a = Ipv4(Wire.i32(b, i))
                    i += size
                }
                if (a != null && a!!.isUnicast()) { println("PASS IPv4 UDP DNS through native tunnel"); return@withTimeoutOrNull a }
            }
            @Suppress("UNREACHABLE_CODE") null
        }
        if (result != null) return result
    }
    error("No usable DNS reply through VPN")
}

/** Small test-only TCP peer: validates SYN/ACK and checksummed HTTP response.
 * Android production TCP is implemented by the OS, not this probe. */
private suspend fun tcpProbe(source: Ipv4, destination: Ipv4, send: Channel<ByteArray>, receive: Channel<ByteArray>) {
    val random = SecureRandom(); val port = 49152 + random.nextInt(10000)
    var sequence = random.nextInt(); var acknowledgement = 0
    fun packet(flags: Int, payload: ByteArray = byteArrayOf()): ByteArray {
        val b = ByteArray(40 + payload.size)
        b[0] = 0x45; Wire.put16(b, 2, b.size); b[8] = 64; b[9] = 6
        Wire.put32(b, 12, source.bits); Wire.put32(b, 16, destination.bits)
        Wire.put16(b, 20, port); Wire.put16(b, 22, 80); Wire.put32(b, 24, sequence); Wire.put32(b, 28, acknowledgement)
        b[32] = 0x50; b[33] = flags.toByte(); Wire.put16(b, 34, 32768); payload.copyInto(b, 40)
        val initial = (source.bits ushr 16).toLong() + (source.bits and 65535) + (destination.bits ushr 16) + (destination.bits and 65535) + 6 + b.size - 20
        Wire.put16(b, 36, Wire.checksum(b, 20, b.size - 20, initial)); Wire.put16(b, 10, Wire.checksum(b, 0, 20)); return b
    }
    suspend fun next(): Pair<Ipv4Packet, Int> {
        while (true) {
            val p = Ipv4Packet.parse(receive.receive(), mtu = 1400); val b = p.bytes; val t = p.headerLength
            if (p.source != destination || p.protocol != 6 || p.fragmented || p.totalLength < t + 20) continue
            if (Wire.u16(b, t) != 80 || Wire.u16(b, t + 2) != port) continue
            val h = (b[t + 12].toInt() ushr 4 and 15) * 4
            check(h >= 20 && t + h <= p.totalLength)
            val initial = (source.bits ushr 16).toLong() + (source.bits and 65535) + (destination.bits ushr 16) + (destination.bits and 65535) + 6 + p.totalLength - t
            check(Wire.checksum(b, t, p.totalLength - t, initial) == 0) { "TCP checksum failure" }
            return p to h
        }
    }
    withTimeout(20_000) {
        send.send(packet(2))
        while (true) {
            val (p, _) = next(); val t = p.headerLength; val b = p.bytes
            check(b[t + 13].toInt() and 4 == 0) { "TCP connection reset" }
            if (b[t + 13].toInt() and 18 == 18 && Wire.i32(b, t + 8) == sequence + 1) { acknowledgement = Wire.i32(b, t + 4) + 1; sequence++; break }
        }
        send.send(packet(16))
        val request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".toByteArray()
        send.send(packet(24, request)); sequence += request.size
        val response = ByteArrayOutputStream()
        while (response.size() < 4096) {
            val (p, h) = next(); val b = p.bytes; val t = p.headerLength
            check(b[t + 13].toInt() and 4 == 0) { "TCP connection reset" }
            val n = p.totalLength - t - h
            if (Wire.i32(b, t + 4) == acknowledgement && n > 0) { response.write(b, t + h, n); acknowledgement += n }
            if (b[t + 13].toInt() and 1 != 0) acknowledgement++
            send.send(packet(16))
            if (String(response.toByteArray(), Charsets.US_ASCII).startsWith("HTTP/1.")) {
                send.send(packet(20)); println("PASS IPv4 TCP HTTP response through native tunnel"); return@withTimeout
            }
            check(b[t + 13].toInt() and 1 == 0) { "TCP ended without HTTP response" }
        }
        error("Unexpected HTTP response")
    }
}
