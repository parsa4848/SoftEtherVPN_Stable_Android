package com.blockto.sevpn.integration

import com.blockto.sevpn.dhcp.*
import com.blockto.sevpn.l2.*
import com.blockto.sevpn.network.*
import com.blockto.sevpn.protocol.*
import com.blockto.sevpn.security.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.*
import java.io.Closeable
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.net.ssl.SSLSocket

/** Real stock-server host probe, shares production protocol/ARP/DHCP code.
 * No kernel tunnel or Android acceptance is claimed by this host test. */
@OptIn(ExperimentalCoroutinesApi::class)
fun main(args: Array<String>) = runBlocking {
    require(args.size >= 4) { "Usage: host port hub user [sha256-pin|-] [scenario] [connections:1..32] [TCP|AUTO|RUDP_DNS_53] [udp-on|udp-off] [hold-seconds]" }
    val host = args[0]; val port = args[1].toInt(); val hub = args[2]; val user = args[3]
    val pin = args.getOrNull(4)?.takeUnless { it == "-" }
    val mode = args.getOrNull(5) ?: "traffic"
    val count = args.getOrNull(6)?.toInt() ?: 1
    val transportMode = args.getOrNull(7)?.let { TransportMode.valueOf(it) } ?: TransportMode.TCP
    val udpEnabled = args.getOrNull(8) in listOf("udp-on", "udp-v1")
    val udpVersion = if (args.getOrNull(8) == "udp-v1") 1 else 2
    val holdSeconds = args.getOrNull(9)?.toLong() ?: 0
    require(count in 1..32 && holdSeconds in 0..300)
    val password = System.getenv("SEVPN_TEST_PASSWORD")?.toCharArray()
        ?: System.console()?.readPassword("Test server password: ") ?: error("Set SEVPN_TEST_PASSWORD or run from an interactive console; never pass passwords as arguments")
    val resources = ProbeResources()
    val closer = launch(start = CoroutineStart.UNDISPATCHED) { try { awaitCancellation() } finally { resources.close() } }
    var session: SoftEtherSession? = null
    try {
        val policy = TlsPolicy(pin)
        suspend fun tcp(): SoftEtherTransport = withContext(Dispatchers.IO) {
            val raw = resources.own(Socket()); raw.connect(InetSocketAddress(host, port), 10_000)
            val tls = resources.own(policy.socketFactory().createSocket(raw, host, port, true) as SSLSocket)
            policy.configure(tls); tls.soTimeout = 15_000; tls.startHandshake()
            resources.own(SocketTransport(tls))
        }
        var rudp: RudpDnsTransport? = null
        val transport = if (transportMode == TransportMode.RUDP_DNS_53) {
            val address = withContext(Dispatchers.IO) { InetAddress.getAllByName(host).first { it is Inet4Address } }
            val socket = resources.own(DatagramSocket(InetSocketAddress("0.0.0.0", 0)))
            val reliable = resources.own(RudpDnsTransport(socket, InetSocketAddress(address, 53), this)); rudp = reliable
            reliable.establish()
            val stream = resources.own(StreamTlsTransport(reliable, policy.engine(host, port)))
            withContext(Dispatchers.IO) { stream.handshake() }; stream
        } else tcp()
        println("PASS TLS (${if (policy.isPinned) "explicit certificate pin" else "trusted CA and hostname"})")
        val udpSocket = if (udpEnabled && transport.type == TransportType.TCP)
            resources.own(DatagramSocket(InetSocketAddress(transport.localAddress!!.address, 0))) else null
        val offer = udpSocket?.let { resources.own(UdpAccelerationOffer(it.localSocketAddress as InetSocketAddress, udpVersion)) }
        session = withContext(Dispatchers.IO) { SoftEtherSession.connect(transport, host, hub, user, password,
            ByteArray(20).also { SecureRandom().nextBytes(it) }, SessionOptions(count, offer)) }
        offer?.close()
        if (session.udpAcceleration == null) udpSocket?.close()
        password.fill('\u0000')
        check(!mode.startsWith("error:") && mode !in listOf("tls-error", "rudp-failure")) { "Expected failure but authentication succeeded" }
        println("PASS native authentication and session")
        val activeSession = session
        coroutineScope {
            var acceleration: UdpAccelerationEngine? = null
            val secondary = java.util.Collections.synchronizedList(mutableListOf<SoftEtherTransport>())
            val factory: (suspend () -> AdditionalConnection)? = if (transport.type == TransportType.TCP) ({
                val next = tcp(); secondary += next
                withContext(Dispatchers.IO) { activeSession.attachAdditional(next, host) }
            }) else null
            val pool = resources.own(SoftEtherConnectionPool(activeSession, this, factory,
                keepAliveBody = { acceleration?.keepAliveBody() ?: byteArrayOf() },
                receivedKeepAlive = { acceleration?.receiveKeepAlive(it) }))
            pool.start()
            val incoming = pool.inbound
            val accelerationConfig = activeSession.udpAcceleration
            if (udpSocket != null && accelerationConfig != null) {
                acceleration = resources.own(UdpAccelerationEngine(udpSocket, accelerationConfig, this, incoming,
                    { pool.sendFrame(it) }, { name -> InetAddress.getAllByName(name).firstOrNull { it is Inet4Address } }))
                acceleration.start()
            }
            val send: suspend (ByteArray) -> Unit = { if (acceleration?.trySend(it) != true) pool.sendFrame(it) }
            try {
                withTimeout(60_000) { while (pool.activeCount < activeSession.negotiatedMaxConnections) delay(100) }
                println("PASS transport=${transport.type} requested=$count negotiated=${activeSession.negotiatedMaxConnections} active_tcp=${pool.activeTcpConnections} session=${activeSession.sessionName}")
                if (mode == "udp-unavailable") {
                    check(accelerationConfig == null) { "Server unexpectedly accepted acceleration" }
                    println("PASS server declined acceleration; TCP remained available")
                }
                if (mode == "login") { delay(holdSeconds * 1000); return@coroutineScope }
                val mac = Mac.generate()
                val lease = try { DhcpClient(mac, send, incoming).acquire() }
                    catch (e: DhcpException) { if (mode == "no-dhcp") { println("PASS DHCP unavailable produces an error"); return@coroutineScope }; throw e }
                check(mode != "no-dhcp") { "Expected missing DHCP but obtained a lease" }
                println("PASS DHCP ${lease.address}/${lease.prefix}, gateway ${lease.gateway}, DNS ${lease.dns.joinToString()}")
                val ipIn = Channel<ByteArray>(64); val ipOut = Channel<ByteArray>(64)
                val endpoint = VirtualEthernetEndpoint(mac, Ipv4RoutingEngine(lease.address, lease.prefix, lease.gateway, lease.routes), 1400, send)
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
                    if (udpEnabled && mode != "udp-unavailable" && transport.type == TransportType.TCP) {
                        check(accelerationConfig?.version == udpVersion) { "Stock server did not negotiate requested UDP acceleration version" }
                        delay(12_000) // Upstream requires 10 seconds of stable authenticated echoes.
                    }
                    val destination = dnsProbe(lease, ipOut, ipIn)
                    tcpProbe(lease.address, destination, ipOut, ipIn)
                    println("PASS forwarded bytes tx=${endpoint.transmittedBytes} rx=${endpoint.receivedBytes}")
                    if (udpEnabled && mode != "udp-unavailable" && transport.type == TransportType.TCP) {
                        check(acceleration?.active == true) { "UDP negotiated but actual bidirectional payload flow was not observed" }
                        println("PASS UDP acceleration v$udpVersion payload tx=${acceleration.bytesSent.get()} rx=${acceleration.bytesReceived.get()}")
                    }
                    if (mode == "udp-drop") {
                        check(udpSocket != null); udpSocket.close(); delay(250)
                        tcpProbe(lease.address, dnsProbe(lease, ipOut, ipIn), ipOut, ipIn)
                        check(acceleration?.active != true); println("PASS UDP loss retained the same session over TCP")
                    }
                    if (mode == "secondary-loss") {
                        check(pool.activeCount > 1); val before = secondary.size; secondary[0].close()
                        tcpProbe(lease.address, dnsProbe(lease, ipOut, ipIn), ipOut, ipIn)
                        withTimeout(60_000) { while (secondary.size == before || pool.activeCount != activeSession.negotiatedMaxConnections) delay(100) }
                        println("PASS secondary loss and restoration retained the same session")
                    }
                    if (rudp != null) {
                        check(pool.activeTcpConnections == 0 && rudp.packetsSent.get() > 0 && rudp.packetsReceived.get() > 0)
                        println("PASS direct UDP destination 53; no TCP underlay; tx=${rudp.packetsSent.get()} rx=${rudp.packetsReceived.get()} retransmissions=${rudp.retransmissions.get()}")
                    }
                    delay(holdSeconds * 1000)
                } finally { bridge.cancelAndJoin() }
            } finally { acceleration?.close(); pool.close() }
        }
    } catch (e: SoftEtherServerException) {
        check(mode == "error:${e.code}") { "Native server rejected connection, code ${e.code}" }
        println("PASS expected server error ${e.code}")
    } catch (e: javax.net.ssl.SSLException) {
        if (mode != "tls-error") throw e
        println("PASS expected TLS validation failure")
    } catch (e: RudpException) {
        if (mode != "rudp-failure" || transportMode != TransportMode.RUDP_DNS_53) throw e
        println("PASS explicit UDP53 failed with ${e.failure}; TCP fallback was not attempted")
    } finally { password.fill('\u0000'); resources.close(); session?.close(); closer.cancelAndJoin() }
}

private class ProbeResources : Closeable {
    private val values = mutableListOf<Closeable>(); private var closed = false
    fun <T : Closeable> own(value: T): T {
        val accepted = synchronized(this) { if (closed) false else { values += value; true } }
        if (!accepted) { value.close(); throw java.io.IOException("Probe cancelled") }; return value
    }
    override fun close() {
        val snapshot = synchronized(this) { if (closed) return; closed = true; values.toList().also { values.clear() } }
        snapshot.forEach { runCatching { it.close() } }
    }
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
