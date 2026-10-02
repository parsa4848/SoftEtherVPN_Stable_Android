package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.Closeable
import java.io.IOException
import java.net.*
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Socket polling and keepalive belong to the session. A full/failed UDP
 * queue immediately uses the reliable pool; loss of acceleration is optional. */
class UdpAccelerationEngine(private val socket: DatagramSocket, private val config: UdpAccelerationConfig,
    private val scope: CoroutineScope, private val inbound: Channel<ByteArray>,
    private val fallback: suspend (ByteArray) -> Unit,
    private val resolveNat: (suspend (String) -> InetAddress?)? = null,
    private val now: () -> Long = { System.nanoTime() / 1_000_000 }) : Closeable {
    private val codec = UdpAccelerationCodec(config)
    private val outgoing = Channel<ByteArray>(128)
    private val random = SecureRandom()
    private var job: Job? = null; private var natJob: Job? = null
    private val nat = AtomicReference<InetAddress?>()
    private var endpoint = config.endpoint
    private var peerTick = 0L; private var echoedTick = 0L; private var endpointTick = 0L
    private var stableSince = 0L; private var lastGood = 0L
    @Volatile private var ready = false
    @Volatile private var stopped = false
    @Volatile private var peerMappedPort = 0
    @Volatile private var myMappedPort = 0
    val bytesSent = AtomicLong(); val bytesReceived = AtomicLong()
    val active get() = ready && !stopped && bytesSent.get() > 0 && bytesReceived.get() > 0
    fun trySend(frame: ByteArray) = ready && !stopped && outgoing.trySend(frame).isSuccess
    fun keepAliveBody(): ByteArray = myMappedPort.takeIf { it != 0 }?.let {
        "NATT_MY_PORT".toByteArray(Charsets.US_ASCII) + ByteBuffer.allocate(2).putShort(it.toShort()).array()
    } ?: byteArrayOf()
    fun receiveKeepAlive(body: ByteArray) {
        val prefix = "NATT_MY_PORT".toByteArray(Charsets.US_ASCII)
        if (body.size >= prefix.size + 2 && prefix.indices.all { body[it] == prefix[it] }) {
            val port = ByteBuffer.wrap(body, prefix.size, 2).short.toInt() and 65535
            if (port != 0) peerMappedPort = port
        }
    }
    fun start() {
        check(job == null)
        if (resolveNat != null && socket.localAddress.address.size == 4) natJob = scope.launch(Dispatchers.IO) {
            // Same NAT-T hostname algorithm as RUDPGetRegisterHostNameByIP.
            val hash = sha1(byteArrayOf(11, random.nextInt(256).toByte(), random.nextInt(256).toByte(), random.nextInt(256).toByte()))
            val hex = hash.take(2).joinToString("") { "%02x".format(it.toInt() and 255) }
            var wait = 5000L
            while (isActive && !stopped && nat.get() == null) {
                try { nat.set(resolveNat("x${hex[2]}.x${hex[3]}.servers.nat-traversal.softether-network.net.")) }
                catch (e: CancellationException) { throw e } catch (_: IOException) {}
                if (nat.get() == null) { delay(wait); wait = minOf(150_000, wait + 5000) }
            }
        }
        job = scope.launch(Dispatchers.IO) {
            var nextKeepalive = 0L; var nextNat = 0L; var natFailures = 0
            val buffer = ByteArray(2049); val incoming = DatagramPacket(buffer, buffer.size)
            socket.soTimeout = 20
            try {
                while (isActive && !stopped) {
                    val time = now()
                    val timeout = if (config.fastDetect) 2100 else 9000
                    if (lastGood == 0L || time - lastGood > timeout) { stableSince = 0; ready = false }
                    else ready = stableSince != 0L && time - stableSince >= 10_000
                    if (time >= nextKeepalive) {
                        send(byteArrayOf(), time, probe = true)
                        nextKeepalive = time + if (config.fastDetect) 500 + random.nextInt(500) else 1000 + random.nextInt(2000)
                    }
                    val natAddress = nat.get()
                    if (!ready && natAddress != null && time >= nextNat) {
                        // Discovery is optional; failure must not disable a usable peer path.
                        try { socket.send(DatagramPacket(byteArrayOf(66), 1, natAddress, 5004)) } catch (_: IOException) {}
                        natFailures++
                        nextNat = time + if (myMappedPort == 0) 3000L * minOf(natFailures, 60) else 300_000L + random.nextInt(300_000)
                    }
                    repeat(64) {
                        val frame = outgoing.tryReceive().getOrNull() ?: return@repeat
                        if (ready) {
                            try { send(frame, time); bytesSent.addAndGet(frame.size.toLong()) }
                            catch (e: IOException) { ready = false; fallback(frame); throw e }
                            catch (e: java.security.GeneralSecurityException) { ready = false; fallback(frame); throw e }
                        }
                        else fallback(frame)
                    }
                    incoming.length = buffer.size
                    try { socket.receive(incoming) } catch (_: SocketTimeoutException) { continue }
                    if (incoming.length > 2048) continue
                    if (natAddress != null && incoming.address == natAddress && incoming.port == 5004) {
                        val mapping = String(buffer, 0, incoming.length, Charsets.US_ASCII)
                        val port = Regex("^IP=[0-9.]+,PORT=(\\d+)(?:#.*)?$").matchEntire(mapping)?.groupValues?.get(1)?.toIntOrNull()
                        if (port != null && port in 1..65535) { myMappedPort = port; natFailures = 0 }
                        continue
                    }
                    val packet = codec.decode(buffer.copyOf(incoming.length)) ?: continue
                    if (packet.echoedTick > now() || peerTick - packet.tick >= 30_000) continue
                    peerTick = maxOf(peerTick, packet.tick); echoedTick = maxOf(echoedTick, packet.echoedTick)
                    if (packet.tick > endpointTick) { endpointTick = packet.tick; endpoint = InetSocketAddress(incoming.address, incoming.port) }
                    if (echoedTick != 0L && now() - echoedTick <= 30_000) {
                        lastGood = now(); if (stableSince == 0L) stableSince = lastGood
                    }
                    if (packet.payload.isNotEmpty() && inbound.trySend(packet.payload).isSuccess) bytesReceived.addAndGet(packet.payload.size.toLong())
                }
            } catch (e: CancellationException) { throw e }
            catch (_: IOException) { /* UDP failure never cancels a working TCP session. */ }
            catch (_: java.security.GeneralSecurityException) { /* Provider failure also falls back. */ }
            finally {
                ready = false; stopped = true; outgoing.close(); socket.close(); codec.close(); natJob?.cancel()
                while (true) { val frame = outgoing.tryReceive().getOrNull() ?: break; if (isActive) fallback(frame) }
            }
        }
    }
    private fun send(frame: ByteArray, tick: Long, probe: Boolean = false) {
        val bytes = codec.encode(frame, maxOf(1, tick), peerTick)
        socket.send(DatagramPacket(bytes, bytes.size, endpoint))
        if (probe && !ready) {
            if (peerMappedPort != 0 && peerMappedPort != endpoint.port) socket.send(DatagramPacket(bytes, bytes.size, endpoint.address, peerMappedPort))
            if (config.alternateAddress != endpoint.address) {
                socket.send(DatagramPacket(bytes, bytes.size, config.alternateAddress, endpoint.port))
                if (peerMappedPort != 0 && peerMappedPort != endpoint.port) socket.send(DatagramPacket(bytes, bytes.size, config.alternateAddress, peerMappedPort))
            }
        }
    }
    override fun close() { stopped = true; ready = false; socket.close(); job?.cancel(); natJob?.cancel(); outgoing.cancel() }
}
