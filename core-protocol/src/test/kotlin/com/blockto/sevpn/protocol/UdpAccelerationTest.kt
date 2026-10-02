package com.blockto.sevpn.protocol

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import org.junit.Assert.*
import org.junit.Test
import java.net.*
import java.util.Properties
import java.util.concurrent.atomic.AtomicLong

class UdpAccelerationTest {
    private val endpoint = InetSocketAddress(InetAddress.getLoopbackAddress(), 40000)
    private fun config(version: Int) = UdpAccelerationConfig(version, endpoint, endpoint.address,
        ByteArray(if (version == 2) 128 else 20) { it.toByte() }, ByteArray(if (version == 2) 128 else 20) { it.toByte() },
        0x01020304, 0x01020304, true)
    private fun fixture(key: String): ByteArray {
        val p = Properties().apply { UdpAccelerationTest::class.java.getResourceAsStream("/transport-vectors.properties")!!.use { load(it) } }
        val hex = p.getProperty(key); return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    @Test fun v2AndV1MatchExecutedUpstreamCPackets() {
        for (version in 1..2) config(version).use { c -> UdpAccelerationCodec(c).use { codec ->
            val payload = ByteArray(60) { (it + 7).toByte() }
            val packet = codec.encode(payload, 100000, 90000, ByteArray(if (version == 2) 12 else 20) { (it + 32).toByte() }, 0)
            assertArrayEquals(fixture("udp_v$version"), packet)
            val decoded = codec.decode(fixture("udp_v$version"))!!
            assertEquals(100000, decoded.tick); assertEquals(90000, decoded.echoedTick); assertArrayEquals(payload, decoded.payload)
        } }
    }
    @Test fun corruptedTruncatedOversizedAndWrongCookiePacketsAreRejected() {
        config(2).use { c -> UdpAccelerationCodec(c).use { codec ->
            val packet = fixture("udp_v2")
            for (i in packet.indices) assertNull(codec.decode(packet.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }))
            for (i in 0 until packet.size) assertNull(codec.decode(packet.copyOf(i)))
            assertNull(codec.decode(ByteArray(2049)))
            UdpAccelerationConfig(2, endpoint, endpoint.address, c.sendKey.copyOf(), c.receiveKey.copyOf(), 5, 5, true).use {
                UdpAccelerationCodec(it).use { wrong -> assertNull(wrong.decode(packet)) }
            }
        } }
    }
    @Test fun keepaliveReadinessEndpointMigrationRealUdpTrafficAndLossFallback() = runBlocking {
        val local = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
        val peer = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 50 }
        val time = AtomicLong(100000); val inbound = Channel<ByteArray>(8)
        val clientConfig = UdpAccelerationConfig(2, peer.localSocketAddress as InetSocketAddress, peer.localAddress, ByteArray(128) { it.toByte() }, ByteArray(128) { it.toByte() }, 1, 2, true)
        val serverConfig = UdpAccelerationConfig(2, local.localSocketAddress as InetSocketAddress, local.localAddress, ByteArray(128) { it.toByte() }, ByteArray(128) { it.toByte() }, 2, 1, true)
        val serverCodec = UdpAccelerationCodec(serverConfig)
        val engine = UdpAccelerationEngine(local, clientConfig, this, inbound, { fail("Unexpected TCP fallback while UDP is usable") }, now = { time.get() })
        val clock = launch { while (isActive) { delay(10); time.addAndGet(200) } }
        fun echo(socket: DatagramSocket, codec: UdpAccelerationCodec, tickOffset: Long) = launch(Dispatchers.IO) {
            val buffer = ByteArray(2048)
            try { while (isActive) {
                val p = DatagramPacket(buffer, buffer.size)
                try { socket.receive(p) } catch (_: SocketTimeoutException) { continue }
                val decoded = codec.decode(buffer.copyOf(p.length)) ?: continue
                val response = codec.encode(decoded.payload, time.get() + tickOffset, decoded.tick)
                socket.send(DatagramPacket(response, response.size, p.socketAddress))
            } } catch (e: SocketException) { if (!socket.isClosed) throw e }
        }
        val echo = echo(peer, serverCodec, 100000)
        val migrated = DatagramSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), 0)).apply { soTimeout = 50 }
        val migratedCodec = UdpAccelerationCodec(serverConfig)
        var migratedJob: Job? = null
        try {
            engine.start(); assertFalse(engine.active)
            val frame = ByteArray(60) { (it + 7).toByte() }
            withTimeout(4000) { while (!engine.trySend(frame)) delay(10) }
            assertArrayEquals(frame, withTimeout(2000) { inbound.receive() })
            withTimeout(1000) { while (!engine.active) delay(10) }
            val movedFrame = ByteArray(60) { (it + 19).toByte() }
            val update = migratedCodec.encode(movedFrame, time.get() + 200000, time.get())
            migrated.send(DatagramPacket(update, update.size, local.localSocketAddress))
            assertArrayEquals(movedFrame, withTimeout(2000) { inbound.receive() })
            migratedJob = echo(migrated, migratedCodec, 200000)
            withTimeout(2000) { while (!engine.trySend(frame)) delay(10) }
            assertArrayEquals(frame, withTimeout(2000) { inbound.receive() })
            peer.close(); migrated.close(); echo.cancelAndJoin(); migratedJob.cancelAndJoin(); clock.cancelAndJoin(); time.addAndGet(10_000)
            delay(100); assertFalse(engine.active); assertFalse(engine.trySend(frame))
        } finally { engine.close(); peer.close(); migrated.close(); echo.cancelAndJoin(); migratedJob?.cancelAndJoin(); clock.cancelAndJoin(); migratedCodec.close(); serverCodec.close(); clientConfig.close(); serverConfig.close() }
        assertTrue(local.isClosed)
    }
}
