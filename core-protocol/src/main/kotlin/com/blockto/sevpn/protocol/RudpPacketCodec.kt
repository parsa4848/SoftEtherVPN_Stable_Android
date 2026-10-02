/* Client segment format from pinned Mayaqua/Network.c, Apache-2.0.
 * Copyright (c) SoftEther VPN Project. See THIRD_PARTY_NOTICES.md. */
package com.blockto.sevpn.protocol

import java.io.Closeable
import java.nio.ByteBuffer
import java.security.MessageDigest

class RudpKeys(initialKey: ByteArray) : Closeable {
    private fun text(value: String) = ByteBuffer.allocate(4).putInt(value.length + 1).array() + value.toByteArray(Charsets.US_ASCII)
    val server = sha1(initialKey, text("zurukko"))
    val client = sha1(initialKey, server, text("yasushineko"))
    val keepAliveRequest = sha1(initialKey, text("Magic_KeepAliveRequest"))
    val keepAliveResponse = sha1(initialKey, text("Magic_KeepAliveResponse"))
    init { require(initialKey.size == 20) }
    override fun close() { server.fill(0); client.fill(0); keepAliveRequest.fill(0); keepAliveResponse.fill(0) }
}

class RudpPacket(val tick: Long, val echoedTick: Long, val cumulativeAck: Long,
    val acknowledgements: LongArray, val sequence: Long, val payload: ByteArray)

enum class RudpFailure { UNREACHABLE, HANDSHAKE_TIMEOUT, INVALID_RESPONSE, SIGNATURE, TIMEOUT, DISCONNECTED, SOFTETHER_HANDSHAKE }
class RudpException(val failure: RudpFailure) : java.io.IOException(when (failure) {
    RudpFailure.UNREACHABLE -> "UDP/53 is unreachable"
    RudpFailure.HANDSHAKE_TIMEOUT -> "R-UDP handshake timed out on UDP/53"
    RudpFailure.INVALID_RESPONSE -> "Invalid R-UDP/DNS response"
    RudpFailure.SIGNATURE -> "R-UDP packet signature validation failed"
    RudpFailure.TIMEOUT -> "R-UDP communication timed out"
    RudpFailure.DISCONNECTED -> "Server disconnected the R-UDP stream"
    RudpFailure.SOFTETHER_HANDSHAKE -> "SoftEther handshake failed after R-UDP establishment"
})

object RudpPacketCodec {
    const val MAX_PACKET_SIZE = 1355
    private val serviceHash = sha1("softether_vpn".toByteArray(Charsets.US_ASCII))
    fun encode(key: ByteArray, packet: RudpPacket, iv: ByteArray, padding: Int): ByteArray {
        require(key.size == 20 && iv.size == 20 && padding in 1..255 && packet.payload.size <= 512 && packet.acknowledgements.size <= 64)
        val body = ByteBuffer.allocate(36 + packet.acknowledgements.size * 8 + packet.payload.size + padding)
            .putLong(packet.tick).putLong(packet.echoedTick).putLong(packet.cumulativeAck).putInt(packet.acknowledgements.size)
        packet.acknowledgements.forEach { body.putLong(it) }
        body.putLong(packet.sequence).put(packet.payload)
        repeat(padding) { body.put(padding.toByte()) }
        val encryptionKey = sha1(iv, key)
        val ciphertext = try { rc4(encryptionKey, body.array()) } finally { encryptionKey.fill(0); body.array().fill(0) }
        val signature = sha1(key, iv, ciphertext)
        for (i in signature.indices) signature[i] = (signature[i].toInt() xor serviceHash[i].toInt()).toByte()
        return signature + iv + ciphertext
    }
    fun decode(key: ByteArray, bytes: ByteArray): RudpPacket {
        if (bytes.size !in 77..MAX_PACKET_SIZE || key.size != 20) throw RudpException(RudpFailure.INVALID_RESPONSE)
        val iv = bytes.copyOfRange(20, 40); val ciphertext = bytes.copyOfRange(40, bytes.size)
        val signature = sha1(key, iv, ciphertext)
        for (i in signature.indices) signature[i] = (signature[i].toInt() xor serviceHash[i].toInt()).toByte()
        if (!MessageDigest.isEqual(signature, bytes.copyOf(20))) throw RudpException(RudpFailure.SIGNATURE)
        val encryptionKey = sha1(iv, key)
        val body = try { rc4(encryptionKey, ciphertext) } finally { encryptionKey.fill(0) }
        try {
            val padding = body.last().toInt() and 255
            if (padding == 0 || padding > body.size - 36) throw RudpException(RudpFailure.INVALID_RESPONSE)
            val b = ByteBuffer.wrap(body, 0, body.size - padding)
            val tick = b.long; val echoed = b.long; val maxAck = b.long; val n = b.int
            if (tick < 0 || echoed < 0 || maxAck < 0 || n !in 0..64 || b.remaining() < n * 8 + 8) throw RudpException(RudpFailure.INVALID_RESPONSE)
            val acks = LongArray(n) { b.long }
            if (acks.any { it < 0 }) throw RudpException(RudpFailure.INVALID_RESPONSE)
            val sequence = b.long
            if (b.remaining() > 512) throw RudpException(RudpFailure.INVALID_RESPONSE)
            return RudpPacket(tick, echoed, maxAck, acks, sequence, ByteArray(b.remaining()).also { b.get(it) })
        } finally { body.fill(0) }
    }
}
