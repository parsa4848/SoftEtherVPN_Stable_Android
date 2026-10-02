package com.blockto.sevpn.protocol

import java.nio.ByteBuffer
import java.security.SecureRandom

/** Exact Network.c DNS query (37 bytes) / response (42 bytes) wrappers.
 * IDs are opaque two bytes; lengths are network order. No DNS resolver. */
object RudpDnsCodec {
    private val random = SecureRandom()
    private val hex = "0123456789abcdef".toByteArray(Charsets.US_ASCII)
    private val query1 = byteArrayOf(1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 8)
    private val query2 = byteArrayOf(0, 0, 0x30, 0, 1, 0, 0, 0x29, 0x10, 0, 0, 0, 0x80.toByte(), 0)
    private val response1 = byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, 1, 0, 0, 0, 0, 8)
    private val response2 = byteArrayOf(0, 0, 0x30, 0, 1, 0xc0.toByte(), 0x0c, 0, 0x30, 0, 1)
    private val response3 = byteArrayOf(1, 0, 3, 8)
    fun query(payload: ByteArray, transaction: ByteArray, label: ByteArray): ByteArray {
        require(payload.size in 1..RudpPacketCodec.MAX_PACKET_SIZE && transaction.size == 2 && label.size == 4)
        val bytes = ByteArray(37 + payload.size)
        transaction.copyInto(bytes); query1.copyInto(bytes, 2)
        for (i in label.indices) {
            val value = label[i].toInt() and 255
            bytes[13 + i * 2] = hex[value ushr 4]; bytes[14 + i * 2] = hex[value and 15]
        }
        query2.copyInto(bytes, 21)
        bytes[35] = (payload.size ushr 8).toByte(); bytes[36] = payload.size.toByte()
        payload.copyInto(bytes, 37); return bytes
    }
    fun query(payload: ByteArray): ByteArray {
        val id = random.nextInt(65535) + 1
        // Stable writes Rand16() directly on its little-endian clients.
        return query(payload, byteArrayOf(id.toByte(), (id ushr 8).toByte()), ByteArray(4).also { random.nextBytes(it) })
    }
    fun responsePayload(bytes: ByteArray): ByteArray {
        if (bytes.size !in 43..(42 + RudpPacketCodec.MAX_PACKET_SIZE)) throw RudpException(RudpFailure.INVALID_RESPONSE)
        fun match(offset: Int, expected: ByteArray) = expected.indices.all { bytes[offset + it] == expected[it] }
        val length = ByteBuffer.wrap(bytes, 36, 2).short.toInt() and 65535
        if (!match(2, response1) || !match(21, response2) || !match(38, response3) || length != bytes.size - 38)
            throw RudpException(RudpFailure.INVALID_RESPONSE)
        if ((13..20).any { bytes[it].toInt().toChar() !in "0123456789abcdef" }) throw RudpException(RudpFailure.INVALID_RESPONSE)
        return bytes.copyOfRange(42, bytes.size)
    }
}
