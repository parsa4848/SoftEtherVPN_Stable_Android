/* Packet layout ported from pinned Stable Cedar/UdpAccel.c (Apache-2.0).
 * Copyright (c) SoftEther VPN Project. See THIRD_PARTY_NOTICES.md. */
package com.blockto.sevpn.protocol

import java.io.Closeable
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class UdpAccelerationPacket(val tick: Long, val echoedTick: Long, val payload: ByteArray)

class UdpAccelerationCodec(private val config: UdpAccelerationConfig) : Closeable {
    private val random = SecureRandom()
    private var nextIv = ByteArray(if (config.version == 2) 12 else 20).also { random.nextBytes(it) }
    internal fun encode(payload: ByteArray, tick: Long, echoedTick: Long, iv: ByteArray, padding: Int): ByteArray {
        require(payload.size <= 1600 && tick > 0 && echoedTick >= 0 && padding in 0..31)
        require(iv.size == if (config.version == 2) 12 else 20)
        val trailer = if (config.version == 1) 20 else 0
        val body = ByteBuffer.allocate(23 + payload.size + padding + trailer)
            .putInt(config.yourCookie.toInt()).putLong(tick).putLong(echoedTick)
            .putShort(payload.size.toShort()).put(0).put(payload).array()
        return if (config.version == 2) {
            val cipher = UdpCrypto.cipher()
            val key = config.sendKey.copyOf(32)
            try {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(iv))
                iv + cipher.doFinal(body)
            } finally { key.fill(0); body.fill(0) }
        } else {
            val key = sha1(config.sendKey, iv)
            try { iv + rc4(key, body) } finally { key.fill(0); body.fill(0) }
        }
    }
    fun encode(payload: ByteArray, tick: Long, echoedTick: Long): ByteArray {
        val base = nextIv.size + 23 + payload.size + if (config.version == 2) 16 else 20
        val maxPadding = minOf(32, 1464 - base).coerceAtLeast(0)
        val packet = encode(payload, tick, echoedTick, nextIv, if (maxPadding > 0) random.nextInt(maxPadding) else 0)
        val end = packet.size - if (config.version == 2) 16 else 0
        packet.copyInto(nextIv, 0, end - nextIv.size, end)
        return packet
    }
    fun decode(packet: ByteArray): UdpAccelerationPacket? {
        val ivSize = if (config.version == 2) 12 else 20
        val trailer = if (config.version == 2) 16 else 20
        if (packet.size !in (ivSize + 23 + trailer)..2048) return null
        val iv = packet.copyOfRange(0, ivSize)
        val encrypted = packet.copyOfRange(ivSize, packet.size)
        val body = try {
            if (config.version == 2) {
                val cipher = UdpCrypto.cipher(); val key = config.receiveKey.copyOf(32)
                try {
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(iv)); cipher.doFinal(encrypted)
                } finally { key.fill(0) }
            } else {
                val key = sha1(config.receiveKey, iv)
                try { rc4(key, encrypted) } finally { key.fill(0) }
            }
        } catch (_: GeneralSecurityException) { return null }
        finally { encrypted.fill(0) }
        try {
            if (body.size < 23 || (config.version == 1 && body.takeLast(20).any { it != 0.toByte() })) return null
            val b = ByteBuffer.wrap(body)
            if ((b.int.toLong() and 0xffffffffL) != config.myCookie) return null
            val tick = b.long; val echoed = b.long; val size = b.short.toInt() and 65535; val flags = b.get().toInt() and 255
            val extra = if (config.version == 1) 20 else 0
            if (tick <= 0 || echoed < 0 || flags != 0 || size > 1600 || size > b.remaining() - extra) return null
            if (size != 0 && size < 14) return null
            return UdpAccelerationPacket(tick, echoed, ByteArray(size).also { b.get(it) })
        } finally { body.fill(0) }
    }
    override fun close() { nextIv.fill(0) }
}
